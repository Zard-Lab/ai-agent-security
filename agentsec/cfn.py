"""Shared AWS CloudFormation template helpers for stack detection + the `cfn-*` guards.

No PyYAML at runtime (agentsec is dependency-free), and cfripper's own approach (`pycfmodel`, a
real structural model) doesn't fit that constraint either — same rule that shaped `agentsec.k8s`.
CloudFormation ships in two formats, so this module supports both, by two different mechanisms:

- **JSON** templates are parsed with the stdlib `json` module — a real, unambiguous parse, no
  regex guessing. `Resources` values are ordinary dicts (`json.loads` on a standard-library-only
  input preserves key order in CPython 3.7+), so a per-resource `Properties` dict is exactly what
  the template author wrote, structurally.
- **YAML** templates (the common case — AWS's own docs default to it) get the same house pattern
  `agentsec.k8s` uses for K8s manifests: indentation-scoped text splitting, not a full YAML parse.
  A CFN template is ONE logical document (unlike K8s's `---`-separated multi-manifest files), so
  the split is by RESOURCE, not by document: every line at the indent level directly under
  `Resources:` that looks like `LogicalId:` opens a new resource block, running until the next
  sibling key at that same indent (or a dedent below it, which closes the whole `Resources:`
  section). CFN's short-form intrinsic-function YAML tags (`!Ref`, `!GetAtt`, `!Sub`, ...) are
  never parsed as tags here — they're just text within whatever value line contains them, which is
  actually convenient for the guards: `MasterUserPassword: !Ref DBPassword` reads as a parameter
  reference (safe), not a literal secret, by the tag being visibly present in the block text a
  guard's regex can check for.

Both paths converge on ONE shape guards consume — `CfnResource(logical_id, resource_type, block)` —
so a guard's own detection regex runs identically against either format's `block` text.

Known, documented limits (same disclosure standard as `agentsec.k8s`'s own docstring):

- **Location is file-level, not line-level** — like every `k8s-*` guard, a `cfn-*` finding reports
  `path/to/template.yaml`, not a line number. CFN resources commonly span many lines and (for JSON)
  a block is a *reconstruction* (`json.dumps`) with no original line mapping to report anyway.
- **`Fn::If`-wrapped resource declarations** (a resource's own existence conditional on a
  CloudFormation Condition, not just a property value) are not unwrapped — the LogicalId itself is
  still found and its block still scanned, but a `Fn::If` sitting at the TOP of `Resources:` itself
  (wrapping multiple candidate resources under one condition, a rarer authoring style) is not
  specially handled and may be missed.
- **YAML block scalars** (`|`/`>`) inside a resource's `Properties` are captured as part of the
  block text like any other content — a guard's pattern could in principle match text that is
  itself inside a literal string value rather than a real CFN property key. Not observed as a
  practical FP source for the property-name-anchored patterns these guards use, but not proven
  impossible either.
- **Nested stacks** (`AWS::CloudFormation::Stack` referencing a separate child template file) are
  not followed — each template file is scanned independently; a vulnerable pattern in a child
  template is caught when that child file is itself scanned, not by following the reference.
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterator
from typing import Literal, NamedTuple

# A CFN template signature: the explicit version key is the strongest signal (present in the
# overwhelming majority of hand-authored templates), but it's optional per the CFN spec — a
# template with no Parameters/Outputs/Conditions can omit it entirely. So the fallback signal is
# structural: a `Resources:`/`"Resources":` key with at least one AWS resource `Type` value nearby
# in the same file — the same "recognize by shape, not by strict schema" approach `agentsec.k8s`
# uses for `kind: Pod`.
_TEMPLATE_FORMAT_VERSION = re.compile(r'AWSTemplateFormatVersion["\']?\s*[:=]')
# A trailing comment on the header (`Resources:  # ...`) is valid YAML and routine in
# hand-authored templates. Missing the `(?:#.*)?` tolerance (as `k8s.py:30`'s `_DOC_SEP`
# already carries) let a commented header go unrecognized: with the version key present the
# `cloudformation` feature still turned ON but `cfn_resources()` returned [], so all cfn-*
# guards silently found nothing (a failure that presents as success). The same tolerance is
# applied to the header match inside `iter_yaml_section_blocks` below (the shared section walker
# `_yaml_resources` and the cfn-rds parameter lookup both consume) (#856/#857).
_RESOURCES_KEY_YAML = re.compile(r"^Resources:\s*(?:#.*)?$", re.MULTILINE)
_RESOURCES_KEY_JSON = re.compile(r'"Resources"\s*:\s*\{')
_AWS_RESOURCE_TYPE = re.compile(r'"?Type"?\s*[:=]\s*["\']?AWS::[A-Za-z0-9]+::[A-Za-z0-9]+["\']?')

# YAML: a line at some indent `N` spaces holding a bare `Name:` (no value on the same line — a
# section-entry name key, not a scalar property) opens a new entry under a template section (a
# `Resources:` LogicalId, a `Parameters:` parameter name, ...). `\w` covers CFN's LogicalId /
# Parameter-name charset (alphanumeric only, no hyphens/underscores permitted by the spec).
_SECTION_ENTRY_KEY = re.compile(r"^([ \t]*)(\w+):[ \t]*(?:#.*)?$")
_YAML_TYPE_LINE = re.compile(
    r'^[ \t]*Type:[ \t]*["\']?(AWS::[A-Za-z0-9]+::[A-Za-z0-9]+)["\']?[ \t]*$', re.MULTILINE
)


class CfnResource(NamedTuple):
    """One `Resources:` entry, format-agnostic. `block` is the text a guard's regex scans —
    the literal source slice for YAML, a `json.dumps` reconstruction for JSON (see module
    docstring for what that reconstruction does and does not preserve). `from_json` records
    which of the two it is, which is what `pragma_dialect` answers from."""

    logical_id: str
    resource_type: str
    block: str
    from_json: bool = False

    @property
    def pragma_dialect(self) -> Literal["yaml"] | None:
        """The `comment_view` dialect a suppress pragma in `block` is matched under — pass it to
        `pragma_present(_PRAGMA, resource.block, dialect=resource.pragma_dialect)` so a pragma
        counts only as a real YAML comment INSIDE this resource (#1040 T3): a `Description:` or
        `Metadata:` scalar quoting it no longer silences the finding, and the reach stays the one
        resource, never the file. A YAML `block` is the literal source slice opening at the
        LogicalId line, so its view is the file's view at those lines. A JSON `block` has no
        comment grammar (and is a reconstruction, so it holds no comment to find), so it stays a
        raw match (`None`), the contract `comment_dialect_for` gives `.json`."""
        return None if self.from_json else "yaml"


def is_cfn_template_text(text: str) -> bool:
    """True if `text` looks like a CloudFormation template (JSON or YAML): the explicit
    `AWSTemplateFormatVersion` key, or a `Resources:`/`"Resources":` key with at least one
    `AWS::Service::Resource`-shaped `Type` value present anywhere in the file."""
    if _TEMPLATE_FORMAT_VERSION.search(text):
        return True
    has_resources_key = bool(_RESOURCES_KEY_YAML.search(text) or _RESOURCES_KEY_JSON.search(text))
    return has_resources_key and bool(_AWS_RESOURCE_TYPE.search(text))


def _json_resources(data: object) -> list[CfnResource]:
    if not isinstance(data, dict):
        return []
    resources = data.get("Resources")
    if not isinstance(resources, dict):
        return []
    out: list[CfnResource] = []
    for logical_id, resource in resources.items():
        if not isinstance(resource, dict):
            continue
        rtype = resource.get("Type")
        if not isinstance(rtype, str):
            continue
        block = json.dumps(resource, indent=2, ensure_ascii=False)
        out.append(CfnResource(logical_id=logical_id, resource_type=rtype, block=block, from_json=True))
    return out


def iter_yaml_section_blocks(text: str, section_key: str) -> Iterator[tuple[str, str]]:
    """Yield `(name, block)` for every immediate named entry directly under a YAML template's
    top-level `<section_key>:` section (`Resources`, `Parameters`, ...), by the same
    indentation-scoped splitting the `cfn-*` guards use everywhere else in this module: every line
    at the indent level directly under the section header that looks like `Name:` (a bare key, no
    value on the same line) opens a new entry block, running until the next sibling key at that
    same indent (or a dedent below it, which closes the whole section). `block` is the literal
    source slice, header line included.

    A trailing comment on the section header (`<section_key>:  # ...`) is tolerated — the same
    `(?:#.*)?` fix `k8s.py`'s `_DOC_SEP` carries, applied here once so both `_yaml_resources`
    (`Resources`) and the `cfn-rds-hardcoded-password-no-echo` guard's parameter lookup
    (`Parameters`) get it from ONE walker rather than each carrying its own drifting copy
    (#856 fixed the `Resources` copy; #857 is the `Parameters` copy this shared helper closes).

    `section_key` is `re.escape`d, so a caller passing an arbitrary section name can't inject
    regex metacharacters into the header pattern. Pure string ops — never raises on `str` input."""
    header = re.compile(rf"^{re.escape(section_key)}:\s*(?:#.*)?$")
    lines = text.splitlines()
    section_indent: int | None = None
    entry_indent: int | None = None
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if section_indent is None:
            if header.match(line):
                section_indent = len(line) - len(line.lstrip(" \t"))
            i += 1
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        indent = len(line) - len(line.lstrip(" \t"))
        if indent <= section_indent:
            break  # dedented out of the section entirely
        m = _SECTION_ENTRY_KEY.match(line)
        if entry_indent is None and m:
            entry_indent = len(m.group(1))
        if m and len(m.group(1)) == entry_indent:
            assert entry_indent is not None  # nosec B101 (type-narrowing only, not a runtime guard: m matched, so it was set above)
            name = m.group(2)
            block_lines = [line]
            j = i + 1
            while j < n:
                nxt = lines[j]
                nxt_stripped = nxt.strip()
                if nxt_stripped and not nxt_stripped.startswith("#"):
                    nxt_indent = len(nxt) - len(nxt.lstrip(" \t"))
                    if nxt_indent <= entry_indent:
                        break
                block_lines.append(nxt)
                j += 1
            yield name, "\n".join(block_lines)
            i = j
            continue
        i += 1


def _yaml_resources(text: str) -> list[CfnResource]:
    out: list[CfnResource] = []
    for logical_id, block in iter_yaml_section_blocks(text, "Resources"):
        type_match = _YAML_TYPE_LINE.search(block)
        if type_match:
            out.append(
                CfnResource(logical_id=logical_id, resource_type=type_match.group(1), block=block)
            )
    return out


def cfn_resources(text: str) -> list[CfnResource]:
    """Every `Resources:` entry in `text`, format-agnostic. Tries a real JSON parse first (the
    unambiguous path); falls back to the YAML indentation-block splitter. A file that is neither
    valid JSON nor recognizably YAML-shaped returns an empty list — never raises (guards must stay
    total, per the codebase-wide convention every other scan helper here follows)."""
    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return []
        return _json_resources(data)
    try:
        return _yaml_resources(text)
    except Exception:
        return []


_NESTED_PROPERTY_KEY = re.compile(r'^([ \t]*)"?(\w+)"?\s*:[ \t]*(?:\{)?[ \t]*(?:#.*)?$')


def nested_property_block(block: str, key: str) -> str | None:
    """The indentation-scoped sub-block under `key` inside a `CfnResource.block`, or `None` if
    `key` isn't present as a nested (non-scalar) property — e.g. carving `AssumeRolePolicyDocument`
    out of an `AWS::IAM::Role` so a guard can scope its scan to that property alone, rather than
    the whole resource block.

    Same walker `_yaml_resources` uses to carve a resource out of `Resources:`: a bare `key:` line
    (JSON: `"key": {` — `json.dumps(indent=2)` always opens an object's `{` on the key's own line,
    so the same one-line-key pattern with an optional trailing `{` covers both formats) opens the
    sub-block, which then runs while later lines are indented STRICTLY MORE than the key line — a
    sibling property or a dedent back out of the block ends it. This is the FIRST such key found
    (a resource property is not repeated), scoped to the block passed in — so scanning a value
    already carved from `Resources:` never bleeds into a sibling resource.

    Returns `None` (not the whole rest of the block) when `key:` appears only as a SCALAR line
    (`key: some_value` — a value on the same line means it isn't a nested object at all), so a
    caller can tell "no such nested property" apart from "an empty one," matching the general
    total-and-honest convention of this module's other lookups.

    Known limitation (disclosed not silently swallowed): a flow-style single-line value
    (`key: {...}` all on one line) also returns `None`, the same as a genuinely absent key — this
    walker only recognizes the indented block-style form. A caller using this to carve out and
    exclude a sub-block (e.g. `AssumeRolePolicyDocument`) will NOT exclude a flow-style occurrence,
    so a finding can still fire on content that is actually inside that sub-block. Flow-style IAM
    policy documents are uncommon in practice but not exotic; fixing this needs brace-counting
    rather than indentation-scoping, since a flow-style value has no indentation structure to walk.
    """
    lines = block.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = _NESTED_PROPERTY_KEY.match(line)
        if not m or m.group(2) != key:
            continue
        indent = len(m.group(1))
        nested_lines = [line]
        for nxt in lines[i + 1 :]:
            nxt_stripped = nxt.strip()
            if not nxt_stripped or nxt_stripped.startswith("#"):
                nested_lines.append(nxt)
                continue
            nxt_indent = len(nxt) - len(nxt.lstrip(" \t"))
            if nxt_indent <= indent:
                break
            nested_lines.append(nxt)
        return "\n".join(nested_lines)
    return None


_STATEMENT_KEY = re.compile(r'^([ \t]*)"?Statement"?\s*:[ \t]*(?:[\[{])?[ \t]*(?:#.*)?$')
_YAML_BULLET = re.compile(r"^[ \t]*-([ \t]|$)")
_JSON_OBJECT_OPEN = re.compile(r"^[ \t]*\{[ \t]*$")


def iter_statement_blocks(block: str) -> list[str]:
    """Every individual policy-statement's own text, from every `Statement` list anywhere in a
    `CfnResource.block` — a resource commonly carries more than one (an `AssumeRolePolicyDocument`
    trust `Statement`, plus one `PolicyDocument.Statement` per `Policies` entry), and each one's
    own list can hold several statements. Lets a guard check a condition against the SAME
    statement it co-occurs with, rather than "somewhere in the whole resource block" — the
    granularity gap behind (`cfn-iam-notaction-with-allow` matched `Effect: Allow` in one
    statement and `NotAction` in an unrelated sibling statement, firing on a legitimate
    `Deny`+`NotAction` guardrail elsewhere in the same resource).

    Splits each `Statement` list's own immediate children by indentation, the same walker
    `nested_property_block` uses to carve the list out in the first place: a YAML `-` bullet
    (`- key: value` or a dash alone on its own line, both valid and common) or a JSON object-only
    `{` line at the list's own shallowest indent opens a new statement, running until the next such
    line at that same indent (deeper lines — the statement's own properties — are content, not new
    statements). A statement's own nested lists (`Action: [...]`) are never mistaken for a new
    statement: their bullets sit at a STRICTLY DEEPER indent than the Statement-list's item indent,
    since they are properties *of* one statement, not siblings of it.

    Recognizes `Statement` as a YAML block list, a JSON array (`"Statement": [`), and a JSON
    single-object (`"Statement": {` — IAM allows a lone statement without wrapping it in an array,
    and `json.dumps(indent=2)` commonly emits it this way).

    Known limitation, disclosed not silently swallowed: a flow-style single-line `Statement`
    (`Statement: [{...}]` or `Statement: {...}` entirely on one line) is not recognized at all —
    this returns `[]` for it the same as a genuinely absent key, so a caller checking a condition
    across statements will see no statements rather than the real one(s). Flow-style single-line
    policies are uncommon in practice but not exotic; fixing this needs brace-counting to split a
    single line into items, not indentation-scoping.
    """
    lines = block.splitlines()
    out: list[str] = []
    i, n = 0, len(lines)
    while i < n:
        m = _STATEMENT_KEY.match(lines[i])
        if not m:
            i += 1
            continue
        key_indent = len(m.group(1))
        j = i + 1
        sub_lines: list[str] = []
        while j < n:
            nxt = lines[j]
            nxt_stripped = nxt.strip()
            if not nxt_stripped or nxt_stripped.startswith("#"):
                sub_lines.append(nxt)
                j += 1
                continue
            if len(nxt) - len(nxt.lstrip(" \t")) <= key_indent:
                break
            sub_lines.append(nxt)
            j += 1
        out.extend(_split_statement_items(sub_lines))
        i = j
    return out


def _split_statement_items(sub_lines: list[str]) -> list[str]:
    indents = [len(ln) - len(ln.lstrip(" \t")) for ln in sub_lines if ln.strip()]
    if not indents:
        return []
    item_indent = min(indents)
    items: list[str] = []
    current: list[str] = []
    for line in sub_lines:
        stripped = line.strip()
        is_new_item = (
            bool(stripped)
            and len(line) - len(line.lstrip(" \t")) == item_indent
            and (_YAML_BULLET.match(line) is not None or _JSON_OBJECT_OPEN.match(line) is not None)
        )
        if is_new_item and current:
            items.append("\n".join(current))
            current = [line]
        else:
            current.append(line)
    if current:
        items.append("\n".join(current))
    return items
