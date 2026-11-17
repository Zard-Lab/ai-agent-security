"""Guard: a tool/function/MCP descriptor exposes a mutating operation on a shared or
multi-agent resource with no per-actor authorization field — CVE-2026-44654 class
(checklist §4, new item; agent-audit-kit's `shared_resource_authz.py`
AAK-AGENT-SHARED-RES-AUTHZ-001).

LibreChat <= 0.8.3 let a shared-agent editor delete file records via `DELETE /api/files`
that the owner had reused across multiple agents (CWE-863 Incorrect Authorization,
CVSS 8.1). Any agent that can call a tool exposing a mutating operation on a resource
reachable in a shared context could mutate another principal's resource, if the tool's
input schema carries no per-actor authorization field.

A JSON descriptor scan, not an AST analyzer: reads tool/function descriptors (`name` +
optional `description` + a parameter schema under `inputSchema`/`input_schema`/
`parameters`). The "shared/multi-agent" precondition is inferred from a file-level
multi-agent signal (an `agents` collection with more than one member, or a
`shared`/`scope: shared|workspace|team|org` marker) OR from shared-resource language in the
tool's own name/description. A tool annotated `"x-aak-shared-authz": "global-ok"` is
treated as an intentional global resource and suppressed.

Fires HIGH when a tool descriptor's name+description both match a mutating verb
(delete/remove/edit/update/overwrite/move) and a resource noun (file/record/resource/
document/entry/item/object/note/message/artifact/dataset/memory/conversation/thread), the
shared-context precondition holds, and no per-actor authorization field (owner/actor/
principal/author/user_id/caller/authoriz*/acl/tenant/requested_by/requester/subject_id)
appears anywhere in the tool's parameter schema.

Suppress an audited case with:

    {"//": "security: allow-shared-resource-authz", ...}

a top-level `"//"` key, which keeps the file valid JSON for every other consumer (a `//` comment
line, also honoured for JSONC-style descriptor files, makes a plain `.json` file unparseable).
Or annotate the specific tool descriptor with `"x-aak-shared-authz": "global-ok"`.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_files, pragma_present, read, rel

# A tool-descriptor `.json` file has no comment syntax (the documented opt-out is a `"//"` string value), so
# its pragma is matched on the raw text by contract (`dialect=None`, #1040 T5).
_PRAGMA = "security: allow-shared-resource-authz"

_MUTATE_RE = re.compile(r"\b(?:delete|remove|edit|update|overwrite|move)s?\b", re.IGNORECASE)
_WORD_SEP_RE = re.compile(r"[_\-]")
_RESOURCE_RE = re.compile(
    r"\b(?:file|record|resource|document|doc|entry|item|object|row|entity|"
    r"note|message|artifact|dataset|memory|conversation|thread)s?\b",
    re.IGNORECASE,
)
_AUTHZ_FIELD_RE = re.compile(
    r"owner|actor|principal|author|user[_-]?id|caller|authoriz|permission|"
    r"\bacl\b|tenant|requested[_-]?by|on[_-]?behalf|requester|subject[_-]?id",
    re.IGNORECASE,
)
_SHARED_TEXT_RE = re.compile(
    r"shared|multi[_-]?agent|cross[_-]?agent|\bteam\b|workspace|collaborat|"
    r"other agents|reused across|org[_-]?wide|tenant",
    re.IGNORECASE,
)
_GLOBAL_OK = "global-ok"
_SCHEMA_KEYS: tuple[str, ...] = ("inputSchema", "input_schema", "parameters")
_MARKERS: tuple[str, ...] = ('"inputSchema"', '"input_schema"', '"parameters"', '"tools"', '"agents"', '"name"')
_MAX_DOC_DEPTH = 12
_MAX_PARAM_DEPTH = 8

_STANDARDS = ["OWASP:A01", "CWE-863"]


def _collect_property_names(schema: Any, depth: int, acc: set[str]) -> None:
    if depth > _MAX_PARAM_DEPTH or not isinstance(schema, dict):
        return
    props = schema.get("properties")
    if isinstance(props, dict):
        for name, sub in props.items():
            acc.add(str(name))
            _collect_property_names(sub, depth + 1, acc)
    items = schema.get("items")
    if isinstance(items, dict):
        _collect_property_names(items, depth + 1, acc)
    for combinator in ("anyOf", "allOf", "oneOf"):
        branches = schema.get(combinator)
        if isinstance(branches, list):
            for branch in branches:
                _collect_property_names(branch, depth + 1, acc)


def _has_authz_field(schema: Any) -> bool:
    names: set[str] = set()
    _collect_property_names(schema, 0, names)
    return any(_AUTHZ_FIELD_RE.search(n) for n in names)


def _doc_shared_signal(node: Any, depth: int) -> bool:
    if depth > _MAX_DOC_DEPTH:
        return False
    if isinstance(node, dict):
        for key, val in node.items():
            kl = str(key).lower()
            if kl in ("agents", "subagents"):
                if isinstance(val, list) and len(val) > 1:
                    return True
                if isinstance(val, dict) and len(val) > 1:
                    return True
            if kl == "shared" and val is True:
                return True
            if kl == "scope" and isinstance(val, str) and val.strip().lower() in (
                "shared", "workspace", "team", "org", "organization",
            ):
                return True
            if _doc_shared_signal(val, depth + 1):
                return True
    elif isinstance(node, list):
        for item in node:
            if _doc_shared_signal(item, depth + 1):
                return True
    return False


def _iter_tool_descriptors(node: Any, depth: int, acc: list[tuple[str, str, dict[str, Any]]]) -> None:
    if depth > _MAX_DOC_DEPTH:
        return
    if isinstance(node, dict):
        name = node.get("name")
        if isinstance(name, str) and name:
            desc = node.get("description")
            desc_str = desc if isinstance(desc, str) else ""
            schema: dict[str, Any] = {}
            for key in _SCHEMA_KEYS:
                val = node.get(key)
                if isinstance(val, dict):
                    schema = val
                    break
            if desc_str or schema or "x-aak-shared-authz" in node:
                marker = node.get("x-aak-shared-authz")
                if isinstance(marker, str):
                    schema = {**schema, "__shared_authz_marker__": marker}
                acc.append((name, desc_str, schema))
        for val in node.values():
            _iter_tool_descriptors(val, depth + 1, acc)
    elif isinstance(node, list):
        for item in node:
            _iter_tool_descriptors(item, depth + 1, acc)


def _is_mutating(name: str, description: str) -> bool:
    blob = _WORD_SEP_RE.sub(" ", f"{name} {description}")
    return bool(_MUTATE_RE.search(blob) and _RESOURCE_RE.search(blob))


class SharedResourceAuthzGuard(Guard):
    id = "shared-resource-authz"
    title = "Tool exposes a mutating op on a shared/multi-agent resource with no per-actor authorization"
    area = "AI agent"

    # tools.json: delete_file tool, shared scope, no owner/actor field -> fires
    # shared-resource-authz/no-per-actor-authz.
    canary_plant = CanaryPlant(
        files={
            "tools.json": (
                '{\n'
                '  "scope": "shared",\n'
                '  "tools": [\n'
                '    {\n'
                '      "name": "delete_file",\n'
                '      "description": "Delete a file record",\n'
                '      "inputSchema": {"properties": {"file_id": {"type": "string"}}}\n'
                '    }\n'
                '  ]\n'
                '}\n'
            ),
        },
        expects=frozenset({
            "shared-resource-authz/no-per-actor-authz",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "mcp" in profile.features or "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".json",)):
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            raw = read(f)
            if not raw or pragma_present(_PRAGMA, raw, dialect=None):
                continue
            if '"name"' not in raw or not any(m in raw for m in _MARKERS):
                continue
            try:
                data = json.loads(raw.lstrip("\ufeff"))  # a Windows editor's BOM is not a parse failure
            except (ValueError, RecursionError):  # hostile deep nesting: skip the file, keep the guard
                continue

            doc_shared = _doc_shared_signal(data, 0)
            descriptors: list[tuple[str, str, dict[str, Any]]] = []
            _iter_tool_descriptors(data, 0, descriptors)

            seen: set[str] = set()
            for name, description, schema in descriptors:
                if not _is_mutating(name, description):
                    continue
                shared = doc_shared or bool(_SHARED_TEXT_RE.search(f"{name} {description}"))
                if not shared:
                    continue
                if schema.get("__shared_authz_marker__") == _GLOBAL_OK:
                    continue
                if _has_authz_field(schema):
                    continue
                if name in seen:
                    continue
                seen.add(name)
                out.append(self._finding(r, name))
        return out

    def _finding(self, r: str, name: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=r,
            message=(
                f"Tool {name!r} performs a mutating op on a shared/multi-agent "
                "resource but exposes no owner/actor/authorization field — "
                "CVE-2026-44654 class. Any agent that can call this tool could mutate "
                "another principal's resource."
            ),
            remediation=(
                "Add and enforce a per-actor authorization parameter (owner/actor/"
                "tenant_id/caller), or annotate the tool "
                '`"x-aak-shared-authz": "global-ok"` if the resource is intentionally '
                "global."
            ),
            rule="shared-resource-authz/no-per-actor-authz",
            standards=list(_STANDARDS),
        )
