"""Shared Azure Bicep helpers for stack detection + the `bicep-*` guards.

Bicep is a distinct DSL (not JSON, not YAML) that the Azure CLI COMPILES to ARM JSON before
deployment — the compiled output is exactly what `agentsec.arm` already scans. This module exists
for the genuinely Bicep-SYNTAX-specific checks (built around Bicep's `@secure()` decorator, `param`/
`output` declarations, and `resource` blocks) that only make sense against the authored `.bicep`
source, before compilation erases the decorator and collapses everything to plain JSON values.

No PyYAML/no real Bicep compiler dependency (agentsec is dependency-free): resources, params, and
outputs are extracted with a text/regex walker, same house style as `agentsec.cfn`/`agentsec.k8s`.
Detecting a `.bicep` file itself needs no content sniffing at all — unlike JSON/YAML formats, the
`.bicep`/`.bicepparam` extensions are unambiguous, so `detect.py` gates the `bicep` feature on file
suffix alone (mirrors how `.tf` gates the `terraform` feature).

`.bicepparam` support (`bicepparam_assignments()`) was added for `bicep-param-file-insecure-secret-
value` (7/7): a `.bicepparam` file is a DISTINCT, smaller sub-syntax from a `.bicep`
template — it only assigns `param <name> = <value>` (no type annotation, since the type comes from
the `using` target template), so it needs its own parser rather than reusing `bicep_params()`.

Bicep's brace-block shape is close enough to Terraform's HCL that this module's line-scanner
mirrors `guards/base.py::_tf_line_scan` structurally, with two syntax differences: Bicep string
literals are single-quoted (`'...'`), not double-quoted, and Bicep has no heredoc syntax (its
multi-line-string equivalent is a triple-single-quote `'''...'''` block, NOT handled here — a
documented limitation, since it is rare in the property values these guards care about).

Known, documented limits (same disclosure standard as `agentsec.k8s`/`agentsec.cfn`/`agentsec.arm`):

- **Location is line-level for params/outputs** (the declaration line itself), but **block-level
  for resources** (no attempt to report the exact nested property line within a resource body).
- **Triple-quote multi-line strings (`'''...'''`) are not brace/quote-aware** — a `{`/`}` or `'`
  inside one could desync structural brace counting for a resource block that contains one. Not
  observed as a practical issue for the property shapes these guards scan (short single-line
  values), but not proven impossible either.
- **Decorators are recognized on the line(s) immediately above a `param`/`output` declaration**,
  skipping any blank lines OR `//` line comments between them, and stripping a `//` comment TRAILING
  on the decorator's own line (`@secure() // note`) before the match (the Bicep compiler treats all
  three as whitespace, so `@secure()` still applies across them). One thing is NOT handled and still
  breaks the association: a `/* ... */` **block** comment between a decorator and its declaration. It
  is an accepted remaining limit, not observed as common in practice (idiomatic Bicep puts a `//` doc
  comment on its OWN line above the declaration, which IS handled).
- **Module-scoped params/outputs** (inside a `module ... = { ... params: { ... } }` block) are not
  distinguished from top-level ones; the regex-based extraction finds `param`/`output`/`resource`
  keywords wherever they appear at the start of a line, regardless of nesting context.
- **Multi-line VALUES are accumulated for `param` defaults only.** A `param` default left open at
  end of line absorbs following lines until its `{}`/`[]` brackets balance (`_accumulate_default`,
  capped at `_MAX_DEFAULT_LINES`) -- without that, a multi-line default is truncated to its bare
  opening token, which is indistinguishable from a populated one-line literal. `output` VALUES and
  `.bicepparam` assignment values are still captured single-line-only; neither is consumed as a
  literal by any current guard (the output guard reads the NAME and decorators; the `.bicepparam`
  guard only asks whether the value opens with a quote, and a truncated `{`/`[` correctly does
  not), so the same accumulation is not carried there until something needs it.
- **A user-defined function is only seen where it is DECLARED** (`bicep_user_functions`); one
  imported from another module (`import { ... } from '...'`) is not resolved.
"""
from __future__ import annotations

import re
from typing import NamedTuple

# --- Bicep-flavored brace/string-aware line scan (single-quoted strings, // comments only) -----
_SQ_STRING = re.compile(r"'(?:\\.|[^'\\])*'")


def _bicep_code_only(line: str) -> str:
    """`line` with single-quoted string CONTENTS emptied and any `//` line comment removed, so a
    structural delimiter sitting inside a string value or a comment can't desync depth tracking.
    Triple-quoted multi-line strings are NOT handled (see module docstring)."""
    return _SQ_STRING.sub("''", line).split("//", 1)[0]


def _bicep_line_scan(line: str) -> int:
    """Structural BRACE delta (`{` vs `}`) for one Bicep line, string/comment aware (see
    `_bicep_code_only`). Drives `resource` block extraction."""
    code = _bicep_code_only(line)
    return code.count("{") - code.count("}")


def _bicep_bracket_scan(fragment: str) -> int:
    """Structural delta counting BOTH brace and square-bracket pairs, string/comment aware (see
    `_bicep_code_only`). Drives multi-line `param` default accumulation, whose value may be either
    an object (`{ ... }`) or an array (`[ ... ]`) literal, so brace-only counting is not enough."""
    code = _bicep_code_only(fragment)
    return (code.count("{") + code.count("[")) - (code.count("}") + code.count("]"))


_DECORATOR_LINE = re.compile(r"^\s*@(?P<name>\w+)\s*\((?P<args>.*)\)\s*$")


def _decorators_above(lines: list[str], idx: int) -> frozenset[str]:
    """The set of decorator names (e.g. `"secure"`) on the consecutive `@name(...)` lines
    immediately above `lines[idx]`. Blank lines and `//` line comments between them are skipped,
    and a `//` comment TRAILING on the decorator's own line (`@secure() // note`) is stripped
    before the match (via `_bicep_code_only`) — the Bicep compiler treats all three as whitespace
    and attaches the decorator to the following declaration regardless. Any other non-decorator
    line stops the walk — so a preceding `param`/`output`/`resource` line still terminates it, and
    a comment cannot leak an earlier declaration's decorators onto a later one. NOT handled (see
    module docstring): a `/* ... */` block comment between the two."""
    names: set[str] = set()
    i = idx - 1
    while i >= 0:
        stripped = lines[i].strip()
        if not stripped or stripped.startswith("//"):
            i -= 1
            continue
        m = _DECORATOR_LINE.match(_bicep_code_only(lines[i]))
        if not m:
            break
        names.add(m.group("name"))
        i -= 1
    return frozenset(names)


# --- resources ------------------------------------------------------------------------------
_RESOURCE_OPEN = re.compile(
    r"^\s*resource\s+(?P<name>\w+)\s+'(?P<type>[^'@]+)@[^']*'\s*=\s*\{"
)


class BicepResource(NamedTuple):
    """One top-level `resource <name> '<type>@<apiVersion>' = { ... }` block. `block` is the
    literal source slice (opening line included, closing `}` line excluded)."""

    resource_type: str
    name: str
    start_line: int
    block: str


def bicep_resources(text: str) -> list[BicepResource]:
    """Every top-level `resource` block in `text`. Brace depth is tracked from the resource's
    own opening line only, string/comment aware (see `_bicep_line_scan`). Never raises."""
    out: list[BicepResource] = []
    lines = text.splitlines()
    n = len(lines)
    i = 0
    while i < n:
        m = _RESOURCE_OPEN.match(lines[i])
        if not m:
            i += 1
            continue
        start = i + 1
        depth = _bicep_line_scan(lines[i])
        body = [lines[i]]
        j = i + 1
        while j < n and depth > 0:
            depth += _bicep_line_scan(lines[j])
            if depth > 0:
                body.append(lines[j])
            j += 1
        out.append(
            BicepResource(resource_type=m.group("type"), name=m.group("name"), start_line=start,
                          block="\n".join(body))
        )
        i = j
    return out


# --- params -----------------------------------------------------------------------------------
_PARAM_LINE = re.compile(
    r"^\s*param\s+(?P<name>\w+)\s+(?P<type>[\w.\[\]]+)\s*(?:=\s*(?P<default>.+?)\s*)?$"
)

# Ceiling on the extra lines a multi-line `param` default may absorb. Bounds the blast radius of an
# unbalanced `{`/`[` in a malformed file: it can swallow at most this many lines, never the rest of
# the file.
_MAX_DEFAULT_LINES = 200


class BicepParam(NamedTuple):
    """One `param <name> <type>` declaration (optionally `@decorator()`-annotated and/or
    `= <default>`-valued). `default` is the raw RHS text (`None` if no default is given)."""

    name: str
    type_str: str
    decorators: frozenset[str]
    default: str | None
    line: int


def _accumulate_default(lines: list[str], idx: int, first: str) -> tuple[str, int]:
    """A `param` default's full raw text plus the index of its LAST line, given the fragment
    `_PARAM_LINE` captured from the declaration line `lines[idx]` itself.

    A default that closes on its own line is returned unchanged. One left open -- an object/array
    literal spanning lines, which is ordinary Bicep formatting -- absorbs the following lines until
    its brackets balance (string/comment aware, see `_bicep_bracket_scan`), capped at
    `_MAX_DEFAULT_LINES`. Without this the captured default of a multi-line literal is just its
    opening `{`/`[` token, which reads as a non-empty literal even when the literal is an empty
    placeholder written across two lines. An unbalanced or truncated literal returns what it
    managed to absorb rather than raising."""
    depth = _bicep_bracket_scan(first)
    if depth <= 0:
        return first, idx
    parts = [first]
    last = idx
    limit = min(len(lines), idx + 1 + _MAX_DEFAULT_LINES)
    j = idx + 1
    while j < limit:
        parts.append(lines[j])
        last = j
        depth += _bicep_bracket_scan(lines[j])
        if depth <= 0:
            break
        j += 1
    return "\n".join(parts), last


def bicep_params(text: str) -> list[BicepParam]:
    """Every top-level `param` declaration in `text`, with its decorators (see
    `_decorators_above`) and raw default-value text if one is given. A default that is a multi-line
    object/array literal is captured whole (see `_accumulate_default`), not truncated to its
    opening token, and the lines it spans are not re-scanned for further declarations. Never
    raises."""
    out: list[BicepParam] = []
    lines = text.splitlines()
    n = len(lines)
    i = 0
    while i < n:
        m = _PARAM_LINE.match(lines[i])
        if not m:
            i += 1
            continue
        default = m.group("default")
        last = i
        if default is not None:
            default, last = _accumulate_default(lines, i, default)
        out.append(
            BicepParam(
                name=m.group("name"),
                type_str=m.group("type"),
                decorators=_decorators_above(lines, i),
                default=default,
                line=i + 1,
            )
        )
        i = last + 1
    return out


# --- outputs ------------------------------------------------------------------------------------
_OUTPUT_LINE = re.compile(r"^\s*output\s+(?P<name>\w+)\s+(?P<type>[\w.\[\]]+)\s*=\s*(?P<value>.+)$")


class BicepOutput(NamedTuple):
    """One `output <name> <type> = <value>` declaration, with its decorators (see
    `_decorators_above`)."""

    name: str
    type_str: str
    decorators: frozenset[str]
    value: str
    line: int


def bicep_outputs(text: str) -> list[BicepOutput]:
    """Every top-level `output` declaration in `text`, with its decorators. Never raises."""
    out: list[BicepOutput] = []
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        m = _OUTPUT_LINE.match(line)
        if not m:
            continue
        out.append(
            BicepOutput(
                name=m.group("name"),
                type_str=m.group("type"),
                decorators=_decorators_above(lines, idx),
                value=m.group("value"),
                line=idx + 1,
            )
        )
    return out


# --- user-defined functions -------------------------------------------------------------------
_FUNC_DECLARATION = re.compile(r"^\s*func\s+(?P<name>\w+)\s*\(")


def bicep_user_functions(text: str) -> frozenset[str]:
    """The names of the user-defined functions DECLARED in `text` (Bicep's own
    `func <name>(<args>) <type> => <expression>` syntax; an `@export()`/`@description()` decorator
    above the declaration does not affect the match).

    Lets a caller tell a user-defined call apart from a built-in one that merely shares its shape.
    `bicep-secure-param-in-nested-deployment` uses it so a user function named `list*` is not
    mistaken for one of Azure's `list*()` credential-retrieval actions -- that family is open-ended
    by design (any resource-provider operation whose name starts with `list`), so it can only be
    matched by prefix, never by an allowlist that would go stale into false negatives.

    A function IMPORTED from another module (`import { ... } from '...'`) is NOT resolved here --
    only local declarations are seen, so an imported `list*`-named function is still treated as an
    Azure action (the same conservative flag-rather-than-miss bias the guard documents). Never
    raises."""
    out: set[str] = set()
    for line in text.splitlines():
        m = _FUNC_DECLARATION.match(line)
        if m:
            out.add(m.group("name"))
    return frozenset(out)


# --- .bicepparam assignments ---------------------------------------------------------------
_PARAM_FILE_ASSIGNMENT = re.compile(r"^\s*param\s+(?P<name>\w+)\s*=\s*(?P<value>.+?)\s*$")


class BicepParamFileAssignment(NamedTuple):
    """One `param <name> = <value>` assignment in a `.bicepparam` file."""

    name: str
    value: str
    line: int


def bicepparam_assignments(text: str) -> list[BicepParamFileAssignment]:
    """Every top-level `param <name> = <value>` assignment in a `.bicepparam` file (a
    distinct, smaller sub-syntax from `.bicep` templates -- no type annotation, since the
    type comes from the `using` target). Never raises."""
    out: list[BicepParamFileAssignment] = []
    for idx, line in enumerate(text.splitlines()):
        m = _PARAM_FILE_ASSIGNMENT.match(line)
        if m:
            out.append(BicepParamFileAssignment(name=m.group("name"), value=m.group("value"), line=idx + 1))
    return out
