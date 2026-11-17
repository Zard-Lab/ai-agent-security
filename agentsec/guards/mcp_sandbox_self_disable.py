"""Guard: a tool/function JSON schema exposes a parameter that disables or weakens
sandboxing/isolation, settable by the LLM (checklist §4, new item;
agent-audit-kit's `sandbox_self_disable.py` AAK-MCP-SANDBOX-SELFDISABLE-001).

This is the **CVE-2026-42074** class: OpenClaude < 0.5.1 exposed
``dangerouslyDisableSandbox`` as part of the BashTool input schema, so the model could set
it to ``true`` in any tool call (CWE-284 Improper Access Control / CWE-306, CVSS 9.8). A
tool-call argument is the one input surface an LLM directly controls — a parameter that
lets the CALLER turn off the sandbox containing its own execution defeats the sandbox by
design, not by a bug in it.

Scope: a JSON-schema/descriptor scan, not an AST analyzer. Walks JSON-Schema
``properties`` (the model-facing parameter surface) under the standard tool-schema
container keys — ``inputSchema`` (MCP), ``input_schema`` (Anthropic tools), ``parameters``
(OpenAI function-calling) — plus a bare schema file whose top-level object itself carries
``properties``. A property is treated as NOT LLM-settable (and not flagged) when annotated
``readOnly: true``, ``"x-mcp-sandbox-control": "ops-only"`` (or ``operator-only`` /
``server-only``), or ``"x-llm-settable": false``.

Suppress an audited case (with these annotations already reviewed for a specific tool
schema file) by adding the string ``security: allow-mcp-sandbox-self-disable`` anywhere
in the file (e.g. a ``"_note"`` field) — JSON has no comment syntax, so this is a plain
substring match, not a ``#``-prefixed comment pragma.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_files, pragma_present, read, rel

# A tool-schema `.json` file has no comment syntax, so its pragma is matched on the raw text by contract
# (`dialect=None`, #1040 T5).
_PRAGMA = "security: allow-mcp-sandbox-self-disable"

_DANGEROUS_PARAM_RE = re.compile(
    r"dangerous(?:ly)?[_-]?disable"
    r"|disable[_-]?sandbox"
    r"|no[_-]?sandbox"
    r"|skip[_-]?isolation",
    re.IGNORECASE,
)
# `allow_unsafe*` on its own also names rendering/parsing switches (`allowUnsafeHtml` on a
# markdown renderer), which have nothing to do with containment. It only counts when the parameter
# name, the property's description, or the tool's name/description also mentions something
# sandbox/exec/shell/filesystem-shaped (`allowUnsafeExecution`, or `allowUnsafe` on a "Run a shell
# command" tool). The other alternatives above name a sandbox control outright and need no anchor.
_ALLOW_UNSAFE_RE = re.compile(r"allow[_-]?unsafe", re.IGNORECASE)
_SANDBOX_ANCHOR_RE = re.compile(
    r"sandbox|isolat|exec|shell|bash|command|subprocess|file[_-]?system|\bfs\b|\beval\b"
    r"|container|interpreter|terminal",
    re.IGNORECASE,
)

_SCHEMA_KEYS: tuple[str, ...] = ("inputSchema", "input_schema", "parameters")

_MARKERS: tuple[str, ...] = (
    '"inputSchema"', '"input_schema"', '"parameters"',
    '"properties"', '"type": "function"', '"type":"function"',
)

_MAX_DOC_DEPTH = 12
_MAX_PARAM_DEPTH = 8

_STANDARDS = ["CWE-284", "CWE-306", "OWASP-ASI:ASI04"]


def _is_ops_only(prop_schema: dict[str, Any]) -> bool:
    if prop_schema.get("readOnly") is True:
        return True
    if prop_schema.get("x-llm-settable") is False:
        return True
    marker = prop_schema.get("x-mcp-sandbox-control")
    return isinstance(marker, str) and marker.strip().lower() in (
        "ops-only", "operator-only", "server-only",
    )


def _text_of(node: Any) -> str:
    """The name/title/description strings of a schema or tool object, space-joined."""
    if not isinstance(node, dict):
        return ""
    return " ".join(
        v for k in ("name", "title", "description") if isinstance(v := node.get(k), str)
    )


def _is_dangerous(name: str, sub: Any, context: str) -> bool:
    if _DANGEROUS_PARAM_RE.search(name):
        return True
    if _ALLOW_UNSAFE_RE.search(name):
        return bool(_SANDBOX_ANCHOR_RE.search(f"{context} {name} {_text_of(sub)}"))
    return False


def _walk_schema_props(
    schema: Any,
    path: str,
    depth: int,
    out: list[tuple[str, str, bool]],
    context: str = "",
) -> None:
    if depth > _MAX_PARAM_DEPTH or not isinstance(schema, dict):
        return

    props = schema.get("properties")
    if isinstance(props, dict):
        for name, sub in props.items():
            child = f"{path}.{name}" if path else str(name)
            if _is_dangerous(str(name), sub, context):
                ops_only = isinstance(sub, dict) and _is_ops_only(sub)
                out.append((child, str(name), ops_only))
            if isinstance(sub, dict):
                _walk_schema_props(sub, child, depth + 1, out, context)

    items = schema.get("items")
    if isinstance(items, dict):
        _walk_schema_props(items, f"{path}[]", depth + 1, out, context)

    for combinator in ("anyOf", "allOf", "oneOf"):
        branches = schema.get(combinator)
        if isinstance(branches, list):
            for i, branch in enumerate(branches):
                _walk_schema_props(branch, f"{path}<{combinator}[{i}]>", depth + 1, out, context)


def _find_schema_objects(
    node: Any, depth: int, acc: list[tuple[dict[str, Any], str]]
) -> None:
    """Collect `(schema, context)` pairs; `context` is the enclosing tool object's own
    name/description plus the schema's, which is what anchors an ambiguous `allow_unsafe*`."""
    if depth > _MAX_DOC_DEPTH:
        return
    if isinstance(node, dict):
        for key, val in node.items():
            if key in _SCHEMA_KEYS and isinstance(val, dict):
                acc.append((val, f"{_text_of(node)} {_text_of(val)}"))
            _find_schema_objects(val, depth + 1, acc)
    elif isinstance(node, list):
        for item in node:
            _find_schema_objects(item, depth + 1, acc)


def _scan_document(data: Any) -> list[tuple[str, str, bool]]:
    schemas: list[tuple[dict[str, Any], str]] = []
    _find_schema_objects(data, 0, schemas)
    if isinstance(data, dict) and isinstance(data.get("properties"), dict):
        schemas.append((data, _text_of(data)))

    hits: list[tuple[str, str, bool]] = []
    seen: set[str] = set()
    for schema, context in schemas:
        local: list[tuple[str, str, bool]] = []
        _walk_schema_props(schema, "", 0, local, context)
        for param_path, name, ops_only in local:
            # Keyed per schema OBJECT: two tools that each expose `dangerouslyDisableSandbox` are
            # two findings (the second used to be dropped because the path text matched).
            dedupe_key = f"{id(schema)}|{param_path}|{ops_only}"
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            hits.append((param_path, name, ops_only))
    return hits


def _key_line(raw_text: str, name: str, nth: int) -> int:
    """1-based line of the `nth` (0-based) `"name":` key in `raw_text`; line 1 if not found."""
    pos = -1
    for _ in range(nth + 1):
        m = re.compile(rf'"{re.escape(name)}"\s*:').search(raw_text, pos + 1)
        if m is None:
            return 1
        pos = m.start()
    return raw_text.count("\n", 0, pos) + 1


class McpSandboxSelfDisableGuard(Guard):
    id = "mcp-sandbox-self-disable"
    title = "Tool schema exposes an LLM-settable sandbox-disable parameter"
    area = "AI agent"

    # tool-schema.json: BashTool inputSchema has a "dangerouslyDisableSandbox" property,
    # not marked readOnly -> fires mcp-sandbox-self-disable/llm-settable-disable.
    canary_plant = CanaryPlant(
        files={
            "tool-schema.json": (
                '{\n'
                '  "name": "BashTool",\n'
                '  "inputSchema": {\n'
                '    "type": "object",\n'
                '    "properties": {\n'
                '      "command": {"type": "string"},\n'
                '      "dangerouslyDisableSandbox": {"type": "boolean"}\n'
                '    }\n'
                '  }\n'
                '}\n'
            ),
        },
        expects=frozenset({
            "mcp-sandbox-self-disable/llm-settable-disable",
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
            raw_text = read(f)
            if not raw_text or pragma_present(_PRAGMA, raw_text, dialect=None):
                continue
            if not any(marker in raw_text for marker in _MARKERS):
                continue
            try:
                data = json.loads(raw_text)
            except (ValueError, RecursionError):  # hostile deep nesting: skip the file, keep the guard
                continue

            seen_names: dict[str, int] = {}
            for param_path, name, ops_only in _scan_document(data):
                if ops_only:
                    continue
                # The n-th hit for a given property name maps to that name's n-th key in the text
                # (both walk the document in order), so several tools in one file each get their
                # own line rather than all pointing at the first.
                nth = seen_names.get(name, 0)
                seen_names[name] = nth + 1
                out.append(self._finding(r, param_path, name, _key_line(raw_text, name, nth)))
        return out

    def _finding(self, r: str, param_path: str, name: str, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="critical",
            title=self.title,
            location=f"{r}:{line}",
            message=(
                f"Tool schema parameter `{param_path}` (`{name}`) disables or weakens "
                "sandboxing/isolation and is LLM-settable (present in the model-facing "
                "input schema) — CVE-2026-42074 class (OpenClaude's "
                "`dangerouslyDisableSandbox`, CVSS 9.8). The model, the one input surface "
                "a caller directly controls via tool-call arguments, can turn off the "
                "containment around its own tool execution."
            ),
            remediation=(
                "Remove the parameter from the model-facing schema entirely (make it an "
                "operator-only server-side setting), or if it must remain in the schema "
                "for another reason, mark it `readOnly: true` / `\"x-llm-settable\": "
                "false` / `\"x-mcp-sandbox-control\": \"ops-only\"`."
            ),
            rule="mcp-sandbox-self-disable/llm-settable-disable",
            standards=list(_STANDARDS),
        )
