"""Guard: an MCP tool's own declared name admits it is a raw code/command-execution primitive
(checklist §4, `4-mcp-tool-trust`; mined from `erayyilmmaz/mcp-security-scanner`'s real
`DangerousTool`/`check_dangerous_tool` check, verified against the real fetched source).

Standards align to the sibling guards already mapped to `4-mcp-tool-trust`
(`mcp-tool-unverified`/`mcp-tool-description-injection`): `OWASP-LLM:LLM01`/`LLM03`,
`OWASP-ASI:ASI04`, plus `CWE-78` (OS Command Injection) for this guard's own exec-primitive
framing.

MCP tool schemas are read by name-and-description before an orchestrator (or a human) decides
whether a call is safe. A tool whose literal `name` is `eval`, `exec`, `system`, `subprocess`,
`run_shell`, or `shell_exec` is not merely under-annotated — it IS a raw interpreter or OS-shell
invocation surface by construction, regardless of what `annotations`/`inputSchema` it carries. No
`destructiveHint`/`readOnlyHint`/confirmation parameter can make arbitrary code or command
execution safe the way they can make a scoped `delete_record` call safer, so this fires
unconditionally rather than only on a missing-annotation gap.

  **`dangerous-tool-name`** (HIGH, surfacing): a tool-schema dict's literal `name` value,
  lowercased, exactly equals one of the raw-execution-primitive names above. A name is evidence of
  intent, not of reachable execution (an audited, sandboxed scripting tool can carry the same
  name), so the guard is a review signal: HIGH still fails the default `--fail-on high` gate, but
  `surfacing = True` ranks it below a proven finding of the same severity.

**Why this is not already covered.** `mcp_tool_description_injection.py`'s existing
`missing-destructive-hint`/`readonly-hint-contradicts-name`/`destructive-tool-missing-
confirmation-param` rules match a MUTATING-verb name (`write|delete|update|create|remove|drop|
execute|modify|purge`) and then check whether the tool DISCLOSES the mutation — a different
question from this guard's "the name itself is a code/command-execution primitive, no annotation
fixes that." The two rule sets barely overlap: `execute_command` happens to satisfy both (the
`execute` verb AND an exact-match in the source's own dangerous-name list), but `eval`/`exec`/
`system`/`subprocess`/`run_shell`/`shell_exec` match none of the mutating verbs at all — a tool
literally named `eval` currently passes every existing MCP guard clean. Verified by grepping
every guard in this project for `rm -rf`/dangerous-tool-name style literal checks before writing
this one; none existed.

**Deliberately narrower than the source.** `erayyilmmaz`'s own `DANGEROUS_TOOLS` set also
includes `rm`, `delete`, `drop_table`, and `truncate` — kept OUT of this guard on purpose:
`delete`/`drop_table` already match the mutating-verb family above (disclosure-based handling is
the right answer for a single scoped destructive action, not a blanket ban), and `rm`/`truncate`
are themselves just one destructive VERB, not a distinct capability class — folding them in here
would re-litigate the same disclosure-vs-ban design question `missing-destructive-hint` already
answers, for no detection gain (a tool bare-named exactly `rm` is vanishingly rare next to
`delete_file`/`remove_item`, which the verb family already reaches). What's novel here is
strictly the ARBITRARY-CODE/SHELL-EXECUTION class, where no scoping or confirmation parameter can
narrow the blast radius the way it can for a delete.

Exact lowercase equality only, not a substring or segment match — `execute_query`/`system_info`/
`get_system_status` must never fire (`system`/`exec` as a SEGMENT inside an ordinary read-only
tool name is common; only the bare primitive name itself is the signal, matching the source's
own `tool_name.lower() in DANGEROUS_TOOLS` exact-equality design, not a wider FP-prone segment
match).

Requires the dict to carry an `inputSchema` or `description` key alongside `name` (the same
disambiguator `mcp_tool_description_injection.py::_first_mutating_tool_line` uses) so an
unrelated `{"name": "eval", "value": ...}` config/payload dict never counts as an MCP tool
declaration. The two keys are not equally strong: `inputSchema` is MCP's own camelCase spelling
and qualifies the dict on its own, so a schema list kept in a module the server imports
(`tools.py`) still fires. A dict with only `description` is ordinary data in most codebases
(`{"name": "system", "description": "SI measurement system"}`, a chat message, a dependency
record), and the `mcp` feature is repo-level, so that form also needs the FILE itself to import
the MCP SDK (`_FILE_HAS_MCP_MARKER`, the same marker `mcp_session_id_security.py` uses), the
per-file half of the sibling's disambiguator.

Python only (dict-literal AST, mirroring the sibling MCP guards' Python-first scope for structural
tool-schema checks). Suppress an audited case (e.g. a deliberately sandboxed scripting tool with
its own isolation layer) with:

    # security: allow-mcp-raw-execution-tool-name
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from agentsec.astutil import safe_ast_parse
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    read,
    rel,
)

_PRAGMA = "security: allow-mcp-raw-execution-tool-name"
_STANDARDS = ["OWASP-LLM:LLM03", "OWASP-LLM:LLM01", "OWASP-ASI:ASI04", "CWE-78"]

_RAW_EXECUTION_NAMES = frozenset({
    "eval", "exec", "system", "subprocess", "run_shell", "shell_exec",
})

# The file imports the MCP SDK. Gates only the description-only dict form (see the docstring).
_FILE_HAS_MCP_MARKER = re.compile(r"^[ \t]*(?:from|import)[ \t]+(?:mcp|fastmcp)\b", re.MULTILINE)


def _dict_str_key(node: ast.Dict, key: str) -> ast.expr | None:
    for k, v in zip(node.keys, node.values, strict=True):
        if isinstance(k, ast.Constant) and k.value == key:
            return v
    return None


def _const_str(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _dict_key_lineno(node: ast.Dict, key: str) -> int:
    for k in node.keys:
        if isinstance(k, ast.Constant) and k.value == key:
            return k.lineno
    return node.lineno


def _iter_dangerous_tool_name_dicts(tree: ast.AST, *, file_is_mcp: bool) -> list[ast.Dict]:
    out: list[ast.Dict] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        name_val = _const_str(_dict_str_key(node, "name"))
        if name_val is None or name_val.lower() not in _RAW_EXECUTION_NAMES:
            continue
        if _dict_str_key(node, "inputSchema") is None and not (
            file_is_mcp and _dict_str_key(node, "description") is not None
        ):
            continue
        out.append(node)
    return out


class McpRawExecutionToolNameGuard(Guard):
    id = "mcp-raw-execution-tool-name"
    title = "MCP tool's own declared name is a raw code/command-execution primitive"
    area = "AI agent"
    surfacing = True

    # mcp_tools.py: a tool schema dict named "eval" with a real inputSchema -> fires
    # mcp-raw-execution-tool-name/dangerous-tool-name (HIGH).
    canary_plant = CanaryPlant(
        files={
            "mcp_tools.py": (
                "EVAL_TOOL = {\n"
                '    "name": "eval",\n'
                '    "description": "Evaluate an expression",\n'
                '    "inputSchema": {"type": "object", "properties": {"expr": {"type": "string"}}},\n'
                "}\n"
            ),
        },
        expects=frozenset({"mcp-raw-execution-tool-name/dangerous-tool-name"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "mcp" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".py",)):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            text = read(f)
            if not text or pragma_present(_PRAGMA, text, dialect="python"):
                continue
            tree = safe_ast_parse(text, filename=f)
            if tree is None:
                continue
            file_is_mcp = bool(_FILE_HAS_MCP_MARKER.search(text))
            for tool in _iter_dangerous_tool_name_dicts(tree, file_is_mcp=file_is_mcp):
                out.append(self._finding(root, f, tool))
        return out

    def _finding(self, root: Path, f: Path, tool: ast.Dict) -> Finding:
        lineno = _dict_key_lineno(tool, "name")
        name_val = _const_str(_dict_str_key(tool, "name")) or ""
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=(
                f"This MCP tool is declared with the name '{name_val}', a raw code or OS-"
                "command execution primitive. No annotation (destructiveHint, readOnlyHint, a "
                "confirmation parameter) narrows this risk the way it can for a scoped "
                "destructive action: exposing eval/exec/system/subprocess/a raw shell runner as "
                "an MCP tool hands any caller (including a model acting on injected instructions) "
                "arbitrary code or command execution."
            ),
            remediation=(
                "Remove this tool, or replace it with a set of narrowly-scoped tools that each "
                "perform one specific, bounded operation instead of exposing raw execution. If a "
                "sandboxed scripting capability is genuinely required, isolate it (a separate "
                f"process/container with no credential access) and suppress with `# {_PRAGMA}`."
            ),
            rule="mcp-raw-execution-tool-name/dangerous-tool-name",
            standards=list(_STANDARDS),
        )
