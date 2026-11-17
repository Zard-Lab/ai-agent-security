"""Guard: LLM-selectable dynamic function dispatch via globals()/getattr() reflection
(OWASP-LLM:LLM06 Excessive Agency, CWE-470 Unsafe Reflection).

An agent framework that lets an LLM's own output choose WHICH function/tool gets called
by NAME, dispatched dynamically, is a code-execution-by-LLM-output risk: if the dispatch
mechanism does not validate the name against a fixed allowlist first, a prompt-injection
attacker who controls (or influences) that name can make the agent invoke an arbitrary
function in the process's namespace.

Two concrete Python reflection idioms, fired only when the LOOKUP and the immediate CALL
happen together on the same line — a lookup that is merely stored, or a lookup keyed by a
hardcoded string literal, is not the dangerous pattern and stays silent:

    globals()[tool_name]()            # dynamic key, called immediately -> fires
    getattr(self, action_name)()      # dynamic name, called immediately -> fires

    globals()["hardcoded_fn"]()       # literal key -> safe, silent
    getattr(obj, "fixed_method_name")()   # literal name -> safe, silent
    handler = getattr(obj, name)      # looked up but not called here -> silent

Provenance gate: the file must ALSO carry an LLM/agent-tool signal (an LLM SDK call, or a
`@tool`/`StructuredTool`/`create_react_agent`/`tool_calls` marker) before either rule fires. The
reflection idiom by itself is ordinary Python (event bus, visitor pattern, CLI dispatch), so
without that same-file signal the guard stays silent even in a repo with the `llm` feature -- it
flags LLM-tool dispatch, not every dynamic call. Conservative / FN-biased (a dispatch split into a
module separate from the LLM call is a documented miss), mirroring the sibling guards' provenance gate.

Sourced from llmarmor/llmarmor's LLM08 "Excessive Agency" rule
(`src/llmarmor/rules/llm08_excessive_agency.py`), cross-checked against agentsec's
`agent-tool-overpermission` guard, which covers dangerous tool CLASSES (ShellTool,
PythonREPLTool), the `allow_dangerous_requests` bypass flag, subprocess-in-a-registered-
tool, and unfiltered toolkit loads -- but not this specific dynamic-name-dispatch pattern
where the callable itself is chosen at runtime by a non-literal name.

Suppress an audited case with a trailing comment on the same line:

    getattr(self, action_name)()  # security: allow-llm-tool-dynamic-dispatch
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    pragma_line_set,
    python_scan_dirs,
    read,
    rel,
    strip_python_strings,
)

# `(?<!\.)` excludes a method call like `self.globals()[...]` / `obj.getattr(...)` from matching
# the builtin — mirrors `code_injection_eval_exec.py`'s same convention for `eval`/`exec`.
_GLOBALS_SUBSCRIPT = re.compile(r"(?<!\.)\bglobals\s*\(\s*\)\s*\[")
_GETATTR_CALL = re.compile(r"(?<!\.)\bgetattr\s*\(")
_PRAGMA = re.compile(r"#\s*security:\s*allow-llm-tool-dynamic-dispatch")

# A whole argument that is nothing but a single quoted string literal (optional r/b/u prefix --
# deliberately NOT f/F, since an f-string can embed a dynamic expression and is therefore treated
# as non-literal, matching the `_FSTRING`-is-dynamic convention the sibling eval/exec and
# dynamic-import guards use). Escape-aware so `"it\'s"` doesn't false-terminate early.
_STATIC_LITERAL = re.compile(
    r'^[rRbBuU]{0,2}(?P<q>[\'"])(?:\\.|(?!(?P=q)).)*(?P=q)$', re.DOTALL
)

_STANDARDS = ["OWASP-LLM:LLM06", "CWE-470"]

# Provenance gate: the reflection idiom (globals()/getattr() dynamic call) is the dangerous
# LLM-tool-dispatch pattern ONLY in a file that actually has an LLM/agent-tool context. Without
# this gate, an ordinary event-bus / visitor / CLI-dispatch idiom
# (`getattr(self, f"on_{event}")(payload)`) fires HIGH on any repo that merely carries the `llm`
# feature. So the guard scans a file only when it also shows a same-file signal: an LLM SDK call
# (mirrors llm_output_html_sink's `_LLM_CALL` provenance gate) OR a tool/agent-construction marker.
# Conservative / FN-biased by design (a dispatch split into a module separate from the LLM call is a
# documented miss), matching the siblings' "prefer a miss over an ordinary-code FP" posture.
_LLM_CALL = re.compile(
    r"\b\w+\.chat\.completions\.create\s*\("
    r"|\b\w+\.responses\.create\s*\("
    r"|\b\w+\.messages\.create\s*\(",
    re.IGNORECASE,
)
_TOOL_CONTEXT = re.compile(
    r"@\s*\w[\w.]*\.tool\b|@\s*tool\b"            # @tool / @agent.tool decorator
    r"|\bStructuredTool\b|\bBaseTool\b"           # langchain tool classes
    r"|\bcreate_react_agent\b|\bAgentExecutor\b"  # agent constructors
    r"|\.bind_tools\s*\("                         # langchain tool binding
    r"|\btool_calls?\b|\bfunction_call\b",        # LLM tool/function-call response fields
)


def _has_agent_context(text: str) -> bool:
    """True if the file carries an LLM/agent-tool signal (an SDK call or a tool/agent marker).
    The provenance gate that keeps the reflection rules from firing on ordinary dynamic dispatch
    in non-LLM code, even in a repo with the `llm` feature."""
    return bool(_LLM_CALL.search(text) or _TOOL_CONTEXT.search(text))


def _is_static_literal(arg: str) -> bool:
    return bool(_STATIC_LITERAL.match(arg.strip()))


def _subscript_extent(line: str, open_bracket: int) -> tuple[str, int]:
    """From the `[` at `open_bracket`, return (content, index just after the matching `]`).
    Bracket- and quote-aware so a `]`/`,` inside a nested call or string literal doesn't
    truncate the scan early. If the line ends before the subscript closes (a multi-line
    expression), returns what was found so far and `len(line)` -- the guard then finds no
    immediate `(` right after and simply does not fire (a documented, accepted gap; same
    single-physical-line limitation the sibling regex guards carry)."""
    depth = 0
    quote = ""
    i = open_bracket + 1
    n = len(line)
    while i < n:
        ch = line[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in "'\"":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if ch == "]" and depth == 0:
                return line[open_bracket + 1 : i], i + 1
            depth -= 1
        i += 1
    return line[open_bracket + 1 :], n


def _split_call_args(line: str, open_paren: int) -> tuple[list[str], int]:
    """From the `(` at `open_paren`, return (top-level comma-split args, index just after the
    matching `)`). Bracket- and quote-aware (mirrors `_subscript_extent`), so a comma inside a
    nested call or string literal is never mistaken for an argument separator. Same
    single-physical-line, best-effort-on-a-multi-line-call contract as `_subscript_extent`."""
    args: list[str] = []
    depth = 0
    quote = ""
    start = open_paren + 1
    i = start
    n = len(line)
    while i < n:
        ch = line[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in "'\"":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if ch == ")" and depth == 0:
                args.append(line[start:i])
                return args, i + 1
            depth -= 1
        elif ch == "," and depth == 0:
            args.append(line[start:i])
            start = i + 1
        i += 1
    args.append(line[start:i])
    return args, n


def _immediately_called(line: str, end: int) -> bool:
    """True if the first non-whitespace character at/after `end` is `(` -- the lookup's result
    is invoked right there, on the same line, with nothing but whitespace in between."""
    i = end
    n = len(line)
    while i < n and line[i] in " \t":
        i += 1
    return i < n and line[i] == "("


class LlmToolDynamicDispatchGuard(Guard):
    id = "llm-tool-dynamic-dispatch"
    title = "LLM-selectable dynamic function dispatch via globals()/getattr() reflection"
    area = "AI agent"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `agent_dynamic_dispatch.py` (which `guardrail-architecture` also trips), so that file stays
    # in `canary.py`'s base owned by no guard. The ownership rule this follows is documented on
    # `xxe_safe.py`.
    # agent_dynamic_dispatch.py: globals()[tool_name]() -> fires globals-dynamic-call.
    canary_plant = CanaryPlant(
        expects=frozenset({
            "llm-tool-dynamic-dispatch/globals-dynamic-call",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        raw = read(f)
        if not _has_agent_context(raw):
            return []  # provenance gate: no LLM/agent-tool context -> not LLM-tool dispatch (FP fix)
        out: list[Finding] = []
        text = strip_python_strings(raw, filename=f)
        # The pragma counts only as a real comment on the line, never quoted in a string
        # there (#1040), numbered on the text walked below (a form feed in a docstring
        # shifts the raw count, #1132).
        pragmas = pragma_line_set(_PRAGMA, text, dialect="python")
        for i, line in enumerate(text.splitlines(), start=1):
            stripped = line.lstrip()
            if stripped.startswith("#") or i in pragmas:
                continue
            out.extend(self._scan_globals(root, f, i, line))
            out.extend(self._scan_getattr(root, f, i, line))
        return out

    def _scan_globals(self, root: Path, f: Path, lineno: int, line: str) -> list[Finding]:
        out: list[Finding] = []
        for m in _GLOBALS_SUBSCRIPT.finditer(line):
            key, end = _subscript_extent(line, m.end() - 1)
            if _is_static_literal(key):
                continue  # a hardcoded key -> not attacker-influenceable
            if not _immediately_called(line, end):
                continue  # looked up but not invoked here -> not the dangerous pattern
            out.append(self._finding(
                root, f, lineno,
                rule="llm-tool-dynamic-dispatch/globals-dynamic-call",
                message=(
                    "globals()[<name>]() is called with a non-literal name and invoked "
                    "immediately. If <name> is influenceable by the LLM's own output (a "
                    "tool-selection field, a parsed function-call argument), a prompt "
                    "injection can redirect the call to ANY function present in the "
                    "module's global namespace -- not just the intended tool set."
                ),
            ))
        return out

    def _scan_getattr(self, root: Path, f: Path, lineno: int, line: str) -> list[Finding]:
        out: list[Finding] = []
        for m in _GETATTR_CALL.finditer(line):
            args, end = _split_call_args(line, m.end() - 1)
            if len(args) < 2:
                continue  # not enough arguments to be the (obj, name[, default]) shape
            if _is_static_literal(args[1]):
                continue  # a hardcoded attribute name -> not attacker-influenceable
            if not _immediately_called(line, end):
                continue  # looked up but not invoked here -> not the dangerous pattern
            out.append(self._finding(
                root, f, lineno,
                rule="llm-tool-dynamic-dispatch/getattr-dynamic-call",
                message=(
                    "getattr(obj, <name>)() is called with a non-literal attribute name "
                    "and invoked immediately. If <name> is influenceable by the LLM's own "
                    "output, a prompt injection can redirect the call to ANY callable "
                    "attribute reachable on obj -- classic reflection-based dynamic "
                    "dispatch (CWE-470)."
                ),
            ))
        return out

    def _finding(self, root: Path, f: Path, line: int, *, rule: str, message: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=message,
            remediation=(
                "Validate the LLM-provided (or otherwise caller-influenced) name against a "
                "fixed allowlist/dispatch table BEFORE calling it -- e.g. "
                "`TOOLS = {\"search\": search_tool, \"lookup\": lookup_tool}; "
                "TOOLS[name](...)` with a KeyError on an unknown name -- instead of indexing "
                "globals() or reflecting onto an object with an unvalidated name."
            ),
            rule=rule,
            standards=list(_STANDARDS),
        )
