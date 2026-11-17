"""Guard: a command-safety approval check parses a command differently than the shell that
actually executes it — CVE-2026-19591 (checklist §8, new item; agent-audit-kit's
`approval_parser_desync.py` AAK-APPROVAL-PARSER-DESYNC-001).

An agent decides whether a command needs human approval by parsing it, then hands the
command to a shell. If the two disagree about what a byte means, the thing that was
approved is not the thing that runs. Codex CLI is the disclosed instance: PowerShell's
stop-parsing token `--%` makes `pwsh` re-read the rest of the line verbatim, and Codex's
safety parser did not implement it — a command classified as safe ran a different command,
writing a file with no approval prompt (and what it could write was Codex's own
configuration, loaded on the next start).

This is a near neighbour of, and distinct from, `mcp-noauth-default`'s sibling checks: it
detects the PowerShell stop-parsing token specifically, not every shell's escaping quirks —
a file that gates commands for `bash` only is not flagged by it.

Fires HIGH when, inside ONE function (or the module-level scope), ALL of: an approval/
safety-check is applied to a value (`isSafe(cmd)`/`isAllowed(`/`checkCommand(`/
`requireApproval(`/`cmd in ALLOWED_LIST`), and that same value reaches the argv of a spawn sink
(`spawn(`/`exec(`/`subprocess.run|Popen|call(`/`Command::new(`/`exec.Command(`) that invokes a
PowerShell-family interpreter (`pwsh`/`powershell(.exe)`) — but NO handling of the PowerShell
stop-parsing token `--%` appears anywhere in the file (rejecting it, stripping it, or refusing
to classify a command containing it all count as handling it).

Function scoping is `ast` for Python and brace matching for the other languages. It is still a
heuristic: the gated value is matched by identifier name, so it does not follow a value that is
renamed, wrapped in a helper, or joined into a string before the spawn.

Suppress an audited case with a comment anywhere in the file (a string quoting it does not count):

    # security: allow-approval-parser-shell-desync
    // security: allow-approval-parser-shell-desync   (JS/TS/Go)
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
    comment_dialect_for,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    read,
    rel,
)

_PRAGMA = re.compile(r"(?:#|//)\s*security:\s*allow-approval-parser-shell-desync")

_SUFFIXES = (".py", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".rs", ".go")

_TS_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_TS_LINE_COMMENT_RE = re.compile(r"//[^\n]*")

_APPROVAL_RE = re.compile(
    r"\bis\w*Safe\w*\s*\(|\bisAllowed\w*\s*\(|\bis_safe\w*\s*\("
    r"|\bcheck\w*Command\w*\s*\(|\brequire\w*Approval\w*\s*\(|\brequest_approval\s*\("
    r"|\bapproval[-_]?polic\w*|\bneedsApproval\b|\bauto[-_]?approve\b"
    r"|\bSAFE_[A-Z_]+\b|\ballow(?:ed)?[-_]?list\b|\bcommand[-_]?safety\b",
    re.IGNORECASE,
)
_POWERSHELL_RE = re.compile(
    r"""['"`]pwsh['"`]|['"`]powershell(?:\.exe)?['"`]|\bpwsh\b\s*,|\bPowerShell\s*Core\b""",
    re.IGNORECASE,
)
_STOP_PARSING_RE = re.compile(r"--%|stop[-_]?parsing|STOP_PARSING", re.IGNORECASE)
_SPAWN_RE = re.compile(
    r"\bspawn\w*\s*\(|\bexec\w*\s*\(|subprocess\s*\.\s*(?:run|Popen|call)\s*\("
    r"|\bCommand\s*::\s*new\s*\(|exec\.Command\s*\(",
)

_STANDARDS = ["CWE-150", "OWASP-ASI:ASI04"]

# The approval gate must be applied TO a value: a call `is_safe(cmd)` or a membership test
# `cmd in ALLOWED`. The bare identifier `approval_policy` (a function that returns True, a
# constant) does not say which command it gates.
_APPROVAL_CALL_RE = re.compile(
    r"\b(?:is\w*Safe\w*|isAllowed\w*|is_safe\w*|check\w*Command\w*|require\w*Approval\w*"
    r"|request_approval|needsApproval|approval[-_]?polic\w*)\s*\(",
    re.IGNORECASE,
)
_APPROVAL_MEMBER_RE = re.compile(
    r"\b(\w+)\s+(?:not\s+)?in\s+[\w.]*(?:allow|safe|approv)\w*", re.IGNORECASE,
)
_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
_NOT_VARS = frozenset({"true", "false", "none", "null", "not", "and", "or", "in", "is", "if", "else", "let", "const"})
_FUNC_HEADER_RE = re.compile(r"\b(?:function|fn|func)\b|=>|\b(\w+)\s*\([^()\n]*\)\s*(?::[^{\n]*|->[^{\n]*)?$")
_NON_FUNC_KEYWORDS = frozenset({"if", "for", "while", "switch", "catch", "with", "match", "else", "return"})


def _strip_comments(text: str, is_py: bool) -> str:
    if is_py:
        return text
    return _TS_LINE_COMMENT_RE.sub(" ", _TS_BLOCK_COMMENT_RE.sub(" ", text))


def _call_args(text: str, open_idx: int) -> str:
    """Text between the `(` at `open_idx` and its matching `)` (bounded, string-unaware)."""
    depth = 0
    for j in range(open_idx, min(len(text), open_idx + 600)):
        ch = text[j]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:j]
    return text[open_idx + 1:open_idx + 600]


def _idents(s: str) -> set[str]:
    return {m for m in _IDENT_RE.findall(s) if m.lower() not in _NOT_VARS}


def _segments(text: str, path: Path) -> list[str]:
    """One text segment per function (Python via `ast`, other languages via brace matching), plus
    the module-level residue, so co-occurrence is judged inside one scope instead of file-wide."""
    if path.suffix == ".py":
        tree = safe_ast_parse(text, filename=path)
        if not isinstance(tree, ast.Module):
            return [text]
        segs: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                seg = ast.get_source_segment(text, node)
                if seg:
                    segs.append(seg)
        top = [
            ast.get_source_segment(text, n) or ""
            for n in tree.body
            if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        ]
        segs.append("\n".join(top))
        return segs
    segs = []
    stack: list[tuple[int, bool]] = []
    for i, ch in enumerate(text):
        if ch == "{":
            line_start = text.rfind("\n", 0, i) + 1
            head = text[line_start:i].rstrip()
            m = _FUNC_HEADER_RE.search(head)
            is_func = m is not None and (m.group(1) or "").lower() not in _NON_FUNC_KEYWORDS
            stack.append((i, is_func))
        elif ch == "}" and stack:
            start, is_func = stack.pop()
            if is_func:
                segs.append(text[start:i + 1])
    return segs or [text]


def _approved_value_reaches_spawn(segment: str) -> bool:
    """Inside one function: a PowerShell interpreter is spawned, and a value the approval gate was
    applied to appears in that spawn's argv."""
    gated: set[str] = set()
    for m in _APPROVAL_CALL_RE.finditer(segment):
        gated |= _idents(_call_args(segment, m.end() - 1))
    for m in _APPROVAL_MEMBER_RE.finditer(segment):
        gated |= _idents(m.group(1))
    if not gated:
        return False
    for m in _SPAWN_RE.finditer(segment):
        args = _call_args(segment, m.end() - 1)
        if _POWERSHELL_RE.search(args) and gated & _idents(args):
            return True
    return False


class ApprovalParserShellDesyncGuard(Guard):
    id = "approval-parser-shell-desync"
    title = "Command-safety approval parser disagrees with the shell about what a command means"
    area = "AI agent"

    # approval.py: isSafeCommand() gate + pwsh spawn, no --% handling anywhere ->
    # fires approval-parser-shell-desync/stop-parsing-token-unhandled.
    canary_plant = CanaryPlant(
        files={
            "approval.py": (
                "import subprocess\n\n"
                "def is_safe_command(cmd):\n"
                "    return cmd not in DENY_LIST\n\n"
                "def run(cmd):\n"
                "    if is_safe_command(cmd):\n"
                "        subprocess.run(['pwsh', '-Command', cmd])\n"
            ),
        },
        expects=frozenset({
            "approval-parser-shell-desync/stop-parsing-token-unhandled",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            raw = read(f)
            if not raw or pragma_present(_PRAGMA, raw, dialect=comment_dialect_for(f)):
                continue
            text = _strip_comments(raw, f.suffix == ".py")
            has_gate = _APPROVAL_RE.search(text) or _APPROVAL_CALL_RE.search(text) or _APPROVAL_MEMBER_RE.search(text)
            if not (has_gate and _POWERSHELL_RE.search(text) and _SPAWN_RE.search(text)):
                continue
            if _STOP_PARSING_RE.search(text):
                continue
            if not any(_approved_value_reaches_spawn(seg) for seg in _segments(text, f)):
                continue
            out.append(self._finding(r))
        return out

    def _finding(self, r: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=r,
            message=(
                "A command-safety check classifies a command and a PowerShell-family "
                "interpreter then executes it, with no handling of the stop-parsing "
                "token `--%`. `pwsh` re-reads everything after `--%` verbatim, so the "
                "command that was approved is not the command that runs and an "
                "approval prompt is skipped entirely (CVE-2026-19591 class, CWE-150)."
            ),
            remediation=(
                "Reject or strip `--%` before classifying a command destined for "
                "PowerShell, or hand the interpreter an argv array directly instead "
                "of a shell-parsed command string."
            ),
            rule="approval-parser-shell-desync/stop-parsing-token-unhandled",
            standards=list(_STANDARDS),
        )
