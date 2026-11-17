"""Guard: a command/argv buffer is approved against a safety check, then rebuilt (re-split,
re-joined, appended to, or extended) before it is handed to a spawn sink, with no re-validation
in between — CVE-2026-53822 (checklist §8, new item; agent-audit-kit's `argv_toctou.py`
AAK-MCP-ARGV-TOCTOU-001).

OpenClaw before 2026.5.18 contained a command-injection vulnerability where a shell-wrapper argv
could change between the moment it was approved as safe and the moment it actually executed
(CVSS 8.8) — a classic Time-Of-Check-to-Time-Of-Use race on program state, not a filesystem race.
Whatever was reviewed and approved is not necessarily what runs.

Fires HIGH when, within ONE function (Python only — AST-scoped via `safe_ast_parse`), ALL of
hold, IN THIS ORDER:

  1. An approval/safety-check call site (`isSafe(`/`isAllowed(`/`checkCommand(`/
     `requireApproval(`/an allow-list/deny-list/command-safety identifier — the same vocabulary
     `approval-parser-shell-desync` uses for this class of check).
  2. AFTER that, on a LATER line in the SAME function, a variable the approval call saw is
     rebuilt: re-split (`x = y.split(`), re-joined (`.join(`), appended to (`x.append(`),
     extended (`x.extend(`), or concatenated (`x += [` / `x = y + [`). The rebuild must take
     an approved variable as input; an unrelated `", ".join(parts)` does not count, and a bare
     `cmd.split(" ")` whose result is never assigned is not a rebuild at all.
  3. AFTER the rebuild, on a LATER line still IN THE SAME FUNCTION, a spawn sink (`spawn(`/
     `exec(`/`subprocess.run|Popen|call(`) whose ARGV (first argument) uses the rebuilt
     variable. A spawn that never touches it (a fully literal argv) is not the bug.

  ...and no SECOND approval-shaped call site appears, within that same function, between the
  rebuild (2) and the spawn (3) — that second check would be the re-validation this pattern is
  missing.

Scoping to one function (rather than the whole file, this guard's first-pass design) is what
keeps it precise: a same-file scope matched unrelated approval/rebuild/spawn-shaped code spread
across entirely different, unconnected functions elsewhere in a large file — a real precision
issue caught by this guard's own self-audit dogfooding before it ever shipped (12 false
positives across agentsec's own codebase in the whole-file draft, none once scoped to a single
function).

Suppress an audited case with:

    # security: allow-argv-toctou
"""
from __future__ import annotations

import ast
import bisect
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
    python_scan_dirs,
    read,
    rel,
)

_PRAGMA = re.compile(r"#\s*security:\s*allow-argv-toctou")

_APPROVAL_RE = re.compile(
    r"\bis\w*Safe\w*\s*\(|\bisAllowed\w*\s*\(|\bis_safe\w*\s*\("
    r"|\bcheck\w*Command\w*\s*\(|\brequire\w*Approval\w*\s*\(|\brequest_approval\s*\("
    r"|\bapproval[-_]?polic\w*|\bneedsApproval\b|\bauto[-_]?approve\b"
    r"|\ballow(?:ed)?[-_]?list\b|\bdeny[-_]?list\b|\bcommand[-_]?safety\b",
    re.IGNORECASE,
)
# A real ALL-CAPS constant name (`SAFE_COMMANDS`, `SAFE_LIST`) — kept case-SENSITIVE and
# separate from `_APPROVAL_RE` above: combining it under that pattern's `re.IGNORECASE` made it
# match any lowercase `safe_...` identifier at all (`safe_ast_parse`, `safe_load`, ...), a real
# precision bug this guard's own self-audit dogfooding caught (a false positive on
# `agentsec/guards/log_injection.py`'s own `safe_ast_parse(` call, unrelated to command approval).
_APPROVAL_CONST_RE = re.compile(r"\bSAFE_[A-Z_]+\b")


def _is_approval_line(line: str) -> bool:
    return bool(_APPROVAL_RE.search(line) or _APPROVAL_CONST_RE.search(line))


_NAME_RE = re.compile(r"\b[A-Za-z_]\w*\b(?!\s*\()")
_IGNORED_NAMES = frozenset({"self", "cls"})
_STANDARDS = ["CWE-367", "CWE-78"]

# Event kinds, ordered so that on ONE line a spawn is seen before a rebuild, and a rebuild before
# an approval (each later stage must come on a strictly later line than the one before it).
_SPAWN, _REBUILD, _APPROVAL = 0, 1, 2


def _names(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and n.id not in _IGNORED_NAMES}


def _is_spawn_call(func: ast.expr) -> bool:
    parts: list[str] = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
    name = ".".join(reversed(parts))
    return bool(
        re.match(r"(?:spawn|exec)\w*$", parts[0] if parts else "")
        or name in {"subprocess.run", "subprocess.Popen", "subprocess.call"}
    )


def _rebuilds_value(value: ast.AST) -> bool:
    """True when `value` re-splits / re-joins / list-concatenates something."""
    for sub in ast.walk(value):
        if (
            isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute)
            and sub.func.attr in {"split", "join"}
        ):
            return True
        if isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.Add) and (
            isinstance(sub.left, ast.List) or isinstance(sub.right, ast.List)
        ):
            return True
    return False


def _function_events(
    fn: ast.AST, text_lines: list[str],
) -> list[tuple[int, int, set[str], set[str]]]:
    """`(lineno, kind, sources, targets)` for every approval line, argv rebuild and spawn call in
    `fn`. `sources` / `targets` are variable names: an approval's names, a rebuild's input and
    output names, a spawn's argv names. Built in ONE pass over the function."""
    start = getattr(fn, "lineno", 0)
    end = min(getattr(fn, "end_lineno", start), len(text_lines))
    events: list[tuple[int, int, set[str], set[str]]] = []
    for ln in range(start, end + 1):
        line = text_lines[ln - 1]
        if _is_approval_line(line):
            names = {n for n in _NAME_RE.findall(line) if n not in _IGNORED_NAMES}
            events.append((ln, _APPROVAL, names, set()))
    for sub in ast.walk(fn):
        if isinstance(sub, (ast.Assign, ast.AnnAssign)) and sub.value is not None:
            if _rebuilds_value(sub.value):
                targets = sub.targets if isinstance(sub, ast.Assign) else [sub.target]
                events.append((sub.lineno, _REBUILD, _names(sub.value), {
                    n for t in targets for n in _names(t)
                }))
        elif isinstance(sub, ast.AugAssign) and isinstance(sub.op, ast.Add):
            if isinstance(sub.value, ast.List):
                names = _names(sub.target)
                events.append((sub.lineno, _REBUILD, names, names))
        elif isinstance(sub, ast.Call):
            f = sub.func
            if isinstance(f, ast.Attribute) and f.attr in {"append", "extend"}:
                names = _names(f.value)
                events.append((sub.lineno, _REBUILD, names, names))
            if _is_spawn_call(f):
                argv: list[ast.expr] = list(sub.args[:1])
                argv += [k.value for k in sub.keywords if k.arg in {"args", "command", "cmd"}]
                events.append((sub.lineno, _SPAWN, set().union(*map(_names, argv)), set()))
    events.sort(key=lambda e: (e[0], e[1]))
    return events


class ArgvToctouGuard(Guard):
    id = "argv-toctou"
    title = "Command argv is rebuilt after approval, with no re-validation before it spawns"
    area = "AI agent"

    # toctou.py: is_safe_command(cmd) approves, then cmd = cmd.split(" ") rebuilds it, then
    # subprocess.run(cmd) spawns with no re-check -> fires
    # argv-toctou/rebuild-after-approval-no-revalidation.
    canary_plant = CanaryPlant(
        files={
            "toctou.py": (
                "import subprocess\n\n"
                "def run(cmd):\n"
                "    if is_safe_command(cmd):\n"
                "        cmd = cmd.split(' ')\n"
                "        subprocess.run(cmd)\n"
            ),
        },
        expects=frozenset({
            "argv-toctou/rebuild-after-approval-no-revalidation",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                r = rel(root, f)
                if is_nonproduct_path(r, profile.archive_segments):
                    continue
                raw = read(f)
                if not raw or pragma_present(_PRAGMA, raw, dialect="python"):
                    continue
                out.extend(self._scan(r, raw))
        return out

    def _scan(self, r: str, raw: str) -> list[Finding]:
        tree = safe_ast_parse(raw, r)
        if tree is None:
            return []
        text_lines = raw.splitlines()
        out: list[Finding] = []
        seen_lines: set[int] = set()
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for hit in self._unrevalidated_chains(_function_events(node, text_lines)):
                if hit not in seen_lines:
                    seen_lines.add(hit)
                    out.append(self._finding(r, hit))
        return out

    def _unrevalidated_chains(
        self, events: list[tuple[int, int, set[str], set[str]]],
    ) -> list[int]:
        """Rebuild lines of every chain approve(V) -> rebuild(V) -> spawn(argv uses V), correlated
        BY VARIABLE (not by line order) and with no approval between the rebuild and the spawn."""
        approvals = [e[0] for e in events if e[1] == _APPROVAL]
        tracked: set[str] = set()      # names an approval call has seen (or that derive from one)
        rebuilt: dict[str, int] = {}   # name -> line of its latest post-approval rebuild
        hits: list[int] = []
        for lineno, kind, sources, targets in events:
            if kind == _APPROVAL:
                tracked |= sources
            elif kind == _REBUILD:
                if sources & tracked:
                    for name in targets:
                        rebuilt[name] = lineno
                    tracked |= targets
            else:
                for name in sources & rebuilt.keys():
                    rebuild = rebuilt[name]
                    i = bisect.bisect_right(approvals, rebuild)
                    revalidated = i < len(approvals) and approvals[i] < lineno
                    if rebuild < lineno and not revalidated:
                        hits.append(rebuild)
        return hits

    def _finding(self, r: str, lineno: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{r}:{lineno}",
            message=(
                "A command/argv buffer is approved against a safety check, then rebuilt "
                "(re-split, re-joined, appended to, or extended) before it reaches a spawn "
                "sink, with no re-validation call between the rebuild and the spawn. "
                "Whatever was reviewed and approved is not necessarily what executes "
                "(CVE-2026-53822 class, CVSS 8.8)."
            ),
            remediation=(
                "Re-run the safety/approval check on the FINAL argv immediately before the "
                "spawn call, after any rebuild — never approve, then mutate, then trust. "
                "Prefer validating the argv exactly once, as close to the spawn call as "
                "possible, with no rebuild step in between."
            ),
            rule="argv-toctou/rebuild-after-approval-no-revalidation",
            standards=list(_STANDARDS),
        )
