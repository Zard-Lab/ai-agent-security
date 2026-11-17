"""Guard: a deny/allow policy is evaluated against a command string truncated to a fixed length,
while the UNTRUNCATED original string still reaches the execution sink — CVE-2026-73614 (a
vendor-independent primitive; the disclosed instance, ClaudeHookBridge, CVSS 8.8, is unpinnable —
the package 404s on GitHub) (checklist §8, new item; agent-audit-kit's `policy_truncation.py`
AAK-POLICY-TRUNCATION-001).

A policy check that only ever sees the first N characters of a command can be defeated by simply
making the command longer than N: pad the front with anything the policy will approve, then place
the real payload past the truncation boundary. The executor runs the FULL string regardless — the
policy's decision was made on a string that is not the string that actually runs. Disclosed
shape: `x = cmd.slice(0, 500)` (or Python's `cmd[:500]`) tested against a deny/block check, while
the untruncated `cmd` still reaches the executor.

Fires HIGH when, within ONE Python function (AST-scoped via `safe_ast_parse`), ALL of hold:

  1. A variable is assigned a FIXED-LENGTH PREFIX SLICE of another variable — `truncated =
     original[:N]` (an `ast.Slice` with `lower` absent/0 and a constant integer `upper`).
  2. That truncated variable is referenced in a policy/deny-check call or membership test
     (`is_blocked(truncated)`/`check_command(truncated)`/`truncated in DENY_LIST`/an
     allow-list/deny-list/command-safety identifier — the same vocabulary
     `approval-parser-shell-desync`/`argv-toctou` use for this class of check).
  3. The ORIGINAL (untruncated) variable — not the truncated one — is later passed to a spawn
     sink (`spawn(`/`exec(`/`subprocess.run|Popen|call(`) in the same function.

Suppress an audited case with:

    # security: allow-policy-truncation
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

_PRAGMA = re.compile(r"#\s*security:\s*allow-policy-truncation")

_POLICY_RE = re.compile(
    r"\bis\w*Safe\w*\s*\(|\bisAllowed\w*\s*\(|\bis_safe\w*\s*\(|\bis_blocked\w*\s*\("
    r"|\bcheck\w*Command\w*\s*\(|\brequire\w*Approval\w*\s*\(|\brequest_approval\s*\("
    r"|\bapproval[-_]?polic\w*|\ballow(?:ed)?[-_]?list\b|\bdeny[-_]?list\b|\bcommand[-_]?safety\b",
    re.IGNORECASE,
)
_POLICY_CONST_RE = re.compile(r"\b(?:SAFE|DENY|DENIED|ALLOW|ALLOWED|BLOCK|BLOCKED)_[A-Z_]+\b")

_STANDARDS = ["CWE-697", "CWE-78"]


def _is_policy_line(line: str) -> bool:
    return bool(_POLICY_RE.search(line) or _POLICY_CONST_RE.search(line))


_IDENT_RE = re.compile(r"[A-Za-z_]\w*")


def _policy_lines_by_name(text_lines: list[str], start: int, end: int) -> dict[str, list[int]]:
    """`name -> ascending line numbers` of every policy/deny-check line in `[start, end]` that
    mentions `name` as an identifier. One pass over the function span."""
    by_name: dict[str, list[int]] = {}
    for ln in range(start, end + 1):
        line = text_lines[ln - 1]
        if not _is_policy_line(line):
            continue
        for name in set(_IDENT_RE.findall(line)):
            by_name.setdefault(name, []).append(ln)
    return by_name


def _call_name(func: ast.expr) -> str:
    """Dotted name of a call target (`subprocess.run`, `spawn`), or "" for anything else."""
    parts: list[str] = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
        return ".".join(reversed(parts))
    return ""


def _is_spawn_call(name: str) -> bool:
    last = name.rsplit(".", 1)[-1]
    return bool(
        re.match(r"(?:spawn|exec)\w*$", last)
        or name in {"subprocess.run", "subprocess.Popen", "subprocess.call"}
    )


def _spawn_lines_by_argv_name(fn: ast.AST) -> dict[str, list[int]]:
    """`name -> ascending line numbers` of every spawn call whose ARGV (first positional
    argument, or an `args=`/`command=`/`cmd=` keyword) references `name`. Names that appear only
    in other arguments (`env=`, `cwd=`, ...) do not count: those don't change what runs."""
    by_name: dict[str, list[int]] = {}
    for sub in ast.walk(fn):
        if not (isinstance(sub, ast.Call) and _is_spawn_call(_call_name(sub.func))):
            continue
        argv: list[ast.expr] = list(sub.args[:1])
        argv += [k.value for k in sub.keywords if k.arg in {"args", "command", "cmd"}]
        names = {n.id for a in argv for n in ast.walk(a) if isinstance(n, ast.Name)}
        for name in names:
            by_name.setdefault(name, []).append(sub.lineno)
    for lines in by_name.values():
        lines.sort()
    return by_name


def _fixed_prefix_truncations(node: ast.AST) -> list[tuple[str, str, int]]:
    """`(truncated_name, original_name, lineno)` for every `truncated = original[:N]` assignment
    inside `node` — a fixed-length prefix slice (no `lower`, or a literal-zero `lower`; a
    constant integer `upper`)."""
    out: list[tuple[str, str, int]] = []
    for sub in ast.walk(node):
        if not (isinstance(sub, ast.Assign) and len(sub.targets) == 1):
            continue
        target = sub.targets[0]
        value = sub.value
        if not (isinstance(target, ast.Name) and isinstance(value, ast.Subscript)):
            continue
        if not isinstance(value.value, ast.Name):
            continue
        sl = value.slice
        if not isinstance(sl, ast.Slice):
            continue
        lower_ok = sl.lower is None or (
            isinstance(sl.lower, ast.Constant) and sl.lower.value == 0
        )
        upper_ok = isinstance(sl.upper, ast.Constant) and isinstance(sl.upper.value, int)
        if lower_ok and upper_ok and sl.step is None:
            out.append((target.id, value.value.id, sub.lineno))
    return out


class PolicyTruncationGuard(Guard):
    id = "policy-truncation"
    title = "A deny/allow policy checks a truncated command while the full, untruncated command spawns"
    area = "AI agent"

    # policy_check.py: safe_cmd = cmd[:500] truncated for the policy check, then the
    # UNTRUNCATED cmd reaches subprocess.run -> fires
    # policy-truncation/untruncated-value-reaches-spawn.
    canary_plant = CanaryPlant(
        files={
            "policy_check.py": (
                "import subprocess\n\n"
                "def run(cmd):\n"
                "    safe_cmd = cmd[:500]\n"
                "    if is_blocked(safe_cmd):\n"
                "        raise ValueError('blocked')\n"
                "    subprocess.run(cmd)\n"
            ),
        },
        expects=frozenset({
            "policy-truncation/untruncated-value-reaches-spawn",
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
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            truncations = _fixed_prefix_truncations(node)
            if not truncations:
                continue
            start, end = node.lineno, getattr(node, "end_lineno", node.lineno)
            # Index the function ONCE (policy lines per name, spawn calls per argv name), so the
            # per-truncation lookups are bisects instead of a rescan of the span per slice.
            policy_lines = _policy_lines_by_name(text_lines, start, min(end, len(text_lines)))
            spawn_lines = _spawn_lines_by_argv_name(node)

            for truncated_name, original_name, trunc_lineno in truncations:
                lines = policy_lines.get(truncated_name, [])
                i = bisect.bisect_right(lines, trunc_lineno)
                if i >= len(lines):
                    continue
                policy_lineno = lines[i]
                spawns = spawn_lines.get(original_name, [])
                j = bisect.bisect_right(spawns, policy_lineno)
                if j < len(spawns):
                    out.append(self._finding(r, spawns[j], original_name, truncated_name))
        return out

    def _finding(self, r: str, lineno: int, original_name: str, truncated_name: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{r}:{lineno}",
            message=(
                f"A policy/deny check evaluates {truncated_name!r} — a fixed-length prefix "
                f"slice of {original_name!r} — but the FULL, untruncated {original_name!r} is "
                "what actually reaches the spawn call. A payload can pad its front with "
                "anything the policy approves, then place the real command past the "
                "truncation boundary (CVE-2026-73614 class, CVSS 8.8)."
            ),
            remediation=(
                "Evaluate the policy against the exact string that will execute — never a "
                "truncated copy. If a length limit is genuinely required, reject (don't "
                "truncate-then-approve) any command longer than the policy can fully inspect."
            ),
            rule="policy-truncation/untruncated-value-reaches-spawn",
            standards=list(_STANDARDS),
        )
