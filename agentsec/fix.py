"""Deterministic, diff-first auto-fix for a curated allowlist of findings.

`agentsec fix` is the fast-clock remediation counterpart to `agentsec audit`: it
re-runs the guards, dispatches each finding whose `rule` is in the `FIXERS`
allowlist to a deterministic, idempotent fixer, shows a unified diff, and — only
when `write=True` — applies it. Everything else is passed through **report-only**
with a plain-language note (the end-user reviews *actions*, never *judgment*;
risky fixes are surfaced, not auto-applied).

Generalizes the `python_harden`/`js_harden` writer pattern from config files to
source files. Safety posture (Epic 6 is the highest-blast-radius epic):

  * **dry-run by default** — writes only on `write=True` (the CLI requires `--write`);
  * the **unified diff is always shown** (dry-run and write);
  * fixers only ever touch a `.py` source file inside the repo, never anything
    outside `root` or in `.github/`/lockfiles/`node_modules` — **enforced** by
    `_is_safe_target` (a `..`/symlink/absolute escape or a denied path is refused,
    not written), so adding a new fixer can't widen the blast radius;
  * each file's change is bounded by a **diff-size cap** (`_MAX_DIFF_LINES`) — a
    runaway fixer is refused, not applied;
  * fixes are **reversible and behavior-preserving** (defusedxml is a drop-in;
    `docs_url=None` only disables a route) — anything that changes runtime
    behavior (CORS) or needs call-site rewriting (CSV) is report-only;
  * **idempotent** (re-running is a no-op) and **total** (never raises); and it
    **never commits** — git is the restore point, and a write prints the exact
    `git restore` undo command for the files it touched.

Deterministic + offline: it reuses `audit(run_scanners=False)` (guard findings
only — every fixable rule is a guard rule), so no network/LLM at fix time.
"""
from __future__ import annotations

import difflib
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from agentsec.audit import audit
from agentsec.findings import Finding
from agentsec.textio import read_text_preserve, write_text_preserve

# A fixer takes the whole file text + the finding and returns (new_text, changed).
# changed=False means already-fixed / not a drop-in-safe form (a no-op).
Fixer = Callable[[str, Finding], tuple[str, bool]]


@dataclass
class FixAction:
    path: str            # repo-relative (or the raw finding location)
    rule: str            # the finding rule that drove it
    status: str          # fixed | would-fix | reported | skipped
    detail: str = ""


@dataclass
class FixResult:
    actions: list[FixAction] = field(default_factory=list)
    remaining: list[Finding] = field(default_factory=list)
    diffs: list[str] = field(default_factory=list)
    written: list[str] = field(default_factory=list)  # repo-rel paths actually written (for the undo hint)
    ok: bool = True


# --- write-safety (G3): enforce the blast-radius bounds the doctrine promises ---

# A fixer may only ever touch a `.py` source file inside the repo. These are denied
# even if a finding's location somehow points at them.
_DENY_SEGMENTS: frozenset[str] = frozenset({".github", "node_modules", ".git"})
# Cap the size of any single file's fix — the curated fixers produce tiny diffs.
_MAX_DIFF_LINES = 80


def _is_safe_target(root: Path, path: Path) -> bool:
    """True if `path` is a `.py` source file safely inside `root` (G3 write-safety).

    Refuses `..`/symlink escapes and absolute paths outside the repo, anything not
    a `.py` source file, and `.github/`/CI/`node_modules`/`.git` — so a new fixer (or
    a finding with a hostile location) can never widen the blast radius."""
    try:
        resolved = path.resolve()
        rel = resolved.relative_to(root.resolve())
    except (ValueError, OSError):
        return False
    if resolved.suffix != ".py":
        return False
    return not set(rel.parts) & _DENY_SEGMENTS


def _diff_line_count(diff: str) -> int:
    """Count added/removed lines in a unified diff (excludes the ---/+++ header)."""
    return sum(
        1 for ln in diff.splitlines()
        if ln[:1] in ("+", "-") and not ln.startswith(("+++", "---"))
    )


# --- fixers -----------------------------------------------------------------

# Drop-in-safe defusedxml rewrites (name-preserving). A bare
# `import xml.etree.ElementTree` (no alias, referenced via the full dotted path)
# is NOT drop-in — it would unbind `xml` — so it is left to report-only.
_XXE_SUBS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^(\s*)import\s+xml\.etree\.ElementTree\s+as\s+(\w+)\s*$"),
     r"\1import defusedxml.ElementTree as \2"),
    (re.compile(r"^(\s*)from\s+xml\.etree\.ElementTree\s+import\s+(.+?)\s*$"),
     r"\1from defusedxml.ElementTree import \2"),
    (re.compile(r"^(\s*)from\s+xml\.dom\.minidom\s+import\s+(.+?)\s*$"),
     r"\1from defusedxml.minidom import \2"),
    (re.compile(r"^(\s*)from\s+xml\.sax\s+import\s+(.+?)\s*$"),
     r"\1from defusedxml.sax import \2"),
]

_FASTAPI_OPEN = re.compile(r"FastAPI\s*\(")


def _line_index(finding: Finding) -> int | None:
    """0-based line index from a `path:line` location (None if no line)."""
    _, _, line = finding.location.partition(":")
    if not line.isdigit():
        return None
    return int(line) - 1


def _fix_xxe_import(text: str, finding: Finding) -> tuple[str, bool]:
    idx = _line_index(finding)
    lines = text.splitlines(keepends=True)
    if idx is None or idx >= len(lines):
        return text, False
    line = lines[idx]
    body = line.rstrip("\r\n")  # strip \r too so a CRLF eol survives the `\s*$` in _XXE_SUBS
    eol = line[len(body):]
    for pat, repl in _XXE_SUBS:
        if pat.match(body):
            new_line = pat.sub(repl, body) + eol
            if new_line == line:
                return text, False
            lines[idx] = new_line
            return "".join(lines), True
    return text, False  # not a drop-in-safe import form → report-only


def _fix_api_docs(text: str, finding: Finding) -> tuple[str, bool]:
    idx = _line_index(finding)
    lines = text.splitlines(keepends=True)
    if idx is None or idx >= len(lines):
        return text, False
    line = lines[idx]
    m = _FASTAPI_OPEN.search(line)
    if not m or "docs_url" in line:
        return text, False  # not the constructor line, or already set (idempotent)
    after = line[m.end():].lstrip()
    insert = "docs_url=None, redoc_url=None" if after.startswith(")") else "docs_url=None, redoc_url=None, "
    lines[idx] = line[: m.end()] + insert + line[m.end():]
    return "".join(lines), True


# `debug = True` / `DEBUG=True` / `DEBUG: bool = True` -> flip the RHS literal to False, the
# guard's own stated remediation ("DEBUG should default to False"). `(?i:debug)` scopes
# case-insensitivity to the attribute name only (matching the guard's own DEBUG/debug/Debug
# tolerance) — `True` itself stays case-SENSITIVE: it's the only syntactically-valid Python
# spelling, so a fixer only ever rewrites that exact literal, never a `true`/`TRUE` typo that
# wouldn't even be valid Python (falls through to report-only instead of guessing).
_DEBUG_TRUE_FIX = re.compile(r"(\b(?i:debug)\b\s*(?::\s*\w+\s*)?=\s*)True\b")


def _fix_debug_default_off(text: str, finding: Finding) -> tuple[str, bool]:
    idx = _line_index(finding)
    lines = text.splitlines(keepends=True)
    if idx is None or idx >= len(lines):
        return text, False
    line = lines[idx]
    new_line, n = _DEBUG_TRUE_FIX.subn(r"\1False", line, count=1)
    if n == 0 or new_line == line:
        return text, False
    lines[idx] = new_line
    return "".join(lines), True


FIXERS: dict[str, Fixer] = {
    "xxe-safe/unsafe-xml-import": _fix_xxe_import,
    "api-docs-exposed/unconditional-docs-route": _fix_api_docs,
    "debug-default-off/debug-enabled": _fix_debug_default_off,
}


# --- engine -----------------------------------------------------------------

def _rel(root: Path, p: Path) -> str:
    try:
        return str(p.relative_to(root)) or "."
    except ValueError:
        return str(p)


def _file_of(finding: Finding) -> str:
    """The path portion of a `path:line` location."""
    path, _, _ = finding.location.partition(":")
    return path


def unified_diff(rel: str, old: str, new: str) -> str:
    return "".join(difflib.unified_diff(
        old.splitlines(keepends=True), new.splitlines(keepends=True),
        fromfile=f"a/{rel}", tofile=f"b/{rel}",
    ))


def fix(root: Path, *, write: bool = False, rules: list[str] | None = None) -> FixResult:
    """Apply (or preview) the allowlisted fixes for `root`'s guard findings."""
    result = FixResult()
    findings = audit(root, run_scanners=False).findings

    by_file: dict[Path, list[Finding]] = {}
    for f in findings:
        if rules is not None and f.rule not in rules:
            continue
        if f.rule in FIXERS and _file_of(f):
            by_file.setdefault((root / _file_of(f)), []).append(f)
        elif rules is None:
            # report-only pass-through (only when the user didn't restrict with --fix)
            result.actions.append(FixAction(f.location, f.rule, "reported", f.title))

    wrote_any = False
    for path, group in sorted(by_file.items()):
        rel = _rel(root, path)
        # G3 write-safety: refuse anything that isn't in-repo Python source.
        if not _is_safe_target(root, path):
            for f in group:
                result.actions.append(FixAction(rel, f.rule, "skipped", "refused: unsafe target (G3 write-safety)"))
            continue
        if not path.is_file():
            for f in group:
                result.actions.append(FixAction(rel, f.rule, "skipped", "file not found"))
            continue
        original = read_text_preserve(path)
        text = original
        applied: list[str] = []
        for f in sorted(group, key=lambda x: _line_index(x) or 0):
            new_text, changed = FIXERS[f.rule](text, f)
            if changed:
                text = new_text
                applied.append(f.rule)
            else:
                result.actions.append(FixAction(rel, f.rule, "skipped", "no drop-in fix / already fixed"))
        if text != original:
            diff = unified_diff(rel, original, text)
            # Diff-size cap: a runaway fixer is refused, not applied.
            if _diff_line_count(diff) > _MAX_DIFF_LINES:
                for rule in dict.fromkeys(applied):
                    result.actions.append(
                        FixAction(rel, rule, "skipped", f"refused: diff exceeds {_MAX_DIFF_LINES}-line cap")
                    )
                continue
            result.diffs.append(diff)
            if write:
                write_text_preserve(path, text)
                wrote_any = True
                result.written.append(rel)
            for rule in dict.fromkeys(applied):
                result.actions.append(FixAction(rel, rule, "fixed" if write else "would-fix", ""))

    result.remaining = audit(root, run_scanners=False).findings if wrote_any else findings
    return result


def render_summary(result: FixResult, *, write: bool) -> str:
    verb = {"fixed": "Fixed", "would-fix": "Would fix", "reported": "Report", "skipped": "Skipped"}
    lines: list[str] = []
    for diff in result.diffs:
        lines.append(diff.rstrip("\n"))
    if result.diffs:
        lines.append("")
    fixes = [a for a in result.actions if a.status in ("fixed", "would-fix")]
    reported = [a for a in result.actions if a.status == "reported"]
    skipped = [a for a in result.actions if a.status == "skipped"]
    if not fixes and not reported and not skipped:
        lines.append("Nothing to fix — no findings.")
    for a in fixes + skipped:
        lines.append(f"  {verb[a.status]} [{a.rule}] {a.path}" + (f" — {a.detail}" if a.detail else ""))
    if reported:
        lines.append("")
        rules = sorted({a.rule for a in reported})
        lines.append(f"Report-only (review/fix manually) — {len(reported)} finding(s): {', '.join(rules)}")
    lines.append("")
    if write:
        lines.append("Review the diffs — nothing was committed.")
        if result.written:
            # git is the restore point; print the exact undo (G3: restore point + printed undo).
            lines.append(f"Undo: git restore -- {' '.join(result.written)}")
    else:
        lines.append("Dry run — nothing was written. Re-run with --write to apply the fixes above.")
    return "\n".join(lines)
