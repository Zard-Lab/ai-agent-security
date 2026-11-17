"""`agentsec harden-python` — deterministic Python (uv) dependency hardener.

The non-interactive counterpart of the `python-supply-chain` guard (detector)
and the `harden-python` skill (interactive fixer). Per detected Python dependency
dir it performs two safe, idempotent mutations:

1. **cooldown** — writes ``exclude-newer = "<hours> hours"`` into ``[tool.uv]``
   (pyproject) or ``uv.toml`` (requirements-only). Pure text edit; no uv needed.
2. **lock** — generates a hash-verified lock via ``uv`` (``uv lock`` for a
   pyproject project, ``uv pip compile … --generate-hashes`` for requirements).

It optionally scaffolds an empty ``pip-audit-exceptions.json``, then re-runs the
guard and reports what remains. Loose specifiers and risky index config are
**reported, not auto-rewritten** (changing them can break private-registry access
or resolution semantics; once a hashed lock exists, integrity no longer depends
on the pyproject specifier being ``==``). Never commits; supports dry-run.

``uv`` is an optional external tool (like Docker/psql for ``agentsec live``):
required only for the lock step, graceful when absent. Runtime is stdlib-only —
``tomllib`` can read but not write TOML, so config edits are careful, idempotent
text insertions.
"""
from __future__ import annotations

import re
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from agentsec.detect import detect
from agentsec.findings import Finding
from agentsec.guards.python_supply_chain import (
    _HASHED_LOCKS,
    _decode,
    _req_files,
    dependency_dirs,
)
from agentsec.guards.python_supply_chain import (
    PythonSupplyChainGuard as _Guard,
)
from agentsec.runners.base import exec_capture, which

UvRunner = Callable[[list[str], Path], "tuple[int, str, str]"]

_TOOL_UV_HEADER = re.compile(r"^[^\S\n]*\[tool\.uv\]\s*$", re.M)
_EXCLUDE_NEWER_LINE = re.compile(r"^[^\S\n]*exclude-newer\s*=", re.M)


# ---------------------------------------------------------------------------
# Pure-Python TOML text editors (no stdlib TOML writer exists)
# ---------------------------------------------------------------------------

def _cooldown_already_set(text: str) -> bool:
    """True if an `exclude-newer` is already configured (read-only check)."""
    if _EXCLUDE_NEWER_LINE.search(text):
        return True
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return False
    tool = data.get("tool")
    uv = tool.get("uv") if isinstance(tool, dict) else None
    if isinstance(uv, dict) and "exclude-newer" in uv:
        return True
    return "exclude-newer" in data  # uv.toml (bare table)


def ensure_cooldown_text(text: str, hours: int, *, is_pyproject: bool) -> tuple[str, bool]:
    """Ensure `exclude-newer = "<hours> hours"` is set in TOML `text`.

    Idempotent: returns ``(text, False)`` unchanged if a cooldown is already
    configured (we never weaken/overwrite an explicit value). Otherwise inserts
    the line and returns ``(new_text, True)``.
    """
    if _cooldown_already_set(text):
        return text, False
    line = f'exclude-newer = "{hours} hours"'
    if not is_pyproject:  # uv.toml — bare table, prepend
        prefix = text if text.endswith("\n") or not text else text + "\n"
        return f"{line}\n{prefix}" if text else f"{line}\n", True
    m = _TOOL_UV_HEADER.search(text)
    if m:  # insert directly under the existing [tool.uv] header
        insert_at = m.end()
        sep = "" if text[insert_at:insert_at + 1] == "\n" else "\n"
        return text[:insert_at] + sep + "\n" + line + text[insert_at:], True
    block = f"\n[tool.uv]\n{line}\n"
    return (text if text.endswith("\n") or not text else text + "\n") + block, True


def empty_exceptions_json() -> str:
    return '{\n  "exceptions": []\n}\n'


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

@dataclass
class HardenAction:
    path: str           # repo-relative
    kind: str           # cooldown | lock | exceptions | report
    status: str         # wrote | would-write | ran | skipped | reported
    detail: str = ""


@dataclass
class HardenResult:
    actions: list[HardenAction] = field(default_factory=list)
    remaining: list[Finding] = field(default_factory=list)
    uv_available: bool = False
    ok: bool = True


def _has_hashed_lock(dep_dir: Path) -> bool:
    if any((dep_dir / lf).is_file() for lf in _HASHED_LOCKS):
        return True
    return any("--hash=" in _decode(f) for f in _req_files(dep_dir))


def _rel(root: Path, p: Path) -> str:
    try:
        return str(p.relative_to(root)) or "."
    except ValueError:
        return str(p)


def harden(
    root: Path,
    *,
    cooldown_hours: int = 48,
    run_lock: bool = True,
    scaffold_exceptions: bool = False,
    dry_run: bool = False,
    uv_runner: UvRunner = exec_capture,
) -> HardenResult:
    """Harden every detected Python dependency dir under `root`."""
    root = root.resolve()
    result = HardenResult(uv_available=which("uv") is not None)
    profile = detect(root)

    for dep_dir in dependency_dirs(root, profile):
        result.actions.append(_apply_cooldown(root, dep_dir, cooldown_hours, dry_run=dry_run))
        if run_lock:
            result.actions.append(
                _apply_lock(root, dep_dir, result.uv_available, dry_run=dry_run, uv_runner=uv_runner)
            )

    if scaffold_exceptions:
        result.actions.append(_apply_exceptions(root, dry_run=dry_run))

    # Re-verify (re-detect so just-written cooldown/lock count).
    findings = _Guard().run(root, detect(root))
    result.remaining = [f for f in findings if f.check_id == "python-supply-chain"]
    for f in result.remaining:
        if any(f.rule.endswith(s) for s in ("unpinned", "extra-index-url", "insecure-index")):
            result.actions.append(
                HardenAction(path=f.location, kind="report", status="reported", detail=f.rule)
            )
    return result


def _apply_cooldown(root: Path, dep_dir: Path, hours: int, *, dry_run: bool) -> HardenAction:
    target = dep_dir / "pyproject.toml"
    is_pyproject = target.is_file()
    if not is_pyproject:
        target = dep_dir / "uv.toml"
    text = _decode(target) if target.is_file() else ""
    new_text, changed = ensure_cooldown_text(text, hours, is_pyproject=is_pyproject)
    rel = _rel(root, target)
    if not changed:
        return HardenAction(path=rel, kind="cooldown", status="skipped", detail="already set")
    if dry_run:
        return HardenAction(path=rel, kind="cooldown", status="would-write", detail=f"{hours}h cooldown")
    # `_decode` preserves the file's existing newlines (e.g. CRLF on Windows); writing
    # with newline="" avoids re-translating "\n"→"\r\n", which would double an existing
    # "\r\n" into "\r\r\n" and corrupt the TOML (uv lock then fails to parse it). Pin
    # utf-8 too, so a pyproject with non-ASCII content isn't re-encoded as cp1252.
    target.write_text(new_text, newline="", encoding="utf-8")
    return HardenAction(path=rel, kind="cooldown", status="wrote", detail=f"{hours}h cooldown")


def _apply_lock(
    root: Path, dep_dir: Path, uv_available: bool, *, dry_run: bool, uv_runner: UvRunner
) -> HardenAction:
    rel = _rel(root, dep_dir)
    if _has_hashed_lock(dep_dir):
        return HardenAction(path=rel, kind="lock", status="skipped", detail="hashed lock present")
    if not uv_available:
        return HardenAction(path=rel, kind="lock", status="skipped", detail="uv not on PATH")
    has_pyproject = (dep_dir / "pyproject.toml").is_file()
    if has_pyproject:
        cmd = ["uv", "lock"]
    else:
        cmd = ["uv", "pip", "compile", "requirements.txt", "-o",
               "requirements-locked.txt", "--generate-hashes"]
    if dry_run:
        return HardenAction(path=rel, kind="lock", status="would-write", detail=" ".join(cmd))
    rc, _out, err = uv_runner(cmd, dep_dir)
    if rc != 0:
        return HardenAction(path=rel, kind="lock", status="skipped", detail=f"`{' '.join(cmd)}` failed: {err.strip()[:120]}")
    return HardenAction(path=rel, kind="lock", status="ran", detail=" ".join(cmd))


def _apply_exceptions(root: Path, *, dry_run: bool) -> HardenAction:
    target = root / "pip-audit-exceptions.json"
    rel = _rel(root, target)
    if target.is_file():
        return HardenAction(path=rel, kind="exceptions", status="skipped", detail="already exists")
    if dry_run:
        return HardenAction(path=rel, kind="exceptions", status="would-write", detail="empty waiver DB")
    target.write_text(empty_exceptions_json(), encoding="utf-8")
    return HardenAction(path=rel, kind="exceptions", status="wrote", detail="empty waiver DB")


def render_summary(result: HardenResult, *, dry_run: bool) -> str:
    lines: list[str] = []
    verb = {"wrote": "Wrote", "would-write": "Would write", "ran": "Ran",
            "skipped": "Skipped", "reported": "Report"}
    if not result.actions:
        lines.append("Nothing to harden — no Python dependency dirs detected.")
    for a in result.actions:
        lines.append(f"  {verb.get(a.status, a.status)} [{a.kind}] {a.path}" + (f" — {a.detail}" if a.detail else ""))

    remaining_rules = sorted({f.rule for f in result.remaining})
    lines.append("")
    if remaining_rules:
        lines.append(f"Remaining python-supply-chain findings ({len(result.remaining)}): {', '.join(remaining_rules)}")
    else:
        lines.append("No remaining python-supply-chain findings. ✅")
    if not result.uv_available:
        lines.append("⚠ uv not found on PATH — install it (e.g. `pipx install uv`) to generate the hashed lock.")
    lines.append("Review the changes — nothing was committed." if not dry_run else "Dry run — nothing was written.")
    return "\n".join(lines)
