"""`agentsec harden-js` — deterministic, offline JS/TS dependency hardener.

The non-interactive counterpart of the `js-supply-chain` guard (detector) and the
`/harden-js` skill (interactive fixer). Per detected package.json dir it writes a
hardened config — `pnpm-workspace.yaml` (pnpm) or `.npmrc` (npm) — that sets a
release-age cooldown, blocks lifecycle scripts, and enables pnpm's trust/exotic
defenses, then re-runs the guard and reports what remains.

Unlike `harden-python` (which shells out to `uv`), this is **fully offline**: its
value is config-file editing, done in pure Python. Lockfile regeneration, pinning
(package.json edits), `packageManager` pinning, and an npm→pnpm migration are
**reported, not performed** (they need judgment / churn package.json). Runtime is
stdlib-only — no YAML/INI writer exists, so edits are idempotent text insertions
that never overwrite an existing key.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from agentsec.detect import detect
from agentsec.findings import Finding
from agentsec.guards.js_supply_chain import (
    JsSupplyChainGuard,
    _load_json,
    ancestors,
    is_pnpm,
    js_dependency_dirs,
)
from agentsec.textio import read_text_preserve, write_text_preserve

# ---------------------------------------------------------------------------
# Pure-Python config editors (idempotent; never overwrite an existing key)
# ---------------------------------------------------------------------------

def ensure_pnpm_workspace(text: str, *, cooldown_min: int, scaffold_allowlist: bool = True) -> tuple[str, list[str]]:
    """Ensure the pnpm-workspace.yaml hardening keys (camelCase). Returns (new_text, added_keys)."""
    desired: list[tuple[str, str]] = [
        ("minimumReleaseAge", str(cooldown_min)),
        ("trustPolicy", "no-downgrade"),
        ("verifyDepsBeforeRun", "true"),
        ("blockExoticSubdeps", "true"),
    ]
    if scaffold_allowlist:
        desired.append(("allowBuilds", "{}"))
    additions, added = [], []
    for key, val in desired:
        if re.search(rf"^\s*{re.escape(key)}\s*:", text, re.M):
            continue
        additions.append(f"{key}: {val}")
        added.append(key)
    if not added:
        return text, []
    block = "\n# agentsec: pnpm supply-chain hardening\n" + "\n".join(additions) + "\n"
    base = text if (not text or text.endswith("\n")) else text + "\n"
    return base + block, added


def ensure_npmrc(text: str, *, cooldown_min: int) -> tuple[str, list[str]]:
    """Ensure the npm .npmrc hardening keys (kebab). npm `min-release-age` is in DAYS."""
    days = (cooldown_min + 1439) // 1440  # ceil minutes→days
    desired: list[tuple[str, str]] = [("ignore-scripts", "true"), ("min-release-age", str(days))]
    additions, added = [], []
    for key, val in desired:
        if re.search(rf"^\s*{re.escape(key)}\s*=", text, re.M):
            continue
        additions.append(f"{key}={val}")
        added.append(key)
    if not added:
        return text, []
    block = "\n# agentsec: npm supply-chain hardening\n" + "\n".join(additions) + "\n"
    base = text if (not text or text.endswith("\n")) else text + "\n"
    return base + block, added


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

@dataclass
class HardenAction:
    path: str
    kind: str       # pnpm-workspace.yaml | .npmrc | report
    status: str     # wrote | would-write | skipped | reported
    detail: str = ""


@dataclass
class HardenResult:
    actions: list[HardenAction] = field(default_factory=list)
    remaining: list[Finding] = field(default_factory=list)
    ok: bool = True


def _rel(root: Path, p: Path) -> str:
    try:
        return str(p.relative_to(root)) or "."
    except ValueError:
        return str(p)


def harden(
    root: Path,
    *,
    cooldown_hours: int = 48,
    scaffold_allowlist: bool = True,
    dry_run: bool = False,
) -> HardenResult:
    """Write hardened pnpm/npm config for every detected package.json dir."""
    root = root.resolve()
    cooldown_min = cooldown_hours * 60
    result = HardenResult()

    for pkg_dir in js_dependency_dirs(root):
        data = _load_json(pkg_dir / "package.json")
        if is_pnpm(ancestors(pkg_dir, root), data):
            target = pkg_dir / "pnpm-workspace.yaml"
            new_text, added = ensure_pnpm_workspace(
                read_text_preserve(target) if target.is_file() else "",
                cooldown_min=cooldown_min, scaffold_allowlist=scaffold_allowlist,
            )
            kind = "pnpm-workspace.yaml"
        else:
            target = pkg_dir / ".npmrc"
            new_text, added = ensure_npmrc(
                read_text_preserve(target) if target.is_file() else "", cooldown_min=cooldown_min
            )
            kind = ".npmrc"

        rel_t = _rel(root, target)
        if not added:
            result.actions.append(HardenAction(rel_t, kind, "skipped", "already hardened"))
        elif dry_run:
            result.actions.append(HardenAction(rel_t, kind, "would-write", ", ".join(added)))
        else:
            write_text_preserve(target, new_text)
            result.actions.append(HardenAction(rel_t, kind, "wrote", ", ".join(added)))

    # Re-verify (re-detect so the just-written config counts).
    findings = JsSupplyChainGuard().run(root, detect(root))
    result.remaining = [f for f in findings if f.check_id == "js-supply-chain"]
    for f in result.remaining:
        if any(f.rule.endswith(s) for s in ("unpinned", "no-packagemanager-pin", "lockfile-missing", "insecure-registry")):
            result.actions.append(HardenAction(path=f.location, kind="report", status="reported", detail=f.rule))
    return result


def render_summary(result: HardenResult, *, dry_run: bool) -> str:
    verb = {"wrote": "Wrote", "would-write": "Would write", "skipped": "Skipped", "reported": "Report"}
    lines: list[str] = []
    if not result.actions:
        lines.append("Nothing to harden — no JS/TS dependency dirs detected.")
    for a in result.actions:
        lines.append(f"  {verb.get(a.status, a.status)} [{a.kind}] {a.path}" + (f" — {a.detail}" if a.detail else ""))
    remaining_rules = sorted({f.rule for f in result.remaining})
    lines.append("")
    if remaining_rules:
        lines.append(f"Remaining js-supply-chain findings ({len(result.remaining)}): {', '.join(remaining_rules)}")
    else:
        lines.append("No remaining js-supply-chain findings. ✅")
    lines.append("Review the changes — nothing was committed." if not dry_run else "Dry run — nothing was written.")
    return "\n".join(lines)
