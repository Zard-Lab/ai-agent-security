"""Triage persistence layer — classification above the exception/suppression layer.

`exceptions.py` handles accepted-risk suppression (hide a finding you know about).
This module handles verdict classification (real vs fp vs guard-improvement) so the
analyst record survives re-scans and feeds the guard-improvement loop.

File on disk: `agentsec-triage.json` at the repo root (alongside `agentsec-exceptions.json`).
Override with `--triage-file PATH` in the CLI.

Verdict values:
  real             — confirmed security issue; may carry fix_status / fix_commit
  fp               — false positive; requires reason; may carry improvement hint
  guard-improvement — guard fires correctly on pattern but too broadly; reason + improvement
  pending          — seen, not yet triaged

Fingerprint: delegates to `Finding.stable_fingerprint()` (issue #325) — the canonical
line-insensitive identity shared with the exception/baseline layer, so a triage verdict
and an exception can be joined on one key.
  - Excludes line number (shifts on refactors)
  - Collapses same-message findings in a file to one verdict (desirable for csv-injection etc.)
  - Same basis as `Finding.fingerprint()` except the `:line[:col]` suffix is stripped
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentsec.findings import Finding

VERDICT_VALUES = frozenset({"real", "fp", "guard-improvement", "pending"})
# NOT bumped for #864 (scanner findings enter triage; `TriageVerdict.rule` added): the version
# tracks the FINGERPRINT basis, which #864 leaves untouched — a bandit/semgrep finding was
# always hashed on `rule or check_id`, it just never reached this layer. A v3 file written
# before #864 has no `rule` key; `load_triage` filters to known fields, so it loads unchanged
# and its verdicts still attach (pinned by `test_v3_verdict_without_rule_key_still_attaches`).
# Bumped 2 → 3 in #567: `stable_fingerprint()` no longer strips a URL PORT as if it were a
# line number, so a verdict keyed on the old value for a `scheme://host:port` location goes
# inert and its finding re-surfaces as untriaged (fail-closed, and the point of the warning).
# Only URL-with-port locations change; every ordinary `path:line` verdict still matches.
# Bumped 1 → 2 in #325: the triage fingerprint now delegates to `Finding.stable_fingerprint()`,
# so its value changed (basis aligned with `Finding.fingerprint()` minus line-sensitivity).
# Verdicts written by v1 will not match under v2 and re-surface as untriaged — a one-time,
# safe (re-surfacing) re-triage. `load_triage` still reads any version (no hard gate).
_TRIAGE_VERSION = 3


@dataclass
class TriageVerdict:
    guard_id: str
    file: str
    fingerprint: str
    verdict: str
    # The finding's `rule` (#864): DESCRIPTIVE, like `file`. For a delegated-scanner finding
    # `guard_id` is the scanner (`bandit`, `semgrep`) and this is the rule it fired
    # (`B608`, a semgrep id), which is what makes the verdict readable — the fingerprint is
    # what it is KEYED on. Placed after `verdict` rather than next to `guard_id` because a
    # dataclass cannot put a defaulted field before the required ones; `""` for a pre-#864
    # verdict or a guard whose findings carry no sub-rule.
    rule: str = ""
    reason: str = ""
    improvement: str = ""
    risk: str = ""
    fix_status: str = ""
    fix_commit: str = ""
    triaged_by: str = ""
    triaged_at: str = ""


@dataclass
class AnnotatedFinding:
    finding: Finding
    verdict: TriageVerdict | None = None


def fingerprint(finding: Finding) -> str:
    """Stable identity for triage keying — delegates to the canonical
    `Finding.stable_fingerprint()` (issue #325) so triage and the exception/baseline
    layer agree on one line-insensitive key. Kept as a module-level function for the
    existing call sites (`apply_triage`, `triage_cli`).

    Line-insensitive (survives line-number shifts); same-message findings in one file
    collapse to one verdict — intentional (csv-injection 279 → 1 verdict).
    """
    return finding.stable_fingerprint()


def _warn_on_version_mismatch(stored: object, path: Path) -> None:
    """Emit one actionable warning when a triage file's stamped schema `version` differs from
    the current `_TRIAGE_VERSION`. No-op when the version is absent or non-int (a minimal
    hand-authored file we can't reason about) or already current."""
    if not isinstance(stored, int) or isinstance(stored, bool) or stored == _TRIAGE_VERSION:
        return
    if stored < _TRIAGE_VERSION:
        print(
            f"warning: triage file {path} was written under fingerprint scheme v{stored} "
            f"(current is v{_TRIAGE_VERSION}); its verdicts may no longer match findings and will "
            f"re-surface as untriaged — re-run `agentsec triage` to re-classify.",
            file=sys.stderr,
        )
    else:  # stored > current: file from a newer agentsec
        print(
            f"warning: triage file {path} was written by a newer agentsec (scheme v{stored} > "
            f"v{_TRIAGE_VERSION}); some verdicts may not match — upgrade agentsec or re-triage.",
            file=sys.stderr,
        )


def load_triage(path: Path) -> list[TriageVerdict]:
    """Load verdicts from a triage file. Degrades gracefully on a missing, unreadable, or
    hand-broken file — the triage file is analyst-editable, so a bad edit must never crash a
    scan. Unreadable/malformed → []; junk entries (non-dict, no fingerprint, unknown or missing
    fields) are skipped with a stderr note rather than raising.

    A file whose stamped `version` differs from `_TRIAGE_VERSION` still loads (verdicts are
    returned), but emits one actionable stderr warning: an older-scheme file's fingerprints no
    longer match current findings (issue #325/#330 changed the scheme), so its verdicts would
    silently re-surface as untriaged. We warn rather than migrate — a verdict is human judgment,
    not a cache, and re-hashing old entries could misapply a decision to the wrong finding."""
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        print(f"warning: ignoring unreadable triage file {path}", file=sys.stderr)
        return []
    if isinstance(data, dict):
        _warn_on_version_mismatch(data.get("version"), path)
    raw = (data.get("verdicts") or []) if isinstance(data, dict) else []
    known = {fld.name for fld in fields(TriageVerdict)}
    out: list[TriageVerdict] = []
    for v in raw:
        if not (isinstance(v, dict) and v.get("fingerprint")):
            continue
        try:
            out.append(TriageVerdict(**{k: val for k, val in v.items() if k in known}))
        except TypeError:
            print(f"warning: skipping malformed triage entry {v.get('fingerprint')!r}", file=sys.stderr)
    return out


def save_triage(verdicts: list[TriageVerdict], path: Path) -> None:
    """Write verdicts to disk. Creates the file if it doesn't exist."""
    payload = {
        "version": _TRIAGE_VERSION,
        "verdicts": [asdict(v) for v in verdicts],
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def apply_triage(
    findings: list[Finding],
    verdicts: list[TriageVerdict],
) -> list[AnnotatedFinding]:
    """Attach verdicts to findings by fingerprint match."""
    index: dict[str, TriageVerdict] = {v.fingerprint: v for v in verdicts}
    result: list[AnnotatedFinding] = []
    for f in findings:
        fp = fingerprint(f)
        result.append(AnnotatedFinding(finding=f, verdict=index.get(fp)))
    return result
