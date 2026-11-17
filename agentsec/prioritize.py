"""Finding prioritization — lead with what is actually exploitable, demote the noise.

A scanner that emits hundreds of equally-weighted findings gets ignored (alert fatigue is the #1
AppSec-tool failure mode). This module adds a cheap, deterministic **reachability + confidence** score on
top of severity, so the report can lead with the few findings that matter and group the rest.

Two axes, both stdlib-cheap (no taint analysis):

- **reachability** — a finding in product code is more likely exploitable than one in a test, a database
  migration, a one-off script, or vendored/build output. Path-based, conservative.
- **confidence** — a *surfacing* guard flags an architecture to review (it does not assert a proven bug),
  so it ranks below a proven finding of the same severity. Reuses `findings._is_review_finding`.

Nothing here changes a `Finding`; it is a pure presentation layer over the same list.
"""
from __future__ import annotations

import re

from agentsec.detect import ARCHIVE_SEGMENTS, NONPRODUCT_DIR_ALT
from agentsec.findings import SEVERITY_RANK, Finding, _is_review_finding, is_historical, sort_findings

# Path segments that mark NON-product code: a finding here is far less likely to be a live,
# attacker-reachable bug, so it is demoted (never dropped). Built from the SINGLE shared
# `NONPRODUCT_DIR_ALT` (the universal test/fixture/migration conventions, shared with the guard
# DROP gate `guards.base`) plus archived/dead-code trees (`ARCHIVE_SEGMENTS`). This is the DEMOTE
# half of the one source of truth — same membership as DROP, different action.
#
# Deliberately NOT listed here (was, pre-consolidation): vendored/build dirs (`node_modules`,
# `.venv`, `dist`, `build`, `vendor`, …) — `walk.DEFAULT_EXCLUDE_DIRS` (Layer 0) already prevents
# them from ever appearing in a finding; and fuzzy/repo-specific dirs (`scripts`, `tools`, `docs`,
# `alembic`) — those are now opt-in per repo via `.agentsec/config.json` `nonproduct_paths` and the
# exclude advisor, so the tool stays project-agnostic instead of guessing globally.
# EPSS >= this is treated as a high-probability signal worth a priority boost. 10% is a widely
# used operational cutoff in vuln-management tooling (the point where EPSS is commonly treated as
# actionable) — not a threshold invented for this codebase.
_EPSS_HIGH_THRESHOLD = 0.10

_ARCHIVE_ALT = "|".join(sorted(ARCHIVE_SEGMENTS))
_NON_PRODUCT = re.compile(
    r"(?:^|[\\/])(?:" + NONPRODUCT_DIR_ALT + r"|" + _ARCHIVE_ALT + r")[\\/]"
    r"|(?:^|[\\/])(?:test_[^\\/]*|conftest)\.py(?::|$)",
    re.I,
)


def reachability(f: Finding) -> str:
    """'product' (default) or 'low' (a hardwired test/fixture/migration path per `_NON_PRODUCT`,
    a finding stamped `superseded` by `sql_state`, or one stamped `nonproduct` by `audit()` for a
    repo's opt-in `.agentsec/config.json` `nonproduct_paths` tree — e.g. `evals/`, `scripts/`).

    `confirmed-live` overrides everything: if Splinter reported this issue in the live DB it is
    NOT historical (regardless of which file declares it), so it stays product-level even when
    the static passes would otherwise demote it (the live DB is the ultimate source of truth)."""
    if getattr(f, "provenance", "") == "confirmed-live":
        return "product"
    if is_historical(f):  # superseded by the dump and not confirmed live — the shared predicate (#800)
        return "low"
    if getattr(f, "nonproduct", False):  # repo's opt-in `nonproduct_paths` (per-repo DEMOTE)
        return "low"
    return "low" if _NON_PRODUCT.search(f.location or "") else "product"


def confidence(f: Finding) -> str:
    """'review' for surfacing guards, else 'proven'."""
    return "review" if _is_review_finding(f) else "proven"


def priority_rank(f: Finding) -> int:
    """Lower = fix first. Severity dominates; surfacing and low-reachability add penalties so a
    proven, product-code high beats a surfacing or test-only one of the same severity. A finding
    the live DB confirms (Splinter cross-confirmation) gets a small boost — it leads its severity."""
    sev = SEVERITY_RANK.get(f.severity, 99) * 10
    conf_penalty = 4 if confidence(f) == "review" else 0
    reach_penalty = 6 if reachability(f) == "low" else 0
    confirmed_boost = -2 if getattr(f, "provenance", "") == "confirmed-live" else 0
    # KEV (CISA Known-Exploited) is the strongest real-world signal — a known-exploited finding
    # leads its severity band (and can edge ahead of a same-severity non-KEV one).
    kev_boost = -3 if getattr(f, "kev", False) else 0
    # EPSS is predictive (a modeled probability), not a confirmation — a smaller boost than KEV's,
    # and only above a documented high-probability operational threshold (10%; widely used by
    # vuln-management tooling as the line where EPSS becomes actionable, not a threshold this
    # codebase invented). A finding can be both KEV AND high-EPSS; the boosts simply add.
    epss = getattr(f, "epss", None)
    epss_boost = -2 if epss is not None and epss >= _EPSS_HIGH_THRESHOLD else 0
    return sev + conf_penalty + reach_penalty + confirmed_boost + kev_boost + epss_boost


def prioritized(findings: list[Finding]) -> list[Finding]:
    """The findings, ordered by (priority_rank, the normal sort_key) — leads with the exploitable few."""
    return sorted(sort_findings(findings), key=priority_rank)


def _triage_internal(findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
    """Split into (actionable, deprioritized).

    Deprioritized = low-reachability findings that are NOT critical/high (the medium/low noise floor in
    tests, migrations, scripts). Everything else is actionable. Conservative: a high+ severity finding is
    always actionable even in a test path (it could still be a real bug).

    The one exception to that carve-out is a superseded (historical) SQL finding, deprioritized at EVERY
    severity (#800). The carve-out protects a path-based *guess*; supersedence is the dump's *answer*:
    anything still live is in the dump at full priority, so the migration copy is a duplicate or history
    whatever its severity. Before this, 138 superseded HIGHs on the flagship stayed "actionable" and the
    stamp was a no-op everywhere a user looked."""
    actionable: list[Finding] = []
    deprioritized: list[Finding] = []
    for f in prioritized(findings):
        is_severe = SEVERITY_RANK.get(f.severity, 99) <= SEVERITY_RANK["high"]
        if is_historical(f) or (reachability(f) == "low" and not is_severe):
            deprioritized.append(f)
        else:
            actionable.append(f)
    return actionable, deprioritized
