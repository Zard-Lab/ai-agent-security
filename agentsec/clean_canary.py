"""Clean canary — proves every static guard stays SILENT on hardened/known-good code.

The mirror image of `canary.py`'s liveness canary. Where the liveness canary
generates an "everything vulnerable" fixture tree with one deliberately-vulnerable plant per
guard and asserts every guard's rule FIRES (proving guards aren't silently dead), this module
generates an "everything hardened" fixture tree — one deliberately-SAFE plant per guard, the
hardened/mitigated form of exactly the pattern that guard detects — and asserts every guard
stays SILENT on it (proving the guard set doesn't false-positive on secure code).

Architecture deliberately mirrors `canary.py` exactly: a generated (never committed) fixture
tree (`CLEAN_FILES`, path -> content) is written to a tempdir and run through the REAL audit
pipeline (detect -> select -> run, guards-only), then the fired rule set is compared against
what SHOULD be silent. Same reasons apply: generated from code so the repo content and the
comparator can never drift apart, deterministic (no scanner binaries, no network), and the
self-test ships in the wheel.

Where the two systems differ on purpose:
  * `canary.py`'s `EXPECTED_RULES` says which rule ID must fire, per guard (positive claim).
    This module's `GUARD_PLANTS` says which file(s) carry a guard's hardened plant — the
    assertion is simply "this guard produced ZERO findings anywhere in the clean tree"
    (`f.check_id == guard_id`), because a hardened plant has no specific rule ID to expect.
  * Every plant here is sourced from that guard's OWN existing FP-bait test (the same fixture its
    unit test already asserts stays silent) or its design doc, not invented from scratch — see
    `docs/knowledge/design-clean-canary.md` for the sourcing methodology and current
    coverage count.
  * `GUARD_PLANTS` may legitimately be a subset of all guards (`COVERED_GUARDS`) — building a
    hand-verified hardened plant for all ~244 guards in one pass is explicitly NOT required;
    what's required is that coverage is never silently overstated (`test_clean_canary_no_silent_gap`
    asserts the reported "covered" count matches `len(GUARD_PLANTS)` exactly, and a guard with
    no plant is reported as "NOT COVERED YET", never folded into "clean").

Consumed by `tests/test_clean_canary.py` (CI drift gate) and `agentsec doctor --clean-canary`
(user-facing self-test of an installed copy — the negative-direction sibling of `--canary`).

Guards-only on purpose, same rationale as `canary.py`: deterministic on any machine, no scanner
binaries, no network.

`CLEAN_FILES`/`GUARD_PLANTS` (the packed fixture data) live in the sibling `clean_canary_fixtures`
module, not here (PR #579 round-2 review) — see that module's own docstring for why. This
module is the real pipeline that ships in the wheel and executes on a user's machine; keeping the
data out of it is what lets the self-audit exclude the data module narrowly instead of blinding
this one too.
"""
from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

from agentsec import clean_canary_fixtures
from agentsec.audit import AuditResult, audit
from agentsec.canary import _find_duplicate_dict_keys
from agentsec.clean_canary_fixtures import CLEAN_FILES, GUARD_PLANTS
from agentsec.findings import Finding
from agentsec.registry import ALL_GUARDS

# Guards covered by a real, sourced, hardened plant. A guard NOT in this set is reported as
# "NOT COVERED YET" — never silently folded into "clean" (the project's no-silent-cap rule).
COVERED_GUARDS: frozenset[str] = frozenset(GUARD_PLANTS)

_DUP_KEY_GUARDED_DICTS = ("CLEAN_FILES", "GUARD_PLANTS")


def write_clean_canary_repo(dest: Path) -> Path:
    """Materialize the clean (hardened) canary repo under `dest`; returns `dest`."""
    fixtures_path = clean_canary_fixtures.__file__
    assert fixtures_path is not None  # nosec B101 (internal invariant, not a security control)
    source = Path(fixtures_path).read_text(encoding="utf-8")
    for name in _DUP_KEY_GUARDED_DICTS:
        dupes = _find_duplicate_dict_keys(source, name)
        if dupes:
            raise AssertionError(
                f"{name} has duplicate key(s), silently clobbering an earlier entry: {dupes}"
            )
    for relpath, content in CLEAN_FILES.items():
        target = dest / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return dest


@dataclass(frozen=True)
class CleanCanaryReport:
    """Outcome of one clean-canary run, keyed by guard id."""

    clean: frozenset[str]                       # covered guards that stayed silent
    noisy: dict[str, tuple[str, ...]]            # covered guards that fired -> finding descriptions
    skipped: tuple[str, ...]                     # covered guards the clean stack failed to select
    uncovered: tuple[str, ...]                   # guards with no hardened plant yet (informational)

    @property
    def ok(self) -> bool:
        return not self.noisy and not self.skipped


def compare_clean(findings: list[Finding], ran_ids: frozenset[str]) -> CleanCanaryReport:
    """Pure comparator: findings from a real audit run + the set of guard ids the pipeline
    actually selected -> report. Split out from `run_clean_canary` so the alarm itself is
    unit-testable (findings from one guard's own hardened plant must produce a `noisy` entry)."""
    by_guard: dict[str, list[Finding]] = {}
    for f in findings:
        by_guard.setdefault(f.check_id, []).append(f)

    clean: set[str] = set()
    noisy: dict[str, tuple[str, ...]] = {}
    skipped: list[str] = []
    for guard_id in COVERED_GUARDS:
        if guard_id not in ran_ids:
            skipped.append(guard_id)
            continue
        hits = by_guard.get(guard_id, [])
        if hits:
            noisy[guard_id] = tuple(
                sorted(f"{f.rule or f.check_id} @ {f.location}: {f.message}" for f in hits)
            )
        else:
            clean.add(guard_id)

    all_guard_ids = {g.id for g in ALL_GUARDS}
    uncovered = tuple(sorted(all_guard_ids - COVERED_GUARDS))

    return CleanCanaryReport(
        clean=frozenset(clean),
        noisy=noisy,
        skipped=tuple(sorted(skipped)),
        uncovered=uncovered,
    )


def run_clean_canary() -> CleanCanaryReport:
    """Generate the clean (hardened) canary repo in a tempdir and run the real audit
    pipeline over it — the negative-direction sibling of `canary.run_canary()`."""
    with tempfile.TemporaryDirectory(prefix="agentsec-clean-canary-") as d:
        root = write_clean_canary_repo(Path(d))
        result = audit(root, run_scanners=False)
    return report_from_clean_audit(result)


def report_from_clean_audit(result: AuditResult) -> CleanCanaryReport:
    """The clean-canary verdict for an `audit()` of a `write_clean_canary_repo` tree."""
    return compare_clean(result.findings, frozenset(result.ran))


def to_text(report: CleanCanaryReport) -> str:
    """Render the doctor --clean-canary output (mirrors canary.py's to_text style, and is
    visually distinguishable from it: 'clean canary' header, CLEAN/NOISY marks instead of
    guard-liveness marks, and an explicit covered/uncovered count so nothing looks complete
    that isn't)."""
    lines = ["agentsec clean canary — end-to-end guard false-positive self-test\n"]
    for guard_id in sorted(COVERED_GUARDS):
        hits = report.noisy.get(guard_id)
        mark = "NOISY" if hits or guard_id in report.skipped else "CLEAN"
        detail = f"  -> FIRED: {'; '.join(hits)}" if hits else ""
        if guard_id in report.skipped:
            detail = "  -> NOT SELECTED (clean stack no longer trips its applies() gate)"
        lines.append(f"  [{mark:<5}] {guard_id:<24}{detail}")

    lines.append(
        f"\n{len(COVERED_GUARDS)} guard(s) covered by a hardened plant, "
        f"{len(report.uncovered)} not covered yet."
    )
    if report.uncovered:
        lines.append(f"  Not covered yet: {', '.join(report.uncovered)}")

    lines.append(
        "\nAll covered guards stayed silent on hardened code."
        if report.ok
        else "\nCLEAN CANARY FAILED — a guard fired on code that is supposed to be safe "
        "(a false positive). Do not trust audits until fixed."
    )
    return "\n".join(lines)
