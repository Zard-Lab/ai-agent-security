"""Clean canary drift suite — "no silent false positives".

Runs the real audit pipeline (detect -> select -> run, guards-only) over the generated
"everything hardened" fixture repo and asserts every covered guard stays SILENT. The
negative-direction sibling of `tests/test_canary.py`: that suite proves a guard never goes
silently dead (false negative); this one proves a guard never silently starts crying wolf on
secure code (false positive). See `agentsec/clean_canary.py`'s module docstring and
`docs/knowledge/design-clean-canary.md` for the architecture and current coverage.
"""
from __future__ import annotations

import inspect

import pytest

from agentsec import clean_canary_fixtures as clean_canary_fixtures_mod
from agentsec.clean_canary import (
    COVERED_GUARDS,
    CleanCanaryReport,
    compare_clean,
    report_from_clean_audit,
    run_clean_canary,
)
from agentsec.clean_canary_fixtures import CLEAN_FILES, GUARD_PLANTS
from agentsec.findings import Finding
from agentsec.registry import ALL_GUARDS
from tests.conftest import SharedAudit


@pytest.fixture(scope="module")
def report(clean_canary_audit: SharedAudit) -> CleanCanaryReport:
    # The session's one shared clean-canary audit (conftest); `test_clean_canary_deterministic`
    # keeps its own fresh `run_clean_canary()`.
    return report_from_clean_audit(clean_canary_audit.load())


# NOTE: `slow` here means "excluded from the fast dev-loop tier" (see dev-workflow.md), NOT
# "skippable before a push" — mirrors the same marker on the liveness canary's equivalent tests.
@pytest.mark.slow
def test_clean_canary_all_covered_guards_selected(report: CleanCanaryReport) -> None:
    # The clean stack must open every COVERED guard's applies() gate; a covered guard the
    # clean stack can't select fails here -> extend CLEAN_FILES's stack-signaling content.
    assert report.skipped == (), f"covered guards not selected by the clean stack: {report.skipped}"


@pytest.mark.slow
def test_clean_canary_every_covered_guard_stays_silent(report: CleanCanaryReport) -> None:
    noisy = {g: list(hits) for g, hits in report.noisy.items()}
    assert not noisy, f"NOISY guards (fired on code that is supposed to be hardened): {noisy}"


def test_clean_canary_guard_plants_reference_real_guards() -> None:
    # A GUARD_PLANTS entry for a nonexistent guard id points the coverage count at a phantom.
    guard_ids = {g.id for g in ALL_GUARDS}
    orphans = sorted(set(GUARD_PLANTS) - guard_ids)
    assert not orphans, f"GUARD_PLANTS references nonexistent guard ids: {orphans}"


def test_clean_canary_no_silent_gap() -> None:
    # The project's "no silent caps" rule, enforced in code: COVERED_GUARDS must be EXACTLY
    # the guard ids GUARD_PLANTS maps — no guard can be silently counted as "covered" without a
    # real plant, and every guard id is in exactly one of COVERED_GUARDS / "not covered yet"
    # (report.uncovered), so coverage can never be double-counted or silently dropped.
    assert frozenset(GUARD_PLANTS) == COVERED_GUARDS
    guard_ids = {g.id for g in ALL_GUARDS}
    assert guard_ids >= COVERED_GUARDS, "GUARD_PLANTS covers a guard id that doesn't exist"


def test_clean_canary_plant_paths_exist_in_clean_files() -> None:
    # Every path a guard claims to be planted at must actually be materialized content —
    # otherwise "covered" would be reporting on a file that doesn't exist.
    missing = [
        (gid, path)
        for gid, paths in GUARD_PLANTS.items()
        for path in paths
        if path not in CLEAN_FILES
    ]
    assert not missing, f"GUARD_PLANTS references path(s) not present in CLEAN_FILES: {missing}"


def test_clean_canary_all_keyed_dicts_have_no_duplicate_keys() -> None:
    # Mirrors test_canary_all_keyed_dicts_have_no_duplicate_keys — a dict literal silently
    # keeps only the LAST value for a repeated key, so this checks the AST of the
    # source text directly, the same guard write_clean_canary_repo() enforces at runtime.
    from agentsec.canary import _find_duplicate_dict_keys
    from agentsec.clean_canary import _DUP_KEY_GUARDED_DICTS

    source = inspect.getsource(clean_canary_fixtures_mod)
    for name in _DUP_KEY_GUARDED_DICTS:
        assert _find_duplicate_dict_keys(source, name) == [], f"{name} has a duplicate key"


@pytest.mark.slow
def test_clean_canary_deterministic(report: CleanCanaryReport) -> None:
    again = run_clean_canary()
    assert again.clean == report.clean
    assert again.noisy == report.noisy
    assert again.skipped == report.skipped


def test_comparator_reports_a_noisy_guard() -> None:
    # The alarm itself must ring: a deliberately-noisy fake "hardened" fixture (a guard firing
    # on its own supposedly-clean plant) must make the comparator report NOISY, not silently
    # pass — the same discipline `test_comparator_reports_dead_guard` applies to canary.py.
    # Use a real guard id from the covered set so this exercises the real comparison path.
    some_guard = next(iter(COVERED_GUARDS))
    noisy_finding = Finding(
        check_id=some_guard,
        severity="high",
        title="fake finding",
        location="clean/py/does_not_matter.py:1",
        message="a guard fired on what should be hardened code",
        rule=f"{some_guard}/fake-rule",
    )
    ran_ids = frozenset(COVERED_GUARDS)
    r = compare_clean([noisy_finding], ran_ids)
    assert some_guard in r.noisy and not r.ok
    # A clean run (no findings) for the same guard set must report ok.
    healthy = compare_clean([], ran_ids)
    assert some_guard in healthy.clean
    assert healthy.ok


def test_comparator_reports_a_skipped_guard() -> None:
    # A covered guard the clean stack fails to select must show up as skipped, not silently
    # vanish from the report (mirrors the liveness canary's "skipped" gate).
    some_guard = next(iter(COVERED_GUARDS))
    other_guards = frozenset(COVERED_GUARDS) - {some_guard}
    r = compare_clean([], other_guards)
    assert some_guard in r.skipped
    assert not r.ok


def test_write_clean_canary_repo_materializes_every_file(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from agentsec.clean_canary import write_clean_canary_repo

    root = write_clean_canary_repo(tmp_path)
    for relpath, content in CLEAN_FILES.items():
        target = root / relpath
        assert target.is_file(), f"{relpath} was not written"
        assert target.read_text(encoding="utf-8") == content


@pytest.mark.slow
def test_clean_canary_visually_distinguishable_from_canary_output(report: CleanCanaryReport) -> None:
    # A user reading terminal output must be able to tell the two canaries apart at a glance —
    # different header, different per-item marks (CLEAN/NOISY vs the liveness canary's checkmarks).
    from agentsec.clean_canary import to_text as clean_to_text

    text = clean_to_text(report)
    assert "clean canary" in text.lower()
    assert "CLEAN" in text or "NOISY" in text
    assert "✓" not in text  # the liveness canary's ✓ glyph must not appear here
