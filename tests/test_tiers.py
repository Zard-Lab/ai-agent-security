"""The baseline-vs-stack tier split (ship-secure-before-detection)."""
from __future__ import annotations

from agentsec.registry import ALL_GUARDS, BASELINE_GUARD_IDS, is_baseline_guard


def test_baseline_split_is_consistent() -> None:
    # universal hygiene = baseline; capability-gated = stack
    assert is_baseline_guard("command-injection") is True
    assert is_baseline_guard("invisible-unicode") is True
    assert is_baseline_guard("dependency-version-floor") is True
    assert is_baseline_guard("stripe-payments") is False  # payments-only
    assert is_baseline_guard("public-table-rls") is False  # sql-only
    assert is_baseline_guard("lethal-trifecta") is False   # llm-only


def test_baseline_tier_is_declared_on_the_guard() -> None:
    # Replaces `test_baseline_ids_reference_real_guards`, which asserted the OPPOSITE invariant:
    # the old `BASELINE_GUARD_IDS` frozenset tolerated FORWARD REFERENCES ("ids for held-but-
    # unmerged guards are allowed, harmless set membership"). A registry-derived tier cannot
    # express one — an unmerged guard has no class to declare `tier` on — so that capability is
    # GONE as of BB4, deliberately and not by accident. Zero forward references existed when the
    # frozenset was drained (measured), so nothing broke; this note exists so the next person
    # does not rediscover the removal as a bug and "fix" it by re-adding the central list.
    baseline = sorted(g.id for g in ALL_GUARDS if g.tier == "baseline")
    assert baseline, "expected some baseline guards present on this branch"
    assert all(is_baseline_guard(gid) for gid in baseline)
    # no baseline guard is also obviously a stack-only id (sanity: disjoint from a few)
    assert "stripe-payments" not in baseline


def test_an_unregistered_id_is_never_baseline() -> None:
    # `is_baseline_guard` is called on every finding's `check_id` (`cli.py::_meta_lines`), and
    # ingested/synthetic ids reach it too. They have no class to declare a tier, so they must
    # land in the stack half rather than raise or silently inflate the "baseline floor" count.
    assert is_baseline_guard("zap") is False
    assert is_baseline_guard("sarif:some-tool") is False
    assert is_baseline_guard("") is False


def test_baseline_frozenset_is_no_longer_the_source_of_truth() -> None:
    # Pinned drained in `tests/test_checkmeta.py`; asserted here too because THIS is the file a
    # contributor opens when they want to add a baseline guard, and the obvious move — appending
    # an id to the frozenset — now works (the resolver still unions it in) while bypassing the
    # declaration. The pin is what turns that into a red test instead of a silent second source.
    assert not BASELINE_GUARD_IDS
