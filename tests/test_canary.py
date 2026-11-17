"""Liveness canary drift suite — "no dead checks".

Runs the real audit pipeline (detect → select → run, guards-only) over the
generated canary repo and asserts every guard fires its planted violation and
the FP-bait stays silent. The end-to-end generalization of the flagship
dead-lint incident: a new guard fails CI here until it has a canary, and a
guard that silently dies fails loudly instead of reporting clean forever.
"""
from __future__ import annotations

import importlib.util
import inspect
import json
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest

from agentsec import canary as canary_mod
from agentsec.canary import (
    _BASE_FILES,
    _FILES,
    _GLOBAL_SUPPRESSORS,
    _LEGACY_EXPECTED,
    CANARY_EXEMPT,
    EXPECTED_RULES,
    CanaryReport,
    _find_duplicate_dict_keys,
    compare,
    diagnose_suppression,
    report_from_audit,
    run_canary,
)
from agentsec.guards.base import CanaryPlant, Guard
from agentsec.registry import ALL_GUARDS
from tests.conftest import SharedAudit

_REPO = Path(__file__).resolve().parents[1]
_GOLDEN = _REPO / "tests" / "canary_golden.json"

# The repin script is the ONE place the manifest shape is defined; the gate below imports its
# builder rather than recomputing it, so the golden and the check can never drift into comparing
# two different things (which would look like a passing gate while checking nothing).
_spec = importlib.util.spec_from_file_location("repin_canary_golden", _REPO / "scripts" / "repin-canary-golden.py")
assert _spec is not None and _spec.loader is not None
_repin = importlib.util.module_from_spec(_spec)
sys.modules["repin_canary_golden"] = _repin
_spec.loader.exec_module(_repin)


@pytest.fixture(scope="module")
def report(canary_audit: SharedAudit) -> CanaryReport:
    # The session's one shared canary audit (conftest). `test_canary_deterministic` still makes its
    # OWN fresh `run_canary()` and compares, so determinism is never judged against itself.
    return report_from_audit(canary_audit.load())


# NOTE: `slow` here means "excluded from the fast dev-loop tier" (see dev-workflow.md), NOT
# "skippable before a push." The full gate (unfiltered) is still the mandatory check before
# anything ships — this marker only lets rapid iteration skip the ~27s module-scoped
# run_canary() setup these 4 tests share, it never substitutes for a real liveness check.
@pytest.mark.slow
def test_canary_selects_all_guards(report: CanaryReport) -> None:
    # The canary stack must open every guard's applies() gate; a new guard whose
    # gate the canary can't open fails here -> extend the canary repo.
    assert report.skipped == (), f"guards not selected by the canary stack: {report.skipped}"


def test_canary_manifest_covers_all_guards() -> None:
    # A new guard fails CI until it has a canary violation + expectation.
    guard_ids = {g.id for g in ALL_GUARDS}
    missing = sorted(guard_ids - set(EXPECTED_RULES))
    orphans = sorted(set(EXPECTED_RULES) - guard_ids)
    assert not missing, f"guards without a canary expectation: {missing}"
    assert not orphans, f"canary expectations for nonexistent guards: {orphans}"


@pytest.mark.slow
def test_canary_every_guard_alive(report: CanaryReport) -> None:
    dead = {g: sorted(rules) for g, rules in report.dead.items()}
    assert not dead, f"DEAD guards (expected rule did not fire through the pipeline): {dead}"


def test_find_duplicate_dict_keys_catches_a_repeated_key() -> None:
    # a dict literal silently keeps only the last value for a repeated key, invisible
    # once the dict object exists — the detector must catch it in the source text instead.
    source = (
        "_FILES: dict[str, str] = {\n"
        '    "a.py": "one",\n'
        '    "b.py": "two",\n'
        '    "a.py": "clobbers the first",\n'
        "}\n"
    )
    assert _find_duplicate_dict_keys(source, "_FILES") == ["a.py"]


def test_find_duplicate_dict_keys_silent_when_all_unique() -> None:
    source = '_FILES: dict[str, str] = {\n    "a.py": "one",\n    "b.py": "two",\n}\n'
    assert _find_duplicate_dict_keys(source, "_FILES") == []


def test_find_duplicate_dict_keys_catches_a_repeated_key_in_a_sibling_dict() -> None:
    # (PR #401 review): the detector is generic — a repeated guard id in EXPECTED_RULES
    # (or _GLOBAL_SUPPRESSORS) silently drops a guard's expected-rule set, the same false-DEAD
    # failure mode as _FILES. Confirm it catches the sibling-dict case too.
    source = (
        "EXPECTED_RULES: dict[str, frozenset[str]] = {\n"
        '    "xxe-safe": frozenset({"a"}),\n'
        '    "cors-wildcard": frozenset({"b"}),\n'
        '    "xxe-safe": frozenset({"clobbers"}),\n'
        "}\n"
    )
    assert _find_duplicate_dict_keys(source, "EXPECTED_RULES") == ["xxe-safe"]


def test_canary_all_keyed_dicts_have_no_duplicate_keys() -> None:
    # The real canary.py must never hit the silent-clobber case for ANY of the guarded dicts —
    # this is exactly what write_canary_repo() enforces at runtime (PR #401 review Low-1).
    from agentsec.canary import _DUP_KEY_GUARDED_DICTS

    source = inspect.getsource(canary_mod)
    for name in _DUP_KEY_GUARDED_DICTS:
        assert _find_duplicate_dict_keys(source, name) == [], f"{name} has a duplicate key"


def test_canary_exempt_is_the_only_empty_expectation() -> None:
    # An empty EXPECTED_RULES passes the liveness gate vacuously — so the ONLY guards
    # allowed an empty expectation are those explicitly in CANARY_EXEMPT. This stops a
    # future accidental `frozenset()` from silently shipping a never-liveness-checked guard.
    empty = {gid for gid, rules in EXPECTED_RULES.items() if not rules}
    assert empty == set(CANARY_EXEMPT), (
        f"guards with an empty canary expectation {sorted(empty)} must equal CANARY_EXEMPT "
        f"{sorted(CANARY_EXEMPT)} — add a real plant or an explicit exemption with a reason"
    )
    guard_ids = {g.id for g in ALL_GUARDS}
    assert set(CANARY_EXEMPT) <= guard_ids, "CANARY_EXEMPT lists a nonexistent guard id"


@pytest.mark.slow
def test_canary_fp_bait_silent(report: CanaryReport) -> None:
    # The RLS-enabled table and the first-party script must never be flagged.
    assert report.unexpected_hits == (), (
        f"false positive: findings reference known-clean bait: {report.unexpected_hits}"
    )


@pytest.mark.slow
def test_canary_deterministic(report: CanaryReport) -> None:
    again = run_canary()
    assert again.fired == report.fired
    assert again.dead == report.dead
    assert again.skipped == report.skipped


def test_comparator_reports_dead_guard() -> None:
    # The alarm itself must ring: remove one guard's rules from the fired set
    # and the comparator must mark that guard dead.
    all_rules = frozenset(r for rules in EXPECTED_RULES.values() for r in rules)
    without_xxe = all_rules - EXPECTED_RULES["xxe-safe"]
    r = compare(without_xxe, hit_text="", skipped=[])
    assert "xxe-safe" in r.dead and not r.ok
    healthy = compare(all_rules, hit_text="", skipped=[])
    assert healthy.ok


def test_global_suppressor_keys_are_real_guards() -> None:
    # Drift gate: every guard the suppressor catalog references must exist, else the
    # diagnostic points at a phantom id. (Mirrors test_canary_manifest_covers_all_guards.)
    orphans = sorted(set(_GLOBAL_SUPPRESSORS) - set(EXPECTED_RULES))
    assert not orphans, f"_GLOBAL_SUPPRESSORS lists nonexistent guard ids: {orphans}"


def test_no_suppressor_marker_in_plants() -> None:
    # The invariant that replaces the 58-line prose NOTE: no global-suppressor marker may
    # appear in any generated plant, or it silences that guard repo-wide (reporting it DEAD).
    # This fails at the SOURCE — naming marker + file + silenced guard — instead of as a
    # downstream generic "guard X DEAD".
    offenders = [
        f"marker {marker!r} in {path} would silence {gid!r} repo-wide"
        for gid, markers in _GLOBAL_SUPPRESSORS.items()
        for marker in markers
        for path, content in _FILES.items()
        if marker in content
    ]
    assert not offenders, "global-suppressor marker present in the canary plants:\n" + "\n".join(offenders)


# --------------------------------------------------------------------------- assembly gates
def _classify(
    golden: Mapping[str, object], live: Mapping[str, object]
) -> tuple[list[str], list[str], list[str]]:
    """(added, removed, changed) between two {key: value} sections of the manifest."""
    added = sorted(set(live) - set(golden))
    removed = sorted(set(golden) - set(live))
    changed = sorted(k for k in set(golden) & set(live) if golden[k] != live[k])
    return added, removed, changed


def test_classify_separates_changed_from_added_plus_removed() -> None:
    # `test_assembled_canary_matches_golden` below can only report ADDED today (no guard has
    # migrated yet), so its REMOVED and CHANGED arms are unreachable in CI until the backfill
    # lands — the same vacuous-gate problem `test_half_migration_detector_actually_fires` exists
    # to solve for the sibling gate. Pin the classification directly instead of waiting.
    #
    # The load-bearing distinction is CHANGED vs ADDED+REMOVED, because they carry OPPOSITE
    # instructions: ADDED means a new guard and you re-pin the golden, CHANGED means a plant
    # migration lost content and you must fix the plant. A classifier that reported a changed
    # key as removed-then-added would tell a contributor to re-pin away a real regression.
    golden = {"same.py": "h1", "gone.py": "h2", "moved.py": "h3"}
    live = {"same.py": "h1", "new.py": "h4", "moved.py": "h3-but-different"}

    added, removed, changed = _classify(golden, live)
    assert added == ["new.py"]
    assert removed == ["gone.py"]
    assert changed == ["moved.py"]
    assert "moved.py" not in added and "moved.py" not in removed, (
        "a CHANGED key must never be reported as REMOVED+ADDED — that inverts the fix instruction"
    )
    # An untouched manifest classifies as nothing at all (the everyday green case).
    assert _classify(golden, dict(golden)) == ([], [], [])


def test_assembled_canary_matches_golden() -> None:
    # The migration rail. `canary.py` assembles the canary from its base PLUS every guard's
    # declared `canary_plant`, so moving a plant from one to the other must be provably
    # byte-identical — this is what proves it, and what stops a lossy move from landing as a
    # silently smaller canary (a guard that no longer fires reports as a clean repo).
    golden = json.loads(_GOLDEN.read_text(encoding="utf-8"))
    live = _repin.build_manifest()

    problems: list[str] = []
    for section in ("files", "expects"):
        added, removed, changed = _classify(golden[section], live[section])
        if added:
            problems.append(f"{section} ADDED (a NEW guard — re-pin, additions are expected): {added}")
        if removed:
            problems.append(f"{section} REMOVED (a plant was dropped on the floor): {removed}")
        if changed:
            problems.append(f"{section} CHANGED (a migration was NOT behavior-preserving): {changed}")

    assert not problems, (
        "assembled canary does not match tests/canary_golden.json:\n  "
        + "\n  ".join(problems)
        + "\n\nHow to read this:\n"
        "  ADDED   -> you added a guard. Re-pin: `python scripts/repin-canary-golden.py`.\n"
        "  REMOVED -> a plant was dropped. Restore it; do NOT re-pin.\n"
        "  CHANGED -> a plant moved but its content changed on the way (whitespace, a partial\n"
        "             copy, a reformat). Fix the plant so the move is byte-identical. Re-pinning\n"
        "             here launders exactly the regression this gate exists to catch."
    )


def _half_migrations(guards: list[Guard]) -> tuple[list[str], list[str]]:
    """(guard ids still keyed in the base, plant paths still in the base) across `guards`."""
    dupe_ids: list[str] = []
    dupe_paths: list[str] = []
    for g in guards:
        plant = g.canary_plant
        if plant is None:
            continue
        if g.id in _LEGACY_EXPECTED:
            dupe_ids.append(g.id)
        dupe_paths += [f"{g.id} declares {path!r}" for path in plant.files if path in _BASE_FILES]
    return dupe_ids, dupe_paths


def test_no_plant_is_declared_twice() -> None:
    # The single-source gate — the only thing that catches a HALF-migration: a guard that
    # declares a `canary_plant` while its legacy entries stay behind in the base. `_assemble()`
    # silently prefers the declaration, so the golden stays green (identical content) and the
    # repo quietly carries two sources of truth for one plant with nothing pointing at it.
    dupe_ids, dupe_paths = _half_migrations(list(ALL_GUARDS))
    assert not dupe_ids, (
        f"guards declaring a canary_plant while _LEGACY_EXPECTED still keys them: {dupe_ids} — "
        "finish the migration by deleting the base entry"
    )
    assert not dupe_paths, (
        f"plant files declared on a guard AND still in _BASE_FILES: {dupe_paths} — "
        "delete the base entry, or (for a file shared by several guards) leave the file in the "
        "base and declare `expects` only"
    )


def test_half_migration_detector_actually_fires(monkeypatch: pytest.MonkeyPatch) -> None:
    # Prove the detector itself can fail, on a guard that keeps BOTH its legacy base entry and a
    # new declaration — otherwise the gate above is untested at exactly the moment it is needed.
    #
    # The legacy id is INJECTED, not borrowed from `_LEGACY_EXPECTED`. Borrowing (`next(iter(...))`)
    # made this self-test quietly depend on the migration being unfinished, so it died with a
    # `StopIteration` the moment #617 batch 16 drained the base — a detector self-test that expires
    # when the thing it detects becomes possible-but-unprecedented is the wrong way round.
    # `setitem` mutates the one dict object `_half_migrations` reads, so the injection is visible
    # regardless of which module holds the reference, and monkeypatch removes the key afterwards.
    legacy_id = "zz-fake-legacy-plant"
    monkeypatch.setitem(_LEGACY_EXPECTED, legacy_id, frozenset({"zz-fake/rule"}))
    base_path = next(iter(_BASE_FILES))
    half = _FakePlantGuard()
    half.id = legacy_id
    half.canary_plant = CanaryPlant(files={base_path: "x"})

    dupe_ids, dupe_paths = _half_migrations([half])
    assert dupe_ids == [legacy_id]
    assert dupe_paths == [f"{legacy_id} declares {base_path!r}"]
    # ...and a fully-migrated guard (declaration only, no base leftovers) is clean.
    clean = _FakePlantGuard()
    clean.canary_plant = CanaryPlant(files={"zz-not-in-base.py": "x"})
    assert _half_migrations([clean]) == ([], [])


class _FakePlantGuard(Guard):
    """A throwaway guard used to drive `_assemble()` directly (never registered)."""

    id = "zz-fake-assembly-probe"


def _with_fake(monkeypatch: pytest.MonkeyPatch, plant: CanaryPlant) -> None:
    fake = _FakePlantGuard()
    fake.canary_plant = plant
    monkeypatch.setattr(canary_mod, "ALL_GUARDS", [*ALL_GUARDS, fake])


def test_assemble_raises_when_a_declared_plant_conflicts_with_the_base(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Two sources disagreeing about one plant file must be loud: whichever ran last would
    # silently overwrite the other's plant, reporting that guard falsely DEAD.
    _with_fake(monkeypatch, CanaryPlant(files={"app.py": "totally different content\n"}))
    with pytest.raises(AssertionError, match="canary plant file collision"):
        canary_mod._assemble()


def test_assemble_allows_an_identical_plant_file(monkeypatch: pytest.MonkeyPatch) -> None:
    # The other direction (Rule 1): identical content is a legitimate no-op merge, NOT a
    # collision. Without this, tightening the collision check into "any shared path raises"
    # would pass the test above while breaking every legitimate re-declaration.
    _with_fake(
        monkeypatch,
        CanaryPlant(files={"app.py": _BASE_FILES["app.py"]}, expects=frozenset({"zz-fake/rule"})),
    )
    files, expected = canary_mod._assemble()
    assert files["app.py"] == _BASE_FILES["app.py"]
    assert expected["zz-fake-assembly-probe"] == frozenset({"zz-fake/rule"})


def test_assemble_supports_an_expects_only_declaration(monkeypatch: pytest.MonkeyPatch) -> None:
    # The shared-scaffolding shape: a guard whose violation sits in a file owned by no single
    # guard declares `expects` and no `files`, leaving the file in the base.
    # Compared against a real assembly rather than `_BASE_FILES`, so this stays true as guards
    # migrate (an expects-only plant adds nothing on top of whatever is already assembled).
    before, _ = canary_mod._assemble()
    _with_fake(monkeypatch, CanaryPlant(expects=frozenset({"zz-fake/rule"})))
    files, expected = canary_mod._assemble()
    assert files == before, "an expects-only plant must not add or alter any file"
    assert expected["zz-fake-assembly-probe"] == frozenset({"zz-fake/rule"})


def test_assemble_with_no_declarations_is_the_legacy_literals(monkeypatch: pytest.MonkeyPatch) -> None:
    # Part A's whole thesis: with zero migrated guards, assembly IS the legacy literals — i.e.
    # `_assemble()` adds nothing of its own and passes the base through untouched.
    # Post-#617 the EXPECTATIONS half of that pair is empty by design (see the tombstone on
    # `_LEGACY_EXPECTED`), so what this still pins is the `_BASE_FILES` passthrough — the shared
    # scaffolding that stays in the base permanently. Kept rather than retired for that half.
    monkeypatch.setattr(canary_mod, "ALL_GUARDS", [])
    assert canary_mod._assemble() == (_BASE_FILES, _LEGACY_EXPECTED)


def test_legacy_expected_stays_drained() -> None:
    # #617's end state, pinned. An expectation belongs on its guard, never in `canary.py` — even
    # when the plant FILE stays in `_BASE_FILES` as shared scaffolding, in which case the guard
    # declares `expects` only (the `xxe_safe.py` shape). So there is no legitimate reason to add a
    # key back here, and the whole point of Part C was that adding a guard must not require editing
    # this file. Without this gate "drained" is a transient state nothing defends.
    assert _LEGACY_EXPECTED == {}, (
        f"_LEGACY_EXPECTED must stay empty; found {sorted(_LEGACY_EXPECTED)} — declare the "
        "expectation on the guard as `canary_plant = CanaryPlant(expects=frozenset({...}))` instead"
    )


def test_every_guard_declares_its_own_plant() -> None:
    # The other half of the end state. With the base drained, `canary_plant is None` no longer
    # means "my plant lives in `canary.py`" (there is nothing left to live in) — it means the guard
    # never declared one, and `test_canary_manifest_covers_all_guards` would then fail with the
    # less obvious "guards without a canary expectation". Every shape has a declaration available:
    # an exclusive plant declares `files` + `expects`, shared scaffolding declares `expects` only,
    # and a `CANARY_EXEMPT` guard declares an empty `expects` (which is why the exemption is
    # expressed as a declaration rather than as `None` — see `CANARY_EXEMPT`).
    undeclared = sorted(g.id for g in ALL_GUARDS if g.canary_plant is None)
    assert not undeclared, (
        f"guards with no `canary_plant` declaration: {undeclared} — declare one on the guard "
        "class (`files` + `expects`, or `expects` only when the plant file is shared scaffolding)"
    )


def test_plant_split_counts_declared_versus_legacy() -> None:
    declared, legacy = canary_mod.plant_split()
    assert declared + legacy == len(ALL_GUARDS)
    assert declared == sum(1 for g in ALL_GUARDS if g.canary_plant is not None)


def test_diagnose_suppression_names_the_offender(monkeypatch: pytest.MonkeyPatch) -> None:
    # With a clean repo the diagnostic is silent...
    assert diagnose_suppression(frozenset({"csv-injection"})) == {}
    # ...but plant a csv-injection suppressor and it must name the file it landed in.
    poisoned = dict(_FILES)
    poisoned["backend/reporting.py"] = "def safe_cell(v):\n    return v\n"
    monkeypatch.setattr(canary_mod, "_FILES", poisoned)
    diag = diagnose_suppression(frozenset({"csv-injection"}))
    assert "csv-injection" in diag
    assert any("safe_cell" in h and "backend/reporting.py" in h for h in diag["csv-injection"])
    # a DEAD guard with no planted marker stays absent from the diagnosis
    assert "xxe-safe" not in diagnose_suppression(frozenset({"xxe-safe"}))
