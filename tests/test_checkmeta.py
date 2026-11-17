"""Guard-declared check metadata (`area` / `tier` / `surfacing`) — BB4.

Three hand-maintained, id-keyed maps in `findings.py`/`registry.py` used to answer questions only
the check itself knows. They moved onto the check classes by the mechanism #617 proved out for
`canary_plant`. This file holds the net under that move. The legacy pins keep every check the old
maps answered on the SAME answer, and constrain nothing added since: a new check declares freely
(#766). The declaration gate keeps each `surfacing_rule_prefixes` entry pointing at a rule its
check names. The coverage/drained gates keep the end state from rotting. What a surfacing
declaration DOES is pinned by a real run in each guard's own test, not here.
"""
from __future__ import annotations

import ast
import importlib.util
import inspect
import sys
from pathlib import Path

import pytest

from agentsec.checkmeta import AREA_ORDER, FALLBACK_AREA
from agentsec.findings import (
    _AREA_LEGACY,
    _NONREGISTRY_AREA,
    _REVIEW_RULE_PREFIXES,
    Finding,
    _area,
    _is_review_finding,
)
from agentsec.prioritize import confidence
from agentsec.registry import (
    _CHECK_META,
    ALL_CHECKS,
    ALL_GUARDS,
    ALL_RUNNERS,
    BASELINE_GUARD_IDS,
    check_meta,
    is_baseline_guard,
)

# --- frozen snapshots of the pre-migration truth -----------------------------
# Hand-copied LITERALS, deliberately NOT `from agentsec.findings import _AREA`. Importing the live
# constant would make every assertion below pass trivially the moment the map is drained — a test
# that presents as success (CLAUDE.md Rule 3) exactly where the migration needs a real net.

_LEGACY_AREA_SNAPSHOT: dict[str, str] = {
    "jwt-alg": "Login & access", "service-role-key": "Login & access",
    "public-table-rls": "Database", "definer-function-grants": "Database", "pg-ssl-required": "Database",
    "cors-wildcard": "Web setup", "security-headers": "Web setup", "api-docs-exposed": "Web setup",
    "debug-default-off": "Web setup", "frontend-xss": "Web & browser", "eslint": "Web & browser",
    "react-doctor": "Web & browser", "csv-injection": "Data export", "stripe-payments": "Payments",
    "sensitive-logging": "Logging", "lethal-trifecta": "AI agent", "system-prompt-leak": "AI agent",
    "input-delimiters": "AI agent", "invisible-unicode": "AI agent",
    "unsafe-deserialization": "Code safety", "command-injection": "Code safety", "ssti": "Code safety",
    "xxe-safe": "Code safety", "bandit": "Code safety", "semgrep": "Code safety",
    "path-traversal": "Files", "background-tasks": "Reliability",
    "js-supply-chain": "Dependencies", "python-supply-chain": "Dependencies",
    "dependency-version-floor": "Dependencies", "pip-audit": "Dependencies", "node-audit": "Dependencies",
    "trivy": "Dependencies", "gitleaks": "Secrets", "hadolint": "Containers",
    "actions-sha-pin": "Build pipeline", "actions-script-injection": "Build pipeline",
}

_LEGACY_BASELINE_SNAPSHOT: frozenset[str] = frozenset({
    "actions-sha-pin", "actions-script-injection", "js-supply-chain", "python-supply-chain",
    "dependency-version-floor",
    "command-injection", "unsafe-deserialization", "ssti", "path-traversal", "redos",
    "xxe-safe", "debug-default-off", "nosql-metadata-injection", "background-tasks",
    "sensitive-logging", "jwt-alg",
    "invisible-unicode", "iam-wildcard",
})

# The checks the pre-migration `_REVIEW_RULE_PREFIXES` covered (`bola/`, `lethal-trifecta/`,
# `system-prompt-leak/`, `input-delimiters/`, `trivy-image/`), each with a rule it REALLY emits and
# the class that tuple gave it. Real rules, not a synthetic `<id>/probe`: trivy's split keys on the
# rule string, and a probe no check emits cannot see a rule-keyed declaration (#766).
_LEGACY_REVIEW_SNAPSHOT: tuple[tuple[str, str, bool], ...] = (
    ("bola", "bola/unscoped-object-fetch", True),
    ("lethal-trifecta", "lethal-trifecta/no-defense", True),
    ("system-prompt-leak", "system-prompt-leak/no-leak-filter", True),
    ("input-delimiters", "input-delimiters/unwrapped-user-input", True),
    ("trivy", "trivy-image/CVE-2024-0001", True),
    ("trivy", "CVE-2024-0001", False),
    ("trivy", "trivy-secret", False),
    ("trivy", "trivy-misconfig", False),
)

# The check ids produced outside the registry (ingest / synthetic). Listed here as a literal for
# the same reason as the snapshots above, and because a NEW ingester that forgets its area is the
# regression this gate exists to catch. The two DYNAMIC prefixes (`sarif:<tool>`, `ingest:<kind>`)
# are intentionally absent — their tails are open-ended, so they fall back by design.
_KNOWN_NONREGISTRY_IDS: tuple[str, ...] = (
    "zap", "splinter", "schemathesis", "jwt-tool", "garak", "promptfoo",
    "deps-monitor", "harden-host", "gitignore-cap",
)


def _probe(check_id: str, rule: str) -> Finding:
    return Finding(check_id=check_id, severity="medium", title="probe", location="x.py", rule=rule)


# --- legacy pins (the checks the migration covered) --------------------------


def test_area_resolution_matches_the_legacy_map_for_every_mapped_id() -> None:
    # Pre-migration equivalence. Every id the old `_AREA` answered must still get the SAME answer
    # from its guard's own declaration. This is #617's byte-identical-passthrough gate
    # (tests/test_canary.py::test_assemble_is_byte_identical_passthrough) applied to the area move:
    # it is what makes a 293-file mechanical edit reviewable, because a mis-typed row fails here
    # instead of quietly re-bucketing a user's report.
    for cid, expected in _LEGACY_AREA_SNAPSHOT.items():
        assert _area(cid) == expected, f"{cid} moved bucket: {expected} -> {_area(cid)}"


def test_review_classification_matches_the_legacy_prefixes_for_every_legacy_check() -> None:
    # Scoped like the area pin above: every check the old tuple answered gets the SAME answer from
    # its own declaration. This used to sweep EVERY registered check against the frozen tuple with a
    # synthetic `<id>/probe` rule, which (1) failed a correct `surfacing = True` on any check added
    # after the migration, so each one was appended to an allowlist here (a seventh file), and (2)
    # could never see a `surfacing_rule_prefixes` declaration, because the probe matches none
    # (#766). A check added since is free to declare. The declaration gate below and that guard's
    # own real-run pin are its net.
    for cid, rule, expected in _LEGACY_REVIEW_SNAPSHOT:
        assert _is_review_finding(_probe(cid, rule)) is expected, f"{cid} changed review class on {rule}"


def test_each_legacy_baseline_id_still_resolves_to_the_baseline_tier() -> None:
    # One direction only, scoped like the area pin: the 18 stay in. The old "and the other 275 stay
    # out" half failed a documented `tier = "baseline"` on any guard added after the migration
    # (#766). A new baseline guard is a visible one-line class diff, and `tests/test_tiers.py`
    # checks the declared set resolves.
    for cid in sorted(_LEGACY_BASELINE_SNAPSHOT):
        assert is_baseline_guard(cid), f"{cid} left the baseline tier"


def test_trivy_image_cves_stay_surfacing_and_fs_scan_cves_stay_proven() -> None:
    # The reason `surfacing` could not be a flat boolean on `Runner`. One runner, one check_id, two
    # classes of finding: a CVE inside a third-party base image (`trivy-image/<CVE>`) is a judgment
    # call, a bare fs-scan `<CVE>` is a proven, fixable bug. Flattening this would add `+4` to every
    # fs-scan CVE's `priority_rank` and demote real work out of "Fix these first". Asserted in ONE
    # test on purpose, so a later "simplification" cannot collapse the split without going red.
    image = _probe("trivy", "trivy-image/CVE-2024-0001")
    fs_scan = _probe("trivy", "CVE-2024-0001")
    assert _is_review_finding(image) is True
    assert _is_review_finding(fs_scan) is False
    assert confidence(image) == "review"
    assert confidence(fs_scan) == "proven"
    # ...and the runner's other two rule shapes are proven too.
    assert _is_review_finding(_probe("trivy", "trivy-secret")) is False
    assert _is_review_finding(_probe("trivy", "trivy-misconfig")) is False


def test_surfacing_is_keyed_on_check_id_not_on_rule_prefix() -> None:
    # Stated explicitly because it differs from the old logic IN PRINCIPLE even where it agrees in
    # practice: a guard whose rule prefix is not its id (the `agent-memory/` family) is now
    # classified by the check that emitted the finding, not by how the rule string happens to start.
    assert _is_review_finding(_probe("bola", "some-other-prefix/x")) is True, "whole check surfaces"
    assert _is_review_finding(_probe("agent-memory-security", "agent-memory/x")) is False


# --- declaration gate --------------------------------------------------------

# The one check whose surfacing rules sit outside its own `<id>/` namespace: the `trivy` runner
# names a base-image CVE `trivy-image/<CVE>` and leaves an fs-scan CVE bare.
_FOREIGN_RULE_NAMESPACE: dict[str, str] = {"trivy": "trivy-image/"}


def _string_literals_outside_the_declaration(check: object) -> list[str]:
    """Every string literal the check's module USES, minus two kinds. One is anything inside a
    `surfacing_rule_prefixes` assignment: without that the gate is vacuous, since a typo'd prefix
    always finds itself. The other is a string statement (a docstring, or a bare string used as a
    comment): guards document their rules there, so a renamed rule's old name would survive in it
    and hide the rename (#1091 round 1)."""
    module = inspect.getmodule(type(check))
    assert module is not None
    tree = ast.parse(inspect.getsource(module))
    skip: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "surfacing_rule_prefixes" for t in node.targets
        ):
            skip.update(id(n) for n in ast.walk(node))
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            skip.add(id(node.value))
    return [
        n.value for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in skip
    ]


def test_surfacing_rule_prefixes_name_rules_their_check_emits() -> None:
    # The flat `surfacing = True` cannot be dead: it covers every rule the check has. A prefix can
    # be: a typo, or a rule renamed underneath it, matches nothing and silently classifies that
    # rule as proven (#766). This is TEXTUAL: each prefix's tail must appear in a string literal
    # the module uses, outside the declaration and outside docstrings. That catches a typo, and a
    # rename unless the old name survives in some other used literal (a message, a constant). It
    # cannot see a rule that stopped firing. What the declaration does is pinned by the real-run
    # `_is_review_finding` test in the guard's own file.
    declared = [c for c in ALL_CHECKS if c.surfacing_rule_prefixes]
    assert declared, "no check declares surfacing_rule_prefixes; this gate would pass vacuously"
    for c in declared:
        prefixes = c.surfacing_rule_prefixes
        assert isinstance(prefixes, tuple), f"{c.id}: surfacing_rule_prefixes must be a tuple"
        assert not c.surfacing, f"{c.id}: flat `surfacing = True` makes its rule prefixes dead"
        namespace = _FOREIGN_RULE_NAMESPACE.get(c.id, f"{c.id}/")
        literals = _string_literals_outside_the_declaration(c)
        for p in prefixes:
            assert isinstance(p, str) and p.startswith(namespace), f"{c.id}: {p!r} is not under {namespace!r}"
            needle = p if c.id in _FOREIGN_RULE_NAMESPACE else p[len(namespace):]
            assert needle, f"{c.id}: {p!r} covers every rule; declare `surfacing = True` instead"
            assert any(needle in s for s in literals), (
                f"{c.id}: no rule in its module matches the surfacing prefix {p!r} (typo or renamed rule?)"
            )


# A guard that renamed its emitted rule but kept documenting the old name, the way real guards list
# their rules in docstrings (#1091 round 1, M1: `ssrf-general`'s docstrings kept a renamed tail alive).
_RENAMED_RULE_MODULE = '''"""Fires `fake-check/old-name` on a thing."""


class FakeCheck:
    """Emits fake-check/old-name."""

    id = "fake-check"
    surfacing_rule_prefixes = ("fake-check/old-name",)

    def run(self):
        """Returns fake-check/old-name findings."""
        rules = []
        "fake-check/old-name is the documented rule"
        rules.append(f"{self.id}/new-name")
        return rules
'''


def _load_check(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, source: str) -> object:
    path = tmp_path / f"{name}.py"
    path.write_text(source, encoding="utf-8")
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)  # `inspect.getmodule` resolves through sys.modules
    spec.loader.exec_module(module)
    return module.FakeCheck()


def test_declaration_gate_ignores_docstrings_so_a_renamed_rule_is_seen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Both directions on one module: the old tail, alive only in docstrings and a bare string
    # statement, is NOT a used literal (so the gate fails the stale prefix), while the emitted
    # f-string's tail still IS one (so a rule built as `f"{self.id}/<rule>"` is not a false failure).
    literals = _string_literals_outside_the_declaration(
        _load_check(tmp_path, monkeypatch, "fake_renamed_surfacing_check", _RENAMED_RULE_MODULE),
    )
    assert not any("old-name" in s for s in literals), literals
    assert any("/new-name" in s for s in literals), literals


# --- coverage gates ----------------------------------------------------------


def test_check_meta_index_covers_every_registered_check() -> None:
    # `{c.id: c for c in ALL_CHECKS}` silently keeps only the LAST of a duplicated id. Guard and
    # runner ids are unique today; assert it rather than assume it, because the failure mode is a
    # check that quietly stops declaring anything while every other gate still passes.
    assert len(_CHECK_META) == len(ALL_GUARDS) + len(ALL_RUNNERS)
    assert len(ALL_CHECKS) == len(ALL_GUARDS) + len(ALL_RUNNERS)


def test_every_registered_check_declares_an_area() -> None:
    # The gate the old `_AREA` never had. Without it, a guard authored exactly to the documented
    # 6-file recipe silently lands 1 of 293 checks in the catch-all bucket and nothing goes red.
    undeclared = sorted(c.id for c in ALL_CHECKS if not c.area)
    assert not undeclared, (
        f'checks with no declared `area`: {undeclared} — set `area = "..."` on the class, '
        "directly under `id`/`title`, using a value from `checkmeta.AREA_ORDER`"
    )


def test_declared_areas_are_in_the_vocabulary() -> None:
    # Keeps the vocabulary closed. With 293 free-string declarations, "Login & access" and
    # "Login & Access" would both exist within a month and the summary would split one bucket in
    # two — invisibly, because both render.
    bad = sorted({c.area for c in ALL_CHECKS} - set(AREA_ORDER))
    assert not bad, f"areas outside the closed vocabulary: {bad} — add to AREA_ORDER or fix the typo"


def test_known_nonregistry_check_ids_have_an_area() -> None:
    # Registry coverage is NOT full coverage of what reaches `to_human_summary()`. These ids are
    # produced by ingesters and by the audit loop itself, have no class to declare on, and would
    # otherwise become the next silently-incomplete map — the exact shape BB4 removed.
    missing = [cid for cid in _KNOWN_NONREGISTRY_IDS if cid not in _NONREGISTRY_AREA]
    assert not missing, f"non-registry check ids with no area: {missing}"
    bad = sorted({_NONREGISTRY_AREA[c] for c in _KNOWN_NONREGISTRY_IDS} - set(AREA_ORDER))
    assert not bad, f"non-registry areas outside the vocabulary: {bad}"


def test_dynamic_ingest_prefixes_fall_back_without_raising() -> None:
    # `sarif:<tool>` and `ingest:<kind>` have open-ended tails that cannot be enumerated, so they
    # are deliberately excluded from `_NONREGISTRY_AREA` and must degrade to the catch-all.
    assert _area("sarif:some-new-tool") == FALLBACK_AREA
    assert _area("ingest:some-new-kind") == FALLBACK_AREA
    assert _area("totally-unknown-id") == FALLBACK_AREA


def test_a_registered_check_wins_over_the_nonregistry_map() -> None:
    # Resolution order must be deterministic where both could answer. Uses a real registered id
    # temporarily present in both maps rather than asserting the order in a comment.
    cid = ALL_GUARDS[0].id
    declared = _area(cid)
    _NONREGISTRY_AREA[cid] = "Payments"
    try:
        assert _area(cid) == declared, "the registry declaration must win"
    finally:
        del _NONREGISTRY_AREA[cid]


# --- drained-and-pinned end state --------------------------------------------


def test_area_legacy_stays_drained() -> None:
    # BB4's end state, pinned. `_area()` still consults this map, so an entry re-added here WORKS
    # — which is why the pin has to be the thing that catches it. Adding a guard must not mean
    # editing `findings.py`; that shared-append is what made the map 37-of-293 in the first place.
    assert _AREA_LEGACY == {}, (
        f"_AREA_LEGACY must stay empty; found {sorted(_AREA_LEGACY)} — declare the bucket on the "
        'check as `area = "..."` (a value from `checkmeta.AREA_ORDER`) instead'
    )


def test_review_prefixes_legacy_stays_drained() -> None:
    assert _REVIEW_RULE_PREFIXES == (), (
        f"_REVIEW_RULE_PREFIXES must stay empty; found {list(_REVIEW_RULE_PREFIXES)} — declare "
        "`surfacing = True` on the check, or `surfacing_rule_prefixes = (...)` when only some of "
        "its rules are review signals (the `trivy` shape)"
    )


def test_baseline_ids_legacy_stays_drained() -> None:
    assert not BASELINE_GUARD_IDS, (
        f"BASELINE_GUARD_IDS must stay empty; found {sorted(BASELINE_GUARD_IDS)} — declare "
        '`tier = "baseline"` on the guard class instead'
    )


@pytest.mark.parametrize("cid", sorted(_LEGACY_BASELINE_SNAPSHOT))
def test_each_legacy_baseline_id_still_resolves_to_a_real_guard(cid: str) -> None:
    # The frozenset tolerated forward references to held-but-unmerged guards; a class attribute
    # cannot express one. Zero existed when it was drained, and this is the gate that would have
    # caught it — see `tests/test_tiers.py::test_baseline_tier_is_declared_on_the_guard`.
    assert check_meta(cid) is not None, f"{cid} names no registered check"


def test_runners_declare_metadata_too() -> None:
    # `Guard` and `Runner` share no base class, so the four attributes are duplicated rather than
    # inherited. Assert the runner half independently — a copy-paste that lands on only one of the
    # two base classes still passes every guard-only sweep above.
    for r in ALL_RUNNERS:
        assert r.area in AREA_ORDER, f"runner {r.id} has no valid area"
        assert r.tier in ("baseline", "stack")
