"""Tests for the finding prioritization layer (reachability + confidence)."""
from __future__ import annotations

from agentsec.findings import Finding
from agentsec.prioritize import _triage_internal as triage
from agentsec.prioritize import confidence, prioritized, reachability


def _f(rule: str, severity: str, location: str) -> Finding:
    return Finding(check_id=rule.split("/")[0], severity=severity, title=rule,
                   location=location, message="", rule=rule)


def test_reachability_product_vs_low() -> None:
    assert reachability(_f("x/y", "high", "app/routes.py:10")) == "product"
    assert reachability(_f("x/y", "high", "tests/test_x.py:3")) == "low"
    assert reachability(_f("x/y", "high", "migrations/0001.py:5")) == "low"
    assert reachability(_f("x/y", "high", "conftest.py:1")) == "low"
    # `scripts/` is no longer a hardwired demote segment — post-consolidation it's a fuzzy,
    # repo-specific dir, opted into demotion per repo via `.agentsec/config.json` nonproduct_paths
    # (surfaced by the exclude advisor). So it ranks as product code by default now.
    assert reachability(_f("x/y", "high", "scripts/seed.py:9")) == "product"


def test_reachability_demotes_archive_trees() -> None:
    # Archived/dead-code trees are always demoted (never dropped) — unlike the opt-in
    # suppression in is_nonproduct_path, demotion only re-ranks.
    assert reachability(_f("x/y", "high", "old/4_agent/agent.py:10")) == "low"
    assert reachability(_f("x/y", "high", "archive/routes.py:3")) == "low"
    assert reachability(_f("x/y", "high", "legacy/db.py:5")) == "low"
    assert reachability(_f("x/y", "high", "backups/dump.py:1")) == "low"
    # Segment-bounded: a dir merely containing the word is still product code.
    assert reachability(_f("x/y", "high", "scaffold/main.py:2")) == "product"
    assert reachability(_f("x/y", "high", "models/legacy_adapter.py:7")) == "product"


def test_confidence_review_vs_proven() -> None:
    assert confidence(_f("bola/unscoped-object-fetch", "medium", "app/r.py:1")) == "review"
    assert confidence(_f("command-injection/shell-exec-untrusted", "high", "app/r.py:1")) == "proven"


def test_proven_product_beats_surfacing_and_test_of_same_severity() -> None:
    proven = _f("command-injection/shell-exec-untrusted", "high", "app/r.py:1")
    surfacing = _f("bola/unscoped-object-fetch", "high", "app/r.py:1")
    in_test = _f("command-injection/shell-exec-untrusted", "high", "tests/test_r.py:1")
    order = prioritized([surfacing, in_test, proven])
    assert order[0] is proven  # same severity, but proven + product code wins


def test_severity_still_dominates() -> None:
    crit_in_test = _f("a/b", "critical", "tests/test_a.py:1")
    high_in_app = _f("c/d", "high", "app/x.py:1")
    assert prioritized([high_in_app, crit_in_test])[0] is crit_in_test


def test_triage_demotes_low_reach_noise_not_severe() -> None:
    noise = _f("a/b", "medium", "tests/test_a.py:1")
    real = _f("c/d", "high", "app/x.py:1")
    severe_in_test = _f("e/f", "critical", "migrations/0001.py:2")
    actionable, deprioritized = triage([noise, real, severe_in_test])
    assert real in actionable
    assert severe_in_test in actionable  # high+ is always actionable, even in a non-product path
    assert noise in deprioritized


def test_prioritized_is_deterministic() -> None:
    items = [_f("a/b", "high", "app/x.py:1"), _f("c/d", "medium", "tests/test.py:2")]
    assert prioritized(items) == prioritized(list(reversed(items)))


def test_triage_deprioritizes_superseded_at_every_severity() -> None:
    """#800: a superseded (historical) SQL finding is deprioritized even at HIGH/CRITICAL. The high+
    carve-out above protects a path-based *guess*; supersedence is the dump's *answer*, so the
    migration copy is a duplicate or history whatever its severity."""
    sup_high = _f("policy-no-role-scope/no-to-clause", "high", "sql/2-old.sql:3")
    sup_crit = _f("rls-permissive-policy/using-true", "critical", "sql/36-old.sql:1")
    sup_high.superseded = sup_crit.superseded = True
    live_high = _f("policy-no-role-scope/no-to-clause", "high", "sql/schema-snapshot.sql:4")
    actionable, deprioritized = triage([sup_high, live_high, sup_crit])
    assert sup_high in deprioritized and sup_crit in deprioritized
    assert live_high in actionable and live_high not in deprioritized


def test_triage_keeps_confirmed_live_superseded_actionable() -> None:
    """The direction traded against: Splinter confirming the issue in the live DB overrides the
    file-based stamp — it IS live, so it stays actionable (and gating) whichever file declares it."""
    f = _f("policy-no-role-scope/no-to-clause", "high", "sql/2-old.sql:3")
    f.superseded, f.provenance = True, "confirmed-live"
    actionable, _ = triage([f])
    assert f in actionable
