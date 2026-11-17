"""Compounding-risk signal — a synthetic finding when two findings are worse together."""
from __future__ import annotations

from agentsec.compounding_risk import _COMPOUND_RISKS, assess
from agentsec.findings import Finding


def _finding(
    check_id: str, rule: str = "", *, nonproduct: bool = False, superseded: bool = False
) -> Finding:
    return Finding(
        check_id=check_id, severity="high", title="t", location="x.py:1",
        rule=rule or f"{check_id}/x", nonproduct=nonproduct, superseded=superseded,
    )


# --- fires when every group of a CompoundRisk has a contributing finding ---------------------

def test_sqli_plus_bola_fires() -> None:
    findings = [_finding("sqlalchemy-text-parameterized"), _finding("bola")]
    out = assess(findings)
    rules = {f.rule for f in out}
    assert "compounding-risk/sqli-plus-idor-account-takeover" in rules
    hit = next(f for f in out if f.rule == "compounding-risk/sqli-plus-idor-account-takeover")
    assert hit.severity == "critical"
    assert hit.check_id == "compounding-risk"
    assert hit.location == ""  # repo-wide, no single file:line — matches lethal-trifecta's convention


def test_any_sqli_guard_in_the_group_satisfies_it() -> None:
    # The SQLi side of the pair is an OR over 4 real guard ids — js-sql-injection alone must
    # satisfy it, not just the Python-specific one used in the test above.
    out = assess([_finding("js-sql-injection"), _finding("bola")])
    assert "compounding-risk/sqli-plus-idor-account-takeover" in {f.rule for f in out}


def test_unauth_route_plus_privileged_write_fires() -> None:
    out = assess([_finding("auth-dependency-not-applied"), _finding("privileged-field-assignment")])
    assert "compounding-risk/unauthenticated-route-plus-privileged-write" in {f.rule for f in out}


def test_exposed_secret_plus_rce_fires() -> None:
    out = assess([_finding("weak-secret-key-literal"), _finding("command-injection")])
    assert "compounding-risk/exposed-secret-plus-code-execution" in {f.rule for f in out}


def test_lethal_trifecta_plus_tool_overpermission_fires() -> None:
    out = assess([_finding("lethal-trifecta"), _finding("agent-tool-overpermission")])
    assert "compounding-risk/lethal-trifecta-plus-tool-overpermission" in {f.rule for f in out}


def test_message_names_the_contributing_rules() -> None:
    out = assess([_finding("bola", "bola/no-user-filter"), _finding("sqlalchemy-text-parameterized", "sqlalchemy-text-parameterized/raw-sql")])
    hit = next(f for f in out if f.rule == "compounding-risk/sqli-plus-idor-account-takeover")
    assert "bola/no-user-filter" in hit.message
    assert "sqlalchemy-text-parameterized/raw-sql" in hit.message


# --- FP-bait: only one side of a pair present must NOT fire ----------------------------------

def test_sqli_alone_does_not_fire() -> None:
    out = assess([_finding("sqlalchemy-text-parameterized")])
    assert out == []


def test_bola_alone_does_not_fire() -> None:
    out = assess([_finding("bola")])
    assert out == []


def test_unrelated_findings_do_not_fire_any_compound() -> None:
    out = assess([_finding("cors-wildcard"), _finding("secure-cookies")])
    assert out == []


def test_empty_findings_list_returns_empty() -> None:
    assert assess([]) == []


def test_does_not_mutate_or_drop_input_findings() -> None:
    findings = [_finding("bola"), _finding("sqlalchemy-text-parameterized")]
    before = list(findings)
    assess(findings)
    assert findings == before  # assess() is pure — the caller does the extend()


def test_multiple_compound_risks_can_fire_independently() -> None:
    out = assess([
        _finding("bola"), _finding("sqlalchemy-text-parameterized"),
        _finding("lethal-trifecta"), _finding("agent-tool-overpermission"),
    ])
    rules = {f.rule for f in out}
    assert "compounding-risk/sqli-plus-idor-account-takeover" in rules
    assert "compounding-risk/lethal-trifecta-plus-tool-overpermission" in rules
    assert len(out) == 2


# --- #683 review fixes -------------------------------------------------------------------------

def test_all_referenced_check_ids_are_registered_guards() -> None:
    # Medium 7: nothing asserted this before — a rename or copy-paste typo in a pair's group would
    # make that pair permanently and silently dead. Registered here rather than as a top-level
    # import to avoid a module-level dependency from compounding_risk.py -> registry.py.
    from agentsec.registry import ALL_GUARDS

    guard_ids = {g.id for g in ALL_GUARDS}
    referenced = frozenset().union(*(g for risk in _COMPOUND_RISKS for g in risk.groups))
    assert referenced <= guard_ids, referenced - guard_ids


def test_synthetic_finding_carries_no_owasp_family_standard() -> None:
    # High 3: compounding-risk mints its own check_id with no checklist mapping, so an OWASP-family
    # tag on it would fail the guard<->checklist reflection gate (validate-checklist.py's
    # reflection_drift) — the ONE of the four drift gates that genuinely applies here. Non-OWASP
    # tags (e.g. CWE-506 on exposed-secret-plus-code-execution) are still allowed through.
    out = assess([_finding("weak-secret-key-literal"), _finding("command-injection")])
    hit = next(f for f in out if f.rule == "compounding-risk/exposed-secret-plus-code-execution")
    assert not any(s.split(":", 1)[0].startswith("OWASP") for s in hit.standards)
    assert "CWE-506" in hit.standards


def test_review_tier_leg_disclaimer_is_carried_into_the_message() -> None:
    # High 4: bola and lethal-trifecta are themselves review-tier signals (each declares
    # `surfacing = True`) whose own caveat would otherwise be silently stripped by the
    # composition, since the synthetic `compounding-risk` finding is not itself surfacing.
    sqli_only = assess([_finding("weak-secret-key-literal"), _finding("command-injection")])
    hit = next(f for f in sqli_only if f.rule == "compounding-risk/exposed-secret-plus-code-execution")
    assert "review-tier" not in hit.message  # neither leg here is review-tier

    out = assess([_finding("bola"), _finding("sqlalchemy-text-parameterized")])
    hit = next(f for f in out if f.rule == "compounding-risk/sqli-plus-idor-account-takeover")
    assert "review-tier" in hit.message
    assert "verify" in hit.message.lower()


def test_nonproduct_demoted_only_when_some_group_has_no_live_member() -> None:
    # High 5 (original review) / High 1 (#683 fix-commit re-review): prioritize() demotes on
    # f.nonproduct, which this synthetic finding's own (empty) location can never trigger on its
    # own. A CompoundRisk is AND-composed over its `groups` (every group needs its own live member
    # for the chain to be real), so the demotion must mirror that: demote only when some group has
    # NO live member at all (every finding contributing to that group is nonproduct) — that group
    # can never supply a live leg, so no all-live combination across groups is possible, however
    # live the OTHER group is. Taking all()/any() over the flat union of every contributing
    # finding (the original shape) collapsed the group structure and let one live finding in an
    # unrelated group mask an entirely-nonproduct group, leaving the compound undemoted.
    #
    # Uses exposed-secret-plus-code-execution (multi-member groups) so "wholly nonproduct" (every
    # member of a group is nonproduct) is distinguishable from "has a live member" (some members
    # live, some not) — the distinction the bug collapsed.
    secret_group_wholly_nonproduct = assess([
        _finding("weak-secret-key-literal", nonproduct=True),
        _finding("command-injection", nonproduct=False),
    ])
    hit = next(
        f for f in secret_group_wholly_nonproduct
        if f.rule == "compounding-risk/exposed-secret-plus-code-execution"
    )
    assert hit.nonproduct is True  # secret group has zero live members -- Dean's pair-3 repro

    secret_group_has_a_live_member = assess([
        _finding("weak-secret-key-literal", nonproduct=True),
        _finding("hardcoded-private-key-in-source", nonproduct=False),
        _finding("command-injection", nonproduct=False),
    ])
    hit = next(
        f for f in secret_group_has_a_live_member
        if f.rule == "compounding-risk/exposed-secret-plus-code-execution"
    )
    assert hit.nonproduct is False  # secret group has a live member -- a real live chain exists

    both_groups_fully_live = assess([
        _finding("weak-secret-key-literal", nonproduct=False),
        _finding("command-injection", nonproduct=False),
    ])
    hit = next(
        f for f in both_groups_fully_live
        if f.rule == "compounding-risk/exposed-secret-plus-code-execution"
    )
    assert hit.nonproduct is False

    both_groups_wholly_nonproduct = assess([
        _finding("weak-secret-key-literal", nonproduct=True),
        _finding("command-injection", nonproduct=True),
    ])
    hit = next(
        f for f in both_groups_wholly_nonproduct
        if f.rule == "compounding-risk/exposed-secret-plus-code-execution"
    )
    assert hit.nonproduct is True


def test_superseded_demoted_only_when_some_group_has_no_live_member() -> None:
    # Same AND-of-groups shape as nonproduct, above -- superseded uses the identical `any(all(...))`
    # composition in the source.
    secret_group_wholly_superseded = assess([
        _finding("weak-secret-key-literal", superseded=True),
        _finding("command-injection", superseded=False),
    ])
    hit = next(
        f for f in secret_group_wholly_superseded
        if f.rule == "compounding-risk/exposed-secret-plus-code-execution"
    )
    assert hit.superseded is True

    secret_group_has_a_live_member = assess([
        _finding("weak-secret-key-literal", superseded=True),
        _finding("hardcoded-private-key-in-source", superseded=False),
        _finding("command-injection", superseded=False),
    ])
    hit = next(
        f for f in secret_group_has_a_live_member
        if f.rule == "compounding-risk/exposed-secret-plus-code-execution"
    )
    assert hit.superseded is False


def test_superseded_compound_names_the_governing_dump() -> None:
    """The report names the dump behind a superseded finding (#1037); a compound demoted by a
    superseded leg carries that leg's dump, and a live compound carries none."""
    stamped = _finding("weak-secret-key-literal", superseded=True)
    stamped.superseded_by = "sql/schema-snapshot.sql"
    demoted = assess([stamped, _finding("command-injection")])
    hit = next(f for f in demoted if f.rule == "compounding-risk/exposed-secret-plus-code-execution")
    assert hit.superseded is True and hit.superseded_by == "sql/schema-snapshot.sql"
    live = assess([stamped, _finding("hardcoded-private-key-in-source"), _finding("command-injection")])
    hit = next(f for f in live if f.rule == "compounding-risk/exposed-secret-plus-code-execution")
    assert hit.superseded is False and hit.superseded_by is None


def test_superseded_compound_names_a_dump_only_when_its_legs_agree() -> None:
    """Each dump governs its own subtree (#1073 review M1), so one audit can have several. The
    compound names the dump behind ITS demoting legs, never one from an unrelated finding, and
    falls back to the generic label when its legs were answered by two different dumps."""
    def _hist(check_id: str, dump: str) -> Finding:
        f = _finding(check_id, superseded=True)
        f.superseded_by = dump
        return f

    unrelated = _hist("rls-permissive-policy", "apps/other/schema.sql")
    leg = _hist("weak-secret-key-literal", "sql/schema-snapshot.sql")
    hit = next(
        f for f in assess([unrelated, leg, _finding("command-injection")])
        if f.rule == "compounding-risk/exposed-secret-plus-code-execution"
    )
    assert hit.superseded is True and hit.superseded_by == "sql/schema-snapshot.sql"
    split = [_hist("weak-secret-key-literal", "apps/a/schema.sql"),
             _hist("cleartext-secret-storage", "apps/b/schema.sql"), _finding("command-injection")]
    hit = next(f for f in assess(split) if f.rule == "compounding-risk/exposed-secret-plus-code-execution")
    assert hit.superseded is True and hit.superseded_by is None
