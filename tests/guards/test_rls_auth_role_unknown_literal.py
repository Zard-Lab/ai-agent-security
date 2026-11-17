from __future__ import annotations

import pytest

from agentsec.findings import Finding
from agentsec.guards.rls_auth_role_unknown_literal import RlsAuthRoleUnknownLiteralGuard
from tests.guards._common import *  # noqa: F401,F403

_LOCKOUT = "rls-auth-role-unknown-literal/not-a-real-role"
_OPEN = "rls-auth-role-unknown-literal/negated-always-true"


def _run(tmp_path: Path, sql_text: str) -> list[Finding]:
    sql = tmp_path / "sql"
    sql.mkdir(exist_ok=True)
    (sql / "p.sql").write_text(sql_text, encoding="utf-8")
    return RlsAuthRoleUnknownLiteralGuard().run(tmp_path, _sqlprof(tmp_path))


def _rules(findings: list[Finding]) -> list[str | None]:
    return sorted(f.rule for f in findings)


def test_rls_auth_role_unknown_literal_fires(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text("CREATE POLICY p ON public.docs USING (auth.role() = 'admin');\n", encoding="utf-8")
    findings = RlsAuthRoleUnknownLiteralGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rls-auth-role-unknown-literal/not-a-real-role"
    assert findings[0].severity == "medium"

def test_rls_auth_role_unknown_literal_fires_reversed_order(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text("CREATE POLICY p ON public.docs USING ('admin' = auth.role());\n", encoding="utf-8")
    assert len(RlsAuthRoleUnknownLiteralGuard().run(tmp_path, _sqlprof(tmp_path))) == 1

def test_rls_auth_role_unknown_literal_fires_in_clause(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (auth.role() IN ('admin', 'authenticated'));\n",
        encoding="utf-8",
    )
    findings = RlsAuthRoleUnknownLiteralGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1  # only 'admin' is unknown; 'authenticated' is a real role

def test_rls_auth_role_unknown_literal_two_distinct_literals(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING "
        "(auth.role() = 'admin' OR auth.role() = 'moderator');\n",
        encoding="utf-8",
    )
    findings = RlsAuthRoleUnknownLiteralGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 2

def test_rls_auth_role_unknown_literal_pragma_opt_out(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (auth.role() = 'admin');"
        "  -- security: allow-auth-role-unknown-literal\n",
        encoding="utf-8",
    )
    assert RlsAuthRoleUnknownLiteralGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_auth_role_unknown_literal_skips_comment(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text("-- CREATE POLICY p ON public.docs USING (auth.role() = 'admin');\n", encoding="utf-8")
    assert RlsAuthRoleUnknownLiteralGuard().run(tmp_path, _sqlprof(tmp_path)) == []

# --- FP-bait ------------------------------------------------------------------------------

def test_rls_auth_role_unknown_literal_passes_known_roles(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (auth.role() = 'service_role');\n",
        encoding="utf-8",
    )
    assert RlsAuthRoleUnknownLiteralGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_auth_role_unknown_literal_passes_unrelated_policy(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text("CREATE POLICY p ON public.docs USING (owner_id = auth.uid());\n", encoding="utf-8")
    assert RlsAuthRoleUnknownLiteralGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_auth_role_unknown_literal_fires_on_quoted_identifier_form(tmp_path: Path) -> None:
    """Regression (Dean's review, PR #893 review): pg_dump/migration-tool output spells this
    call quoted (`"auth"."role"()`), the flagship's own real shape — was silent before the fix."""
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        'CREATE POLICY p ON public.docs USING ("auth"."role"() = \'admin\');\n',
        encoding="utf-8",
    )
    findings = RlsAuthRoleUnknownLiteralGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rls-auth-role-unknown-literal/not-a-real-role"

def test_rls_auth_role_unknown_literal_fires_on_quoted_identifier_in_clause(tmp_path: Path) -> None:
    """Regression: the quoted form inside an IN (...) clause must also fire."""
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING "
        "(\"auth\".\"role\"() IN ('admin', 'authenticated'));\n",
        encoding="utf-8",
    )
    findings = RlsAuthRoleUnknownLiteralGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1  # only 'admin' is unknown


def test_rls_auth_role_unknown_literal_not_in_is_always_true_not_lockout(tmp_path: Path) -> None:
    # #924 (was `..._silent_on_not_in`, the PR #893 #B narrowing): `auth.role() NOT IN ('admin')`
    # is ALWAYS TRUE (auth.role() never returns 'admin'), so it admits every row. It now fires the
    # permissive rule at HIGH, and still never the inverted "denies every row" lockout.
    findings = _run(tmp_path, "CREATE POLICY p ON public.docs USING (auth.role() NOT IN ('admin'));\n")
    assert _rules(findings) == [_OPEN]
    assert findings[0].severity == "high"
    assert findings[0].location.endswith("p.sql:1")
    assert "admits every row" in findings[0].message

def test_rls_auth_role_unknown_literal_passes_quoted_non_auth_schema(tmp_path: Path) -> None:
    # FP-bait for the quoted-form widening (PR #893 re-review MEDIUM #A): only the `auth` schema is
    # auth.role(); a same-shaped call on another schema (`"public"."role"()`) must stay silent.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        'CREATE POLICY p ON public.docs USING ("public"."role"() = \'admin\');\n',
        encoding="utf-8",
    )
    assert RlsAuthRoleUnknownLiteralGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_auth_role_unknown_literal_passes_quoted_known_role(tmp_path: Path) -> None:
    # FP-bait for the quoted-form widening: the quoted form of a KNOWN role is not an unknown
    # literal and must stay silent (the known-role exclusion must survive the widening).
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        'CREATE POLICY p ON public.docs USING ("auth"."role"() = \'service_role\');\n',
        encoding="utf-8",
    )
    assert RlsAuthRoleUnknownLiteralGuard().run(tmp_path, _sqlprof(tmp_path)) == []


# --- negated-always-true (#924): fires ------------------------------------------------------
# Every case is `TO authenticated`-scoped, so `policy-no-role-scope/no-to-clause` can never be the
# reason an end-to-end audit reports it — the rule under test is the only one that can.

@pytest.mark.parametrize(
    "using",
    [
        "auth.role() NOT IN ('admin')",
        "auth.role() <> 'admin'",
        "'admin' != auth.role()",
        "auth.role() IS DISTINCT FROM 'admin'",
        "'admin' IS DISTINCT FROM auth.role()",
        "NOT (auth.role() = 'admin')",
        "NOT auth.role() IN ('admin')",
        "auth.role() NOT IN ('admin', 'moderator')",
        "x = 1 OR auth.role() <> 'admin'",  # a depth-0 OR disjunct opens the whole clause
        "(x = 1 OR (y = 2 OR auth.role() <> 'admin'))",  # nested disjunct
        # A quoted `or` is literal content, never a disjunction (structure is read literal-blanked).
        "auth.role() <> 'sales or support'",
        # pg_dump shapes: single-literal NOT IN deparses to `<>`, multi-literal to `<> ALL (ARRAY[...])`.
        "(\"auth\".\"role\"() <> 'admin'::\"text\")",
        "(\"auth\".\"role\"() <> ALL (ARRAY['admin'::\"text\", 'x'::\"text\"]))",
        # Two NOTs cancel (PR #1033 round 1 #1): `NOT NOT e` is `e`, so the always-true atom stands.
        "NOT NOT (auth.role() <> 'admin')",
        "NOT (NOT (x = 1 OR auth.role() <> 'admin'))",
        # The OR after END is the clause's own (round 2): a whole CASE is one disjunct.
        "CASE WHEN p THEN owner_id = auth.uid() ELSE false END OR auth.role() <> 'admin'",
    ],
)
def test_negated_unknown_role_fires_always_true(tmp_path: Path, using: str) -> None:
    findings = _run(tmp_path, f"CREATE POLICY p ON public.docs FOR SELECT TO authenticated USING ({using});\n")
    assert _rules(findings) == [_OPEN], using
    assert findings[0].severity == "high"
    assert "`authenticated`" in findings[0].message
    assert "unauthenticated" not in findings[0].message


def test_negated_always_true_to_anon_names_unauthenticated_exposure(tmp_path: Path) -> None:
    findings = _run(tmp_path, "CREATE POLICY p ON public.docs FOR SELECT TO anon USING (auth.role() <> 'admin');\n")
    assert _rules(findings) == [_OPEN]
    assert "reachable by unauthenticated callers" in findings[0].message


def test_negated_always_true_unscoped_targets_public(tmp_path: Path) -> None:
    findings = _run(tmp_path, "CREATE POLICY p ON public.docs USING (auth.role() <> 'admin');\n")
    assert _rules(findings) == [_OPEN]
    assert "`PUBLIC`" in findings[0].message and "unauthenticated" in findings[0].message


def test_negated_always_true_fires_on_insert_with_check_and_no_using(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "CREATE POLICY p ON public.docs FOR INSERT TO authenticated WITH CHECK (auth.role() <> 'admin');\n",
    )
    assert _rules(findings) == [_OPEN]
    assert "WITH CHECK expression" in findings[0].message


def test_negated_always_true_fires_through_a_restrictive_policy_name(tmp_path: Path) -> None:
    # #893 #C trap: the quoted name "mark as restrictive" must not read as an AS RESTRICTIVE clause
    # (blank_policy_names), which would silently skip a real PERMISSIVE always-true policy.
    findings = _run(
        tmp_path,
        'CREATE POLICY "mark as restrictive" ON public.docs FOR SELECT TO authenticated '
        "USING (auth.role() <> 'admin');\n",
    )
    assert _rules(findings) == [_OPEN]


def test_negated_always_true_honours_the_shared_pragma(tmp_path: Path) -> None:
    # One opt-out for both rules: a literal declared a real role makes both claims false.
    assert _run(
        tmp_path,
        "CREATE POLICY p ON public.docs FOR SELECT TO authenticated USING (auth.role() <> 'admin');"
        "  -- security: allow-auth-role-unknown-literal\n",
    ) == []


# --- negated-always-true: FP-bait (the widening's benign neighbours stay silent) ------------

@pytest.mark.parametrize(
    "policy",
    [
        # A known role in the list (or as the operand) makes it a real gate that excludes someone.
        "TO authenticated USING (auth.role() NOT IN ('admin', 'anon'))",
        "TO authenticated USING (auth.role() NOT IN ('anon'))",
        "USING (auth.role() <> 'anon')",
        "TO authenticated USING (NOT (auth.role() IN ('admin', 'anon')))",
        # A non-literal list member is never classified.
        "TO authenticated USING (auth.role() NOT IN ('admin', current_setting('app.role')))",
        # A conjunct only narrows: the policy is scoped, the dead `<> 'admin'` changes nothing.
        "TO authenticated USING (owner_id = auth.uid() AND auth.role() <> 'admin')",
        "TO authenticated USING ((x = 1 OR y = 2) AND auth.role() <> 'admin')",
        "TO authenticated USING (status = 'a or b' AND auth.role() <> 'admin')",
        # The atom is the WHOLE disjunct or nothing: wrapped in a CASE it gates a scoped branch,
        # and compared to false it is never true at all.
        "TO authenticated USING (CASE WHEN auth.role() <> 'admin' THEN owner_id = auth.uid() ELSE false END)",
        # An OR inside a CASE body is a branch's, not the clause's (PR #1033 round 2): the atom
        # opens only that WHEN / ELSE, and the other branch is still scoped.
        "TO authenticated USING (CASE WHEN p OR auth.role() <> 'admin' OR q THEN owner_id = auth.uid() ELSE false END)",
        "TO authenticated USING (CASE WHEN p THEN owner_id = auth.uid() ELSE r OR auth.role() <> 'admin' OR s END)",
        "TO authenticated USING ((auth.role() <> 'admin') = false)",
        # Not auth.role(): another schema's role() function.
        "TO authenticated USING (\"public\".\"role\"() <> 'admin')",
        # Policy-level gates: a RESTRICTIVE no-op floor, a service_role-only (RLS-bypass) policy,
        # and the documented write-check-open limit (scoped USING + always-true WITH CHECK).
        "AS RESTRICTIVE FOR SELECT TO authenticated USING (auth.role() <> 'admin')",
        "TO service_role USING (auth.role() <> 'admin')",
        "TO authenticated USING (owner_id = auth.uid()) WITH CHECK (auth.role() <> 'admin')",
        # An odd NOT run over an always-true atom makes it never true (PR #1033 round 1 #1).
        "TO authenticated USING (NOT (auth.role() <> 'admin'))",
        "TO authenticated USING (NOT NOT NOT (auth.role() <> 'admin'))",
    ],
)
def test_negated_always_true_stays_silent_on_benign_neighbours(tmp_path: Path, policy: str) -> None:
    findings = _run(tmp_path, f"CREATE POLICY p ON public.docs {policy};\n")
    assert _OPEN not in _rules(findings), policy


# --- not-a-real-role: the negation skip (C9) and the clause-level suppression -----------------

@pytest.mark.parametrize(
    "using",
    [
        "NOT (auth.role() = 'admin')",  # #924 C9: always true, was reported as a lockout
        "NOT ((auth.role() = 'admin'))",
        "NOT 'admin' = auth.role()",
    ],
)
def test_negated_equality_is_never_a_lockout(tmp_path: Path, using: str) -> None:
    findings = _run(tmp_path, f"CREATE POLICY p ON public.docs USING ({using});\n")
    assert _rules(findings) == [_OPEN], using


@pytest.mark.parametrize(
    "using",
    [
        # Under a conjunction the clause is not always-true, so only the negation skip keeps
        # the inverted lockout claim away: `owner AND NOT F` is `owner`, not "denies every row".
        "owner_id = auth.uid() AND NOT (auth.role() = 'admin')",
        "owner_id = auth.uid() AND NOT auth.role() IN ('admin')",
        "owner_id = auth.uid() AND NOT EXISTS (SELECT 1 WHERE auth.role() = 'admin')",
        "owner_id = auth.uid() AND id NOT IN (SELECT doc_id FROM t WHERE auth.role() = 'admin')",
        # A bare NOT binds below IN, so it negates the whole `id IN (...)` (PR #1033 round 1 #1).
        "owner_id = auth.uid() AND NOT id IN (SELECT doc_id FROM t WHERE auth.role() = 'admin')",
        # An AND inside the subquery closes only its own depth: the outer NOT still reaches.
        "owner_id = auth.uid() AND NOT EXISTS (SELECT 1 FROM t WHERE t.x = 1 AND auth.role() = 'admin')",
    ],
)
def test_lockout_skips_a_negated_comparison_inside_a_conjunction(tmp_path: Path, using: str) -> None:
    assert _run(tmp_path, f"CREATE POLICY p ON public.docs TO authenticated USING ({using});\n") == [], using


@pytest.mark.parametrize(
    "using",
    [
        # NOT binds over the whole CASE ... END (PR #1033 round 2 #1). 'admin' is never returned,
        # so both branches give NOT FALSE: an admit-all, and the lockout claim would be inverted.
        # Through a CASE the always-true rule cannot prove it, so the guard stays silent.
        "NOT CASE WHEN x = 1 THEN auth.role() = 'admin' ELSE false END",
        "owner_id = auth.uid() AND NOT CASE WHEN x = 1 THEN auth.role() = 'admin' ELSE false END",
    ],
)
def test_lockout_skips_a_comparison_inside_a_negated_case(tmp_path: Path, using: str) -> None:
    assert _run(tmp_path, f"CREATE POLICY p ON public.docs TO authenticated USING ({using});\n") == [], using


def test_lockout_is_not_claimed_for_a_clause_that_admits_every_row(tmp_path: Path) -> None:
    # The dead `= 'moderator'` disjunct sits beside an always-true one: the clause admits every
    # row, so "silently denies every row" would be the opposite of the truth.
    findings = _run(
        tmp_path,
        "CREATE POLICY p ON public.docs TO authenticated "
        "USING (auth.role() <> 'admin' OR auth.role() = 'moderator');\n",
    )
    assert _rules(findings) == [_OPEN]


# --- not-a-real-role: narrowing still-fires (rule 1) -----------------------------------------

@pytest.mark.parametrize(
    "using",
    [
        # The word NOT elsewhere in the clause must not trigger the negation skip.
        "auth.role() = 'admin' AND deleted_at IS NOT NULL",
        "NOT is_archived AND auth.role() = 'admin'",
        "id NOT IN (1, 2) AND auth.role() = 'admin'",
        # Only NOT EXISTS is negated: a bare EXISTS over a never-true subquery is still a lockout.
        "EXISTS (SELECT 1 WHERE auth.role() = 'admin')",
        "owner_id = auth.uid() AND id IN (SELECT doc_id FROM t WHERE auth.role() = 'admin')",
        # A NOT that a later AND / comma / CASE keyword closes never reaches the comparison.
        "coalesce(NOT is_archived, auth.role() = 'admin')",
        "CASE WHEN NOT is_archived THEN auth.role() = 'admin' ELSE false END",
        "CASE WHEN a THEN NOT is_archived ELSE auth.role() = 'admin' END",
        # END closes the CASE: a NOT before it ends at the next AND like any other (round 2 #1).
        "NOT CASE WHEN a THEN b ELSE c END AND auth.role() = 'admin'",
        # Malformed (no END): the `)` still closes its own group, so the outer NOT ends at the AND.
        "NOT (CASE WHEN a THEN b) AND auth.role() = 'admin'",
    ],
)
def test_lockout_still_fires_beside_an_unrelated_not(tmp_path: Path, using: str) -> None:
    findings = _run(tmp_path, f"CREATE POLICY p ON public.docs TO authenticated USING ({using});\n")
    assert _rules(findings) == [_LOCKOUT], using


@pytest.mark.parametrize(
    "using",
    [
        # Two negations cancel, so the never-true comparison is a lockout again (PR #1033 round 1
        # #1: the first negation-skip counted negated groups, not their parity, and went silent).
        "NOT NOT (auth.role() = 'admin')",
        "NOT (NOT (auth.role() = 'admin'))",
        "NOT NOT auth.role() = 'admin'",
        "NOT NOT auth.role() IN ('admin')",
        "NOT id NOT IN (SELECT doc_id FROM t WHERE auth.role() = 'admin')",
    ],
)
def test_lockout_still_fires_under_an_even_number_of_negations(tmp_path: Path, using: str) -> None:
    findings = _run(tmp_path, f"CREATE POLICY p ON public.docs TO authenticated USING ({using});\n")
    assert _rules(findings) == [_LOCKOUT], using


def test_lockout_still_fires_on_a_never_true_check_beside_an_open_using(tmp_path: Path) -> None:
    # The clause-level suppression is per clause: an always-true USING does not hide a WITH CHECK
    # that no write can ever pass. Both claims are true, each for its own clause.
    findings = _run(
        tmp_path,
        "CREATE POLICY p ON public.docs TO authenticated "
        "USING (auth.role() <> 'admin') WITH CHECK (auth.role() = 'moderator');\n",
    )
    assert _rules(findings) == [_OPEN, _LOCKOUT]
    assert {f.severity for f in findings} == {"high", "medium"}


def test_lockout_still_fires_through_a_using_shaped_policy_name(tmp_path: Path) -> None:
    # blank_policy_names: a `using (` inside the quoted name used to be read as the USING clause
    # (body `anything`), silencing the real lockout behind it.
    findings = _run(
        tmp_path,
        "CREATE POLICY \"read using (anything)\" ON public.docs USING (auth.role() = 'admin');\n",
    )
    assert _rules(findings) == [_LOCKOUT]
