from __future__ import annotations

import re
from collections.abc import Callable

import pytest

from agentsec.guards import policy_no_role_scope as _mod
from agentsec.guards.policy_no_role_scope import PolicyNoRoleScopeGuard
from tests._timing import (
    NormalizedCostBudget,
    assert_growth,
    assert_normalized_cost,
    calibration_seconds,
    register_normalized,
)
from tests.guards._common import *  # noqa: F401,F403

_FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "policy_no_role_scope"


def test_policy_no_role_scope_fires_on_no_to_clause(tmp_path: Path) -> None:
    # The checklist `verified_by` anchor: an identity-free predicate with no TO clause is reachable
    # by anon and stays HIGH after #801 (the self-scoped twin of this fixture is graded LOW below).
    (tmp_path / "schema.sql").write_text(
        "CREATE POLICY published_docs ON public.profiles USING (status = 'published');\n",
        encoding="utf-8",
    )
    findings = PolicyNoRoleScopeGuard().run(tmp_path, _pgprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].rule == "policy-no-role-scope/no-to-clause"
    assert "public.profiles" in findings[0].message
    assert "OWASP:A01" in findings[0].standards


def test_policy_no_role_scope_self_scoped_no_to_clause_grades_low(tmp_path: Path) -> None:
    # #801: for anon `auth.uid()` IS NULL, `user_id = NULL` is NULL, and Postgres hides the row —
    # the missing TO clause is hygiene, not exposure. Same rule id, LOW, remediation names the fix.
    (tmp_path / "schema.sql").write_text(
        "CREATE POLICY user_isolation ON public.profiles USING (user_id = auth.uid());\n",
        encoding="utf-8",
    )
    findings = PolicyNoRoleScopeGuard().run(tmp_path, _pgprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity == "low"
    assert findings[0].rule == "policy-no-role-scope/no-to-clause"
    assert "public.profiles" in findings[0].message
    assert "TO authenticated" in findings[0].remediation
    assert "OWASP:A01" in findings[0].standards


def test_policy_no_role_scope_fires_on_to_public(tmp_path: Path) -> None:
    (tmp_path / "schema.sql").write_text(
        "CREATE POLICY p ON public.profiles TO public USING (user_id = auth.uid());\n",
        encoding="utf-8",
    )
    findings = PolicyNoRoleScopeGuard().run(tmp_path, _pgprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "policy-no-role-scope/to-public"


def test_policy_no_role_scope_to_public_follows_the_same_grade_as_no_to_clause(tmp_path: Path) -> None:
    # An explicit `TO public` has identical exploitability to no TO clause: the predicate decides.
    (tmp_path / "schema.sql").write_text(
        "CREATE POLICY open ON public.profiles TO public USING (true);\n"
        "CREATE POLICY own ON public.profiles TO public USING (user_id = auth.uid());\n",
        encoding="utf-8",
    )
    findings = PolicyNoRoleScopeGuard().run(tmp_path, _pgprof(tmp_path))
    assert [(f.rule, f.severity) for f in findings] == [
        ("policy-no-role-scope/to-public", "high"),
        ("policy-no-role-scope/to-public", "low"),
    ]


def test_policy_no_role_scope_fires_on_to_public_alongside_named_role(tmp_path: Path) -> None:
    # PUBLIC is a pseudo-role that matches everyone regardless of what else is listed.
    (tmp_path / "schema.sql").write_text(
        "CREATE POLICY p ON public.profiles TO public, authenticated "
        "USING (user_id = auth.uid());\n",
        encoding="utf-8",
    )
    findings = PolicyNoRoleScopeGuard().run(tmp_path, _pgprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "policy-no-role-scope/to-public"


def test_policy_no_role_scope_silent_when_scoped_to_authenticated(tmp_path: Path) -> None:
    (tmp_path / "schema.sql").write_text(
        "CREATE POLICY user_isolation ON public.profiles TO authenticated "
        "USING (user_id = auth.uid());\n",
        encoding="utf-8",
    )
    assert PolicyNoRoleScopeGuard().run(tmp_path, _pgprof(tmp_path)) == []


def test_policy_no_role_scope_silent_when_scoped_to_service_role(tmp_path: Path) -> None:
    # service_role bypasses RLS entirely -- scoping a policy to it is never an
    # anon-widening concern (same carve-out as rls-permissive-policy).
    (tmp_path / "schema.sql").write_text(
        "CREATE POLICY admin_only ON public.profiles TO service_role USING (true);\n",
        encoding="utf-8",
    )
    assert PolicyNoRoleScopeGuard().run(tmp_path, _pgprof(tmp_path)) == []


def test_policy_no_role_scope_silent_when_scoped_to_multiple_named_roles(tmp_path: Path) -> None:
    (tmp_path / "schema.sql").write_text(
        "CREATE POLICY p ON public.profiles TO authenticated, service_role "
        "USING (user_id = auth.uid());\n",
        encoding="utf-8",
    )
    assert PolicyNoRoleScopeGuard().run(tmp_path, _pgprof(tmp_path)) == []


def test_policy_no_role_scope_pragma_suppresses_only_its_own_statement(tmp_path: Path) -> None:
    # Statement-local pragma: the intentionally-public policy is suppressed, but a SECOND,
    # unrelated unscoped policy in the same file still fires (rule 4, CLAUDE.md).
    (tmp_path / "schema.sql").write_text(
        "CREATE POLICY public_read ON public.announcements "
        "USING (true);  -- security: allow-policy-no-role-scope\n"
        "CREATE POLICY user_isolation ON public.profiles USING (user_id = auth.uid());\n",
        encoding="utf-8",
    )
    findings = PolicyNoRoleScopeGuard().run(tmp_path, _pgprof(tmp_path))
    assert len(findings) == 1
    assert "public.profiles" in findings[0].message


def test_policy_no_role_scope_applies_gate() -> None:
    assert PolicyNoRoleScopeGuard().applies(mkprofile(Path("/tmp"), features={"supabase"})) is True
    assert PolicyNoRoleScopeGuard().applies(mkprofile(Path("/tmp"), features={"postgres"})) is True
    assert PolicyNoRoleScopeGuard().applies(mkprofile(Path("/tmp"), features={"python"})) is False


def test_policy_no_role_scope_no_sql_files(tmp_path: Path) -> None:
    assert PolicyNoRoleScopeGuard().run(tmp_path, _pgprof(tmp_path)) == []


def test_policy_no_role_scope_skips_examples_dir(tmp_path: Path) -> None:
    d = tmp_path / "examples"
    d.mkdir()
    (d / "schema.sql").write_text(
        "CREATE POLICY p ON public.profiles USING (user_id = auth.uid());\n", encoding="utf-8"
    )
    assert PolicyNoRoleScopeGuard().run(tmp_path, _pgprof(tmp_path)) == []


def test_policy_no_role_scope_quoted_policy_name_containing_to_is_not_mistaken_for_role_clause(
    tmp_path: Path,
) -> None:
    # Adversarial FP-bait: a policy NAME containing the standalone word "to" must not be
    # parsed as a (fake) role clause that happens to satisfy the guard -- the policy is
    # genuinely unscoped here and must still fire, for the REAL reason (no TO clause).
    (tmp_path / "schema.sql").write_text(
        'CREATE POLICY "Grant read access to profiles" ON public.profiles '
        "USING (user_id = auth.uid());\n",
        encoding="utf-8",
    )
    findings = PolicyNoRoleScopeGuard().run(tmp_path, _pgprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "policy-no-role-scope/no-to-clause"


def test_policy_no_role_scope_hostile_headless_sql_is_linear(tmp_path: Path) -> None:
    # Regression (issue #419 class): a head-to-`;` scan that re-runs from every candidate
    # head is O(n^2) on hostile `;`-less input. `iter_statement_spans` stops at the first
    # head with no following `;`. Actual ~0.01s; the quadratic form at this size takes minutes.
    import time

    (tmp_path / "hostile.sql").write_text("create policy " * 30_000, encoding="utf-8")
    start = time.monotonic()
    findings = PolicyNoRoleScopeGuard().run(tmp_path, _pgprof(tmp_path))
    # 8.0s ceiling over a ~0.5s healthy run (measured, >10x headroom, tests/test_timing_budgets.py's
    # gate) — the quadratic form at this input size takes minutes, not single-digit seconds, so this
    # stays exactly as discriminating (2026-08-25).
    assert time.monotonic() - start < 8.0, "quadratic policy scan reintroduced"
    assert findings == []


def test_policy_no_role_scope_pragma_survives_a_preceding_block_comment(tmp_path: Path) -> None:
    # Regression: `strip_sql_comments` deletes a `/* ... */` block comment's internal
    # newlines, desyncing the stripped-text line count from the raw file's for everything
    # after it. The pragma window used to be sliced from the WRONG raw lines whenever a
    # multi-line block comment preceded the statement, silently voiding a pragma physically
    # on the statement's own line (CLAUDE.md Rule 4).
    (tmp_path / "schema.sql").write_text(
        "/*\nline2\nline3\nline4\nline5\nline6\n*/\n"
        "CREATE POLICY p ON t USING (true); -- security: allow-policy-no-role-scope\n",
        encoding="utf-8",
    )
    findings = PolicyNoRoleScopeGuard().run(tmp_path, _pgprof(tmp_path))
    assert findings == []


def test_policy_no_role_scope_line_number_correct_after_a_preceding_block_comment(
    tmp_path: Path,
) -> None:
    # Same fixture, no pragma: the statement genuinely fires, and must report its OWN line
    # (8), not a line inside the preceding block comment.
    (tmp_path / "schema.sql").write_text(
        "/*\nline2\nline3\nline4\nline5\nline6\n*/\nCREATE POLICY p ON t USING (true);\n",
        encoding="utf-8",
    )
    findings = PolicyNoRoleScopeGuard().run(tmp_path, _pgprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location == "schema.sql:8"


def test_policy_no_role_scope_string_literal_double_dash_no_longer_merges_spans(
    tmp_path: Path,
) -> None:
    # fix-round review Critical, closed by `strip_sql_comments(text, blank=True)`
    # replacing the guard's own non-string-aware `_LINE_COMMENT` regex. A `--` inside a string
    # literal used to over-blank to end of line, eating the statement's own terminating `;`;
    # `iter_statement_spans` then ran on into the NEXT `CREATE POLICY` and merged the two spans,
    # so the first (genuinely unscoped) policy inherited the second statement's `TO` clause and
    # went silent (#693 review). Now: `strip_sql_comments` is quote-aware, so the `--` inside
    # `'a--b'` is recognized as string content, not a comment — p1 fires on its own line and p2
    # (correctly scoped) stays silent, exactly like the FP-bait sibling below.
    (tmp_path / "schema.sql").write_text(
        "CREATE POLICY p1 ON t USING (x = 'a--b');\n"
        "CREATE POLICY p2 ON t TO authenticated USING (y = 1);\n",
        encoding="utf-8",
    )
    findings = PolicyNoRoleScopeGuard().run(tmp_path, _pgprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location == "schema.sql:1"
    assert findings[0].rule == "policy-no-role-scope/no-to-clause"
    assert findings[0].severity == "high"


def test_policy_no_role_scope_plain_string_literal_still_fires(tmp_path: Path) -> None:
    # Same shape as the `--`-in-literal test above, but WITHOUT a `--` inside the literal —
    # control case showing the span-merge risk was specific to an unblanked `--`, not the
    # presence of a string literal or `iter_statement_spans` itself.
    (tmp_path / "schema.sql").write_text(
        "CREATE POLICY p1 ON t USING (x = 'plain');\n"
        "CREATE POLICY p2 ON t TO authenticated USING (y = 1);\n",
        encoding="utf-8",
    )
    findings = PolicyNoRoleScopeGuard().run(tmp_path, _pgprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "policy-no-role-scope/no-to-clause"


# --- issue #559: a `;` inside a quoted policy name must not hide the TO clause ------------------
def test_policy_no_role_scope_semicolon_in_policy_name_does_not_hide_the_to_clause(
    tmp_path: Path,
) -> None:
    # The FALSE-POSITIVE arm of #559: on main the carve ended at the `;` inside the name, the
    # `TO authenticated` clause fell outside the statement, and both policies were reported as
    # unscoped — two HIGH on correct SQL (measured). The issue itself only claimed a silent miss.
    (tmp_path / "schema.sql").write_text(
        'CREATE POLICY "grant; select" ON public.documents FOR INSERT TO authenticated USING (x);\n'
        'CREATE POLICY "another; one" ON public.documents FOR INSERT TO authenticated USING (y);\n',
        encoding="utf-8",
    )
    assert PolicyNoRoleScopeGuard().run(tmp_path, _pgprof(tmp_path)) == []


def test_policy_no_role_scope_semicolon_in_policy_name_still_fires_when_unscoped(
    tmp_path: Path,
) -> None:
    # The direction the fix trades against: same name shape, genuinely no TO clause — still one
    # finding, attributed to the right table (the `ON` clause is past the quoted `;` too).
    (tmp_path / "schema.sql").write_text(
        'CREATE POLICY "any; body" ON public.documents FOR SELECT USING (x);\n',
        encoding="utf-8",
    )
    findings = PolicyNoRoleScopeGuard().run(tmp_path, _pgprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "policy-no-role-scope/no-to-clause"
    assert "public.documents" in findings[0].message
    assert findings[0].severity == "high"


# --- issue #801: the flagship pg_dump oracle --------------------------------------------------
# The disconfirming artifact, checked in and asserted EXACTLY (#827 postmortem lesson 3: guard,
# tests and wiki agreed with each other for four rounds while the guard downgraded 0 of 28 on the
# real dump, because every fixture used the bare spelling and pg_dump quotes every identifier).
def _flagship_line_sets() -> tuple[set[int], set[int], set[int], set[int]]:
    """(scoped-by-TO, deny, low, high) 1-based start lines, derived from the fixture text itself."""
    text = (_FIXTURE_ROOT / "sql" / "flagship_pg_dump_policies.sql").read_text(encoding="utf-8")
    scoped: set[int] = set()
    deny: set[int] = set()
    low: set[int] = set()
    high: set[int] = set()
    for m in re.finditer(r"^CREATE POLICY\b.*?;", text, re.S | re.M):  # `^`: not the header comment
        line = text.count("\n", 0, m.start()) + 1
        stmt = m.group(0)
        if re.search(r"\bTO\b", stmt):
            scoped.add(line)
        elif "USING (false)" in stmt:
            deny.add(line)
        elif "USING (true)" in stmt:
            high.add(line)
        else:
            low.add(line)
    return scoped, deny, low, high


def test_policy_no_role_scope_flagship_pg_dump_oracle() -> None:
    scoped, deny, low, high = _flagship_line_sets()
    # The fixture's own census, so a silently truncated file cannot pass (Rule 3).
    assert (len(scoped), len(deny), len(low), len(high)) == (61, 8, 28, 1)
    findings = PolicyNoRoleScopeGuard().run(
        _FIXTURE_ROOT, mkprofile(_FIXTURE_ROOT, features={"postgres"}, sql_dir="sql")
    )
    assert len(findings) == 29, "the guard must SEE the fixture (29 findings, not 0) and grade it"
    assert all(f.rule == "policy-no-role-scope/no-to-clause" for f in findings)
    # `rel()` reports OS-native separators (`sql\…` on the Windows CI leg): normalise before comparing.
    assert all(f.location.replace("\\", "/").startswith("sql/flagship_pg_dump_policies.sql:") for f in findings)
    by_sev: dict[str, set[int]] = {"high": set(), "low": set()}
    for f in findings:
        by_sev[f.severity].add(int(f.location.rsplit(":", 1)[1]))
    assert by_sev["high"] == high
    assert by_sev["low"] == low
    assert not (by_sev["high"] | by_sev["low"]) & (scoped | deny)
    (high_finding,) = [f for f in findings if f.severity == "high"]
    assert "public.maintenance_message" in high_finding.message
    assert all("TO authenticated" in f.remediation for f in findings if f.severity == "low")


# --- issue #801: the predicate corpora ---------------------------------------------------------
# Salvaged from #827 (commit 50c60207) as DATA and re-labelled under the closed-whitelist model:
# a predicate is LOW only when every path through its boolean skeleton hits a leaf the grader
# positively recognises as NULL-or-FALSE for a caller with no identity; anything unrecognised is
# HIGH, exactly as before #801. Each list is the other's Rule-1 pairing (CLAUDE.md).
_SCOPED_LOW = [
    "USING (auth.uid() = id)",
    "USING (user_id = auth.uid())",
    "USING ((select auth.uid()) = id)",
    "USING (EXISTS (SELECT 1 FROM public.user_profiles WHERE id = auth.uid() AND is_admin = true))",
    "USING (public.is_admin())",
    "USING (auth.uid() = owner OR public.is_admin())",
    "USING (auth.uid() = id AND deleted_at IS NULL)",
    "USING ((auth.uid() = id OR public.is_admin()) AND status <> 'archived')",
    "USING (auth.uid() IS NOT NULL)",  # NULL IS NOT NULL is FALSE
    # an IS NULL INSIDE the subquery is the subquery's business, not an escape for anon
    "USING (EXISTS (SELECT 1 FROM members m WHERE m.user_id = auth.uid() AND m.left_at IS NULL))",
    # a `JOIN … USING (col)` inside the body is not a second policy clause
    "USING (EXISTS (SELECT 1 FROM members m JOIN teams t USING (team_id) WHERE m.user_id = auth.uid()))",
    # `author`/`order_index` contain the letters of the operators and must not be split on
    "USING (author_id = auth.uid() AND order_index > 0)",
    "FOR INSERT WITH CHECK (user_id = auth.uid())",
    "FOR ALL USING (auth.uid() = id) WITH CHECK (auth.uid() = id)",
    # a deny USING beside a scoped WITH CHECK: nothing anon-reachable, one scoped clause (not deny)
    "FOR UPDATE USING (false) WITH CHECK (auth.uid() = id)",
    "USING (((select auth.uid())) = id)",  # nested initplan wrapper
    "USING (auth.uid() NOTNULL)",  # the shorthand of IS NOT NULL, not of IS NULL
    "USING (id IN (SELECT team_id FROM members WHERE user_id = auth.uid()))",  # IN (empty) → FALSE
    "USING (id = ANY (SELECT team_id FROM members WHERE user_id = auth.uid()))",  # ANY: same
    "USING (COALESCE(x, y) = auth.uid())",  # COALESCE on the OTHER operand: `x = NULL` is still NULL
    "USING (auth.uid() = id AND deleted_at IS NOT TRUE)",  # the postfix IS is a SEPARATE conjunct
    "USING (owner = x AND (select auth.uid()) = id)",  # `AND (` is a grouping paren
    "USING (public.is_admin( ))",  # argument-less, spaced parens
    # An `E'…'` escape string in an ordinary conjunct must not widen a self-scoped policy
    r"USING (auth.uid() = id AND note <> E'x\'y')",
    # `BETWEEN`'s own AND is split like any AND: the range halves are unrecognised, the identity
    # conjunct still gates — `… AND NULL` is never TRUE whatever the halves evaluate to
    "USING (created_at BETWEEN start_ts AND end_ts AND auth.uid() = owner)",
    "USING (auth.uid() = owner AND created_at NOT BETWEEN a AND b)",
    # an ordinary literal is not a dollar-quoted one (#827 round 4)
    "USING (note = 'a$$b' AND auth.uid() = owner)",
    "USING (greeting = 'hi $name$ there' AND auth.uid() = owner)",
    'USING (note = "a$$b" AND auth.uid() = owner)',
    # NOT over a NULL identity comparison is NULL; NOT over `auth.uid() IS NULL` (TRUE) is FALSE
    "USING (NOT (auth.uid() = id))",
    "USING (NOT (auth.uid() IS NULL))",
    "USING (NOT auth.uid() IS NULL)",  # IS binds tighter than NOT
    "USING (NOT (auth.uid() = id OR public.is_admin()))",  # NOT (NULL OR FALSE/NULL) is NULL
    # --- pg_dump's quoted, schema-qualified spelling (byte-exact from the flagship fixture) ---
    'USING ((( SELECT "auth"."uid"() AS "uid") = "user_id"))',
    'USING ((( SELECT "auth"."uid"()) = "user_id"))',  # dump without the alias
    'USING (("auth"."uid"() = "id"))',  # quoted call, no initplan wrapper
    'USING ("public"."is_admin"())',
    'USING ((EXISTS ( SELECT 1\n   FROM "public"."user_profiles"\n  WHERE (("user_profiles"."id" = '
    '( SELECT "auth"."uid"() AS "uid")) AND ("user_profiles"."is_admin" = true)))))',
    # the flagship's 28th: `IS DISTINCT FROM` on a COLUMN inside an AND is not an escape
    'USING ((( SELECT "auth"."uid"() AS "uid") = "id")) WITH CHECK (((( SELECT "auth"."uid"() AS '
    '"uid") = "id") AND (NOT ("is_admin" IS DISTINCT FROM false))))',
    # A quoted identifier spelling a keyword: `"t"."or"` must not split the conjunction
    'USING (("auth"."uid"() = "id") AND "t"."or")',
    'USING (("auth"."uid"() = "id") AND "or" = 1)',
    'USING ("auth"."email"() = "email")',
]


@pytest.mark.parametrize("clause", _SCOPED_LOW)
def test_policy_no_role_scope_scoped_predicate_grades_low(tmp_path: Path, clause: str) -> None:
    (tmp_path / "schema.sql").write_text(
        f"CREATE POLICY p ON public.documents {clause};\n", encoding="utf-8"
    )
    findings = PolicyNoRoleScopeGuard().run(tmp_path, _pgprof(tmp_path))
    assert len(findings) == 1, clause
    assert findings[0].severity == "low", clause
    assert findings[0].rule == "policy-no-role-scope/no-to-clause"
    assert "public.documents" in findings[0].message
    assert "TO authenticated" in findings[0].remediation
    assert "OWASP:A01" in findings[0].standards


# The direction the downgrade trades against (CLAUDE.md rule 1): every shape anon can satisfy
# stays HIGH — the identity-free class, and every identity-bearing escape.
_REACHABLE_HIGH = [
    "USING (true)",
    "USING ((true))",
    "USING (1 = 1)",
    "",  # no expression at all: Postgres defaults it to TRUE
    "USING (status = 'published')",
    "USING (auth.uid() IS NULL)",
    "USING (owner = auth.uid() OR auth.uid() IS NULL)",
    "USING (auth.uid() = id OR true)",
    "USING (auth.uid() = id OR is_public)",
    "USING ((auth.uid() = id OR is_public) AND deleted_at IS NULL)",
    "USING (auth.uid() = id AND deleted_at IS NULL OR is_public)",  # AND binds tighter
    "USING (NOT (auth.uid() IS NOT NULL))",
    "USING (NOT EXISTS (SELECT 1 FROM banned WHERE user_id = auth.uid()))",
    "USING (x = 'auth.uid()')",  # a string literal cannot fake a scope
    "USING (has_role('admin'))",  # an opaque helper is not trusted
    "FOR ALL USING (auth.uid() = id) WITH CHECK (true)",  # anon can still INSERT
    # --- the anon key IS a JWT with role 'anon' — these are TRUE for anon ---
    "USING (auth.role() = 'anon')",
    "USING (auth.jwt() ->> 'role' = 'anon')",
    "USING (current_setting('request.jwt.claim.role', true) = 'anon')",
    "USING (auth.jwt() IS NOT NULL)",  # anon has a JWT
    "USING ((auth.jwt() ->> 'exp')::int > 0)",  # an anon-key claim
    "USING (auth.role() <> 'anon')",
    # --- a NULL identity laundered into a value, or not reaching the leaf ---
    "USING (COALESCE(auth.uid(), '11111111-1111-1111-1111-111111111111'::uuid) = id)",
    "USING (concat(auth.uid(), '') = x)",
    "USING (has_access(auth.uid()))",  # an opaque helper given the identity: its NULL handling is unknown
    "USING (is_admin(auth.uid()))",  # only the ARGUMENT-LESS is_admin() is trusted, by name
    "USING (CASE WHEN owner = auth.uid() THEN true ELSE true END)",
    "USING (EXISTS (SELECT 1 FROM m WHERE m.user_id = COALESCE(auth.uid(), m.user_id)))",
    "USING (EXISTS (SELECT 1 FROM m WHERE m.user_id = auth.uid() OR m.public))",
    "USING (EXISTS (SELECT 1 FROM m))",  # no WHERE: TRUE whenever m has rows
    "USING (EXISTS (SELECT 1 FROM a UNION SELECT 1 FROM b WHERE b.owner = auth.uid()))",
    "USING (x NOT IN (SELECT user_id FROM m WHERE user_id = auth.uid()))",  # NOT IN (empty) is TRUE
    "USING (x <> ALL (SELECT user_id FROM m WHERE user_id = auth.uid()))",  # ALL over empty is TRUE
    "USING (auth.uid() <> ALL (SELECT banned FROM b WHERE b.row = id))",  # NULL <> ALL (empty) is TRUE
    "USING (auth.uid() = ALL (SELECT banned FROM b WHERE b.row = id))",
    "USING ((SELECT count(*) FROM m WHERE owner = auth.uid()) = 0)",  # an aggregate of nothing is 0
    # An aggregate query yields ONE row over empty input: EXISTS is TRUE for anon.
    "USING (EXISTS (SELECT count(*) FROM m WHERE m.user_id = auth.uid()))",
    "USING (EXISTS (SELECT 1 FROM m WHERE m.user_id = auth.uid() HAVING true))",  # no GROUP BY → 1 row
    "USING (EXISTS (SELECT 1 FROM m WHERE m.user_id = auth.uid() ORDER BY count(*)))",
    "USING (EXISTS (WITH c AS (SELECT 1) SELECT 1 FROM c WHERE user_id = auth.uid() OR true))",
    "USING (EXISTS (SELECT 1 FROM m WHERE m.user_id = auth.uid()) OR is_public)",
    # --- NULL-safe comparison and the ISNULL spelling ---
    "USING (auth.uid() IS DISTINCT FROM id)",  # TRUE for anon on every non-NULL id
    "USING (auth.uid() IS NOT DISTINCT FROM id)",  # TRUE for anon where id IS NULL
    "USING (auth.uid() ISNULL OR owner = auth.uid())",
    # --- postfix IS tests a NULL operand PASSES are escapes ---
    # For anon `auth.uid() = id` is NULL, and NULL IS NOT TRUE / IS NOT FALSE / IS UNKNOWN are
    # all TRUE — the policy is unconditionally TRUE for anon on every row.
    "USING ((auth.uid() = id) IS NOT TRUE)",
    "USING ((auth.uid() = id) IS NOT FALSE)",
    "USING (auth.uid() = id IS UNKNOWN)",  # IS binds looser than `=`, so no parens are needed (L0 beats L5)
    "USING (EXISTS (SELECT 1 FROM m WHERE (m.user_id = auth.uid()) IS NOT TRUE))",  # every m row
    'USING ((( SELECT "auth"."uid"() AS "uid") IS NULL))',  # pg_dump alias + IS NULL: TRUE for anon
    # --- a call's own argument list is not a grouping paren: no whitespace classification ---
    "USING (is_admin (auth.uid()))",
    "USING (is_admin\xa0(auth.uid()))",  # NBSP (#827 round 6): not Postgres whitespace, not a word char
    "USING (is_admin\xa0())",  # a function literally named `is_admin<NBSP>` is not the trusted helper
    "USING (is_superuser (auth.uid()))",
    "USING (has_access (auth.uid()))",
    "USING (coalesce (auth.uid(), x) = id)",
    "USING (is_admin(user_id))",
    "USING (is_admin (user_id))",
    "USING (other.is_admin())",  # only the bare / `public.` spelling is the trusted name
    # EXISTS tests row PRESENCE: the subquery returns one (NULL) row, so this is TRUE for anon.
    "USING (EXISTS (SELECT auth.uid()))",
    # --- NOT over an unrecognised leaf must stay unrecognised (a single worst-case TRUE would flip) ---
    "USING (NOT is_public)",  # TRUE for every private row
    "USING (NOT has_role('x'))",
    "USING (NOT (auth.uid() = id AND is_public))",  # NOT (NULL AND FALSE) is TRUE
    "USING (NOT (x IS NOT DISTINCT FROM auth.uid()))",  # TRUE where x IS NOT NULL
    "USING (NOT public.is_admin())",  # a helper returns FALSE/NULL for anon; NOT FALSE is TRUE
    # --- `E'…'` escape strings must not desync the blanker (#827 round 3 H1) ---
    r"USING (status = E'a\'b' OR x = 'auth.uid()')",
    r"USING (status = E'a\'b\'c' OR x = 'auth.uid()')",
    r"USING (auth.uid() = id AND note = E'x\'y' OR is_public)",
    # --- `NOT BETWEEN` escapes: NOT (NULL AND …) is TRUE past the bound ---
    "USING (id NOT BETWEEN auth.uid() AND high_id)",
    "USING (id NOT BETWEEN low_id AND auth.uid())",
    # --- a dollar-quoted literal is content, never a scope ---
    "USING (x = $$auth.uid()$$)",
    "USING (x = $tag$auth.uid()$tag$)",
    "USING (x = $$it's a trap$$)",
    "USING (x$$ = auth.uid() OR true)",  # `x$$` is an identifier, not a dollar-quote opener
    # --- pg_dump spellings of anon-REACHABLE policies ---
    'USING (("auth"."uid"() IS NULL))',
    'USING (((( SELECT "auth"."uid"() AS "uid") = "user_id") OR "is_public"))',
    'USING ("public"."is_admin"("user_id"))',  # a quoted helper GIVEN the identity stays opaque
    'USING ((( SELECT "auth"."uid"() AS "uid") = "user_id") IS NOT TRUE)',
    'USING ("auth.uid()" = id)',  # a column literally named `auth.uid()` is not the identity
    'USING (x = "auth.uid()")',
    'USING (("auth"."uid"() = "id") OR "t"."or")',  # a quoted `"or"` column beside a REAL OR
    # --- identifiers whose TAIL spells a keyword are not keywords ---
    "USING (my_and (auth.uid()))",
    "USING (my_intersect (auth.uid()))",
    "USING (x_select (auth.uid()) = id)",
    # --- a body the grader cannot read is never downgraded ---
    "USING (auth.uid() = id) WITH CHECK",  # a clause with no parenthesised body
]


@pytest.mark.parametrize("clause", _REACHABLE_HIGH)
def test_policy_no_role_scope_reachable_predicate_stays_high(tmp_path: Path, clause: str) -> None:
    (tmp_path / "schema.sql").write_text(
        f"CREATE POLICY p ON public.documents {clause};\n", encoding="utf-8"
    )
    findings = PolicyNoRoleScopeGuard().run(tmp_path, _pgprof(tmp_path))
    assert len(findings) == 1, clause
    assert findings[0].severity == "high", clause
    assert findings[0].rule == "policy-no-role-scope/no-to-clause"
    assert "public.documents" in findings[0].message


# Scoped in reality, HIGH by design in v1: the whitelist does not recognise the shape, and the
# worst-case default keeps it where it was before #801. Each entry names the widening it would
# need; each widening is its own follow-up with a fires/stays-silent pair, never a patch here.
# None of these appear among the flagship's 28 (the oracle above).
_RETAINED_HIGH_BY_DESIGN = [
    # auth.jwt() / auth.role() / the JWT GUCs are outside the identity set: the anon key IS a JWT,
    # so NULL-ness depends on the claim. Widening: a per-claim model of the anon key.
    "USING (auth.jwt() ->> 'sub' = owner::text)",
    "USING (auth.role() = 'authenticated')",
    "USING ('authenticated' = auth.role())",
    "USING (auth.jwt() ->> 'role' = 'authenticated')",
    "USING ((current_setting('request.jwt.claims', true)::json ->> 'sub') = user_id::text)",
    "USING (current_setting('request.jwt.claim.sub', true) = user_id::text)",
    "USING (((current_setting('request.jwt.claims', true)::json->>'sub')::uuid) = user_id)",
    # a function wrapping the identity. Widening: a STRICT built-in list (lower, trim, …).
    "USING (lower(auth.email()) = email)",
    "USING (trim (auth.email()) = email)",
    # postfix IS tests a NULL operand FAILS. Widening: L0 split by which test is applied.
    "USING ((auth.uid() = id) IS TRUE)",
    "USING ((auth.uid() = id) IS FALSE)",
    "USING ((auth.uid() = id) IS NOT UNKNOWN)",
    "USING ((auth.uid() = id) IS NOT NULL)",
    # a subquery with no WHERE yields NULL, not TRUE. Widening: `IN`/`= ANY` over a bare identity.
    "USING (id IN (SELECT auth.uid()))",
    "USING (id = ANY (SELECT auth.uid()))",
    # BETWEEN propagates NULL (`id >= NULL` is NULL). Widening: a BETWEEN leaf.
    "USING (id BETWEEN auth.uid() AND high_id)",
    # HAVING makes an aggregate query; with a GROUP BY an empty input yields no group, so this IS
    # empty — but telling that apart from the HAVING-without-GROUP-BY shape (one row, TRUE) is
    # modelling, and the v1 rule is simply "HAVING → unrecognised".
    "USING (EXISTS (SELECT 1 FROM m WHERE m.user_id = auth.uid() GROUP BY 1 HAVING true))",
    # a locking clause after the WHERE. Widening: `FOR UPDATE/SHARE` in the WHERE tail set.
    "USING (id IN (SELECT team_id FROM members WHERE user_id = auth.uid() FOR UPDATE))",
]


@pytest.mark.parametrize("clause", _RETAINED_HIGH_BY_DESIGN)
def test_policy_no_role_scope_retained_high_by_design_stays_high(tmp_path: Path, clause: str) -> None:
    (tmp_path / "schema.sql").write_text(
        f"CREATE POLICY p ON public.documents {clause};\n", encoding="utf-8"
    )
    findings = PolicyNoRoleScopeGuard().run(tmp_path, _pgprof(tmp_path))
    assert len(findings) == 1, clause
    assert findings[0].severity == "high", clause
    assert findings[0].rule == "policy-no-role-scope/no-to-clause"


_DENY = [
    "USING (false)",
    "USING (FALSE)",
    "FOR INSERT WITH CHECK (false)",
    "USING (false) WITH CHECK (false)",
    "USING ((false))",
    "USING (1 = 0)",
]


@pytest.mark.parametrize("clause", _DENY)
def test_policy_no_role_scope_deny_rule_does_not_fire(tmp_path: Path, clause: str) -> None:
    # `USING (false)` grants nothing to anyone; a TO clause would change nothing — no finding.
    (tmp_path / "schema.sql").write_text(
        f"CREATE POLICY p ON public.audit_logs {clause};\n", encoding="utf-8"
    )
    assert PolicyNoRoleScopeGuard().run(tmp_path, _pgprof(tmp_path)) == [], clause


def test_policy_no_role_scope_deny_rule_does_not_hide_the_next_statement(tmp_path: Path) -> None:
    # The deny skip is per statement: the open policy right after it still fires, on its own line.
    (tmp_path / "schema.sql").write_text(
        "CREATE POLICY deny_writes ON public.audit_logs FOR UPDATE USING (false);\n"
        "CREATE POLICY open_read ON public.audit_logs FOR SELECT USING (true);\n",
        encoding="utf-8",
    )
    findings = PolicyNoRoleScopeGuard().run(tmp_path, _pgprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].location == "schema.sql:2"


def test_policy_no_role_scope_pragma_governs_the_low_tier_too(tmp_path: Path) -> None:
    # Rule 4 (CLAUDE.md): the opt-out is checked before the grade, so it silences a LOW too.
    (tmp_path / "schema.sql").write_text(
        "CREATE POLICY p ON public.documents USING (auth.uid() = id); "
        "-- security: allow-policy-no-role-scope\n",
        encoding="utf-8",
    )
    assert PolicyNoRoleScopeGuard().run(tmp_path, _pgprof(tmp_path)) == []


def test_policy_no_role_scope_identity_text_in_policy_name_does_not_downgrade(tmp_path: Path) -> None:
    # A policy name is free text: `auth.uid()` INSIDE the quoted name must not read as a scope for
    # an identity-free body — quoted-identifier content is blanked on the structural view, and a
    # `using (` spelled inside the name is not a clause either.
    (tmp_path / "schema.sql").write_text(
        'CREATE POLICY "auth.uid() = id" ON public.documents USING (true);\n'
        'CREATE POLICY "x using (auth.uid() = id)" ON public.documents USING (visibility = \'public\');\n',
        encoding="utf-8",
    )
    findings = PolicyNoRoleScopeGuard().run(tmp_path, _pgprof(tmp_path))
    assert [f.severity for f in findings] == ["high", "high"]


def test_policy_no_role_scope_multiline_dump_shape_grades_low(tmp_path: Path) -> None:
    # A `supabase db dump` policy: multi-line, quoted name, `FOR SELECT`, self-scoped, no TO
    # clause — LOW, reported on the statement's first line.
    (tmp_path / "schema.sql").write_text(
        'CREATE POLICY "Users can view own profile" ON public.profiles\n'
        "  FOR SELECT\n"
        "  USING (auth.uid() = id);\n",
        encoding="utf-8",
    )
    findings = PolicyNoRoleScopeGuard().run(tmp_path, _pgprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity == "low"
    assert findings[0].location == "schema.sql:1"
    assert "public.profiles" in findings[0].message


def test_policy_no_role_scope_unbalanced_expression_is_never_downgraded(tmp_path: Path) -> None:
    # The statement carve ends at the `;` before the expression's `)` closes, so the body does not
    # balance: a statement the guard cannot read is reported as anon-reachable (HIGH), never
    # graded down on a guess.
    (tmp_path / "schema.sql").write_text(
        "CREATE POLICY p ON public.documents USING ((auth.uid() = id);\n", encoding="utf-8"
    )
    findings = PolicyNoRoleScopeGuard().run(tmp_path, _pgprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_policy_no_role_scope_grader_exception_degrades_to_high(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # #827 round-1 H1: an exception inside a guard is swallowed by audit.py's per-guard `except`,
    # which drops EVERY finding of the guard and exits 0 — a failure that presents as success. A
    # grader bug must instead degrade to the pre-#801 HIGH for that statement and lose nothing else.
    (tmp_path / "a.sql").write_text(
        "CREATE POLICY scoped ON public.t USING (auth.uid() = id);\n", encoding="utf-8"
    )
    (tmp_path / "b.sql").write_text(
        "CREATE POLICY open ON public.t USING (status = 'published');\n", encoding="utf-8"
    )
    monkeypatch.setattr(_mod, "_eval", lambda *a, **k: 1 / 0)
    findings = PolicyNoRoleScopeGuard().run(tmp_path, _pgprof(tmp_path))
    assert sorted((f.location, f.severity) for f in findings) == [("a.sql:1", "high"), ("b.sql:1", "high")]


def _right_nested_gated_or(n: int) -> str:
    # `auth.uid() = id1 OR (auth.uid() = id2 OR (… ))`: every disjunct is gated, so nothing can
    # short-circuit and the descent has to go the full depth — the shape that raised RecursionError.
    expr = f"auth.uid() = id{n}"
    for i in range(n - 1, 0, -1):
        expr = f"auth.uid() = id{i} OR ({expr})"
    return expr


def test_policy_no_role_scope_deep_nesting_grades_high_and_keeps_other_findings(tmp_path: Path) -> None:
    # #827 round-1 H1, verbatim: a right-nested OR 800 deep raised RecursionError out of run(),
    # audit.py swallowed it, and EVERY finding of the scan was lost while the gate exited 0. Now:
    # no exception, the deep statement is unreadable beyond _MAX_DEPTH and grades HIGH (never
    # downgraded on a guess), and the plainly exploitable policy in the OTHER file still fires.
    # Redundant paren LAYERS are not depth: E1 strips them in one loop, so that one reads through.
    (tmp_path / "a.sql").write_text(
        "CREATE POLICY open ON public.t USING (status = 'published');\n", encoding="utf-8"
    )
    (tmp_path / "b.sql").write_text(
        f"CREATE POLICY deep ON public.t USING ({_right_nested_gated_or(5_000)});\n", encoding="utf-8"
    )
    (tmp_path / "c.sql").write_text(
        f"CREATE POLICY wrapped ON public.t USING ({'(' * 5_000}auth.uid() = id{')' * 5_000});\n",
        encoding="utf-8",
    )
    findings = PolicyNoRoleScopeGuard().run(tmp_path, _pgprof(tmp_path))
    assert sorted((f.location, f.severity) for f in findings) == [
        ("a.sql:1", "high"),
        ("b.sql:1", "high"),
        ("c.sql:1", "low"),
    ]


def test_policy_no_role_scope_postgres_whitespace_matches_the_regex_class() -> None:
    # The leaf regexes spell Postgres whitespace out (`_WS`) and the trim uses the same set
    # (`_PG_WS`); the two must agree, or a blank the regex skips is one the trim keeps — the #827
    # round-6 class, where a charset drift flipped a grade. Pinned as data, not prose.
    rx = re.compile(_mod._WS)
    for code in range(0x80):
        assert (rx.fullmatch(chr(code)) is not None) == (chr(code) in _mod._PG_WS), hex(code)
    assert rx.fullmatch("\xa0") is None and "\xa0" not in _mod._PG_WS


# --- growth class, not wall-clock (tests/_timing.py) ------------------------------------------
# The constant-factor half of the three growth workloads below, in calibration units per item so
# machine speed is divided out (tests/_timing.py, "normalized cost"). It replaced an absolute 1.0s
# backstop on one extra single-shot run, which sized its headroom from a linux reading (0.051s) and
# then ran on the self-hosted Windows leg, where the same scan is 0.23s idle (4.6x): ~4x of real
# room, which the leg's own `-n 3` load used up on 12 of ~27 Windows attempts in the week to
# 2026-11-06 (1.05s-2.17s), always with the growth half passing. The reading checked now is
# `assert_growth`'s own min-of-repeats at the top size, not a fresh single shot, since the noise is
# one-sided; a true hang is still bounded by `assert_growth`'s ceiling.
#
# Measured on the Windows CI host (2026-11-06, n=2000, 5 runs): healthy 0.521-0.532 units per
# conjunct for the pg_dump workload, the slowest of the three (nested OR 0.21-0.22, paren layers
# 0.03); `regression` is the pg_dump workload with `_depth0` monkeypatched to re-walk its whole
# prefix per match, the #827 round-5 H-1 class ("never re-scan a prefix per match"): 16.7-17.8
# units (7.6s), and `assert_growth` reads it as quadratic. The 31x window matches the 33x the linux
# readings gave (0.051s vs 1.68s). 5.0 is 9.4x healthy and 3.3x under the bug, tighter than the
# old 1.0s backstop, which tripped only at ~20x healthy on linux.
_C801_COST = register_normalized(
    NormalizedCostBudget(
        name="policy-no-role-scope: predicate workload cost per item",
        units_per_item=5.0,
        measured=0.532,
        regression=16.7,
        why="a depth-0 scan that re-walks its prefix per match (#827 round 5 H-1), quadratic in "
        "the conjunct count",
    )
)


def _grade_workload(
    tmp_path: Path, name: str, sizes: list[int], body_for: Callable[[int], str]
) -> tuple[Callable[[int], None], dict[int, list[str]]]:
    roots: dict[int, Path] = {}
    for n in sizes:
        root = tmp_path / f"{name}{n}"
        root.mkdir()
        (root / "p.sql").write_text(
            f'CREATE POLICY p ON "public"."t" USING ({body_for(n)});\n', encoding="utf-8"
        )
        roots[n] = root
    guard = PolicyNoRoleScopeGuard()
    graded: dict[int, list[str]] = {}

    def scan(n: int) -> None:
        graded[n] = [f.severity for f in guard.run(roots[n], _pgprof(roots[n]))]

    return scan, graded


@pytest.mark.slow
def test_policy_no_role_scope_pg_dump_conjuncts_cost_is_linear(tmp_path: Path) -> None:
    # n ANDed pg_dump-spelled conjuncts WITH the `AS "uid"` alias (the #827 round-5 shape that
    # collapsed onto a quadratic path). Behavioural half: the dump spelling still grades LOW.
    sizes = [250, 500, 1000, 2000]
    scan, graded = _grade_workload(
        tmp_path, "conj", sizes, lambda n: " AND ".join(['( SELECT "auth"."uid"() AS "uid") = "id"'] * n)
    )
    calibration = calibration_seconds()
    elapsed = assert_growth(scan, sizes, expected="linear")
    assert_normalized_cost(elapsed[-1], sizes[-1], _C801_COST, calibration=calibration)
    assert all(graded[n] == ["low"] for n in sizes), graded


@pytest.mark.slow
def test_policy_no_role_scope_nested_or_cost_is_linear_in_depth(tmp_path: Path) -> None:
    # n right-nested ORs, each disjunct gated: the descent stops at _MAX_DEPTH and each level is
    # one linear pass, so past the cap the cost grows with the expression's LENGTH.
    sizes = [250, 500, 1000, 2000]
    scan, graded = _grade_workload(tmp_path, "or", sizes, _right_nested_gated_or)
    calibration = calibration_seconds()
    elapsed = assert_growth(scan, sizes, expected="linear")
    assert_normalized_cost(elapsed[-1], sizes[-1], _C801_COST, calibration=calibration)
    assert all(graded[n] == ["high"] for n in sizes), graded


@pytest.mark.slow
def test_policy_no_role_scope_redundant_paren_layers_cost_is_linear(tmp_path: Path) -> None:
    # n redundant layers around a self-scoped predicate: E1 strips them in one loop over the
    # paren map, never re-scanning from the start per layer.
    sizes = [250, 500, 1000, 2000]
    scan, graded = _grade_workload(tmp_path, "wrap", sizes, lambda n: f"{'(' * n}auth.uid() = id{')' * n}")
    calibration = calibration_seconds()
    elapsed = assert_growth(scan, sizes, expected="linear")
    assert_normalized_cost(elapsed[-1], sizes[-1], _C801_COST, calibration=calibration)
    assert all(graded[n] == ["low"] for n in sizes), graded


def test_policy_no_role_scope_skips_restrictive_policy(tmp_path: Path) -> None:
    # FP-bait: an AS RESTRICTIVE policy can only narrow access, never grant it -- it must
    # never be misclassified as a HIGH "reachable by anon" no-role-scope finding, even
    # with a literal `USING (true)` and no TO clause (found via a canary interaction with
    # rls_permissive_policy.py's own restrictive-always-true finding).
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE TABLE public.t (id uuid PRIMARY KEY);\n"
        "ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY p ON public.t AS RESTRICTIVE USING (true);\n", encoding="utf-8"
    )
    assert PolicyNoRoleScopeGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_policy_no_role_scope_quoted_name_as_restrictive_still_fires(tmp_path: Path) -> None:
    # Widening (PR #893 re-review MEDIUM #C): a quoted policy NAME containing "as restrictive"
    # must NOT be read as an `AS RESTRICTIVE` clause and wrongly skip the statement, voiding a
    # real no-TO-clause HIGH (a gate-evasion reachable by choosing a policy name).
    # `blank_policy_names` space-fills the name before the skip check; the FP-bait above
    # (genuine `AS RESTRICTIVE`) pins the other direction.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        'CREATE POLICY "mark as restrictive" ON public.t USING (true);\n',
        encoding="utf-8",
    )
    findings = PolicyNoRoleScopeGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "policy-no-role-scope/no-to-clause"
    assert findings[0].severity == "high"
