from __future__ import annotations

import os
import time
from collections.abc import Callable

import pytest

from agentsec.audit import audit
from agentsec.guards.rls_auth_uid_unwrapped import RlsAuthUidUnwrappedGuard
from tests._timing import TimingBudget, assert_growth, assert_within, register
from tests.conftest import PG_DUMP_HEAD
from tests.guards._common import *  # noqa: F401,F403


def _prof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"supabase"}, sql_dir="sql")


def _run(tmp_path: Path, sql: str) -> list:
    sql_dir = tmp_path / "sql"
    sql_dir.mkdir(exist_ok=True)
    (sql_dir / "p.sql").write_text(sql, encoding="utf-8")
    return RlsAuthUidUnwrappedGuard().run(tmp_path, _prof(tmp_path))


def test_rls_auth_uid_unwrapped_na_without_supabase() -> None:
    assert RlsAuthUidUnwrappedGuard().applies(mkprofile(Path("/tmp"), features={"sql"})) is False


def test_rls_auth_uid_unwrapped_applies_with_supabase() -> None:
    assert RlsAuthUidUnwrappedGuard().applies(mkprofile(Path("/tmp"), features={"supabase"})) is True


def test_flags_unwrapped_auth_uid_in_using(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        'CREATE POLICY "read own" ON public.notes FOR SELECT USING (auth.uid() = user_id);\n',
    )
    assert len(findings) == 1
    assert findings[0].rule == "rls-auth-uid-unwrapped/uid-unwrapped"
    assert findings[0].severity == "medium"
    assert findings[0].standards == ["OWASP:A04"]


def test_flags_unwrapped_auth_uid_in_with_check(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        'CREATE POLICY "own rows" ON public.notes FOR UPDATE '
        "USING ((select auth.uid()) = user_id) "
        "WITH CHECK (auth.uid() = user_id);\n",
    )
    assert len(findings) == 1
    assert "auth.uid()" in findings[0].message


def test_flags_unwrapped_auth_jwt(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        'CREATE POLICY "org scoped" ON public.notes FOR SELECT '
        "USING ((auth.jwt() ->> 'org_id') = org_id);\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "rls-auth-uid-unwrapped/jwt-unwrapped"


def test_flags_both_clauses_unwrapped_as_two_findings(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        'CREATE POLICY "own rows" ON public.notes FOR UPDATE '
        "USING (auth.uid() = user_id) "
        "WITH CHECK (auth.uid() = user_id);\n",
    )
    assert len(findings) == 2


def test_fp_bait_wrapped_auth_uid_stays_silent(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        'CREATE POLICY "read own" ON public.notes FOR SELECT '
        "USING ((select auth.uid()) = user_id);\n",
    )
    assert findings == []


def test_fp_bait_wrapped_auth_jwt_stays_silent(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        'CREATE POLICY "org scoped" ON public.notes FOR SELECT '
        "USING ((SELECT auth.jwt()) ->> 'org_id' = org_id);\n",
    )
    assert findings == []


def test_fp_bait_wrapped_form_is_case_and_whitespace_insensitive(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        'CREATE POLICY "read own" ON public.notes FOR SELECT\n'
        "  USING (\n"
        "    ( SELECT   AUTH.UID(  )  )\n"
        "    = user_id\n"
        "  );\n",
    )
    assert findings == []


def test_pragma_opt_out(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "-- security: allow-rls-auth-uid-unwrapped\n"
        'CREATE POLICY "read own" ON public.notes FOR SELECT USING (auth.uid() = user_id);\n',
    )
    assert findings == []


def test_na_without_sql_dir(tmp_path: Path) -> None:
    # No sql/ dir at all -> nothing to scan, no crash.
    assert RlsAuthUidUnwrappedGuard().run(tmp_path, _prof(tmp_path)) == []


def test_rls_auth_uid_unwrapped_skips_examples_dir(tmp_path: Path) -> None:
    # Regression: this guard originally had no `is_reference_sql_path` filter, unlike every
    # sibling guard in the same batch (policy-no-role-scope, storage-no-rls, matview-exposed,
    # sensitive-columns) — it fired MEDIUM on tutorial/example SQL none of those guards do.
    d = tmp_path / "sql" / "examples"
    d.mkdir(parents=True)
    (d / "demo.sql").write_text(
        'CREATE POLICY "read own" ON public.notes FOR SELECT USING (auth.uid() = user_id);\n',
        encoding="utf-8",
    )
    assert RlsAuthUidUnwrappedGuard().run(tmp_path, _prof(tmp_path)) == []


def test_line_number_points_at_the_unwrapped_call(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        '-- header comment\n'
        'CREATE POLICY "read own"\n'
        "  ON public.notes\n"
        "  FOR SELECT\n"
        "  USING (auth.uid() = user_id);\n",
    )
    assert len(findings) == 1
    assert findings[0].location.endswith("p.sql:5")


def test_hostile_many_heads_no_terminator_bounded_time(tmp_path: Path) -> None:
    # Adversarial: many `create policy` heads with no `;` anywhere — `iter_statement_spans`
    # bails after the FIRST failed terminator search rather than retrying from every head
    # (issue #419's shape). Actual ~0.01s; a re-scan-from-every-head regression takes minutes.
    sql = "create policy " * 30_000 + "\n"
    (tmp_path / "sql").mkdir()
    (tmp_path / "sql" / "hostile.sql").write_text(sql, encoding="utf-8")
    start = time.monotonic()
    findings = RlsAuthUidUnwrappedGuard().run(tmp_path, _prof(tmp_path))
    elapsed = time.monotonic() - start
    # 8.0s ceiling over a ~0.65s healthy run (measured, >10x headroom, tests/test_timing_budgets.py's
    # gate) — a re-scan-from-every-head regression takes minutes at this input size, not
    # single-digit seconds, so this stays exactly as discriminating (2026-08-25).
    assert elapsed < 8.0, f"took {elapsed:.2f}s - unbounded head rescan reintroduced"
    assert findings == []


def test_many_findings_bounded_time(tmp_path: Path) -> None:
    # #587-shaped regression class: a per-finding offset->line lookup that rescans the file from
    # position 0 for every finding is only visible with MANY findings — a hostile input yielding
    # zero findings never enters that code path. Mirrors
    # test_policy_rls_disabled_many_findings_bounded_time exactly, for this guard's own
    # bisect-based newline index.
    sql = "".join(
        f'CREATE POLICY "p{i}" ON public.t{i} FOR SELECT USING (auth.uid() = user_id);\n'
        for i in range(20000)
    )
    (tmp_path / "sql").mkdir()
    (tmp_path / "sql" / "big.sql").write_text(sql, encoding="utf-8")
    guard = RlsAuthUidUnwrappedGuard()
    start = time.monotonic()
    findings = guard.run(tmp_path, _prof(tmp_path))
    elapsed = time.monotonic() - start
    assert len(findings) == 20000, "the perf path must actually report, or this proves nothing"
    # 30.0s ceiling over a ~2.7s healthy run (measured across 3 repeats, worst 2.83s -> >10x
    # headroom, tests/test_timing_budgets.py's gate). A generous multiple rather than a tight
    # one deliberately, since this test does real O(n) work rather than near-zero constant
    # overhead — a reintroduced O(n^2) per-finding rescan at 20,000 findings would take far
    # longer than 30s, so this stays discriminating. A real TimingBudget/assert_normalized_cost
    # conversion (mirroring test_policy_exists_rls_disabled.py's own pattern) is the more
    # precise fix and is still owed as follow-up (2026-08-25).
    assert elapsed < 30.0, f"took {elapsed:.2f}s - per-finding file rescan reintroduced"


def test_string_literal_double_dash_does_not_hide_an_unwrapped_call(tmp_path: Path) -> None:
    # Was pinned as a known false negative (#693 review): the guard's private `--[^\n]*` blank
    # was not string-aware, so the `--` inside 'a--b' blanked the rest of the line, call
    # included. The guard now reads the shared quote-aware `strip_sql_comments(blank=True)`
    # (#442 phase 2b), so the literal stays a literal and the unwrapped call fires.
    findings = _run(
        tmp_path,
        "CREATE POLICY p ON public.t FOR SELECT USING (note = 'a--b' AND auth.uid() = user_id);\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "rls-auth-uid-unwrapped/uid-unwrapped"


def test_plain_string_literal_still_fires(tmp_path: Path) -> None:
    # Same shape as the double-dash test above, but WITHOUT a `--` inside the literal: the
    # control that the literal and the AND clause never mattered.
    findings = _run(
        tmp_path,
        "CREATE POLICY p ON public.t FOR SELECT USING (note = 'plain' AND auth.uid() = user_id);\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "rls-auth-uid-unwrapped/uid-unwrapped"


# --- #855: "wrapped" is a property (the nearest sub-SELECT is self-contained), not a spelling ----
# Every deparsed shape below is verbatim Postgres 17 output (`pg_dump` plain, and the quote-all
# `supabase db dump` runs), measured from the Supabase image for the #855 RCA.

_UID = "rls-auth-uid-unwrapped/uid-unwrapped"
_JWT = "rls-auth-uid-unwrapped/jwt-unwrapped"


def _policy(expr: str) -> str:
    return f'CREATE POLICY "p" ON "public"."t" FOR SELECT USING ({expr});\n'


@pytest.mark.parametrize(
    "sql",
    [
        # the issue's exact case: plain `pg_dump` / `supabase db diff` names the output column
        "CREATE POLICY p ON public.t FOR SELECT USING ((( SELECT auth.uid() AS uid) = id));\n",
        'CREATE POLICY "p" ON "public"."t"\n  FOR SELECT\n  USING ((( SELECT auth.uid() AS uid)\n    = id));\n',
        # `supabase db dump` (quote-all): silent before #855 only because the quoted call was invisible
        _policy('(( SELECT "auth"."uid"() AS "uid") = "id")'),
    ],
)
def test_fp_bait_pg_dump_deparsed_wrapped_call_stays_silent(tmp_path: Path, sql: str) -> None:
    assert _run(tmp_path, sql) == []


@pytest.mark.parametrize(
    "expr",
    [
        # an operator target gets no alias, but the deparser parenthesizes it and casts the key
        "(( SELECT (auth.jwt() ->> 'org'::text)) = org)",
        "(( SELECT ((auth.jwt() -> 'a'::text) ->> 'b'::text)) = org)",
        '(( SELECT ("auth"."jwt"() ->> \'org\'::"text")) = "org")',
        # a cast target is named after its type
        "(( SELECT ((auth.jwt() ->> 'sub'::text))::uuid AS uuid) = id)",
        "(( SELECT (auth.uid())::text AS uid) = owner)",
        '(( SELECT (("auth"."jwt"() ->> \'sub\'::"text"))::"uuid" AS "uuid") = "id")',
        '(( SELECT ("auth"."uid"())::"text" AS "uid") = "owner")',
    ],
)
def test_fp_bait_deparsed_operator_and_cast_targets_stay_silent(tmp_path: Path, expr: str) -> None:
    assert _run(tmp_path, _policy(expr)) == []


@pytest.mark.parametrize(
    "expr",
    [
        # supabase/supabase's Clerk example, verbatim
        "((select auth.jwt()->>'org_role') = 'org:admin')",
        "(organization_id = (select coalesce(auth.jwt()->>'org_id', auth.jwt()->'o'->>'id')))",
        "((select auth.jwt()->'fva'->>1) != '-1')",
        "((select auth.uid()::text) = owner)",
        "((select auth.uid() as me) = id)",
        "((select(auth.uid())) = id)",  # no space after `select`: a Known bypass before #855
        # a schema-qualified helper around the call: pg_dump qualifies every non-catalog function
        "(( SELECT public.is_org_member(auth.uid()) AS is_org_member) = true)",
        '(( SELECT "public"."is_org_member"("auth"."uid"()) AS "is_org_member") = true)',
    ],
)
def test_fp_bait_hand_written_wrapped_forms_stay_silent(tmp_path: Path, expr: str) -> None:
    assert _run(tmp_path, _policy(expr)) == []


def test_fp_bait_flagship_pg_dump_policies_stay_silent(tmp_path: Path) -> None:
    # 98 real flagship policies in the quote-all spelling, 35 wrapped `"auth"."uid"()` calls among
    # them: the shape that turns into a wall of new FPs if the quoted-call fix ships without the
    # structural wrapped check (#855's alternative D).
    src = _REPO_ROOT / "tests" / "fixtures" / "policy_no_role_scope" / "sql" / "flagship_pg_dump_policies.sql"
    sql = src.read_text(encoding="utf-8")
    assert sql.count('"auth"."uid"()') >= 35, "fixture drifted: no longer the quoted-dump oracle"
    assert _run(tmp_path, sql) == []


@pytest.mark.parametrize(
    ("expr", "rule"),
    [
        ('("auth"."uid"() = "id")', _UID),
        ('(("auth"."jwt"() ->> \'org\'::"text") = "org")', _JWT),
    ],
)
def test_flags_quoted_unwrapped_call_from_a_dump(tmp_path: Path, expr: str, rule: str) -> None:
    # The sibling FN: `"auth"."uid"()` matched neither alternative of the old regex, so a genuinely
    # unwrapped policy in a `supabase db dump` / `db pull` file was silent.
    findings = _run(tmp_path, _policy(expr))
    assert [f.rule for f in findings] == [rule]


@pytest.mark.parametrize(
    "expr",
    [
        "((select auth.uid() = user_id))",  # hand-written, correlated
        "( SELECT (auth.uid() = t.id))",  # the deparse of the above (outer refs come qualified)
        '( SELECT ("auth"."uid"() = "t"."id"))',
        '(( SELECT COALESCE(auth.uid(), t.id) AS "coalesce") = id)',
        '(( SELECT COALESCE("auth"."uid"(), "t"."id") AS "coalesce") = "id")',
        "(( SELECT public.is_org_member(auth.uid(), t.org_id) AS is_org_member) = true)",
    ],
)
def test_flags_call_in_a_correlated_sub_select(tmp_path: Path, expr: str) -> None:
    # The direction traded against: a sub-SELECT that reads the outer row is a per-row subplan,
    # not an initplan, so "inside `( select`" alone must never count as wrapped (#855 alt C).
    assert [f.rule for f in _run(tmp_path, _policy(expr))] == [_UID]


@pytest.mark.parametrize(
    "expr",
    [
        "(EXISTS ( SELECT 1\n   FROM public.members m\n  WHERE (m.user_id = auth.uid())))",
        '(EXISTS ( SELECT 1\n   FROM "public"."members" "m"\n  WHERE ("m"."user_id" = "auth"."uid"())))',
        # an OUTER wrapper must not launder the EXISTS body: only the NEAREST sub-SELECT decides
        "(( SELECT (EXISTS ( SELECT 1 FROM m WHERE m.user_id = auth.uid()))) = true)",
    ],
)
def test_flags_call_inside_exists_from_sub_select(tmp_path: Path, expr: str) -> None:
    assert [f.rule for f in _run(tmp_path, _policy(expr))] == [_UID]


def test_fp_bait_wrapped_call_inside_exists_stays_silent(tmp_path: Path) -> None:
    # The recommended membership shape: the inner `(select auth.uid())` is its own initplan.
    expr = "(EXISTS (SELECT 1 FROM m WHERE m.user_id = (select auth.uid())))"
    assert _run(tmp_path, _policy(expr)) == []


def test_wrapped_and_bare_in_one_policy_fires_once_at_the_bare_call(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        'CREATE POLICY "p" ON public.t FOR SELECT\n'
        "  USING ((( SELECT auth.uid() AS uid) = id)\n"
        "    OR (auth.uid() = owner));\n",
    )
    assert len(findings) == 1
    assert findings[0].location.endswith("p.sql:3")


def test_deparsed_multi_line_policy_reports_the_bare_calls_line(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        'CREATE POLICY "h" ON "public"."t855"\n'
        "  FOR SELECT\n"
        '  USING ((EXISTS ( SELECT 1\n   FROM "public"."m" "x"\n  WHERE ("x"."id" = "auth"."uid"()))));\n',
    )
    assert len(findings) == 1
    assert findings[0].location.endswith("p.sql:5")


@pytest.mark.parametrize(
    "expr",
    [
        "(\"auth.uid()\" = id)",  # a quoted column NAMED like the call
        "(note = 'auth.uid()')",  # a string literal
        "(myauth.uid() = id)",  # a different schema
    ],
)
def test_fp_bait_call_spelling_inside_a_name_or_literal_stays_silent(tmp_path: Path, expr: str) -> None:
    assert _run(tmp_path, _policy(expr)) == []


def test_bare_call_beside_a_literal_or_policy_name_spelling_still_fires_once(tmp_path: Path) -> None:
    # The traded-against direction of the narrowing above: the real call next to them still fires,
    # exactly once (the old regex fired on the policy name and the literal too: three findings).
    findings = _run(
        tmp_path,
        'CREATE POLICY "owner: auth.uid() = user_id" ON public.t FOR SELECT '
        "USING (note <> 'auth.uid()' AND auth.uid() = user_id);\n",
    )
    assert [f.rule for f in findings] == [_UID]


def test_flags_unwrapped_call_in_a_do_block_policy(tmp_path: Path) -> None:
    # The idempotent-migration idiom. `blank_sql_literals` space-fills a whole `$$` body, so the
    # views are built per STATEMENT: built per file they hid 61 of 334 real calls (#855).
    do_block = (
        "DO $$\nBEGIN\n"
        "  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'own') THEN\n"
        '    CREATE POLICY "own" ON public.notes FOR SELECT USING ({expr});\n'
        "  END IF;\nEND\n$$;\n"
    )
    findings = _run(tmp_path, do_block.format(expr="auth.uid() = user_id"))
    assert [f.rule for f in findings] == [_UID]
    assert findings[0].location.endswith("p.sql:4")
    assert _run(tmp_path, do_block.format(expr="(select auth.uid()) = user_id")) == []


def test_flags_unwrapped_call_in_dynamic_execute_sql(tmp_path: Path) -> None:
    # A policy built in an EXECUTE literal: the per-statement view starts INSIDE the literal, so
    # its body reads as code. Fired before #855 too; pinned so a file-level view cannot drop it.
    sql = (
        "DO $$ BEGIN\n"
        "  EXECUTE 'CREATE POLICY own ON public.notes FOR SELECT USING (auth.uid() = user_id)';\n"
        "END $$;\n"
    )
    assert [f.rule for f in _run(tmp_path, sql)] == [_UID]


@pytest.mark.parametrize(
    "expr",
    [
        "((select auth.uid() from (select 1) s limit 1) = id)",  # a FROM, even an uncorrelated one
        "((select (auth.jwt() ->> 'exp')::timestamp with time zone) > now())",  # a multi-word type
        "((select auth.uid() uid) = id)",  # an alias without AS (pg_dump always writes AS)
    ],
)
def test_unreadable_sub_select_body_is_a_known_residual_that_fires(tmp_path: Path, expr: str) -> None:
    # KNOWN, ACCEPTED residual, in the SAFE direction: a body the residue test cannot positively
    # read as uncorrelated keeps firing. Pinned so a widening of the strip list is a knowing change.
    assert [f.rule for f in _run(tmp_path, _policy(expr))] in ([_UID], [_JWT])


@pytest.mark.parametrize(
    ("sql", "rule"),
    [
        # `( select` never closes inside the statement: its body is unreadable, so the call fires.
        # Read as "body runs to the end of the statement" instead, both would go silent.
        ('CREATE POLICY "p" ON "public"."t" FOR SELECT USING ((select auth.uid();\n', _UID),
        ('CREATE POLICY "p" ON "public"."t" FOR SELECT USING ((select auth.jwt() ->> \'org\';\n', _JWT),
        # A `)` inside a literal must not close the sub-SELECT early and drop the outer-row column
        # after it from the body: paired on the raw text, each of these goes silent. (An `E'` or a
        # `$tag$` opener would leave a word character in the cut-off body and fire regardless.)
        (_policy("((select auth.uid()::text || ')' || t.name) = owner)"), _UID),
        (_policy("((select auth.uid()::text || $$)$$ || t.name) = owner)"), _UID),
    ],
)
def test_unbalanced_or_literal_paren_sub_select_still_fires(tmp_path: Path, sql: str, rule: str) -> None:
    # The safe direction of the paren pass, pinned (#1035 review M1): an unbalanced sub-SELECT, or a
    # paren that only a literal holds, must never let a call read as wrapped.
    assert [f.rule for f in _run(tmp_path, sql)] == [rule]


def test_dump_copy_of_unwrapped_policy_gates(tmp_path: Path) -> None:
    # #855's failure that presented as success, end to end. A migration holds the unwrapped policy and
    # `supabase/schema.sql` holds its quoted dump; since #829 the migration copy is `superseded`
    # (non-gating), so before #855 the guard's GATING output was empty on a real per-row policy.
    # Assert the artifact: the dump's own copy is reported, and it gates.
    mig = tmp_path / "supabase" / "migrations"
    mig.mkdir(parents=True)
    (mig / "001_init.sql").write_text(
        'create policy "own" on public.profiles for select using (auth.uid() = id);\n', encoding="utf-8"
    )
    (tmp_path / "supabase" / "schema.sql").write_text(
        PG_DUMP_HEAD
        + 'CREATE POLICY "own" ON "public"."profiles" FOR SELECT USING (("auth"."uid"() = "id"));\n',
        encoding="utf-8",
    )
    res = audit(tmp_path, run_scanners=False, exceptions_path=Path(os.devnull))
    got = {
        f.location.replace("\\", "/").split(":")[0]: f.superseded
        for f in res.findings
        if f.check_id == "rls-auth-uid-unwrapped"
    }
    assert got == {"supabase/schema.sql": False, "supabase/migrations/001_init.sql": True}


# --- growth class, not wall-clock (tests/_timing.py) ------------------------------------------
# One absolute backstop for the four growth workloads at n=2000, so a true hang fails loudly instead
# of running to `assert_growth`'s own ceiling. Both figures measured 2026-10-06 on the linux dev box,
# min of 5 runs at n=2000: `measured` is the slowest workload, the alternating wrapped/bare calls
# (0.074s; nested sub-SELECTs 0.044s, one shared sub-SELECT 0.037s, deep parens 0.005s);
# `regression` is the cheaper of the two quadratic paths these tests exist to catch, nested
# sub-SELECTs with the innermost-only short-circuit removed so every body is re-scanned (2.99s;
# 0.76s at n=1000). The memo removed on the shared sub-SELECT measured 3.63s. 1.5s clears the
# healthy value 20x and stays under both.
_C855_GROWTH_BUDGET = register(
    TimingBudget(
        name="rls-auth-uid-unwrapped: n=2000 sub-SELECT workload",
        seconds=1.5,
        measured=0.074,
        regression=2.99,
        why="a sub-SELECT body re-scanned per call or per enclosing level (#855), quadratic in the "
        "call or nesting count",
    )
)


def _growth_workload(
    tmp_path: Path, name: str, sizes: list[int], expr_for: Callable[[int], str]
) -> tuple[Callable[[int], None], dict[int, int]]:
    roots: dict[int, Path] = {}
    for n in sizes:
        root = tmp_path / f"{name}{n}"
        (root / "sql").mkdir(parents=True)
        (root / "sql" / "p.sql").write_text(_policy(expr_for(n)), encoding="utf-8")
        roots[n] = root
    guard = RlsAuthUidUnwrappedGuard()
    counts: dict[int, int] = {}

    def scan(n: int) -> None:
        counts[n] = len(guard.run(roots[n], _prof(roots[n])))

    return scan, counts


@pytest.mark.slow
@pytest.mark.parametrize(
    ("name", "expr_for", "expected_for"),
    [
        # n nested correlated sub-SELECTs, each with its own call: only the innermost is
        # self-contained. Re-scanning each enclosing body is the quadratic path.
        ("nested", lambda n: "(select auth.uid() = " * n + "1" + ")" * n, lambda n: n - 1),
        # n calls in ONE sub-SELECT: the memo checks its body once, not once per call.
        ("shared", lambda n: "(select coalesce(" + ", ".join(["auth.jwt()->>'a'"] * n) + ")) = id", lambda n: 0),
        # a single call at the bottom of n redundant paren layers
        ("deep", lambda n: "(" * n + "auth.uid() = id" + ")" * n, lambda n: 1),
        # n calls in one statement, alternating bare and wrapped (both in the dump spelling)
        (
            "many",
            lambda n: " OR ".join(
                '(( SELECT "auth"."uid"() AS "uid") = "id")' if i % 2 else '("auth"."uid"() = "o")'
                for i in range(n)
            ),
            lambda n: n // 2,
        ),
    ],
)
def test_sub_select_scan_cost_is_linear(
    tmp_path: Path,
    name: str,
    expr_for: Callable[[int], str],
    expected_for: Callable[[int], int],
) -> None:
    sizes = [250, 500, 1000, 2000]
    scan, counts = _growth_workload(tmp_path, name, sizes, expr_for)
    assert_growth(scan, sizes, expected="linear")
    assert counts == {n: expected_for(n) for n in sizes}, counts
    start = time.monotonic()
    scan(sizes[-1])
    assert_within(time.monotonic() - start, _C855_GROWTH_BUDGET, name)
