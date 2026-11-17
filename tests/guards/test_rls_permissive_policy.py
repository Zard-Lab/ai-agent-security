from __future__ import annotations

from agentsec.guards.rls_permissive_policy import RlsPermissivePolicyGuard
from tests.guards._common import *  # noqa: F401,F403


def test_rls_permissive_flags_using_true(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text("CREATE POLICY p ON public.t USING (true);\n", encoding="utf-8")
    findings = RlsPermissivePolicyGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rls-permissive-policy/always-true"
    assert findings[0].severity == "high"

def test_rls_permissive_flags_with_check_and_1eq1(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text("CREATE POLICY w ON public.t WITH CHECK (true);\n", encoding="utf-8")
    (sql / "b.sql").write_text("CREATE POLICY n ON public.t USING ( 1=1 );\n", encoding="utf-8")
    assert len(RlsPermissivePolicyGuard().run(tmp_path, _sqlprof(tmp_path))) == 2

def test_rls_permissive_passes_scoped_policy(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text("CREATE POLICY p ON public.t USING (user_id = auth.uid());\n", encoding="utf-8")
    assert RlsPermissivePolicyGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_permissive_pragma_opt_out(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text("CREATE POLICY p ON public.t USING (true);  -- security: allow-permissive-policy\n", encoding="utf-8")
    assert RlsPermissivePolicyGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_permissive_skips_comment(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text("-- CREATE POLICY p ON public.t USING (true);\n", encoding="utf-8")
    assert RlsPermissivePolicyGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_permissive_na_without_sql() -> None:
    assert RlsPermissivePolicyGuard().applies(mkprofile(Path("/tmp"), features={"python"})) is False

def test_rls_permissive_skips_service_role_only(tmp_path: Path) -> None:
    # service_role bypasses RLS, so a permissive policy for it is a no-op (FP-class).
    assert _rls_run(tmp_path, "CREATE POLICY p ON t FOR ALL TO service_role USING (true) WITH CHECK (true);") == []
    # multiline + quoted forms too
    assert _rls_run(tmp_path, 'CREATE POLICY p ON "public"."t"\n  TO "service_role"\n  USING (true);') == []

def test_rls_permissive_fires_on_authenticated_and_names_role(tmp_path: Path) -> None:
    findings = _rls_run(tmp_path, "CREATE POLICY p ON t FOR SELECT TO authenticated USING (true);")
    assert len(findings) == 1 and findings[0].severity == "high"
    assert "authenticated" in findings[0].message

def test_rls_permissive_flags_anon_as_internet_reachable(tmp_path: Path) -> None:
    findings = _rls_run(tmp_path, "CREATE POLICY p ON t FOR SELECT TO anon USING (true);")
    assert len(findings) == 1
    assert "anon" in findings[0].message and "unauthenticated" in findings[0].message

def test_rls_permissive_no_to_clause_is_public_and_fires(tmp_path: Path) -> None:
    findings = _rls_run(tmp_path, "CREATE POLICY p ON t USING (true);")
    assert len(findings) == 1 and "PUBLIC" in findings[0].message

def test_rls_permissive_mixed_roles_still_fires(tmp_path: Path) -> None:
    # service_role + a real role → not RLS-bypassed for the real role.
    assert len(_rls_run(tmp_path, "CREATE POLICY p ON t TO service_role, authenticated USING (true);")) == 1

def test_rls_permissive_with_check_insert_kept_high(tmp_path: Path) -> None:
    # INSERT forgery (e.g. audit_logs) is a real integrity risk — not downgraded.
    findings = _rls_run(tmp_path, "CREATE POLICY p ON audit_logs FOR INSERT TO authenticated WITH CHECK (true);")
    assert len(findings) == 1 and findings[0].severity == "high"

def test_rls_permissive_to_inside_policy_name_not_mistaken_for_role(tmp_path: Path) -> None:
    # A quoted policy name containing "to" must not be parsed as the TO clause — the real
    # target is service_role, so this must be SKIPPED (regression: flagship file_upload_tracking).
    sql = (
        'CREATE POLICY "Allow service role full access to file uploads"\n'
        "ON file_upload_tracking\n  FOR ALL\n  TO service_role\n  USING (true) WITH CHECK (true);"
    )
    assert _rls_run(tmp_path, sql) == []


# --- issue #500: comment blanking must not hide a live policy -----------------------------------
# The guard used to blank comments with a raw, string-unaware `re.sub(r"/\*.*?\*/", …, re.DOTALL)`.
# Any `/*` — in a literal, in an `E'…'` literal, or orphaned by the `--` pass eating its `*/` —
# opened a comment that ran to the next `*/` anywhere later in the file, blanking the live policies
# in between. Measured before the fix: each case below returned 0 instead of 1, with no error and no
# warning. Both directions are pinned: the poison cases must FIRE, the controls must stay SILENT.

_LIVE = "create policy p on public.docs for select to anon using (true);"


def test_rls_permissive_block_open_inside_string_literal_still_fires(tmp_path: Path) -> None:
    # Vector B: a `/*` inside an ordinary single-quoted literal is DATA, not a comment opener.
    # The trailing real comment supplies the `*/` the old regex ran to.
    sql = f"insert into notes(body) values ('see /* the docs');\n{_LIVE}\n/* an ordinary comment */\n"
    assert len(_rls_run(tmp_path, sql)) == 1


def test_rls_permissive_line_comment_inside_block_comment_still_fires(tmp_path: Path) -> None:
    # Vector C, and the reason block comments must be blanked BEFORE the `--` pass: blanking `--`
    # first eats the `*/` of `/* legacy note -- superseded */`, orphaning its opener so it runs on
    # to the next `*/`. A naive swap-in of the shared helper that KEEPS the old line-first order
    # still returns 0 here while passing every other case in this file.
    sql = f"/* legacy note -- superseded, see ticket 12 */\n{_LIVE}\n/* an ordinary comment */\n"
    assert len(_rls_run(tmp_path, sql)) == 1


def test_rls_permissive_pg_escape_string_still_fires(tmp_path: Path) -> None:
    # Vector F: Postgres `E'…'` escapes with a backslash whatever `standard_conforming_strings`
    # says, so `E'it\'s'` closes at its FINAL quote. Reading the escaped quote as the close resumed
    # code-mode lexing inside the literal, where its own `/*` became a real opener.
    sql = f"comment on table docs is E'it\\'s a note /* a fake opener';\n{_LIVE}\n/* ordinary */\n"
    assert len(_rls_run(tmp_path, sql)) == 1


def test_rls_permissive_commented_out_policy_stays_silent(tmp_path: Path) -> None:
    # FP-bait for the widening above: the fix makes previously-hidden findings fire, so the
    # direction traded against is a policy that is GENUINELY commented out. It must stay silent.
    assert _rls_run(tmp_path, f"/*\n{_LIVE}\n*/\n") == []


def test_rls_permissive_backslash_in_plain_string_still_fires(tmp_path: Path) -> None:
    # FP-bait for the `E'…'` narrowing: a backslash in an ORDINARY literal is not an escape
    # (standard_conforming_strings), so `'C:\'` closes at its own quote. Honoring the backslash
    # here would eat the closing quote and swallow the policy below — the #441 false positive.
    assert len(_rls_run(tmp_path, f"update t set p = 'C:\\';\n{_LIVE}\n")) == 1


def test_rls_permissive_pragma_survives_a_poisoned_file(tmp_path: Path) -> None:
    # Rule 4: a suppression must not be able to void a user's own opt-out, and the reverse — the
    # blanking change must not resurrect a finding the user pragma'd. The pragma is matched against
    # the RAW lines, never the blanked text, so it is unaffected either way.
    sql = (
        "insert into notes(body) values ('see /* the docs');\n"
        "-- security: allow-permissive-policy\n"
        f"{_LIVE}\n/* an ordinary comment */\n"
    )
    assert _rls_run(tmp_path, sql) == []


def test_rls_permissive_line_numbers_survive_a_poisoned_file(tmp_path: Path) -> None:
    # Blanking (not deleting) is what keeps reported line numbers valid; the shared helper is
    # length- and newline-preserving, so the policy must still be reported on its own line.
    sql = f"insert into notes(body) values ('see /* the docs');\n{_LIVE}\n/* ordinary */\n"
    findings = _rls_run(tmp_path, sql)
    assert len(findings) == 1 and findings[0].location.endswith(":2")


def test_rls_permissive_hostile_headless_sql_is_linear(tmp_path: Path) -> None:
    # Regression (issue #419): the `create\s+policy\b.*?;` finditer re-scanned to EOF from every
    # head when no `;` exists — O(n²) on hostile SQL. `iter_statement_spans` bails after one
    # linear pass. Actual ~0.01s; the quadratic form at this size takes minutes.
    import time

    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "hostile.sql").write_text("create policy " * 30_000, encoding="utf-8")  # no `;` anywhere
    start = time.monotonic()
    findings = RlsPermissivePolicyGuard().run(tmp_path, _sqlprof(tmp_path))
    assert time.monotonic() - start < 5.0, "quadratic statement scan reintroduced"
    assert findings == []


def test_rls_permissive_dollar_quoted_prose_does_not_hide_a_real_policy(tmp_path: Path) -> None:
    # Issue #602's SQL half: dollar-quoted prose is not a string context to the comment blanker,
    # so the `/*` of `docs/*.md` paired with the trailing audit comment and blanked the live
    # permissive policy between them — measured 1 finding to 0 before the fix.
    findings = _rls_run(
        tmp_path,
        "INSERT INTO help(topic, body) VALUES ('files', $$See docs/*.md for details$$);\n"
        "CREATE POLICY p ON accounts FOR SELECT USING (true);\n"
        "/* reviewed 2026-08 */\n",
    )
    assert len(findings) == 1 and findings[0].severity == "high"


def test_rls_permissive_commented_out_policy_next_to_dollar_quote_stays_silent(tmp_path: Path) -> None:
    # FP-bait for the #602 widening: an UNCLOSED `$tag$` is data, never a licence to skip the
    # tail — the genuine block comment below it still blanks its commented-out policy.
    assert _rls_run(
        tmp_path,
        "SELECT $body$ unclosed\n/* CREATE POLICY old ON t USING (true); */\n",
    ) == []

# --- always-false (pgrls SEC010) --------------------------------------------

def test_rls_permissive_flags_using_false(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text("CREATE POLICY p ON public.t USING (false);\n", encoding="utf-8")
    findings = RlsPermissivePolicyGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rls-permissive-policy/always-false"
    assert findings[0].severity == "medium"

def test_rls_permissive_flags_with_check_false(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.t FOR INSERT WITH CHECK (1 = 0);\n", encoding="utf-8"
    )
    findings = RlsPermissivePolicyGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rls-permissive-policy/always-false"

def test_rls_permissive_always_false_pragma_silences(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.t USING (false);  -- security: allow-policy-always-false\n", encoding="utf-8"
    )
    assert RlsPermissivePolicyGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_permissive_scoped_policy_not_flagged_as_always_false(tmp_path: Path) -> None:
    # FP-bait: a real predicate must never be mistaken for the literal false.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.t USING (deleted_at IS NOT NULL);\n", encoding="utf-8"
    )
    assert RlsPermissivePolicyGuard().run(tmp_path, _sqlprof(tmp_path)) == []


# --- write-check-open (pgrls SEC020) ----------------------------------------

def test_rls_permissive_flags_write_check_open(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.documents FOR ALL TO app "
        "USING (tenant_id = current_setting('app.tenant_id')::int) "
        "WITH CHECK (true);\n", encoding="utf-8"
    )
    findings = RlsPermissivePolicyGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rls-permissive-policy/write-check-open"
    assert findings[0].severity == "medium"

def test_rls_permissive_write_check_open_pragma_silences(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.documents FOR ALL TO app "
        "USING (tenant_id = current_setting('app.tenant_id')::int) "
        "WITH CHECK (true);  -- security: allow-write-check-open\n", encoding="utf-8"
    )
    assert RlsPermissivePolicyGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_permissive_scoped_both_clauses_not_flagged_as_write_check_open(tmp_path: Path) -> None:
    # FP-bait: WITH CHECK mirroring USING (the recommended fix) must stay silent.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.documents FOR ALL TO app "
        "USING (tenant_id = current_setting('app.tenant_id')::int) "
        "WITH CHECK (tenant_id = current_setting('app.tenant_id')::int);\n", encoding="utf-8"
    )
    assert RlsPermissivePolicyGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_permissive_using_true_not_double_flagged_as_write_check_open(tmp_path: Path) -> None:
    # A fully-open USING(true) + WITH CHECK(true) is the existing always-true finding,
    # not also a write-check-open finding (using_polarity == "true" excludes it).
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.t USING (true) WITH CHECK (true);\n", encoding="utf-8"
    )
    findings = RlsPermissivePolicyGuard().run(tmp_path, _sqlprof(tmp_path))
    rules = {f.rule for f in findings}
    assert rules == {"rls-permissive-policy/always-true"}


# --- restrictive-always-true (pgrls SEC031) ---------------------------------

def test_rls_permissive_flags_restrictive_always_true(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.t AS RESTRICTIVE USING (true);\n", encoding="utf-8"
    )
    findings = RlsPermissivePolicyGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rls-permissive-policy/restrictive-always-true"
    assert findings[0].severity == "medium"

def test_rls_permissive_quoted_name_as_restrictive_still_fires_high(tmp_path: Path) -> None:
    # Widening (PR #893 re-review MEDIUM #C): a quoted policy NAME containing "as restrictive"
    # must NOT be read as an `AS RESTRICTIVE` clause and silently downgrade the gating
    # always-true HIGH to a non-gating restrictive MEDIUM. `blank_policy_names` space-fills
    # the name first. The genuine `AS RESTRICTIVE` case above pins the other direction.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        'CREATE POLICY "mark as restrictive" ON public.t USING (true);\n',
        encoding="utf-8",
    )
    findings = RlsPermissivePolicyGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rls-permissive-policy/always-true"
    assert findings[0].severity == "high"

def test_rls_permissive_restrictive_true_pragma_silences(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.t AS RESTRICTIVE USING (true);  -- security: allow-restrictive-always-true\n", encoding="utf-8"
    )
    assert RlsPermissivePolicyGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_permissive_restrictive_scoped_not_flagged(tmp_path: Path) -> None:
    # FP-bait: a genuinely scoped RESTRICTIVE policy must stay silent.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.t AS RESTRICTIVE USING (tenant_id = current_setting('app.tenant_id')::int);\n", encoding="utf-8"
    )
    assert RlsPermissivePolicyGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_permissive_permissive_true_not_flagged_as_restrictive(tmp_path: Path) -> None:
    # FP-bait: an ordinary PERMISSIVE always-true policy (no AS RESTRICTIVE) must not
    # also trigger the RESTRICTIVE-specific finding.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text("CREATE POLICY p ON public.t USING (true);\n", encoding="utf-8")
    findings = RlsPermissivePolicyGuard().run(tmp_path, _sqlprof(tmp_path))
    rules = {f.rule for f in findings}
    assert rules == {"rls-permissive-policy/always-true"}

# --- buried "OR true" disjunct (pgrls SEC011) ------------------------------------

def test_rls_permissive_flags_buried_or_true(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text("CREATE POLICY p ON public.t USING (owner_id = 1 OR true);\n", encoding="utf-8")
    findings = RlsPermissivePolicyGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rls-permissive-policy/always-true"
    assert findings[0].severity == "high"

def test_rls_permissive_flags_buried_or_true_leading(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text("CREATE POLICY p ON public.t USING (true OR owner_id = 1);\n", encoding="utf-8")
    findings = RlsPermissivePolicyGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rls-permissive-policy/always-true"

def test_rls_permissive_buried_or_true_pragma_silences(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.t USING (owner_id = 1 OR true);"
        "  -- security: allow-permissive-policy\n", encoding="utf-8"
    )
    assert RlsPermissivePolicyGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_permissive_buried_or_true_restrictive_not_always_true(tmp_path: Path) -> None:
    # FP-bait: an AS RESTRICTIVE policy's buried OR-true must route to the
    # restrictive-always-true finding, not always-true -- same exclusion the literal
    # `USING (true)` case already gets.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.t AS RESTRICTIVE USING (owner_id = 1 OR true);\n", encoding="utf-8"
    )
    findings = RlsPermissivePolicyGuard().run(tmp_path, _sqlprof(tmp_path))
    rules = {f.rule for f in findings}
    assert rules == {"rls-permissive-policy/restrictive-always-true"}

def test_rls_permissive_passes_or_false(tmp_path: Path) -> None:
    # FP-bait: a buried OR-false is a no-op (OR with false doesn't change anything), not
    # the "OR true" always-open shape -- must stay silent.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text("CREATE POLICY p ON public.t USING (owner_id = auth.uid() OR false);\n", encoding="utf-8")
    assert RlsPermissivePolicyGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_permissive_passes_idiomatic_public_or_owner(tmp_path: Path) -> None:
    # H1 (Dean's review, PR #893 review): `is_public = true OR owner_id = auth.uid()` is a
    # correctly-scoped, idiomatic public-or-owner policy -- `true` here is the RHS of a
    # comparison, not a bare OR-disjunct. Verified failing before the fix (fired HIGH).
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.t USING (is_public = true OR owner_id = auth.uid());\n", encoding="utf-8"
    )
    assert RlsPermissivePolicyGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_permissive_passes_idiomatic_admin_or_owner(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.t USING (is_admin = true OR user_id = auth.uid());\n", encoding="utf-8"
    )
    assert RlsPermissivePolicyGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_permissive_passes_comparison_true_not_bare_operand(tmp_path: Path) -> None:
    # The reverse order also stays silent: `x = 1 OR is_active = true` -- neither side is a
    # bare `true` operand.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.t USING (owner_id = 1 OR is_active = true);\n", encoding="utf-8"
    )
    assert RlsPermissivePolicyGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_permissive_flags_buried_or_true_still_fires_after_h1_fix(tmp_path: Path) -> None:
    # Direction traded against (CLAUDE.md rule 1): the H1 tightening must not silence the
    # genuine bare-operand cases the buried-OR-true detection was built for.
    sql = tmp_path / "sql"
    sql.mkdir()
    stmts = (
        "CREATE POLICY p1 ON public.t1 USING (owner_id = 1 OR true);",
        "CREATE POLICY p2 ON public.t2 USING (true OR owner_id = 1);",
        "CREATE POLICY p3 ON public.t3 USING ((true) OR x = 1);",
        "CREATE POLICY p4 ON public.t4 USING (a = 1 OR TRUE OR b = 2);",
    )
    for i, stmt in enumerate(stmts):
        (sql / f"p{i}.sql").write_text(stmt + "\n", encoding="utf-8")
    findings = RlsPermissivePolicyGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 4

def test_rls_permissive_passes_scoped_and_true_word_in_identifier(tmp_path: Path) -> None:
    # FP-bait: "true" as a SUBSTRING of a longer identifier (e.g. a column named
    # is_true_positive) must not match the bare-word `true` disjunct check.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.t USING (owner_id = auth.uid() OR is_true_positive = false);\n", encoding="utf-8"
    )
    assert RlsPermissivePolicyGuard().run(tmp_path, _sqlprof(tmp_path)) == []
