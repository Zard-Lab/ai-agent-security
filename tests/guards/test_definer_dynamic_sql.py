from __future__ import annotations

from agentsec.guards.definer_dynamic_sql import DefinerDynamicSqlGuard
from tests.guards._common import *  # noqa: F401,F403


def test_definer_dynamic_flags_execute_of_argument(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE FUNCTION public.execute_custom_sql(query text)\n"
        "RETURNS SETOF record LANGUAGE plpgsql SECURITY DEFINER AS $$\n"
        "BEGIN RETURN QUERY EXECUTE query; END $$;\n",
        encoding="utf-8",
    )
    findings = DefinerDynamicSqlGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "definer-dynamic-sql/dynamic-execute"
    assert findings[0].severity == "critical"
    assert "execute_custom_sql" in findings[0].message


def test_definer_dynamic_fires_even_when_grants_and_search_path_hardened(tmp_path: Path) -> None:
    # The whole point: this guard is INDEPENDENT of the axes definer-function-grants and
    # pg-function-search-path cover. Even with EXECUTE revoked from anon/authenticated AND
    # search_path pinned, an argument-derived EXECUTE is still an arbitrary-SQL RLS bypass.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE FUNCTION public.execute_custom_sql(query text)\n"
        "RETURNS SETOF record LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$\n"
        "BEGIN RETURN QUERY EXECUTE query; END $$;\n",
        encoding="utf-8",
    )
    (sql / "111.sql").write_text(
        "REVOKE EXECUTE ON FUNCTION public.execute_custom_sql(text) FROM PUBLIC, anon, authenticated;\n"
        "GRANT EXECUTE ON FUNCTION public.execute_custom_sql(text) TO service_role;\n",
        encoding="utf-8",
    )
    findings = DefinerDynamicSqlGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1 and findings[0].severity == "critical"


def test_definer_dynamic_execute_format(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE FUNCTION public.run_it(tbl text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$\n"
        "BEGIN EXECUTE format('DELETE FROM %I', tbl); END $$;\n",
        encoding="utf-8",
    )
    assert len(DefinerDynamicSqlGuard().run(tmp_path, _sqlprof(tmp_path))) == 1


def test_definer_static_execute_literal_silent(tmp_path: Path) -> None:
    # A purely static `EXECUTE 'literal'` is not dynamic — no argument-derived SQL.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE FUNCTION public.refresh_mv() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$\n"
        "BEGIN EXECUTE 'REFRESH MATERIALIZED VIEW public.mv'; END $$;\n",
        encoding="utf-8",
    )
    assert DefinerDynamicSqlGuard().run(tmp_path, _sqlprof(tmp_path)) == []


def test_definer_dynamic_execute_parenthesized_query(tmp_path: Path) -> None:
    # Regression (#322 review): `EXECUTE (query)` is valid PL/pgSQL and behaves identically
    # to the bare `EXECUTE query` form — it must fire too, not just the unparenthesized one.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE FUNCTION public.execute_custom_sql(query text)\n"
        "RETURNS SETOF record LANGUAGE plpgsql SECURITY DEFINER AS $$\n"
        "BEGIN RETURN QUERY EXECUTE (query); END $$;\n",
        encoding="utf-8",
    )
    findings = DefinerDynamicSqlGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1 and findings[0].severity == "critical"


def test_definer_dynamic_execute_parenthesized_static_literal_silent(tmp_path: Path) -> None:
    # The parenthesized form of a purely static literal, `EXECUTE ('literal')`, is just as
    # static as the bare `EXECUTE 'literal'` — must stay silent, not a paren-triggered FP.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE FUNCTION public.refresh_mv() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$\n"
        "BEGIN EXECUTE ('REFRESH MATERIALIZED VIEW public.mv'); END $$;\n",
        encoding="utf-8",
    )
    assert DefinerDynamicSqlGuard().run(tmp_path, _sqlprof(tmp_path)) == []


def test_definer_dynamic_execute_parenthesized_query_no_space(tmp_path: Path) -> None:
    # Regression (#322 round-7 review): `EXECUTE(query)` — no space before the paren — is
    # equally valid PL/pgSQL (`(` is self-delimiting) and must fire, same as `EXECUTE (query)`.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE FUNCTION public.execute_custom_sql(query text)\n"
        "RETURNS SETOF record LANGUAGE plpgsql SECURITY DEFINER AS $$\n"
        "BEGIN RETURN QUERY EXECUTE(query); END $$;\n",
        encoding="utf-8",
    )
    findings = DefinerDynamicSqlGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1 and findings[0].severity == "critical"


def test_definer_dynamic_execute_parenthesized_static_literal_no_space_silent(tmp_path: Path) -> None:
    # The no-space static-literal form, `EXECUTE('literal')`, is just as static as the spaced
    # and bare forms — must stay silent.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE FUNCTION public.refresh_mv() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$\n"
        "BEGIN EXECUTE('REFRESH MATERIALIZED VIEW public.mv'); END $$;\n",
        encoding="utf-8",
    )
    assert DefinerDynamicSqlGuard().run(tmp_path, _sqlprof(tmp_path)) == []


def test_definer_dynamic_execute_parenthesized_literal_concat_fires(tmp_path: Path) -> None:
    # Regression (#322 round-7 review, Low coverage gap): a static literal concatenated with
    # a variable INSIDE parens, `EXECUTE ('literal' || var)`, is genuinely dynamic and must
    # fire — the static-literal exclusion only applies when the parens contain *just* the
    # literal, not a literal plus concatenation.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE FUNCTION public.run_it(tbl text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$\n"
        "BEGIN EXECUTE ('DELETE FROM ' || tbl); END $$;\n",
        encoding="utf-8",
    )
    findings = DefinerDynamicSqlGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1 and findings[0].severity == "critical"


def test_definer_dynamic_invoker_function_silent(tmp_path: Path) -> None:
    # SECURITY INVOKER (default): RLS applies to the caller, so a dynamic EXECUTE is the
    # caller's own privilege — not a definer bypass primitive.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE FUNCTION public.run_q(q text) RETURNS void LANGUAGE plpgsql AS $$\n"
        "BEGIN EXECUTE q; END $$;\n",
        encoding="utf-8",
    )
    assert DefinerDynamicSqlGuard().run(tmp_path, _sqlprof(tmp_path)) == []


def test_definer_dynamic_no_execute_silent(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE FUNCTION public.is_admin(uid uuid)\n"
        "RETURNS boolean LANGUAGE sql SECURITY DEFINER AS $$ SELECT true $$;\n",
        encoding="utf-8",
    )
    assert DefinerDynamicSqlGuard().run(tmp_path, _sqlprof(tmp_path)) == []


def test_definer_dynamic_trailing_do_block_not_misattributed(tmp_path: Path) -> None:
    # Regression (#322 review, High): a dynamic EXECUTE in a standalone DO block that
    # FOLLOWS a SECURITY DEFINER function (with no intervening CREATE FUNCTION) must NOT
    # be attributed to that innocent function. Body-scoped detection isolates each fn.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE FUNCTION public.safe_helper() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$\n"
        "BEGIN PERFORM 1; END $$;\n"
        "-- later maintenance, unrelated to the function above\n"
        "DO $$ BEGIN EXECUTE format('REINDEX TABLE %I', 'users'); END $$;\n",
        encoding="utf-8",
    )
    assert DefinerDynamicSqlGuard().run(tmp_path, _sqlprof(tmp_path)) == []


def test_definer_dynamic_execute_word_in_string_literal_silent(tmp_path: Path) -> None:
    # Regression (#322 review, Medium): the word `execute` inside a string literal (a
    # RAISE message, a logged value) must NOT be read as a dynamic EXECUTE statement.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE FUNCTION public.guarded() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$\n"
        "BEGIN\n"
        "  IF NOT is_admin() THEN RAISE EXCEPTION 'not allowed to execute this action'; END IF;\n"
        "  INSERT INTO audit(msg) VALUES ('user tried to execute something');\n"
        "  UPDATE t SET x = 1;\n"
        "END $$;\n",
        encoding="utf-8",
    )
    assert DefinerDynamicSqlGuard().run(tmp_path, _sqlprof(tmp_path)) == []


def test_definer_dynamic_second_function_dynamic_not_attributed_to_first(tmp_path: Path) -> None:
    # A definer fn (no dynamic EXECUTE) followed by a NON-definer fn that does EXECUTE a
    # variable: neither should fire (the definer body is clean; the dynamic one is INVOKER).
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE FUNCTION public.a() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$\n"
        "BEGIN PERFORM 1; END $$;\n"
        "CREATE FUNCTION public.b(q text) RETURNS void LANGUAGE plpgsql AS $$\n"
        "BEGIN EXECUTE q; END $$;\n",
        encoding="utf-8",
    )
    assert DefinerDynamicSqlGuard().run(tmp_path, _sqlprof(tmp_path)) == []


def test_definer_dynamic_security_definer_after_body(tmp_path: Path) -> None:
    # SECURITY DEFINER can sit AFTER the AS $$…$$ body — still detected.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE FUNCTION public.run_it(q text) RETURNS void LANGUAGE plpgsql AS $$\n"
        "BEGIN EXECUTE q; END $$ SECURITY DEFINER;\n",
        encoding="utf-8",
    )
    assert len(DefinerDynamicSqlGuard().run(tmp_path, _sqlprof(tmp_path))) == 1


def test_definer_dynamic_single_quoted_body_definer_not_misattributed(tmp_path: Path) -> None:
    # Regression (#322 round-2, Major FP): a SECURITY DEFINER function with a single-quoted
    # body (AS 'BEGIN … END', valid Postgres) has no $$; it must NOT adopt a *following*
    # function's dollar-quoted dynamic EXECUTE and get flagged. Region-bound + blank-first.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE FUNCTION public.innocent() RETURNS void LANGUAGE plpgsql SECURITY DEFINER "
        "AS 'BEGIN PERFORM 1; END';\n"
        "CREATE FUNCTION public.dyn(q text) RETURNS void LANGUAGE plpgsql AS $$\n"
        "BEGIN EXECUTE q; END $$;\n",
        encoding="utf-8",
    )
    # `dyn` is SECURITY INVOKER, `innocent` has no dynamic EXECUTE -> nothing fires.
    assert DefinerDynamicSqlGuard().run(tmp_path, _sqlprof(tmp_path)) == []


def test_definer_dynamic_dollar_tag_in_header_literal_still_fires(tmp_path: Path) -> None:
    # Regression (#322 round-2, FN): a `$tag$` inside a header string literal (a param
    # default) must not be mistaken for the body delimiter — the real $$ body is still
    # scanned and the dynamic EXECUTE fires.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE FUNCTION public.f(sep text DEFAULT '$tag$', q text DEFAULT '') "
        "RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$\n"
        "BEGIN EXECUTE q; END $$;\n",
        encoding="utf-8",
    )
    assert len(DefinerDynamicSqlGuard().run(tmp_path, _sqlprof(tmp_path))) == 1


def test_definer_dynamic_create_function_in_literal_still_fires(tmp_path: Path) -> None:
    # Regression (#322 round-3, Major FN): a `CREATE FUNCTION …` substring inside a string
    # literal (dynamic DDL, or a RAISE message quoting SQL) must NOT truncate the enclosing
    # function's region. The real dynamic `EXECUTE u` after it must still fire.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE FUNCTION public.mk(u text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$\n"
        "BEGIN\n"
        "  EXECUTE 'CREATE FUNCTION helper() RETURNS int LANGUAGE sql AS $x$ SELECT 1 $x$';\n"
        "  EXECUTE u;\n"
        "END $$;\n",
        encoding="utf-8",
    )
    findings = DefinerDynamicSqlGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1 and findings[0].severity == "critical"
    assert "mk" in findings[0].message


def test_definer_dynamic_bare_apostrophe_in_dollar_body_does_not_drop_later_fn(tmp_path: Path) -> None:
    # Regression (#322 round-4, Critical): a bare apostrophe in a dollar-quoted body (valid
    # Postgres via a distinct nested tag, or a balanced escaped '' string) must not corrupt
    # the scan of a LATER SECURITY DEFINER function. The stateful mask keeps them isolated.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        # `$m$don't worry$m$` — a bare apostrophe inside a dollar string with a DISTINCT tag
        "CREATE FUNCTION public.log_event() RETURNS void LANGUAGE plpgsql AS $t$\n"
        "BEGIN RAISE NOTICE $m$don't worry$m$; END $t$;\n"
        # ...followed by the flagship pattern, which must still be detected.
        "CREATE FUNCTION public.execute_custom_sql(query text) RETURNS SETOF record\n"
        "LANGUAGE plpgsql SECURITY DEFINER AS $$\n"
        "BEGIN RAISE NOTICE 'starting query'; RETURN QUERY EXECUTE query; END $$;\n",
        encoding="utf-8",
    )
    findings = DefinerDynamicSqlGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1 and "execute_custom_sql" in findings[0].message


def test_definer_dynamic_escaped_quote_body_does_not_drop_later_fn(tmp_path: Path) -> None:
    # Same protection via a balanced escaped-quote string (`'don''t'`) in the first fn's body.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE FUNCTION public.log_event() RETURNS void LANGUAGE plpgsql AS $$\n"
        "BEGIN RAISE NOTICE 'don''t worry'; END $$;\n"
        "CREATE FUNCTION public.execute_custom_sql(query text) RETURNS SETOF record\n"
        "LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN RETURN QUERY EXECUTE query; END $$;\n",
        encoding="utf-8",
    )
    findings = DefinerDynamicSqlGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1 and "execute_custom_sql" in findings[0].message


def test_definer_dynamic_dollar_quoted_param_default_fires_body_not_default(tmp_path: Path) -> None:
    # Regression (#322 round-5, Major FN): a dollar-quoted PARAMETER DEFAULT (valid Postgres)
    # must not be mistaken for the body. The real `AS $$ … EXECUTE q … $$` body still fires.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE FUNCTION public.f(x text DEFAULT $tag$hello$tag$, q text)\n"
        "RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN EXECUTE q; END $$;\n",
        encoding="utf-8",
    )
    findings = DefinerDynamicSqlGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1 and findings[0].message.split("`")[1].rstrip("()") == "f"


def test_definer_dynamic_dollar_quoted_default_with_execute_word_silent(tmp_path: Path) -> None:
    # Regression (#322 round-5, Major FP): a dollar-quoted default whose TEXT contains
    # "execute …" must not be read as the body — the real body is a static PERFORM.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE FUNCTION public.g(note text DEFAULT $d$please execute the migration$d$)\n"
        "RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN PERFORM 1; END $$;\n",
        encoding="utf-8",
    )
    assert DefinerDynamicSqlGuard().run(tmp_path, _sqlprof(tmp_path)) == []


def test_definer_dynamic_revoke_loop_not_flagged(tmp_path: Path) -> None:
    # A top-level DO-block that EXECUTE format(...)s a REVOKE is NOT a CREATE FUNCTION
    # body, so it must not be treated as a definer-dynamic-SQL function.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "DO $$ BEGIN\n"
        "  EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', 'foo()');\n"
        "END $$;\n",
        encoding="utf-8",
    )
    assert DefinerDynamicSqlGuard().run(tmp_path, _sqlprof(tmp_path)) == []


def test_definer_dynamic_pragma_opt_out(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "-- security: allow-definer-dynamic-sql\n"
        "CREATE FUNCTION public.audited(q text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$\n"
        "BEGIN EXECUTE q; END $$;\n",
        encoding="utf-8",
    )
    assert DefinerDynamicSqlGuard().run(tmp_path, _sqlprof(tmp_path)) == []


def test_definer_dynamic_not_applicable_without_sql() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert DefinerDynamicSqlGuard().applies(prof) is False


def test_definer_dynamic_pragma_quoted_on_the_line_above_does_not_opt_out(tmp_path: Path) -> None:
    # #424 E3: the line-or-line-above check reads the comment-only view (`pragma_line_set`), so the
    # phrase inside a string literal on the line above the CREATE is content, not a pragma.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "INSERT INTO docs VALUES ('opt out with -- security: allow-definer-dynamic-sql');\n"
        "CREATE FUNCTION public.audited(q text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$\n"
        "BEGIN EXECUTE q; END $$;\n",
        encoding="utf-8",
    )
    assert len(DefinerDynamicSqlGuard().run(tmp_path, _sqlprof(tmp_path))) == 1
