from __future__ import annotations

from agentsec.guards.pg_function_immutable_reads_session import PgFunctionImmutableReadsSessionGuard
from tests.guards._common import *  # noqa: F401,F403


def test_pg_function_immutable_reads_session_fires(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FUNCTION app.cur_tenant() RETURNS text "
        "LANGUAGE sql IMMUTABLE AS $$ SELECT current_setting('app.tenant', true) $$;\n", encoding="utf-8"
    )
    findings = PgFunctionImmutableReadsSessionGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "pg-function-immutable-reads-session/should-be-stable"
    assert findings[0].severity == "high"

def test_pg_function_immutable_reads_session_fires_on_multi_statement_plpgsql_body(
    tmp_path: Path,
) -> None:
    # C1 (Dean's review, PR #893 review): a real PL/pgSQL body with a `;` INSIDE the $$ ... $$
    # dollar-quoted body used to end the "statement" early (find_statement_end has no notion of
    # dollar quoting), so the RETURN line carrying the session read was never scanned at all.
    # This is Dean's exact verified-failing repro input.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FUNCTION app.cur_tenant() RETURNS text LANGUAGE plpgsql IMMUTABLE AS $$\n"
        "DECLARE v text;\n"
        "BEGIN v := 'x'; RETURN current_setting('app.tenant', true); END; $$;\n", encoding="utf-8"
    )
    findings = PgFunctionImmutableReadsSessionGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "pg-function-immutable-reads-session/should-be-stable"


def test_pg_function_immutable_reads_session_multiple_functions_in_one_file(
    tmp_path: Path,
) -> None:
    # The dollar-tag search must be bounded to THIS function's own region — a later, unrelated
    # function's dollar body must never be misattributed to an earlier one with no body at all.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FUNCTION app.safe_fn() RETURNS int LANGUAGE sql STABLE AS $$ SELECT 1 $$;\n"
        "CREATE FUNCTION app.cur_tenant() RETURNS text LANGUAGE plpgsql IMMUTABLE AS $$\n"
        "DECLARE v text;\n"
        "BEGIN v := 'x'; RETURN current_setting('app.tenant', true); END; $$;\n", encoding="utf-8"
    )
    findings = PgFunctionImmutableReadsSessionGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert "cur_tenant" in findings[0].message


def test_pg_function_immutable_reads_session_fires_on_auth_call(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FUNCTION app.cur_user() RETURNS uuid "
        "LANGUAGE sql IMMUTABLE AS $$ SELECT auth.uid() $$;\n", encoding="utf-8"
    )
    assert len(PgFunctionImmutableReadsSessionGuard().run(tmp_path, _sqlprof(tmp_path))) == 1

def test_pg_function_immutable_reads_session_passes_stable(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FUNCTION app.cur_tenant() RETURNS text "
        "LANGUAGE sql STABLE AS $$ SELECT current_setting('app.tenant', true) $$;\n", encoding="utf-8"
    )
    assert PgFunctionImmutableReadsSessionGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_pg_function_immutable_reads_session_passes_immutable_no_session_read(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FUNCTION app.double_it(x int) RETURNS int "
        "LANGUAGE sql IMMUTABLE AS $$ SELECT x * 2 $$;\n", encoding="utf-8"
    )
    assert PgFunctionImmutableReadsSessionGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_pg_function_immutable_reads_session_passes_not_immutable(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FUNCTION app.cur_tenant() RETURNS text "
        "LANGUAGE sql NOT IMMUTABLE AS $$ SELECT current_setting('app.tenant', true) $$;\n", encoding="utf-8"
    )
    assert PgFunctionImmutableReadsSessionGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_pg_function_immutable_reads_session_pragma_opt_out(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FUNCTION app.cur_tenant() RETURNS text "
        "LANGUAGE sql IMMUTABLE AS $$ SELECT current_setting('app.tenant', true) $$;"
        "  -- security: allow-function-immutable-reads-session\n", encoding="utf-8"
    )
    assert PgFunctionImmutableReadsSessionGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_pg_function_immutable_reads_session_ignores_session_read_shape_inside_a_literal(
    tmp_path: Path,
) -> None:
    # M1: a genuinely IMMUTABLE function with no real session read must not fire just
    # because a session-read-shaped string sits inside a plain string literal in its body.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FUNCTION app.double_it(x int) RETURNS int LANGUAGE sql IMMUTABLE AS $$ "
        "SELECT x * 2 FROM (SELECT 'do not call current_setting(app.tenant) here' AS note) t "
        "$$;\n", encoding="utf-8"
    )
    assert PgFunctionImmutableReadsSessionGuard().run(tmp_path, _sqlprof(tmp_path)) == []


def test_pg_function_immutable_reads_session_ignores_immutable_word_inside_a_literal(
    tmp_path: Path,
) -> None:
    # A correctly-STABLE function whose body happens to mention the word "immutable" inside a
    # string literal must not be misread as carrying the IMMUTABLE keyword.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FUNCTION app.cur_tenant() RETURNS text LANGUAGE sql STABLE AS $$ "
        "SELECT current_setting('app.tenant', true) "
        "WHERE 'this function used to be immutable, now fixed' IS NOT NULL "
        "$$;\n", encoding="utf-8"
    )
    assert PgFunctionImmutableReadsSessionGuard().run(tmp_path, _sqlprof(tmp_path)) == []


def test_pg_function_immutable_reads_session_fires_on_single_quoted_body(tmp_path: Path) -> None:
    # (Dean's re-review of the M1 fix): a `LANGUAGE sql AS '...'` body has no
    # `$$…$$` wrapper for `dollar_quotes=False` to skip — the body IS a plain `'...'` literal, so
    # the M1 literal-masking fix blanked the whole thing (a silent miss, no test covered this
    # shape before). Postgres's own doubled-`''` escape for the nested `'app.tenant'` argument.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FUNCTION app.cur_tenant() RETURNS text "
        "LANGUAGE sql IMMUTABLE AS 'SELECT current_setting(''app.tenant'', true)';\n", encoding="utf-8"
    )
    findings = PgFunctionImmutableReadsSessionGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "pg-function-immutable-reads-session/should-be-stable"


def test_pg_function_immutable_reads_session_fires_on_auth_call_single_quoted_body(
    tmp_path: Path,
) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FUNCTION app.cur_user() RETURNS uuid LANGUAGE sql IMMUTABLE AS 'SELECT auth.uid()';\n", encoding="utf-8"
    )
    assert len(PgFunctionImmutableReadsSessionGuard().run(tmp_path, _sqlprof(tmp_path))) == 1


def test_pg_function_immutable_reads_session_passes_stable_single_quoted_body(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FUNCTION app.cur_tenant() RETURNS text "
        "LANGUAGE sql STABLE AS 'SELECT current_setting(''app.tenant'', true)';\n", encoding="utf-8"
    )
    assert PgFunctionImmutableReadsSessionGuard().run(tmp_path, _sqlprof(tmp_path)) == []


def test_pg_function_immutable_reads_session_passes_not_immutable_single_quoted_body(
    tmp_path: Path,
) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FUNCTION app.cur_tenant() RETURNS text "
        "LANGUAGE sql NOT IMMUTABLE AS 'SELECT current_setting(''app.tenant'', true)';\n", encoding="utf-8"
    )
    assert PgFunctionImmutableReadsSessionGuard().run(tmp_path, _sqlprof(tmp_path)) == []


def test_pg_function_immutable_reads_session_ignores_default_literal_before_single_quoted_body(
    tmp_path: Path,
) -> None:
    # Rule 1, the direction traded against: restoring the single-quoted body's own text must not
    # reopen M1 for literal content BEFORE that body (a parameter DEFAULT), which the M1 fix's
    # masking still covers — this function is genuinely STABLE, and the word "immutable" only
    # appears inside the default's literal text.
    #
    # #956 round-2 re-review, M2: the body MUST carry a real session read and the literal must NOT
    # say "not immutable". The first version (`'not immutable, …'` + `AS 'SELECT 1'`) passed on
    # every tree, including the rejected skip-masking-without-`$$` patch, because the guard
    # returned at the session-read gate and `_NOT_IMMUTABLE` stripped the literal anyway. This
    # one fires on `main` and under that patch, and stays silent only with the masking in place.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FUNCTION app.f(mode text DEFAULT 'immutable') RETURNS text "
        "LANGUAGE sql STABLE AS 'SELECT current_setting(''app.tenant'', true)';\n",
        encoding="utf-8",
    )
    assert PgFunctionImmutableReadsSessionGuard().run(tmp_path, _sqlprof(tmp_path)) == []


def test_pg_function_immutable_reads_session_fires_when_an_earlier_literal_ends_in_as(
    tmp_path: Path,
) -> None:
    # #956 round-2 re-review, M1 (still-fires): a literal BEFORE a single-quoted body whose own
    # text ends in the word `as` — a parameter DEFAULT or a `SET` config value — used to win the
    # `AS '` anchor search on the raw statement, so the "body" restored was the stretch between
    # that literal and the real body's opening quote, and the real body stayed blanked (0
    # findings, where `main` fired). The anchor is now searched on the masked view.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FUNCTION app.f(label text DEFAULT 'known as') RETURNS text "
        "LANGUAGE sql IMMUTABLE AS 'SELECT current_setting(''app.tenant'', true)';\n"
        "CREATE FUNCTION app.g() RETURNS text LANGUAGE sql IMMUTABLE SET app.note = 'such as' "
        "AS 'SELECT current_setting(''app.tenant'', true)';\n",
        encoding="utf-8",
    )
    findings = PgFunctionImmutableReadsSessionGuard().run(tmp_path, _sqlprof(tmp_path))
    # `endswith`, not the full string: `rel()` gives `sql\a.sql:1` on Windows (#956 round 3, H1).
    locs = sorted(f.location for f in findings)
    assert len(locs) == 2 and locs[0].endswith("a.sql:1") and locs[1].endswith("a.sql:2"), locs


def test_pg_function_immutable_reads_session_fires_when_dollar_tag_text_is_not_the_body(
    tmp_path: Path,
) -> None:
    # #956 round 3, M1 (still-fires): `has_dollar_tag` was computed on the raw statement, so
    # `as $…$`-shaped text that is NOT the body — inside a literal before it, or inside the
    # single-quoted body itself — made the guard treat an `AS '...'` body as dollar-quoted and
    # leave it blanked (0 findings, where `main` fired). It is now computed on the masked view.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FUNCTION app.h(note text DEFAULT 'noted as $$x$$') RETURNS text "
        "LANGUAGE sql IMMUTABLE AS 'SELECT current_setting(''app.tenant'', true)';\n"
        "CREATE FUNCTION app.m() RETURNS text LANGUAGE sql IMMUTABLE "
        "AS 'SELECT current_setting(''app.tenant'', true) as $$x$$';\n",
        encoding="utf-8",
    )
    findings = PgFunctionImmutableReadsSessionGuard().run(tmp_path, _sqlprof(tmp_path))
    locs = sorted(f.location for f in findings)
    assert len(locs) == 2 and locs[0].endswith("a.sql:1") and locs[1].endswith("a.sql:2"), locs


def test_pg_function_immutable_reads_session_masks_default_with_dollar_tag_text(
    tmp_path: Path,
) -> None:
    # Rule 1 FP-bait for the M1 widening above: restoring the body must not unmask the DEFAULT
    # that carries the `as $$` text. A STABLE function whose only "immutable" is inside that
    # literal stays silent (`main`, which masks nothing, fires on it).
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FUNCTION app.h(note text DEFAULT 'immutable, noted as $$x$$') RETURNS text "
        "LANGUAGE sql STABLE AS 'SELECT current_setting(''app.tenant'', true)';\n",
        encoding="utf-8",
    )
    assert PgFunctionImmutableReadsSessionGuard().run(tmp_path, _sqlprof(tmp_path)) == []


def test_pg_function_immutable_reads_session_dollar_body_never_takes_the_quoted_path(
    tmp_path: Path,
) -> None:
    # Pins `has_dollar_tag` for a REAL `$$` body (the other side of the M1 line above; nothing
    # else in this file goes red if it is forced False). Synthetic on purpose: an `AS '...'`
    # sitting in the dollar body's own code. Taken as a quoted body, it would unmask
    # 'immutable' and fire on a STABLE function.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FUNCTION app.q() RETURNS text LANGUAGE plpgsql STABLE AS $$ "
        "BEGIN RETURN current_setting('app.tenant', true) AS 'immutable'; END; $$;\n",
        encoding="utf-8",
    )
    assert PgFunctionImmutableReadsSessionGuard().run(tmp_path, _sqlprof(tmp_path)) == []


def test_pg_function_immutable_reads_session_skips_comment(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "-- CREATE FUNCTION app.cur_tenant() RETURNS text LANGUAGE sql IMMUTABLE "
        "AS $$ SELECT current_setting('app.tenant', true) $$;\n", encoding="utf-8"
    )
    assert PgFunctionImmutableReadsSessionGuard().run(tmp_path, _sqlprof(tmp_path)) == []
