from __future__ import annotations

from agentsec.guards.pg_function_leakproof import PgFunctionLeakproofGuard
from tests.guards._common import *  # noqa: F401,F403


def test_pg_function_leakproof_fires_on_create_function(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FUNCTION public.leaky(val text) RETURNS boolean "
        "LANGUAGE sql LEAKPROOF AS $$ SELECT val = 'x' $$;\n", encoding="utf-8"
    )
    findings = PgFunctionLeakproofGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "pg-function-leakproof/marked-leakproof"
    assert findings[0].severity == "medium"

def test_pg_function_leakproof_fires_on_alter_function(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text("ALTER FUNCTION public.leaky(text) LEAKPROOF;\n", encoding="utf-8")
    findings = PgFunctionLeakproofGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1

def test_pg_function_leakproof_passes_not_leakproof(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FUNCTION public.safe(val text) RETURNS boolean "
        "LANGUAGE sql NOT LEAKPROOF AS $$ SELECT val = 'x' $$;\n", encoding="utf-8"
    )
    assert PgFunctionLeakproofGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_pg_function_leakproof_passes_ordinary_function(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FUNCTION public.plain(val text) RETURNS boolean "
        "LANGUAGE sql AS $$ SELECT val = 'x' $$;\n", encoding="utf-8"
    )
    assert PgFunctionLeakproofGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_pg_function_leakproof_ignores_the_word_inside_a_literal(tmp_path: Path) -> None:
    # M1: a function with no real LEAKPROOF keyword must not fire just because its
    # body mentions the word inside a plain string literal.
    #
    # (Dean's review re-review): the original fixture's literal ("this function is
    # not leakproof...") never discriminated — `_NOT_LEAKPROOF`'s own "not leakproof" strip
    # already cleared it before this fix existed, so the test passed on `main` too and proved
    # nothing about the masking this test exists to cover. A literal with no "not" in it does:
    # unmasked, `main` false-positives on the bare word; masked, it stays silent.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FUNCTION public.safe(val text) RETURNS boolean LANGUAGE sql AS $$ "
        "SELECT val = 'must remain leakproof for safety reasons' "
        "$$;\n", encoding="utf-8"
    )
    assert PgFunctionLeakproofGuard().run(tmp_path, _sqlprof(tmp_path)) == []


def test_pg_function_leakproof_pragma_opt_out(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FUNCTION public.leaky(val text) RETURNS boolean "
        "LANGUAGE sql LEAKPROOF AS $$ SELECT val = 'x' $$;"
        "  -- security: allow-function-leakproof\n", encoding="utf-8"
    )
    assert PgFunctionLeakproofGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_pg_function_leakproof_skips_comment(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "-- CREATE FUNCTION public.leaky(val text) RETURNS boolean LANGUAGE sql LEAKPROOF AS $$ SELECT val $$;\n", encoding="utf-8"
    )
    assert PgFunctionLeakproofGuard().run(tmp_path, _sqlprof(tmp_path)) == []


def test_pg_function_leakproof_pragma_inside_the_function_body_opts_out(tmp_path: Path) -> None:
    # #1040 T2: the statement window is the same slice of the comment-only view, and that view reads
    # a `$$…$$` body as code (as Postgres re-lexes it), so a `--` line inside the body is a real
    # comment in the statement's window and opts it out.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FUNCTION public.leaky(val text) RETURNS boolean LANGUAGE sql LEAKPROOF AS $$\n"
        "  -- security: allow-function-leakproof\n"
        "  SELECT val = 'x'\n"
        "$$;\n",
        encoding="utf-8",
    )
    assert PgFunctionLeakproofGuard().run(tmp_path, _sqlprof(tmp_path)) == []


def test_pg_function_leakproof_pragma_quoted_inside_the_function_body_does_not_opt_out(tmp_path: Path) -> None:
    # The direction #1040 T2 trades against: inside the body a literal is still content.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FUNCTION public.leaky(val text) RETURNS boolean LANGUAGE sql LEAKPROOF AS $$\n"
        "  SELECT val = '-- security: allow-function-leakproof'\n"
        "$$;\n",
        encoding="utf-8",
    )
    assert len(PgFunctionLeakproofGuard().run(tmp_path, _sqlprof(tmp_path))) == 1
