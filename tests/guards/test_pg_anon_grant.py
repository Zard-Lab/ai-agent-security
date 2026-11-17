from __future__ import annotations

import pytest

from agentsec.guards.pg_anon_grant import PgAnonGrantGuard
from tests.guards._common import *  # noqa: F401,F403


def test_pg_anon_grant_fires(tmp_path: Path) -> None:
    (tmp_path / "schema.sql").write_text(
        "GRANT SELECT ON TABLE users TO anon;\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"supabase"})
    findings = PgAnonGrantGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "pg-anon-grant/grant-to-anon-public"
    assert findings[0].severity == "high"
    assert findings[0].standards == ["OWASP:A01", "CIS:6.3"]

def test_pg_anon_grant_fires_multiple(tmp_path: Path) -> None:
    (tmp_path / "schema.sql").write_text(
        "GRANT SELECT ON TABLE users TO anon;\n"
        "GRANT ALL ON SCHEMA app TO public;\n"
        "grant insert on orders to anon;\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"postgres"})
    findings = PgAnonGrantGuard().run(tmp_path, profile)
    assert len(findings) == 3

def test_pg_anon_grant_silent_safe(tmp_path: Path) -> None:
    (tmp_path / "schema.sql").write_text(
        "GRANT SELECT ON TABLE logs TO service_role;\n"
        "GRANT USAGE ON SCHEMA public TO authenticated;\n"
        "REVOKE ALL ON TABLE secrets FROM anon;\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"supabase"})
    findings = PgAnonGrantGuard().run(tmp_path, profile)
    assert findings == []

def test_pg_anon_grant_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "schema.sql").write_text(
        "-- security: allow-pg-anon-grant\n"
        "GRANT SELECT ON TABLE users TO anon;\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"supabase"})
    findings = PgAnonGrantGuard().run(tmp_path, profile)
    assert findings == []

def test_pg_anon_grant_not_applies(tmp_path: Path) -> None:
    (tmp_path / "schema.sql").write_text(
        "GRANT SELECT ON TABLE users TO anon;\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"})
    assert PgAnonGrantGuard().applies(profile) is False

def test_pg_anon_grant_case_insensitive(tmp_path: Path) -> None:
    (tmp_path / "schema.sql").write_text(
        "grant insert on orders to anon;\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"postgres"})
    findings = PgAnonGrantGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "pg-anon-grant/grant-to-anon-public"

def test_pg_anon_grant_schema_usage_is_low(tmp_path: Path) -> None:
    # GRANT USAGE ON SCHEMA = namespace access, not table data — needed for the anon RPC pattern.
    findings = _pgag_run(tmp_path, "GRANT USAGE ON SCHEMA workbook TO anon, authenticated, service_role;")
    assert len(findings) == 1 and findings[0].severity == "low"

def test_pg_anon_grant_schema_all_stays_high(tmp_path: Path) -> None:
    # GRANT ALL/CREATE ON SCHEMA is not USAGE — stays HIGH.
    findings = _pgag_run(tmp_path, "GRANT ALL ON SCHEMA app TO anon;")
    assert len(findings) == 1 and findings[0].severity == "high"

def test_pg_anon_grant_invoker_function_is_medium(tmp_path: Path) -> None:
    findings = _pgag_run(
        tmp_path,
        "GRANT EXECUTE ON FUNCTION match_docs(int) TO anon;\n"
        "CREATE FUNCTION match_docs(int) RETURNS int LANGUAGE sql AS $$ SELECT 1 $$;\n",
    )
    assert len(findings) == 1 and findings[0].severity == "medium"

def test_pg_anon_grant_definer_function_escalates_to_high(tmp_path: Path) -> None:
    # EXECUTE to anon on a SECURITY DEFINER function bypasses RLS — the exec_sql class.
    findings = _pgag_run(
        tmp_path,
        "GRANT EXECUTE ON FUNCTION public.exec_sql(text) TO anon;\n"
        "CREATE FUNCTION public.exec_sql(text) RETURNS void LANGUAGE plpgsql "
        "SECURITY DEFINER AS $$ BEGIN EXECUTE $1; END; $$;\n",
    )
    assert len(findings) == 1 and findings[0].severity == "high"
    assert "DEFINER" in findings[0].title and "exec_sql" in findings[0].message

def test_pg_anon_grant_table_grant_stays_high(tmp_path: Path) -> None:
    findings = _pgag_run(tmp_path, "GRANT SELECT ON TABLE users TO anon;")
    assert len(findings) == 1 and findings[0].severity == "high"


def test_pg_anon_grant_hostile_sql_is_linear(tmp_path: Path) -> None:
    # Regression (issue #419): `GRANT\s+.+\s+ON\s+.+\s+TO\s+…` backtracked quadratically on a
    # hostile long GRANT line (two unbounded greedy runs), and the tempered SECURITY DEFINER
    # scan re-checked a lookahead per char. Both are now ordered bounded searches. Actual
    # ~0.1s; a quadratic form at this size takes minutes.
    import time

    (tmp_path / "a.sql").write_text("GRANT ALL ON t " * 20_000 + "\n", encoding="utf-8")  # no TO anon
    (tmp_path / "b.sql").write_text(
        "CREATE OR REPLACE FUNCTION f(x int) RETURNS void AS $$ SELECT 1 $$ LANGUAGE sql; " * 3_000,
        encoding="utf-8",
    )
    start = time.monotonic()
    findings = PgAnonGrantGuard().run(tmp_path, mkprofile(tmp_path, features={"supabase"}))
    assert time.monotonic() - start < 5.0, "quadratic GRANT/DEFINER scan reintroduced"
    assert findings == []


def test_pg_anon_grant_pragma_quoted_in_a_literal_does_not_suppress(tmp_path: Path) -> None:
    # #424 E3: the documented `-- security: …` form inside a string literal (a COMMENT ON, a seed
    # row) is SQL content, not a comment - only a real `--` comment (the test above) opts out.
    (tmp_path / "schema.sql").write_text(
        "GRANT SELECT ON TABLE users TO anon;\n"
        "COMMENT ON TABLE users IS 'opt out with -- security: allow-pg-anon-grant';\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"supabase"})
    findings = PgAnonGrantGuard().run(tmp_path, profile)
    assert len(findings) == 1


# --- #442: comments are blanked line-for-line, not deleted --------------------------------------

def test_pg_anon_grant_line_below_block_comment_header_is_the_raw_line(tmp_path: Path) -> None:
    # Delete-mode stripping dropped the header's newlines, so this reported `g.sql:2` (#442).
    findings = _pgag_run(tmp_path, "/* license\n a\n b\n c\n*/\nGRANT SELECT ON TABLE users TO anon;\n")
    assert [f.location.endswith(":6") for f in findings] == [True]


@pytest.mark.parametrize(
    "sql",
    [
        "-- GRANT SELECT ON TABLE users TO anon;\n",
        "SELECT 1; -- GRANT SELECT ON TABLE users TO anon;\n",
        "/* GRANT SELECT ON TABLE users TO anon; */\n",
        "/*\nGRANT SELECT ON TABLE users TO anon;\n*/\n",
    ],
    ids=["whole-line", "trailing", "single-line-block", "multi-line-block"],
)
def test_pg_anon_grant_commented_out_grant_is_silent(tmp_path: Path, sql: str) -> None:
    assert _pgag_run(tmp_path, sql) == []


def test_pg_anon_grant_live_grant_with_trailing_comment_still_fires(tmp_path: Path) -> None:
    findings = _pgag_run(tmp_path, "/* a\n*/\nGRANT SELECT ON TABLE users TO anon; -- needed for the demo\n")
    assert [(f.severity, f.location.endswith(":3")) for f in findings] == [("high", True)]


def test_pg_anon_grant_form_feed_inside_a_comment_keeps_raw_line_numbering(tmp_path: Path) -> None:
    # Blank mode keeps only `\n` inside a comment, so `blanked.splitlines()` loses the form feed's
    # line break while `raw.splitlines()` keeps it. The guard numbers lines the raw way.
    findings = _pgag_run(tmp_path, "/* a\x0cb */\nGRANT SELECT ON TABLE users TO anon;\n")
    assert [f.location.endswith(":3") for f in findings] == [True]


# --- #442 phase 2: a `/*` inside a dollar-quoted body cannot hide the SQL after it -------------

def test_pg_anon_grant_grant_after_a_dollar_quoted_glob_still_fires(tmp_path: Path) -> None:
    # The glob's `/*` blanked the grant through to the trailing comment's `*/`.
    findings = _pgag_run(tmp_path, _dollar_glob_sandwich("GRANT SELECT ON TABLE users TO anon;"))
    assert [(f.severity, f.location.endswith(":2")) for f in findings] == [("high", True)]


def test_pg_anon_grant_definer_after_a_dollar_quoted_glob_still_escalates(tmp_path: Path) -> None:
    # The definer index reads delete-mode text, so hiding the function there dropped the grant on
    # it from HIGH to MEDIUM.
    findings = _pgag_run(
        tmp_path,
        "GRANT EXECUTE ON FUNCTION public.exec_sql(text) TO anon;\n"
        + _dollar_glob_sandwich(
            "CREATE FUNCTION public.exec_sql(text) RETURNS void LANGUAGE plpgsql "
            "SECURITY DEFINER AS $fn$ BEGIN EXECUTE $1; END; $fn$;"
        ),
    )
    assert [f.severity for f in findings] == ["high"]


def test_pg_anon_grant_grant_commented_out_inside_a_do_body_is_silent(tmp_path: Path) -> None:
    grant = "GRANT SELECT ON TABLE users TO anon;"
    assert _pgag_run(tmp_path, _dollar_glob_sandwich(_do_commented_out(grant))) == []
    # Control: the guard reads DO bodies, so the same grant left live in one fires.
    assert len(_pgag_run(tmp_path, f"DO $$ BEGIN\n{grant}\nEND $$;\n")) == 1
