from __future__ import annotations

import pytest

from agentsec.guards.pg_extension_in_public import PgExtensionInPublicGuard
from tests.guards._common import *  # noqa: F401,F403


def test_pg_extension_in_public_explicit_fires_high(tmp_path: Path) -> None:
    (tmp_path / "schema.sql").write_text("CREATE EXTENSION dblink SCHEMA public;\n", encoding="utf-8")
    findings = PgExtensionInPublicGuard().run(tmp_path, _pg_ext_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "pg-extension-in-public/explicit-public-schema"
    assert findings[0].severity == "high"

def test_pg_extension_in_public_no_schema_fires_medium(tmp_path: Path) -> None:
    (tmp_path / "schema.sql").write_text("CREATE EXTENSION IF NOT EXISTS uuid-ossp;\n", encoding="utf-8")
    findings = PgExtensionInPublicGuard().run(tmp_path, _pg_ext_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "pg-extension-in-public/no-schema-clause"
    assert findings[0].severity == "medium"

def test_pg_extension_in_public_named_schema_silent(tmp_path: Path) -> None:
    (tmp_path / "schema.sql").write_text("CREATE EXTENSION pgcrypto SCHEMA extensions;\n", encoding="utf-8")
    assert PgExtensionInPublicGuard().run(tmp_path, _pg_ext_prof(tmp_path)) == []

def test_pg_extension_in_public_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "schema.sql").write_text(
        "-- security: allow-extension-in-public\nCREATE EXTENSION uuid-ossp;\n",
        encoding="utf-8",
    )
    assert PgExtensionInPublicGuard().run(tmp_path, _pg_ext_prof(tmp_path)) == []



def test_pg_extension_in_public_skips_examples_dir(tmp_path: Path) -> None:
    # §C.2: a public-schema extension in reference/example SQL is not the deployed schema.
    d = tmp_path / "examples"
    d.mkdir()
    (d / "schema.sql").write_text("CREATE EXTENSION dblink SCHEMA public;\n", encoding="utf-8")
    assert PgExtensionInPublicGuard().run(tmp_path, _pg_ext_prof(tmp_path)) == []


def test_pg_extension_in_public_still_fires_on_supabase_migrations(tmp_path: Path) -> None:
    # CRITICAL regression (PR #484 review): `migrations/` is the deployed schema for SQL — the guard
    # must still flag a public-schema extension there (Supabase `supabase/migrations/*.sql`).
    d = tmp_path / "supabase" / "migrations"
    d.mkdir(parents=True)
    (d / "0001_init.sql").write_text("CREATE EXTENSION pg_trgm SCHEMA public;\n", encoding="utf-8")
    findings = PgExtensionInPublicGuard().run(tmp_path, _pg_ext_prof(tmp_path))
    assert any(f.rule == "pg-extension-in-public/explicit-public-schema" for f in findings)


# --- #442: a commented-out install, or a commented schema clause, is not one --------------------

@pytest.mark.parametrize(
    "sql",
    [
        # The flagship shape verbatim (sql/vault-migration/01-verify-vault.sql:50).
        "-- CREATE EXTENSION IF NOT EXISTS supabase_vault CASCADE;\n",
        "SELECT 1; -- CREATE EXTENSION dblink;\n",
        "/* CREATE EXTENSION dblink; */\n",
        "/*\nCREATE EXTENSION dblink SCHEMA public;\n*/\n",
    ],
    ids=["whole-line", "trailing", "single-line-block", "multi-line-block"],
)
def test_pg_extension_in_public_commented_out_install_is_silent(tmp_path: Path, sql: str) -> None:
    (tmp_path / "schema.sql").write_text(sql, encoding="utf-8")
    assert PgExtensionInPublicGuard().run(tmp_path, _pg_ext_prof(tmp_path)) == []


def test_pg_extension_in_public_trailing_comment_is_not_a_schema_clause(tmp_path: Path) -> None:
    # Read raw, the comment's `SCHEMA public` escalated this to the HIGH explicit-public rule. The
    # install itself is real and has no SCHEMA clause, so it is the MEDIUM rule, still firing.
    (tmp_path / "schema.sql").write_text("CREATE EXTENSION dblink; -- was SCHEMA public\n", encoding="utf-8")
    findings = PgExtensionInPublicGuard().run(tmp_path, _pg_ext_prof(tmp_path))
    assert [(f.rule, f.severity) for f in findings] == [("pg-extension-in-public/no-schema-clause", "medium")]


def test_pg_extension_in_public_live_install_below_a_comment_still_fires_high(tmp_path: Path) -> None:
    (tmp_path / "schema.sql").write_text(
        "/* extensions\n   for the app */\nCREATE EXTENSION dblink SCHEMA public; -- reviewed\n",
        encoding="utf-8",
    )
    findings = PgExtensionInPublicGuard().run(tmp_path, _pg_ext_prof(tmp_path))
    assert [(f.severity, f.location.endswith(":3")) for f in findings] == [("high", True)]


# --- #442 phase 2: a `/*` inside a dollar-quoted body cannot hide the install after it ---------

def test_pg_extension_in_public_install_after_a_dollar_quoted_glob_still_fires(tmp_path: Path) -> None:
    # Silent since #1006 moved this guard onto `sql_code_lines`: the glob's `/*` blanked the
    # install through to the trailing comment's `*/`.
    (tmp_path / "m.sql").write_text(_dollar_glob_sandwich("CREATE EXTENSION IF NOT EXISTS dblink;"), encoding="utf-8")
    findings = PgExtensionInPublicGuard().run(tmp_path, _pg_ext_prof(tmp_path))
    assert [(f.rule, f.location.endswith(":2")) for f in findings] == [("pg-extension-in-public/no-schema-clause", True)]


def test_pg_extension_in_public_install_commented_out_inside_a_do_body_is_silent(tmp_path: Path) -> None:
    install = "CREATE EXTENSION IF NOT EXISTS dblink;"
    (tmp_path / "m.sql").write_text(_dollar_glob_sandwich(_do_commented_out(install)), encoding="utf-8")
    assert PgExtensionInPublicGuard().run(tmp_path, _pg_ext_prof(tmp_path)) == []
    # Control: the guard reads DO bodies, so the same install left live in one fires.
    (tmp_path / "m.sql").write_text(f"DO $$ BEGIN\n{install}\nEND $$;\n", encoding="utf-8")
    assert len(PgExtensionInPublicGuard().run(tmp_path, _pg_ext_prof(tmp_path))) == 1
