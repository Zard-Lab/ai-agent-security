from __future__ import annotations

import os
from pathlib import Path

from agentsec.audit import audit
from agentsec.guards.pg_role_bypassrls import PgRoleBypassrlsGuard
from agentsec.sql_state import build_sql_state
from tests.conftest import PG_DUMP_HEAD
from tests.guards._common import *  # noqa: F401,F403


def test_pg_role_bypassrls_fires_on_create_role(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text("CREATE ROLE app_role LOGIN BYPASSRLS PASSWORD 'x';\n", encoding="utf-8")
    findings = PgRoleBypassrlsGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "pg-role-bypassrls/attribute-granted"
    assert findings[0].severity == "high"

def test_pg_role_bypassrls_fires_on_alter_role(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text("ALTER ROLE app_role BYPASSRLS;\n", encoding="utf-8")
    findings = PgRoleBypassrlsGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1

def test_pg_role_bypassrls_passes_nobypassrls(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text("CREATE ROLE app_role LOGIN NOBYPASSRLS PASSWORD 'x';\n", encoding="utf-8")
    assert PgRoleBypassrlsGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_pg_role_bypassrls_passes_no_bypassrls_with_space(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text("ALTER ROLE app_role NO BYPASSRLS;\n", encoding="utf-8")
    assert PgRoleBypassrlsGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_pg_role_bypassrls_passes_superuser(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text("CREATE ROLE admin_role SUPERUSER BYPASSRLS;\n", encoding="utf-8")
    assert PgRoleBypassrlsGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_pg_role_bypassrls_passes_ordinary_role(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text("CREATE ROLE app_role LOGIN PASSWORD 'x';\n", encoding="utf-8")
    assert PgRoleBypassrlsGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_pg_role_bypassrls_pragma_opt_out(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE ROLE etl_role LOGIN BYPASSRLS;  -- security: allow-role-bypassrls\n", encoding="utf-8"
    )
    assert PgRoleBypassrlsGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_pg_role_bypassrls_pragma_in_a_quoted_identifier_holding_a_semicolon_still_fires(tmp_path: Path) -> None:
    """#1040: the `;` revoked the identifier's comment-immunity, so the comment view read the `--`
    form inside it as a real pragma, on the statement's line and on the line above alike."""
    ident = 'SELECT "x ; -- security: allow-role-bypassrls";'
    for name, text in {
        "same-line": f"CREATE ROLE etl_role LOGIN BYPASSRLS; {ident}\n",
        "line-above": f"{ident}\nCREATE ROLE etl_role LOGIN BYPASSRLS;\n",
    }.items():
        sql = tmp_path / name / "sql"
        sql.mkdir(parents=True)
        (sql / "a.sql").write_text(text, encoding="utf-8")
        (f,) = PgRoleBypassrlsGuard().run(tmp_path / name, _sqlprof(tmp_path / name))
        assert f.rule == "pg-role-bypassrls/attribute-granted", name


def test_pg_role_bypassrls_real_pragma_after_a_quoted_identifier_holding_a_semicolon(tmp_path: Path) -> None:
    """The direction the #1040 fix trades against: a real comment after such an identifier is
    still a comment, so the opt-out still works."""
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        'SELECT "x;y"; CREATE ROLE etl_role LOGIN BYPASSRLS;  -- security: allow-role-bypassrls\n',
        encoding="utf-8",
    )
    assert PgRoleBypassrlsGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_pg_role_bypassrls_skips_comment(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text("-- CREATE ROLE app_role LOGIN BYPASSRLS;\n", encoding="utf-8")
    assert PgRoleBypassrlsGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_pg_role_bypassrls_not_superseded_by_schema_dump(tmp_path: Path) -> None:
    """Regression (Dean's review, PR #893 review): a BYPASSRLS grant must stay GATING even
    when the repo ships a per-database schema dump — roles are cluster-level objects a standard
    dump cannot reproduce, so schema_state must be False on this guard, not True. Before the fix,
    the mere presence of ANY schema-snapshot.sql silently demoted this finding to non-gating."""
    # Real Supabase-detection triggers, so the guard's own applies() ("supabase" or "postgres"
    # in features) is true through the full audit() pipeline — SQL files alone don't fingerprint
    # either (mirrors tests/test_sql_state.py::_dumped_repo's own setup).
    (tmp_path / "requirements.txt").write_text("supabase\nfastapi\n", encoding="utf-8")
    (tmp_path / "supabase").mkdir()
    (tmp_path / "supabase" / "config.toml").write_text("[api]\nport = 54321\n", encoding="utf-8")
    sql = tmp_path / "sql"
    sql.mkdir()
    # A per-database schema dump present in the repo — but it says nothing about roles at all.
    (sql / "schema-snapshot.sql").write_text(
        PG_DUMP_HEAD + "CREATE TABLE t (id int primary key);\n", encoding="utf-8"
    )
    (sql / "12-add-etl-role.sql").write_text(
        "CREATE ROLE etl_role LOGIN BYPASSRLS PASSWORD 'x';\n", encoding="utf-8"
    )
    # Not vacuous: the audit really sees a dump (since #1037 it must carry pg_dump's preamble), so
    # `superseded is False` below is the guard's `schema_state = False` answering, not a missing dump.
    assert build_sql_state(tmp_path, sorted(tmp_path.rglob("*.sql"))).snapshot == "sql/schema-snapshot.sql"
    res = audit(tmp_path, run_scanners=False, exceptions_path=Path(os.devnull))
    hit = next(f for f in res.findings if f.check_id == "pg-role-bypassrls")
    assert hit.superseded is False
