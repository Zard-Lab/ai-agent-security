from __future__ import annotations

import os
from pathlib import Path

from agentsec.audit import audit
from agentsec.guards.pg_role_bypassrls_membership import PgRoleBypassrlsMembershipGuard
from agentsec.sql_state import build_sql_state
from tests.conftest import PG_DUMP_HEAD
from tests.guards._common import *  # noqa: F401,F403


def test_pg_role_bypassrls_membership_fires(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE ROLE admin BYPASSRLS NOLOGIN;\n"
        "CREATE ROLE app LOGIN;\n"
        "GRANT admin TO app;\n", encoding="utf-8"
    )
    findings = PgRoleBypassrlsMembershipGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "pg-role-bypassrls-membership/set-role-path"
    assert findings[0].severity == "high"
    assert "app" in findings[0].message
    assert "admin" in findings[0].message

def test_pg_role_bypassrls_membership_cross_file(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text("CREATE ROLE admin BYPASSRLS NOLOGIN;\n", encoding="utf-8")
    (sql / "b.sql").write_text("CREATE ROLE app LOGIN;\nGRANT admin TO app;\n", encoding="utf-8")
    findings = PgRoleBypassrlsMembershipGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1

def test_pg_role_bypassrls_membership_multiple_members(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE ROLE admin BYPASSRLS NOLOGIN;\n"
        "CREATE ROLE app1 LOGIN;\n"
        "CREATE ROLE app2 LOGIN;\n"
        "GRANT admin TO app1, app2;\n", encoding="utf-8"
    )
    findings = PgRoleBypassrlsMembershipGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 2

def test_pg_role_bypassrls_membership_passes_no_bypassrls_role(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE ROLE ordinary LOGIN;\n"
        "CREATE ROLE app LOGIN;\n"
        "GRANT ordinary TO app;\n", encoding="utf-8"
    )
    assert PgRoleBypassrlsMembershipGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_pg_role_bypassrls_membership_passes_privilege_grant(tmp_path: Path) -> None:
    # GRANT ... ON ... TO ... is a privilege grant, not role membership -- must not
    # misparse "SELECT" as a role name granted to a table.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE ROLE admin BYPASSRLS NOLOGIN;\n"
        "GRANT SELECT ON public.docs TO admin;\n", encoding="utf-8"
    )
    assert PgRoleBypassrlsMembershipGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_pg_role_bypassrls_membership_fires_when_a_co_grantee_is_quoted_with_on(
    tmp_path: Path,
) -> None:
    # L2: a real bypassrls role ("admin") granted alongside a second, unrelated role
    # whose OWN quoted name happens to spell "on" as a standalone word (legal, if exotic, in
    # Postgres) must not have the WHOLE grant statement misread as a privilege grant's
    # `ON <object>` clause -- the classification scans the whole `roles_span` text, so the
    # second role's quoting alone was enough to hide the first, genuinely dangerous one.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE ROLE admin BYPASSRLS NOLOGIN;\n"
        "CREATE ROLE app LOGIN;\n"
        'GRANT admin, "audit on call" TO app;\n', encoding="utf-8"
    )
    findings = PgRoleBypassrlsMembershipGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert "app" in findings[0].message
    assert "admin" in findings[0].message

def test_pg_role_bypassrls_membership_passes_superuser_grantor_role(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE ROLE admin SUPERUSER BYPASSRLS NOLOGIN;\n"
        "CREATE ROLE app LOGIN;\n"
        "GRANT admin TO app;\n", encoding="utf-8"
    )
    assert PgRoleBypassrlsMembershipGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_pg_role_bypassrls_membership_pragma_opt_out(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE ROLE admin BYPASSRLS NOLOGIN;\n"
        "CREATE ROLE app LOGIN;\n"
        "GRANT admin TO app;  -- security: allow-role-bypassrls-membership\n", encoding="utf-8"
    )
    assert PgRoleBypassrlsMembershipGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_pg_role_bypassrls_membership_not_superseded_by_schema_dump(tmp_path: Path) -> None:
    """Regression (Dean's review, PR #893 review): role membership grants are cluster-level
    objects a standard per-database schema dump cannot reproduce — schema_state must be False,
    same reasoning and same fix as the sibling pg-role-bypassrls guard."""
    (tmp_path / "requirements.txt").write_text("supabase\nfastapi\n", encoding="utf-8")
    (tmp_path / "supabase").mkdir()
    (tmp_path / "supabase" / "config.toml").write_text("[api]\nport = 54321\n", encoding="utf-8")
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "schema-snapshot.sql").write_text(
        PG_DUMP_HEAD + "CREATE TABLE t (id int primary key);\n", encoding="utf-8"
    )
    (sql / "8-grant-admin.sql").write_text(
        "CREATE ROLE admin BYPASSRLS NOLOGIN;\n"
        "CREATE ROLE app LOGIN;\n"
        "GRANT admin TO app;\n",
        encoding="utf-8",
    )
    # Not vacuous: the audit really sees a dump (since #1037 it must carry pg_dump's preamble).
    assert build_sql_state(tmp_path, sorted(tmp_path.rglob("*.sql"))).snapshot == "sql/schema-snapshot.sql"
    res = audit(tmp_path, run_scanners=False, exceptions_path=Path(os.devnull))
    hit = next(f for f in res.findings if f.check_id == "pg-role-bypassrls-membership")
    assert hit.superseded is False
