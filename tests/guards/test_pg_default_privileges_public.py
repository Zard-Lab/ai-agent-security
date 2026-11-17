from __future__ import annotations

from agentsec.guards.pg_default_privileges_public import PgDefaultPrivilegesPublicGuard
from tests.guards._common import *  # noqa: F401,F403


def test_pg_default_privileges_public_fires_on_select_to_public(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO PUBLIC;\n", encoding="utf-8"
    )
    findings = PgDefaultPrivilegesPublicGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "pg-default-privileges-public/row-access-to-public"
    assert findings[0].severity == "high"

def test_pg_default_privileges_public_fires_on_multiple_privs(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "ALTER DEFAULT PRIVILEGES FOR ROLE app_owner GRANT SELECT, INSERT ON TABLES TO PUBLIC;\n", encoding="utf-8"
    )
    findings = PgDefaultPrivilegesPublicGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1

def test_pg_default_privileges_public_fires_cluster_wide(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text("ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO PUBLIC;\n", encoding="utf-8")
    findings = PgDefaultPrivilegesPublicGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1

def test_pg_default_privileges_public_passes_anon_authenticated(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO anon, authenticated;\n", encoding="utf-8"
    )
    assert PgDefaultPrivilegesPublicGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_pg_default_privileges_public_passes_non_row_access(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT REFERENCES ON TABLES TO PUBLIC;\n", encoding="utf-8"
    )
    assert PgDefaultPrivilegesPublicGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_pg_default_privileges_public_passes_named_role(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA reporting GRANT SELECT ON TABLES TO reporting_reader;\n", encoding="utf-8"
    )
    assert PgDefaultPrivilegesPublicGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_pg_default_privileges_public_pragma_opt_out(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO PUBLIC;"
        "  -- security: allow-default-privileges-public\n", encoding="utf-8"
    )
    assert PgDefaultPrivilegesPublicGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_pg_default_privileges_public_skips_comment(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "-- ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO PUBLIC;\n", encoding="utf-8"
    )
    assert PgDefaultPrivilegesPublicGuard().run(tmp_path, _sqlprof(tmp_path)) == []
