from __future__ import annotations

from agentsec.guards.db_role_privilege_excessive import DbRolePrivilegeExcessiveGuard
from tests.guards._common import *  # noqa: F401,F403


def _run_sql(tmp_path: Path, sql: str) -> list:
    sql_dir = tmp_path / "sql"
    sql_dir.mkdir(exist_ok=True)
    (sql_dir / "0001.sql").write_text(sql, encoding="utf-8")
    return DbRolePrivilegeExcessiveGuard().run(tmp_path, _sqlprof(tmp_path))


def _rules(findings: list) -> set[str]:
    return {f.rule for f in findings}


# -- applies() -----------------------------------------------------------------------------

def test_db_role_privilege_excessive_applies_on_sql_feature(tmp_path: Path) -> None:
    assert DbRolePrivilegeExcessiveGuard().applies(_sqlprof(tmp_path)) is True


def test_db_role_privilege_excessive_not_applies_without_sql_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"python", "fastapi"})
    assert DbRolePrivilegeExcessiveGuard().applies(prof) is False


# -- CREATE/ALTER ROLE: SUPERUSER / CREATEDB / CREATEROLE ----------------------------------

def test_flags_alter_role_superuser(tmp_path: Path) -> None:
    findings = _run_sql(tmp_path, "ALTER ROLE app_user WITH SUPERUSER;")
    assert len(findings) == 1
    assert findings[0].rule == "db-role-privilege-excessive/role-superuser"
    assert findings[0].severity == "high"
    assert findings[0].standards == ["OWASP:A01", "SOC2:CC6.3"]


def test_flags_create_role_superuser(tmp_path: Path) -> None:
    findings = _run_sql(
        tmp_path, "CREATE ROLE app_user WITH LOGIN PASSWORD 'x' SUPERUSER;"
    )
    assert len(findings) == 1
    assert findings[0].rule == "db-role-privilege-excessive/role-superuser"


def test_flags_alter_role_createdb(tmp_path: Path) -> None:
    findings = _run_sql(tmp_path, "ALTER ROLE app_user CREATEDB;")
    assert len(findings) == 1
    assert findings[0].rule == "db-role-privilege-excessive/role-createdb"


def test_flags_alter_role_createrole(tmp_path: Path) -> None:
    findings = _run_sql(tmp_path, "ALTER ROLE app_user CREATEROLE;")
    assert len(findings) == 1
    assert findings[0].rule == "db-role-privilege-excessive/role-createrole"


def test_flags_create_user_alias(tmp_path: Path) -> None:
    # CREATE USER is a documented Postgres alias for CREATE ROLE ... WITH LOGIN.
    findings = _run_sql(tmp_path, "CREATE USER app_user WITH SUPERUSER;")
    assert len(findings) == 1


def test_two_separate_alter_role_statements_each_fire(tmp_path: Path) -> None:
    # Adversarial: an evasion attempt spreading the excessive grant across two statements
    # instead of one does not need to be "combined" to be caught — each independently fires.
    findings = _run_sql(
        tmp_path,
        "ALTER ROLE app_user CREATEDB;\nALTER ROLE app_user CREATEROLE;\n",
    )
    rules = _rules(findings)
    assert "db-role-privilege-excessive/role-createdb" in rules
    assert "db-role-privilege-excessive/role-createrole" in rules
    assert len(findings) == 2


def test_negated_attributes_stay_silent(tmp_path: Path) -> None:
    # FP-bait: NOSUPERUSER/NOCREATEDB/NOCREATEROLE are the SAFE negated forms and must not
    # match the bare attribute regex (no word boundary between "NO" and the keyword).
    findings = _run_sql(
        tmp_path, "ALTER ROLE app_user NOSUPERUSER NOCREATEDB NOCREATEROLE;"
    )
    assert findings == []


def test_migration_role_name_is_exempt(tmp_path: Path) -> None:
    # A role explicitly named as a migration-tool role SHOULD be exempt: it is documented as
    # NOT the app's runtime connection, and elevated rights there are the expected shape.
    findings = _run_sql(tmp_path, "ALTER ROLE db_migrator WITH SUPERUSER;")
    assert findings == []
    findings2 = _run_sql(tmp_path, "CREATE ROLE admin_migration WITH SUPERUSER;")
    assert findings2 == []


def test_pragma_silences_role_attrs(tmp_path: Path) -> None:
    findings = _run_sql(
        tmp_path,
        "-- security: allow-db-role-privilege-excessive\n"
        "ALTER ROLE app_user WITH SUPERUSER;\n",
    )
    assert findings == []


# -- ALTER SCHEMA ... OWNER TO ---------------------------------------------------------------

def test_flags_schema_owner_transfer_to_app_role(tmp_path: Path) -> None:
    findings = _run_sql(tmp_path, "ALTER SCHEMA app OWNER TO app_user;")
    assert len(findings) == 1
    assert findings[0].rule == "db-role-privilege-excessive/schema-owner"


def test_schema_owner_postgres_bootstrap_role_is_silent(tmp_path: Path) -> None:
    # FP-bait: `ALTER SCHEMA public OWNER TO postgres;` is routine pg_dump boilerplate, not an
    # app-layer privilege decision.
    findings = _run_sql(tmp_path, "ALTER SCHEMA public OWNER TO postgres;")
    assert findings == []


def test_schema_owner_migration_role_is_silent(tmp_path: Path) -> None:
    findings = _run_sql(tmp_path, "ALTER SCHEMA app OWNER TO migrator;")
    assert findings == []


# -- GRANT ALL ON SCHEMA / DATABASE ----------------------------------------------------------

def test_flags_grant_all_on_schema(tmp_path: Path) -> None:
    findings = _run_sql(tmp_path, "GRANT ALL ON SCHEMA app TO app_user;")
    assert len(findings) == 1
    assert findings[0].rule == "db-role-privilege-excessive/broad-grant"


def test_flags_grant_all_privileges_on_database(tmp_path: Path) -> None:
    findings = _run_sql(
        tmp_path, "GRANT ALL PRIVILEGES ON DATABASE appdb TO app_user;"
    )
    assert len(findings) == 1
    assert findings[0].rule == "db-role-privilege-excessive/broad-grant"


def test_scoped_grant_stays_silent(tmp_path: Path) -> None:
    # FP-bait per the guard's own contrast case: a properly scoped grant on specific tables,
    # naming only the CRUD operations the app needs, must never fire.
    findings = _run_sql(
        tmp_path,
        "GRANT SELECT, INSERT, UPDATE, DELETE ON specific_table TO app_user;",
    )
    assert findings == []


def test_grant_all_to_anon_public_is_pg_anon_grant_territory(tmp_path: Path) -> None:
    # FP-bait: anon/public/authenticated/service_role grants are a DIFFERENT threat model
    # (unauthenticated RLS bypass), already covered by `pg-anon-grant` — not duplicated here.
    findings = _run_sql(tmp_path, "GRANT ALL ON SCHEMA app TO anon;")
    assert findings == []
    findings2 = _run_sql(tmp_path, "GRANT ALL ON SCHEMA app TO public;")
    assert findings2 == []
    findings3 = _run_sql(tmp_path, "GRANT ALL ON SCHEMA app TO service_role;")
    assert findings3 == []


def test_grant_all_keyword_split_across_lines(tmp_path: Path) -> None:
    # Adversarial: a different (but valid) SQL keyword ordering/layout — ALL and PRIVILEGES
    # split across physical lines — must not evade detection.
    findings = _run_sql(
        tmp_path,
        "GRANT ALL\nPRIVILEGES\nON SCHEMA app_schema\nTO app_user;\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "db-role-privilege-excessive/broad-grant"


def test_grant_all_multi_role_list_flags_each_non_exempt_role(tmp_path: Path) -> None:
    # Adversarial: a multi-statement-shaped GRANT (comma role list) naming a legitimate
    # migration role alongside the app's own role — only the non-exempt one fires.
    findings = _run_sql(tmp_path, "GRANT ALL ON SCHEMA app TO app_user, migrator;")
    assert len(findings) == 1
    assert "app_user" in findings[0].message


def test_grant_all_pragma_silences(tmp_path: Path) -> None:
    findings = _run_sql(
        tmp_path,
        "-- security: allow-db-role-privilege-excessive\n"
        "GRANT ALL ON SCHEMA app TO app_user;\n",
    )
    assert findings == []


# -- is_reference_sql_path honored -----------------------------------------------------------

def test_fixtures_dir_is_out_of_scope(tmp_path: Path) -> None:
    sql_dir = tmp_path / "sql" / "fixtures"
    sql_dir.mkdir(parents=True)
    (sql_dir / "seed.sql").write_text(
        "ALTER ROLE app_user WITH SUPERUSER;", encoding="utf-8"
    )
    prof = mkprofile(tmp_path, features={"sql"}, sql_dir="sql")
    assert DbRolePrivilegeExcessiveGuard().run(tmp_path, prof) == []


def test_migrations_dir_stays_in_scope(tmp_path: Path) -> None:
    # Unlike the shared `is_nonproduct_path`, `is_reference_sql_path` deliberately keeps
    # `migrations/` in scope for SQL guards — it is the DEPLOYED schema, not test noise.
    sql_dir = tmp_path / "sql" / "migrations"
    sql_dir.mkdir(parents=True)
    (sql_dir / "0001_init.sql").write_text(
        "ALTER ROLE app_user WITH SUPERUSER;", encoding="utf-8"
    )
    prof = mkprofile(tmp_path, features={"sql"}, sql_dir="sql")
    findings = DbRolePrivilegeExcessiveGuard().run(tmp_path, prof)
    assert len(findings) == 1


# -- compose: app's own connection string uses the bootstrap superuser account --------------

def _write_compose(tmp_path: Path, name: str, content: str) -> None:
    (tmp_path / name).write_text(content, encoding="utf-8")


def test_flags_compose_superuser_connection_string(tmp_path: Path) -> None:
    _write_compose(
        tmp_path,
        "docker-compose.yml",
        "services:\n"
        "  web:\n"
        "    environment:\n"
        '      DATABASE_URL: "postgresql://postgres:supersecret@db:5432/app"\n',
    )
    findings = DbRolePrivilegeExcessiveGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "db-role-privilege-excessive/superuser-connection-string"


def test_flags_compose_superuser_connection_string_sqlalchemy_dialect(tmp_path: Path) -> None:
    # Adversarial: the SQLAlchemy dialect+driver DSN form must still match.
    _write_compose(
        tmp_path,
        "docker-compose.yml",
        "services:\n"
        "  web:\n"
        "    environment:\n"
        '      SQLALCHEMY_DATABASE_URI: "postgresql+asyncpg://postgres:pw@db/app"\n',
    )
    findings = DbRolePrivilegeExcessiveGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1


def test_compose_scoped_app_role_connection_string_silent(tmp_path: Path) -> None:
    # FP-bait: a dedicated, scoped app role in the connection string must stay silent.
    _write_compose(
        tmp_path,
        "docker-compose.yml",
        "services:\n"
        "  web:\n"
        "    environment:\n"
        '      DATABASE_URL: "postgresql://app_user:pw@db:5432/app"\n',
    )
    findings = DbRolePrivilegeExcessiveGuard().run(tmp_path, _sqlprof(tmp_path))
    assert findings == []


def test_dev_compose_superuser_connection_string_is_out_of_scope(tmp_path: Path) -> None:
    # Scoping decision (documented in the module docstring): local dev compose files using
    # postgres/postgres is the overwhelmingly common low-value-signal convention.
    _write_compose(
        tmp_path,
        "docker-compose.dev.yml",
        "services:\n"
        "  web:\n"
        "    environment:\n"
        '      DATABASE_URL: "postgresql://postgres:postgres@db:5432/app"\n',
    )
    findings = DbRolePrivilegeExcessiveGuard().run(tmp_path, _sqlprof(tmp_path))
    assert findings == []


def test_compose_pragma_silences(tmp_path: Path) -> None:
    _write_compose(
        tmp_path,
        "docker-compose.yml",
        "# security: allow-db-role-privilege-excessive\n"
        "services:\n"
        "  web:\n"
        "    environment:\n"
        '      DATABASE_URL: "postgresql://postgres:supersecret@db:5432/app"\n',
    )
    findings = DbRolePrivilegeExcessiveGuard().run(tmp_path, _sqlprof(tmp_path))
    assert findings == []


def test_compose_pragma_quoted_in_a_scalar_does_not_silence(tmp_path: Path) -> None:
    # #424 E3: the compose site reads the YAML comment view, so a quoted scalar carrying the
    # documented `# security: …` form is content, not a comment (the test above keeps the real
    # comment form working).
    _write_compose(
        tmp_path,
        "docker-compose.yml",
        "services:\n"
        "  web:\n"
        "    environment:\n"
        '      HELP: "opt out with # security: allow-db-role-privilege-excessive"\n'
        '      DATABASE_URL: "postgresql://postgres:supersecret@db:5432/app"\n',
    )
    findings = DbRolePrivilegeExcessiveGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
