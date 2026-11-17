from __future__ import annotations

from agentsec.guards.pg_foreign_table_exposed import PgForeignTableExposedGuard
from tests.guards._common import *  # noqa: F401,F403


def test_pg_foreign_table_exposed_fires(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FOREIGN TABLE public.stripe_customers (id text, email text) SERVER stripe;\n"
        "GRANT SELECT ON public.stripe_customers TO anon;\n", encoding="utf-8"
    )
    findings = PgForeignTableExposedGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "pg-foreign-table-exposed/granted-to-low-trust-role"
    assert findings[0].severity == "high"

def test_pg_foreign_table_exposed_fires_authenticated(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FOREIGN TABLE public.stripe_customers (id text) SERVER stripe;\n"
        "GRANT SELECT ON public.stripe_customers TO authenticated;\n", encoding="utf-8"
    )
    assert len(PgForeignTableExposedGuard().run(tmp_path, _sqlprof(tmp_path))) == 1

def test_pg_foreign_table_exposed_cross_file(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FOREIGN TABLE public.stripe_customers (id text) SERVER stripe;\n", encoding="utf-8"
    )
    (sql / "b.sql").write_text("GRANT SELECT ON public.stripe_customers TO anon;\n", encoding="utf-8")
    findings = PgForeignTableExposedGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1

def test_pg_foreign_table_exposed_passes_no_grant(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FOREIGN TABLE public.stripe_customers (id text) SERVER stripe;\n", encoding="utf-8"
    )
    assert PgForeignTableExposedGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_pg_foreign_table_exposed_passes_grant_to_service_role(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FOREIGN TABLE public.stripe_customers (id text) SERVER stripe;\n"
        "GRANT SELECT ON public.stripe_customers TO service_role;\n", encoding="utf-8"
    )
    assert PgForeignTableExposedGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_pg_foreign_table_exposed_passes_ordinary_table_grant(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE TABLE public.docs (id uuid, body text);\n"
        "GRANT SELECT ON public.docs TO anon;\n", encoding="utf-8"
    )
    assert PgForeignTableExposedGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_pg_foreign_table_exposed_passes_unrelated_public_table_same_name(tmp_path: Path) -> None:
    # H4 (Dean's review, PR #893 review): the collector used to ALSO always store a forced
    # `public.<name>` entry regardless of the foreign table's real schema, so an ordinary,
    # correctly-RLS'd `public.stripe_customers` collided with an unrelated foreign
    # `external.stripe_customers` and was wrongly reported as exposed.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FOREIGN TABLE external.stripe_customers (id text) SERVER stripe;\n"
        "CREATE TABLE public.stripe_customers (id uuid);\n"
        "ALTER TABLE public.stripe_customers ENABLE ROW LEVEL SECURITY;\n"
        "GRANT SELECT ON public.stripe_customers TO anon;\n", encoding="utf-8"
    )
    assert PgForeignTableExposedGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_pg_foreign_table_exposed_fires_with_grant_option_tail(tmp_path: Path) -> None:
    # H8 (Dean's review, PR #893 review): `WITH GRANT OPTION` left attached to the role list
    # made "anon" parse as "anon with grant option", never matching the low-trust role set.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FOREIGN TABLE public.stripe_customers (id text) SERVER stripe;\n"
        "GRANT SELECT ON public.stripe_customers TO anon WITH GRANT OPTION;\n", encoding="utf-8"
    )
    findings = PgForeignTableExposedGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1

def test_pg_foreign_table_exposed_pragma_opt_out(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE FOREIGN TABLE public.stripe_customers (id text) SERVER stripe;\n"
        "GRANT SELECT ON public.stripe_customers TO anon;\n"
        "-- security: allow-foreign-table-exposed\n", encoding="utf-8"
    )
    assert PgForeignTableExposedGuard().run(tmp_path, _sqlprof(tmp_path)) == []
