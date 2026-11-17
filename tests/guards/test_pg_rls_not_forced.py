from __future__ import annotations

from agentsec.guards.pg_rls_not_forced import PgRlsNotForcedGuard
from tests.guards._common import *  # noqa: F401,F403


def test_pg_rls_not_forced_fires_on_enable_without_force(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY p ON public.docs USING (owner_id = auth.uid());\n", encoding="utf-8"
    )
    findings = PgRlsNotForcedGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "pg-rls-not-forced/enabled-without-force"
    assert findings[0].severity == "medium"

def test_pg_rls_not_forced_passes_when_forced(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;\n"
        "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;\n"
        "CREATE POLICY p ON public.docs USING (owner_id = auth.uid());\n", encoding="utf-8"
    )
    assert PgRlsNotForcedGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_pg_rls_not_forced_cross_file_forced_elsewhere(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text("ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;\n", encoding="utf-8")
    (sql / "b.sql").write_text("ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;\n", encoding="utf-8")
    assert PgRlsNotForcedGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_pg_rls_not_forced_bare_name_matches_qualified_force(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text("ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n", encoding="utf-8")
    (sql / "b.sql").write_text("ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;\n", encoding="utf-8")
    assert PgRlsNotForcedGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_pg_rls_not_forced_pragma_opt_out(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;\n"
        "-- security: allow-rls-not-forced\n", encoding="utf-8"
    )
    assert PgRlsNotForcedGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_pg_rls_not_forced_skips_comment(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text("-- ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;\n", encoding="utf-8")
    assert PgRlsNotForcedGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_pg_rls_not_forced_skips_generated_dump(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "dump.sql").write_text(
        "-- PostgreSQL database dump\n"
        "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;\n", encoding="utf-8"
    )
    assert PgRlsNotForcedGuard().run(tmp_path, _sqlprof(tmp_path)) == []
