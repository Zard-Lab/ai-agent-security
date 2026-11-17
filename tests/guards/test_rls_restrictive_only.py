from __future__ import annotations

from agentsec.guards.rls_restrictive_only import RlsRestrictiveOnlyGuard
from tests.guards._common import *  # noqa: F401,F403


def test_rls_restrictive_only_fires_on_restrictive_only_table(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY p ON public.docs AS RESTRICTIVE USING (owner = auth.uid());\n", encoding="utf-8"
    )
    findings = RlsRestrictiveOnlyGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rls-restrictive-only/no-permissive-policy"
    assert findings[0].severity == "medium"

def test_rls_restrictive_only_passes_with_a_permissive_policy(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY perm ON public.docs USING (owner = auth.uid());\n"
        "CREATE POLICY restr ON public.docs AS RESTRICTIVE USING (tenant_id = current_setting('app.tenant_id')::int);\n", encoding="utf-8"
    )
    assert RlsRestrictiveOnlyGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_restrictive_only_passes_zero_policies(tmp_path: Path) -> None:
    # A table with RLS enabled and NO policies at all is pg-rls-no-policy's domain, not this one.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text("ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;\n", encoding="utf-8")
    assert RlsRestrictiveOnlyGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_restrictive_only_cross_file_permissive_elsewhere(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY restr ON public.docs AS RESTRICTIVE USING (tenant_id = current_setting('app.tenant_id')::int);\n", encoding="utf-8"
    )
    (sql / "b.sql").write_text("CREATE POLICY perm ON public.docs USING (owner = auth.uid());\n", encoding="utf-8")
    assert RlsRestrictiveOnlyGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_restrictive_only_pragma_opt_out(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY p ON public.docs AS RESTRICTIVE USING (owner = auth.uid());\n"
        "-- security: allow-restrictive-only\n", encoding="utf-8"
    )
    assert RlsRestrictiveOnlyGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_restrictive_only_multiple_restrictive_still_fires_once(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY p1 ON public.docs AS RESTRICTIVE USING (owner = auth.uid());\n"
        "CREATE POLICY p2 ON public.docs AS RESTRICTIVE USING (tenant_id = current_setting('app.tenant_id')::int);\n", encoding="utf-8"
    )
    findings = RlsRestrictiveOnlyGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
