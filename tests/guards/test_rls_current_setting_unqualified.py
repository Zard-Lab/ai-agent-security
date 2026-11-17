from __future__ import annotations

from agentsec.guards.rls_current_setting_unqualified import RlsCurrentSettingUnqualifiedGuard
from tests.guards._common import *  # noqa: F401,F403


def test_rls_current_setting_unqualified_fires(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (tenant_id = current_setting('tenant_id', true)::int);\n", encoding="utf-8"
    )
    findings = RlsCurrentSettingUnqualifiedGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rls-current-setting-unqualified/no-namespace-prefix"
    assert findings[0].severity == "low"

def test_rls_current_setting_unqualified_fires_with_check(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs FOR INSERT "
        "WITH CHECK (tenant_id = current_setting('tenant_id', true)::int);\n", encoding="utf-8"
    )
    assert len(RlsCurrentSettingUnqualifiedGuard().run(tmp_path, _sqlprof(tmp_path))) == 1

def test_rls_current_setting_unqualified_passes_qualified(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (tenant_id = current_setting('app.tenant_id', true)::int);\n", encoding="utf-8"
    )
    assert RlsCurrentSettingUnqualifiedGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_current_setting_unqualified_passes_builtin(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (current_setting('role') = 'admin');\n", encoding="utf-8"
    )
    assert RlsCurrentSettingUnqualifiedGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_current_setting_unqualified_pragma_opt_out(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (tenant_id = current_setting('tenant_id', true)::int);"
        "  -- security: allow-current-setting-unqualified\n", encoding="utf-8"
    )
    assert RlsCurrentSettingUnqualifiedGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_current_setting_unqualified_skips_comment(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "-- CREATE POLICY p ON public.docs USING (tenant_id = current_setting('tenant_id', true));\n", encoding="utf-8"
    )
    assert RlsCurrentSettingUnqualifiedGuard().run(tmp_path, _sqlprof(tmp_path)) == []
