from __future__ import annotations

from agentsec.guards.rls_current_user_tenant_key import RlsCurrentUserTenantKeyGuard
from tests.guards._common import *  # noqa: F401,F403


def test_rls_current_user_tenant_key_fires_on_using_comparison(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (owner_role = current_user);\n", encoding="utf-8"
    )
    findings = RlsCurrentUserTenantKeyGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rls-current-user-tenant-key/role-identity-comparison"
    assert findings[0].severity == "medium"

def test_rls_current_user_tenant_key_fires_reversed_order(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (current_user = owner_role);\n", encoding="utf-8"
    )
    findings = RlsCurrentUserTenantKeyGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1

def test_rls_current_user_tenant_key_fires_session_user(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (owner_role = session_user);\n", encoding="utf-8"
    )
    findings = RlsCurrentUserTenantKeyGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1

def test_rls_current_user_tenant_key_fires_with_check(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs FOR INSERT WITH CHECK (owner_role = current_user);\n", encoding="utf-8"
    )
    findings = RlsCurrentUserTenantKeyGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1

def test_rls_current_user_tenant_key_pragma_opt_out(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (owner_role = current_user);"
        "  -- security: allow-current-user-tenant-key\n", encoding="utf-8"
    )
    assert RlsCurrentUserTenantKeyGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_current_user_tenant_key_skips_comment(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "-- CREATE POLICY p ON public.docs USING (owner_role = current_user);\n", encoding="utf-8"
    )
    assert RlsCurrentUserTenantKeyGuard().run(tmp_path, _sqlprof(tmp_path)) == []

# --- FP-bait: the pgrls-documented non-findings ---------------------------------------------

def test_rls_current_user_tenant_key_passes_scoped_policy(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text("CREATE POLICY p ON public.docs USING (owner_id = auth.uid());\n", encoding="utf-8")
    assert RlsCurrentUserTenantKeyGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_current_user_tenant_key_passes_function_argument(tmp_path: Path) -> None:
    # current_user as a FUNCTION ARGUMENT (an admin/role-privilege check), not a comparison
    # operand -- pg_has_role(current_user, 'pg_read_all_data', 'MEMBER') is the standard
    # admin-escape branch of a policy, not a tenant key.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs "
        "USING (owner_id = auth.uid() OR pg_has_role(current_user, 'pg_read_all_data', 'MEMBER'));\n", encoding="utf-8"
    )
    assert RlsCurrentUserTenantKeyGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_current_user_tenant_key_passes_literal_comparison(tmp_path: Path) -> None:
    # current_user compared only to a LITERAL -- a check for one specific role
    # (a superuser/admin escape), not a per-row data match. No column operand.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (current_user = 'postgres' OR owner_id = auth.uid());\n", encoding="utf-8"
    )
    assert RlsCurrentUserTenantKeyGuard().run(tmp_path, _sqlprof(tmp_path)) == []
