from __future__ import annotations

from agentsec.guards.rls_hardcoded_tenant_literal import RlsHardcodedTenantLiteralGuard
from tests.guards._common import *  # noqa: F401,F403


def test_rls_hardcoded_tenant_literal_fires_on_using(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text("CREATE POLICY p ON public.docs USING (tenant_id = 1);\n", encoding="utf-8")
    findings = RlsHardcodedTenantLiteralGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rls-hardcoded-tenant-literal/identity-column-pinned"
    assert findings[0].severity == "info"

def test_rls_hardcoded_tenant_literal_fires_reversed_order(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text("CREATE POLICY p ON public.docs USING (1 = tenant_id);\n", encoding="utf-8")
    assert len(RlsHardcodedTenantLiteralGuard().run(tmp_path, _sqlprof(tmp_path))) == 1

def test_rls_hardcoded_tenant_literal_fires_string_literal(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (org_id = 'acme'::text);\n", encoding="utf-8"
    )
    assert len(RlsHardcodedTenantLiteralGuard().run(tmp_path, _sqlprof(tmp_path))) == 1

def test_rls_hardcoded_tenant_literal_fires_with_check(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs FOR INSERT WITH CHECK (owner_id = 1);\n", encoding="utf-8"
    )
    assert len(RlsHardcodedTenantLiteralGuard().run(tmp_path, _sqlprof(tmp_path))) == 1

def test_rls_hardcoded_tenant_literal_pragma_opt_out(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (tenant_id = 1);"
        "  -- security: allow-hardcoded-tenant-literal\n", encoding="utf-8"
    )
    assert RlsHardcodedTenantLiteralGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_hardcoded_tenant_literal_skips_comment(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text("-- CREATE POLICY p ON public.docs USING (tenant_id = 1);\n", encoding="utf-8")
    assert RlsHardcodedTenantLiteralGuard().run(tmp_path, _sqlprof(tmp_path)) == []

# --- FP-bait -----------------------------------------------------------------------------

def test_rls_hardcoded_tenant_literal_passes_scoped_policy(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text("CREATE POLICY p ON public.docs USING (tenant_id = current_setting('app.tenant_id')::int);\n", encoding="utf-8")
    assert RlsHardcodedTenantLiteralGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_hardcoded_tenant_literal_passes_attribute_column(tmp_path: Path) -> None:
    # A non-identity attribute column compared to a literal is a legitimate, deliberate
    # comparison (`is_public = true`), not a tenant-pinning footgun.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text("CREATE POLICY p ON public.docs USING (is_public = true);\n", encoding="utf-8")
    assert RlsHardcodedTenantLiteralGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_hardcoded_tenant_literal_passes_additive_sentinel(tmp_path: Path) -> None:
    # The literal comparison is one OR-disjunct alongside a real per-request scope, not the
    # sole discriminator -- a legitimate "mark shared rows too" pattern pgrls itself
    # documents as a non-finding. This guard's narrower whole-clause-only scope means it
    # stays silent here (a disclosed false-negative trade, not a claim of full recall).
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs "
        "USING (tenant_id = 1 OR tenant_id = current_setting('app.tenant_id')::int);\n", encoding="utf-8"
    )
    assert RlsHardcodedTenantLiteralGuard().run(tmp_path, _sqlprof(tmp_path)) == []
