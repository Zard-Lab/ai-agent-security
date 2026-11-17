from __future__ import annotations

from agentsec.guards.rls_auth_users_unbound_exists import RlsAuthUsersUnboundExistsGuard
from tests.guards._common import *  # noqa: F401,F403


def test_rls_auth_users_unbound_exists_fires(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (EXISTS (SELECT 1 FROM auth.users "
        "WHERE raw_app_meta_data ->> 'role' = 'admin'));\n", encoding="utf-8"
    )
    findings = RlsAuthUsersUnboundExistsGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rls-auth-users-unbound-exists/no-caller-binding"
    assert findings[0].severity == "high"

def test_rls_auth_users_unbound_exists_fires_with_check(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs FOR INSERT WITH CHECK "
        "(EXISTS (SELECT 1 FROM auth.users WHERE raw_app_meta_data ->> 'role' = 'admin'));\n", encoding="utf-8"
    )
    assert len(RlsAuthUsersUnboundExistsGuard().run(tmp_path, _sqlprof(tmp_path))) == 1

def test_rls_auth_users_unbound_exists_fires_on_quoted_pg_dump_spelling(tmp_path: Path) -> None:
    # H6 (Dean's review, PR #893 review): pg_dump quotes every identifier — the unbound
    # violation on `FROM "auth"."users"` went completely undetected before the fix.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        'CREATE POLICY p ON public.docs USING (EXISTS (SELECT 1 FROM "auth"."users" '
        "WHERE role='admin'));\n", encoding="utf-8"
    )
    findings = RlsAuthUsersUnboundExistsGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rls-auth-users-unbound-exists/no-caller-binding"

def test_rls_auth_users_unbound_exists_pragma_opt_out(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (EXISTS (SELECT 1 FROM auth.users "
        "WHERE raw_app_meta_data ->> 'role' = 'admin'));  -- security: allow-auth-users-unbound-exists\n", encoding="utf-8"
    )
    assert RlsAuthUsersUnboundExistsGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_auth_users_unbound_exists_skips_comment(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "-- CREATE POLICY p ON public.docs USING (EXISTS (SELECT 1 FROM auth.users "
        "WHERE raw_app_meta_data ->> 'role' = 'admin'));\n", encoding="utf-8"
    )
    assert RlsAuthUsersUnboundExistsGuard().run(tmp_path, _sqlprof(tmp_path)) == []

# --- FP-bait ------------------------------------------------------------------------------

def test_rls_auth_users_unbound_exists_passes_bound_with_auth_uid(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (EXISTS (SELECT 1 FROM auth.users "
        "WHERE id = auth.uid() AND raw_app_meta_data ->> 'role' = 'admin'));\n", encoding="utf-8"
    )
    assert RlsAuthUsersUnboundExistsGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_auth_users_unbound_exists_passes_bound_with_quoted_auth_uid(tmp_path: Path) -> None:
    # H3 (Dean's review, PR #893 review): a CORRECTLY bound policy using pg_dump's quoted
    # "auth"."uid"() spelling was misread as unbound and fired HIGH on safe code before the fix.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        'CREATE POLICY p ON public.docs USING (EXISTS (SELECT 1 FROM auth.users '
        'WHERE id = "auth"."uid"() AND raw_app_meta_data ->> \'role\' = \'admin\'));\n', encoding="utf-8"
    )
    assert RlsAuthUsersUnboundExistsGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_auth_users_unbound_exists_passes_unrelated_table(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (EXISTS (SELECT 1 FROM team_members "
        "WHERE role = 'admin'));\n", encoding="utf-8"
    )
    assert RlsAuthUsersUnboundExistsGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_auth_users_unbound_exists_passes_no_exists(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text("CREATE POLICY p ON public.docs USING (owner_id = auth.uid());\n", encoding="utf-8")
    assert RlsAuthUsersUnboundExistsGuard().run(tmp_path, _sqlprof(tmp_path)) == []
