from __future__ import annotations

from agentsec.guards.rls_auth_email_lockout import RlsAuthEmailLockoutGuard
from tests.guards._common import *  # noqa: F401,F403


def test_rls_auth_email_lockout_fires(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (owner_email = auth.email());\n",
        encoding="utf-8",
    )
    findings = RlsAuthEmailLockoutGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rls-auth-email-lockout/gated-on-email"
    assert findings[0].severity == "medium"

def test_rls_auth_email_lockout_fires_with_check(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs FOR INSERT WITH CHECK (owner_email = auth.email());\n",
        encoding="utf-8",
    )
    assert len(RlsAuthEmailLockoutGuard().run(tmp_path, _sqlprof(tmp_path))) == 1

def test_rls_auth_email_lockout_pragma_opt_out(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (owner_email = auth.email());"
        "  -- security: allow-auth-email-lockout\n",
        encoding="utf-8",
    )
    assert RlsAuthEmailLockoutGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_auth_email_lockout_skips_comment(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "-- CREATE POLICY p ON public.docs USING (owner_email = auth.email());\n",
        encoding="utf-8",
    )
    assert RlsAuthEmailLockoutGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_auth_email_lockout_passes_auth_uid(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text("CREATE POLICY p ON public.docs USING (owner_id = auth.uid());\n", encoding="utf-8")
    assert RlsAuthEmailLockoutGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_auth_email_lockout_fires_on_quoted_identifier_form(tmp_path: Path) -> None:
    """Regression (Dean's review, PR #893 review): pg_dump/migration-tool output spells this
    call quoted (`"auth"."email"()`), the flagship's own real shape — was silent before the fix,
    the same H3/H5/H6 root cause 3 other guards already had."""
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        'CREATE POLICY p ON public.docs USING (owner_email = "auth"."email"());\n',
        encoding="utf-8",
    )
    findings = RlsAuthEmailLockoutGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rls-auth-email-lockout/gated-on-email"


def test_rls_auth_email_lockout_passes_quoted_non_auth_schema(tmp_path: Path) -> None:
    # FP-bait for the quoted-form widening (PR #893 re-review MEDIUM #A): `pg_auth_call_pattern`
    # matches only the `auth` schema, so a same-shaped call on ANOTHER schema
    # (`"public"."email"()`) is not auth.email() and must stay silent.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        'CREATE POLICY p ON public.docs USING (owner_email = "public"."email"());\n',
        encoding="utf-8",
    )
    assert RlsAuthEmailLockoutGuard().run(tmp_path, _sqlprof(tmp_path)) == []
