from __future__ import annotations

from agentsec.guards.rls_pattern_match_auth_context import RlsPatternMatchAuthContextGuard
from tests.guards._common import *  # noqa: F401,F403


def test_rls_pattern_match_auth_context_fires_column_left(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (user_email ILIKE current_setting('app.email'));\n",
        encoding="utf-8",
    )
    findings = RlsPatternMatchAuthContextGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rls-pattern-match-auth-context/wildcard-shape-controlled"
    assert findings[0].severity == "high"

def test_rls_pattern_match_auth_context_fires_auth_left(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (current_setting('app.pattern') ~ user_email);\n",
        encoding="utf-8",
    )
    assert len(RlsPatternMatchAuthContextGuard().run(tmp_path, _sqlprof(tmp_path))) == 1

def test_rls_pattern_match_auth_context_fires_current_user(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (current_user ILIKE owner_role);\n",
        encoding="utf-8",
    )
    assert len(RlsPatternMatchAuthContextGuard().run(tmp_path, _sqlprof(tmp_path))) == 1

def test_rls_pattern_match_auth_context_passes_current_username_column(tmp_path: Path) -> None:
    # H2 (Dean's review, PR #893 review): `current_user`/`current_role`/`session_user`
    # lacked \b anchors, so they matched as a SUBSTRING of an ordinary column name.
    # `current_username` is a plausible real column, not the identity function.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (owner_id ILIKE current_username);\n",
        encoding="utf-8",
    )
    assert RlsPatternMatchAuthContextGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_pattern_match_auth_context_passes_prefixed_current_role_column(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (mycurrent_role ILIKE owner_role);\n",
        encoding="utf-8",
    )
    assert RlsPatternMatchAuthContextGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_pattern_match_auth_context_passes_custom_session_user_column(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (custom_session_user ILIKE owner_role);\n",
        encoding="utf-8",
    )
    assert RlsPatternMatchAuthContextGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_pattern_match_auth_context_passes_session_username_column(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (session_username ILIKE owner_role);\n",
        encoding="utf-8",
    )
    assert RlsPatternMatchAuthContextGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_pattern_match_auth_context_fires_on_quoted_auth_uid(tmp_path: Path) -> None:
    """Regression (Dean's review, PR #893 review): auth.uid()/auth.role()/auth.jwt() were
    anchored to the bare spelling only, missing the pg_dump/migration-tool `"auth"."uid"()`
    quoted form (the flagship's own real shape) — was silent before the fix."""
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        'CREATE POLICY p ON public.docs USING (owner_id ILIKE "auth"."uid"());\n',
        encoding="utf-8",
    )
    findings = RlsPatternMatchAuthContextGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rls-pattern-match-auth-context/wildcard-shape-controlled"

def test_rls_pattern_match_auth_context_pragma_opt_out(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (user_email ILIKE current_setting('app.email'));"
        "  -- security: allow-pattern-match-auth-context\n",
        encoding="utf-8",
    )
    assert RlsPatternMatchAuthContextGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_pattern_match_auth_context_skips_comment(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "-- CREATE POLICY p ON public.docs USING (user_email ILIKE current_setting('app.email'));\n",
        encoding="utf-8",
    )
    assert RlsPatternMatchAuthContextGuard().run(tmp_path, _sqlprof(tmp_path)) == []

# --- FP-bait ------------------------------------------------------------------------------

def test_rls_pattern_match_auth_context_passes_equality(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (tenant_id = current_setting('app.tenant_id')::int);\n",
        encoding="utf-8",
    )
    assert RlsPatternMatchAuthContextGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_pattern_match_auth_context_passes_hardcoded_pattern(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (user_email LIKE '%@example.com');\n",
        encoding="utf-8",
    )
    assert RlsPatternMatchAuthContextGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_pattern_match_auth_context_passes_auth_vs_literal_pattern(tmp_path: Path) -> None:
    # Auth value on the LEFT compared to a LITERAL pattern -- the author wrote the wildcard,
    # nothing session-controlled drives the shape. pgrls's own documented non-finding.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (current_user LIKE 'admin%');\n",
        encoding="utf-8",
    )
    assert RlsPatternMatchAuthContextGuard().run(tmp_path, _sqlprof(tmp_path)) == []


def test_rls_pattern_match_auth_context_passes_quoted_non_auth_schema(tmp_path: Path) -> None:
    # FP-bait for the quoted-form widening (PR #893 re-review MEDIUM #A): only the `auth` schema\'s
    # quoted call is an auth-context value; a same-shaped call on another schema
    # (`"public"."uid"()`) must stay silent.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        'CREATE POLICY p ON public.docs USING (owner_id ILIKE "public"."uid"());\n',
        encoding="utf-8",
    )
    assert RlsPatternMatchAuthContextGuard().run(tmp_path, _sqlprof(tmp_path)) == []
