from __future__ import annotations

from agentsec.guards.rls_inverted_auth_check import RlsInvertedAuthCheckGuard
from tests.guards._common import *  # noqa: F401,F403


def test_rls_inverted_auth_flags_using_is_null_or(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (auth.uid() IS NULL OR owner_id = auth.uid());\n", encoding="utf-8"
    )
    findings = RlsInvertedAuthCheckGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rls-inverted-auth-check/is-null-or-bypass"
    assert findings[0].severity == "high"

def test_rls_inverted_auth_flags_quoted_pg_dump_spelling(tmp_path: Path) -> None:
    # H5 (Dean's review, PR #893 review): pg_dump/migration-tool output quotes every
    # identifier ("auth"."uid"()) — the flagship's own schema shape. Verified failing before
    # the fix (0 findings; the unquoted form fired correctly).
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        'CREATE POLICY p ON public.docs USING ("auth"."uid"() IS NULL OR '
        'owner_id = "auth"."uid"());\n', encoding="utf-8"
    )
    findings = RlsInvertedAuthCheckGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rls-inverted-auth-check/is-null-or-bypass"

def test_rls_inverted_auth_flags_reversed_order(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (owner_id = auth.uid() OR auth.uid() IS NULL);\n", encoding="utf-8"
    )
    findings = RlsInvertedAuthCheckGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity == "high"

def test_rls_inverted_auth_flags_with_check(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs FOR INSERT "
        "WITH CHECK (auth.uid() IS NULL OR owner_id = auth.uid());\n", encoding="utf-8"
    )
    findings = RlsInvertedAuthCheckGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert "WITH CHECK" in findings[0].message
    assert "USING" not in findings[0].message.split("clause")[0]

def test_rls_inverted_auth_both_clauses_one_finding(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs FOR ALL "
        "USING (auth.uid() IS NULL OR owner_id = auth.uid()) "
        "WITH CHECK (auth.uid() IS NULL OR owner_id = auth.uid());\n", encoding="utf-8"
    )
    findings = RlsInvertedAuthCheckGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert "USING and WITH CHECK" in findings[0].message

def test_rls_inverted_auth_current_setting_two_arg_true(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs "
        "USING (current_setting('app.tenant_id', true) IS NULL OR tenant_id::text = current_setting('app.tenant_id', true));\n", encoding="utf-8"
    )
    findings = RlsInvertedAuthCheckGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1

def test_rls_inverted_auth_named_role_is_medium(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs TO authenticated "
        "USING (auth.uid() IS NULL OR owner_id = auth.uid());\n", encoding="utf-8"
    )
    findings = RlsInvertedAuthCheckGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity == "medium"

def test_rls_inverted_auth_pragma_opt_out(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (auth.uid() IS NULL OR owner_id = auth.uid());"
        "  -- security: allow-inverted-auth-check\n", encoding="utf-8"
    )
    assert RlsInvertedAuthCheckGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_inverted_auth_skips_comment(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "-- CREATE POLICY p ON public.docs USING (auth.uid() IS NULL OR owner_id = auth.uid());\n", encoding="utf-8"
    )
    assert RlsInvertedAuthCheckGuard().run(tmp_path, _sqlprof(tmp_path)) == []

# --- FP-bait: scoped policies, non-nullable IS NULL checks, AND-gated (not OR) --------------

def test_rls_inverted_auth_passes_scoped_policy(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text("CREATE POLICY p ON public.docs USING (owner_id = auth.uid());\n", encoding="utf-8")
    assert RlsInvertedAuthCheckGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_inverted_auth_passes_current_user_is_null(tmp_path: Path) -> None:
    # current_user is never NULL (no unauthenticated Postgres backend) -- a policy that
    # compares against it can carry an `IS NULL` disjunct on an unrelated column and stay
    # legitimate; current_user itself must never be treated as a nullable auth function.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (current_user IS NULL OR owner_role = current_user);\n", encoding="utf-8"
    )
    assert RlsInvertedAuthCheckGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_inverted_auth_passes_current_setting_one_arg(tmp_path: Path) -> None:
    # The one-arg current_setting() form RAISES on an unset GUC rather than returning NULL --
    # an IS NULL disjunct built on it can never actually be satisfied.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs "
        "USING (current_setting('app.tenant_id') IS NULL OR tenant_id::text = current_setting('app.tenant_id'));\n", encoding="utf-8"
    )
    assert RlsInvertedAuthCheckGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_inverted_auth_passes_and_gated_is_null(tmp_path: Path) -> None:
    # auth.uid() IS NULL gated by AND (not OR) is not a standalone anonymous-access hole --
    # it NARROWS the policy rather than opening it.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs USING (is_archived = false AND auth.uid() IS NULL);\n", encoding="utf-8"
    )
    assert RlsInvertedAuthCheckGuard().run(tmp_path, _sqlprof(tmp_path)) == []
