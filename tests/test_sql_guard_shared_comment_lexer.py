"""Cross-guard pin for #442 phase 2b: the 15 SQL-statement guards that ran a private comment
lexer now read `strip_sql_comments(sql, blank=True)`, and each one gets the shared lexer's
verdict on the four shapes where the private lexers disagreed with it.

Both directions, per CLAUDE.md rule 1, against each guard's own violation:

- widening (must FIRE): a `$$…/*…$$` body before the violation and a `*/` after it (the #602
  shape: the private copies handled it, and the shared lexer only does since #442 phase 2a), and a
  `--` inside a string literal earlier on the violation's line (the private `--[^\\n]*` blank
  was not string-aware, so it hid the violation);
- narrowing (must stay SILENT): the violation `/* */`-commented inside a `DO` body (the private
  copies' block pass skipped dollar bodies as opaque, so the comment stayed live), and the
  violation as a `COPY … FROM stdin` data row (the private copies lexed data rows as SQL).

Each case is measured against the same guard's plain violation (the control), so a violation
that stopped firing on its own fails as a broken control, not as a passing narrowing. The two
narrowing shapes fire on the pre-2b tree (measured in all 15 guards), so they reach the change.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from agentsec.detect import StackProfile
from agentsec.guards.auth_users_exposed_view import AuthUsersExposedViewGuard
from agentsec.guards.base import Guard
from agentsec.guards.policy_exists_rls_disabled import PolicyExistsRlsDisabledGuard
from agentsec.guards.rls_anon_write_access import RlsAnonWriteAccessGuard
from agentsec.guards.rls_auth_email_lockout import RlsAuthEmailLockoutGuard
from agentsec.guards.rls_auth_role_unknown_literal import RlsAuthRoleUnknownLiteralGuard
from agentsec.guards.rls_auth_uid_unwrapped import RlsAuthUidUnwrappedGuard
from agentsec.guards.rls_auth_users_unbound_exists import RlsAuthUsersUnboundExistsGuard
from agentsec.guards.rls_current_setting_unqualified import RlsCurrentSettingUnqualifiedGuard
from agentsec.guards.rls_current_user_tenant_key import RlsCurrentUserTenantKeyGuard
from agentsec.guards.rls_hardcoded_tenant_literal import RlsHardcodedTenantLiteralGuard
from agentsec.guards.rls_inverted_auth_check import RlsInvertedAuthCheckGuard
from agentsec.guards.rls_multiple_permissive_policies import RlsMultiplePermissivePoliciesGuard
from agentsec.guards.rls_pattern_match_auth_context import RlsPatternMatchAuthContextGuard
from agentsec.guards.rls_permissive_policy import RlsPermissivePolicyGuard
from agentsec.guards.sensitive_columns import SensitiveColumnsGuard

_RLS_ON = "ALTER TABLE public.t ENABLE ROW LEVEL SECURITY; "

# One minimal violation per guard, each on a single line and free of `--`, `/*` and `$`, so the
# wrappers below are the only comment or dollar syntax in the file.
_VIOLATIONS: dict[type[Guard], str] = {
    RlsPermissivePolicyGuard: _RLS_ON
    + "CREATE POLICY p ON public.t FOR SELECT TO authenticated USING (true);",
    RlsMultiplePermissivePoliciesGuard: _RLS_ON
    + "CREATE POLICY a ON public.t FOR SELECT TO authenticated USING (owner_id = (select auth.uid())); "
    + "CREATE POLICY b ON public.t FOR SELECT TO authenticated USING (team_id = 7);",
    PolicyExistsRlsDisabledGuard: "CREATE TABLE public.t (id int, owner_id uuid); "
    + "CREATE POLICY p ON public.t FOR SELECT TO authenticated USING (owner_id = (select auth.uid()));",
    AuthUsersExposedViewGuard: "CREATE VIEW public.user_emails AS SELECT id, email FROM auth.users;",
    RlsAuthUidUnwrappedGuard: "CREATE POLICY p ON public.t FOR SELECT USING (auth.uid() = user_id);",
    SensitiveColumnsGuard: "CREATE TABLE public.accounts (id uuid PRIMARY KEY, password text NOT NULL);",
    RlsAnonWriteAccessGuard: _RLS_ON + "CREATE POLICY p ON public.t FOR INSERT TO anon WITH CHECK (true);",
    RlsAuthEmailLockoutGuard: _RLS_ON + "CREATE POLICY p ON public.t USING (owner_email = auth.email());",
    RlsAuthRoleUnknownLiteralGuard: _RLS_ON + "CREATE POLICY p ON public.t USING (auth.role() = 'admin');",
    RlsAuthUsersUnboundExistsGuard: _RLS_ON
    + "CREATE POLICY p ON public.t USING "
    + "(EXISTS (SELECT 1 FROM auth.users WHERE raw_app_meta_data ->> 'role' = 'admin'));",
    RlsCurrentSettingUnqualifiedGuard: _RLS_ON
    + "CREATE POLICY p ON public.t USING (tenant_id = current_setting('tenant_id', true)::int);",
    RlsCurrentUserTenantKeyGuard: _RLS_ON + "CREATE POLICY p ON public.t USING (owner_role = current_user);",
    RlsHardcodedTenantLiteralGuard: _RLS_ON + "CREATE POLICY p ON public.t USING (tenant_id = 1);",
    RlsInvertedAuthCheckGuard: _RLS_ON
    + "CREATE POLICY p ON public.t USING (auth.uid() IS NULL OR owner_id = auth.uid());",
    RlsPatternMatchAuthContextGuard: _RLS_ON
    + "CREATE POLICY p ON public.t USING (user_email ILIKE current_setting('app.email'));",
}
_CASES = sorted(_VIOLATIONS.items(), key=lambda kv: kv[0].__name__)
_IDS = [cls.__name__ for cls, _ in _CASES]


def _count(tmp_path: Path, guard: Guard, sql: str) -> int:
    (tmp_path / "sql").mkdir(exist_ok=True)
    (tmp_path / "sql" / "m.sql").write_text(sql, encoding="utf-8")
    profile = StackProfile(root=tmp_path, features={"sql", "postgres", "supabase", "rls"}, sql_dir="sql")
    assert guard.applies(profile)
    return len(guard.run(tmp_path, profile))


def _control(tmp_path: Path, guard: Guard, violation: str) -> int:
    n = _count(tmp_path, guard, violation + "\n")
    assert n >= 1, f"{type(guard).__name__}: the plain violation no longer fires (broken control)"
    return n


@pytest.mark.parametrize(("cls", "violation"), _CASES, ids=_IDS)
def test_dollar_body_comment_opener_does_not_hide_a_later_violation(
    tmp_path: Path, cls: type[Guard], violation: str
) -> None:
    guard = cls()
    expected = _control(tmp_path, guard, violation)
    sql = "COMMENT ON FUNCTION f() IS $$See docs/*.md$$;\n" + violation + "\n/* note */\n"
    assert _count(tmp_path, guard, sql) == expected


@pytest.mark.parametrize(("cls", "violation"), _CASES, ids=_IDS)
def test_double_dash_inside_a_literal_does_not_hide_the_violation(
    tmp_path: Path, cls: type[Guard], violation: str
) -> None:
    guard = cls()
    expected = _control(tmp_path, guard, violation)
    assert _count(tmp_path, guard, "SELECT 'x--y'; " + violation + "\n") == expected


@pytest.mark.parametrize(("cls", "violation"), _CASES, ids=_IDS)
def test_violation_block_commented_inside_a_do_body_stays_silent(
    tmp_path: Path, cls: type[Guard], violation: str
) -> None:
    guard = cls()
    _control(tmp_path, guard, violation)
    assert _count(tmp_path, guard, "DO $do$ BEGIN /* " + violation + " */ END $do$;\n") == 0


@pytest.mark.parametrize(("cls", "violation"), _CASES, ids=_IDS)
def test_violation_shaped_copy_data_row_stays_silent(
    tmp_path: Path, cls: type[Guard], violation: str
) -> None:
    guard = cls()
    _control(tmp_path, guard, violation)
    assert _count(tmp_path, guard, "COPY public.seed FROM stdin;\n" + violation + "\n\\.\n") == 0
