"""Cross-guard pins for #1040 T2: the SQL guards' suppress pragma counts only as a real comment,
read from the SQL comment view at the guard's own slice, and that view reads a `$$` body as code.

Both directions, per CLAUDE.md rule 1, against each guard's own violation:

- the 17 T2 guards (converted from a raw match on the line or statement window):
  - widening (must FIRE): the pragma phrase inside a `'…'` literal and a `"…"` identifier holding
    a `;` on the violation's own line, which the raw match read as an opt-out;
  - must stay SILENT: a real comment on that line, and a real comment inside the `DO` body the
    violation is written in (rule 4: the converted check must keep every opt-out the raw one had);
  - reach (must FIRE): a real comment two statements above, outside every window, still does not
    reach the violation, so the conversion did not widen any scope.
- every SQL guard with a pragma whose detection reads a `DO` body: its canary `.sql` plants, wrapped
  in one, are silenced by a real pragma comment on each line. Before T2 the view read a body as
  literal, so this failed in every already-anchored SQL guard; the opt-out written in the common
  idempotent `DO $$ BEGIN … CREATE POLICY … END $$;` migration did nothing.

Each case is measured against the same guard's plain violation (the control), so a violation that
stopped firing on its own fails as a broken control, not as a passing case.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from agentsec.canary import _FILES
from agentsec.detect import StackProfile, detect
from agentsec.guards.auth_users_exposed_view import AuthUsersExposedViewGuard
from agentsec.guards.base import Guard
from agentsec.guards.definer_function_grants import DefinerFunctionGrantsGuard
from agentsec.guards.pg_role_bypassrls_membership import PgRoleBypassrlsMembershipGuard
from agentsec.guards.policy_exists_rls_disabled import PolicyExistsRlsDisabledGuard
from agentsec.guards.policy_no_role_scope import PolicyNoRoleScopeGuard
from agentsec.guards.rls_anon_write_access import RlsAnonWriteAccessGuard
from agentsec.guards.rls_auth_email_lockout import RlsAuthEmailLockoutGuard
from agentsec.guards.rls_auth_role_unknown_literal import RlsAuthRoleUnknownLiteralGuard
from agentsec.guards.rls_auth_users_unbound_exists import RlsAuthUsersUnboundExistsGuard
from agentsec.guards.rls_current_setting_unqualified import RlsCurrentSettingUnqualifiedGuard
from agentsec.guards.rls_current_user_tenant_key import RlsCurrentUserTenantKeyGuard
from agentsec.guards.rls_hardcoded_tenant_literal import RlsHardcodedTenantLiteralGuard
from agentsec.guards.rls_inverted_auth_check import RlsInvertedAuthCheckGuard
from agentsec.guards.rls_no_user_metadata_claim import RlsNoUserMetadataClaimGuard
from agentsec.guards.rls_pattern_match_auth_context import RlsPatternMatchAuthContextGuard
from agentsec.guards.rls_permissive_policy import RlsPermissivePolicyGuard
from agentsec.guards.rls_update_privileged_column import RlsUpdatePrivilegedColumnGuard
from agentsec.registry import ALL_GUARDS
from tests.test_pragma_anchoring import _body, _pragma_tokens

_RLS_ON = "ALTER TABLE public.t ENABLE ROW LEVEL SECURITY; "

# (violation on ONE line, free of `--`, `/*` and `$` unless the guard needs one; its pragma).
_VIOLATIONS: dict[type[Guard], tuple[str, str]] = {
    AuthUsersExposedViewGuard: (
        "CREATE VIEW public.user_emails AS SELECT id, email FROM auth.users;", "allow-auth-users-view"
    ),
    DefinerFunctionGrantsGuard: (
        "CREATE OR REPLACE FUNCTION public.is_admin(uid uuid) RETURNS boolean LANGUAGE sql "
        "SECURITY DEFINER AS $$ SELECT true $$;",
        "allow-definer-public",
    ),
    PgRoleBypassrlsMembershipGuard: (
        "CREATE ROLE admin BYPASSRLS NOLOGIN; CREATE ROLE app LOGIN; GRANT admin TO app;",
        "allow-role-bypassrls-membership",
    ),
    PolicyExistsRlsDisabledGuard: (
        "CREATE TABLE public.t (id int, owner_id uuid); "
        "CREATE POLICY p ON public.t FOR SELECT TO authenticated USING (owner_id = (select auth.uid()));",
        "allow-policy-without-rls",
    ),
    PolicyNoRoleScopeGuard: (
        "CREATE POLICY published_docs ON public.profiles USING (status = 'published');",
        "allow-policy-no-role-scope",
    ),
    RlsAnonWriteAccessGuard: (
        _RLS_ON + "CREATE POLICY p ON public.t FOR INSERT TO anon WITH CHECK (true);", "allow-anon-write-access"
    ),
    RlsAuthEmailLockoutGuard: (
        _RLS_ON + "CREATE POLICY p ON public.t USING (owner_email = auth.email());", "allow-auth-email-lockout"
    ),
    RlsAuthRoleUnknownLiteralGuard: (
        _RLS_ON + "CREATE POLICY p ON public.t USING (auth.role() = 'admin');", "allow-auth-role-unknown-literal"
    ),
    RlsAuthUsersUnboundExistsGuard: (
        _RLS_ON + "CREATE POLICY p ON public.t USING "
        "(EXISTS (SELECT 1 FROM auth.users WHERE raw_app_meta_data ->> 'role' = 'admin'));",
        "allow-auth-users-unbound-exists",
    ),
    RlsCurrentSettingUnqualifiedGuard: (
        _RLS_ON + "CREATE POLICY p ON public.t USING (tenant_id = current_setting('tenant_id', true)::int);",
        "allow-current-setting-unqualified",
    ),
    RlsCurrentUserTenantKeyGuard: (
        _RLS_ON + "CREATE POLICY p ON public.t USING (owner_role = current_user);", "allow-current-user-tenant-key"
    ),
    RlsHardcodedTenantLiteralGuard: (
        _RLS_ON + "CREATE POLICY p ON public.t USING (tenant_id = 1);", "allow-hardcoded-tenant-literal"
    ),
    RlsInvertedAuthCheckGuard: (
        _RLS_ON + "CREATE POLICY p ON public.t USING (auth.uid() IS NULL OR owner_id = auth.uid());",
        "allow-inverted-auth-check",
    ),
    RlsNoUserMetadataClaimGuard: (
        "CREATE POLICY p ON t USING ((auth.jwt() ->> 'user_metadata') = 'admin');", "allow-user-metadata-claim"
    ),
    RlsPatternMatchAuthContextGuard: (
        _RLS_ON + "CREATE POLICY p ON public.t USING (user_email ILIKE current_setting('app.email'));",
        "allow-pattern-match-auth-context",
    ),
    RlsPermissivePolicyGuard: (
        _RLS_ON + "CREATE POLICY p ON public.t FOR SELECT TO authenticated USING (true);", "allow-permissive-policy"
    ),
    RlsUpdatePrivilegedColumnGuard: (
        "CREATE TABLE public.user_profiles (id uuid PRIMARY KEY, full_name text, "
        "is_admin boolean default false, tokens integer default 0); "
        'CREATE POLICY "own profile" ON public.user_profiles FOR UPDATE TO authenticated '
        "USING (auth.uid() = id) WITH CHECK (auth.uid() = id AND is_admin IS NOT DISTINCT FROM false);",
        "allow-self-update-privileged-column",
    ),
}
_CASES = sorted(_VIOLATIONS.items(), key=lambda kv: kv[0].__name__)
_IDS = [cls.__name__ for cls, _ in _CASES]

# The DO-body wrapper's tag: a guard violation may carry its own `$$` body, which a `$$` wrapper
# would close early.
_TAG = "$agentsec_do$"


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


@pytest.mark.parametrize(("cls", "case"), _CASES, ids=_IDS)
def test_a_pragma_in_a_literal_or_identifier_on_the_line_does_not_suppress(
    tmp_path: Path, cls: type[Guard], case: tuple[str, str]
) -> None:
    violation, token = case
    guard = cls()
    expected = _control(tmp_path, guard, violation)
    pragma = f"-- security: {token}"
    sql = f"{violation} SELECT '{pragma}', \"x ; {pragma}\";\n"
    assert _count(tmp_path, guard, sql) == expected


@pytest.mark.parametrize(("cls", "case"), _CASES, ids=_IDS)
def test_a_real_comment_on_the_line_still_suppresses(tmp_path: Path, cls: type[Guard], case: tuple[str, str]) -> None:
    violation, token = case
    guard = cls()
    _control(tmp_path, guard, violation)
    assert _count(tmp_path, guard, f"{violation}  -- security: {token}\n") == 0


@pytest.mark.parametrize(("cls", "case"), _CASES, ids=_IDS)
def test_a_real_comment_inside_a_do_body_still_suppresses(
    tmp_path: Path, cls: type[Guard], case: tuple[str, str]
) -> None:
    violation, token = case
    guard = cls()
    expected = _control(tmp_path, guard, violation)
    body = f"DO {_TAG} BEGIN\n  {violation}{{}}\nEND {_TAG};\n"
    assert _count(tmp_path, guard, body.format("")) == expected, "the guard must read the DO body (control)"
    assert _count(tmp_path, guard, body.format(f"  -- security: {token}")) == 0


@pytest.mark.parametrize(("cls", "case"), _CASES, ids=_IDS)
def test_a_real_comment_outside_the_window_does_not_reach(
    tmp_path: Path, cls: type[Guard], case: tuple[str, str]
) -> None:
    violation, token = case
    guard = cls()
    expected = _control(tmp_path, guard, violation)
    sql = f"-- security: {token}\nSELECT 1;\nSELECT 2;\n{violation}\n"
    assert _count(tmp_path, guard, sql) == expected


def test_definer_function_grants_reads_a_comment_after_as_dollar() -> None:
    """The CREATE line of a multi-line function ends `AS $$`, so a trailing comment on it lies inside
    the body, which the view now reads as code (#1040 T2); a quoted phrase there still does not count."""
    head = "CREATE FUNCTION public.f() RETURNS boolean LANGUAGE sql SECURITY DEFINER AS $$"
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        guard = DefinerFunctionGrantsGuard()
        assert _count(tmp, guard, f"{head}  -- security: allow-definer-public\n  SELECT true\n$$;\n") == 0
        assert _count(tmp, guard, f"{head}\n  SELECT 'security: allow-definer-public'\n$$;\n") == 1


# -- every SQL guard: the canary `.sql` plants inside a DO body -----------------------------------
_SQL_PLANTS = {p: c for p, c in _FILES.items() if p.endswith(".sql")}
_SCAFFOLD = {"requirements.txt": "supabase\nfastapi\n", "supabase/config.toml": "[api]\nport = 54321\n"}

# Guards whose detection does not read a statement inside a DO body at all, so a wrapped plant
# cannot fire and the comment has nothing to suppress: exact, so a guard that starts reading
# bodies fails here until it is measured (and must then honour an in-body opt-out).
_NO_DO_BODY_DETECTION: dict[str, str] = {
    "definer-dynamic-sql": "reads structure on `_mask_quoted`, which spaces out dollar-body content, the wrapper's too",
    "supabase-vault-exposure": "reads structure with dollar bodies masked (`blank_sql_literals`), the wrapper's too",
}


def _plant(root: Path, files: dict[str, str]) -> StackProfile:
    for p, c in {**_SCAFFOLD, **files}.items():
        (root / p).parent.mkdir(parents=True, exist_ok=True)
        (root / p).write_text(c, encoding="utf-8", newline="")
    return detect(root)


def _sql_findings(guard: Guard, files: dict[str, str]) -> int | None:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        profile = _plant(root, files)
        if not guard.applies(profile):
            return None
        return sum(
            1 for f in guard.run(root, profile) if f.location.replace("\\", "/").split(":")[0].endswith(".sql")
        )


def _wrap(content: str, comment: str) -> str:
    lines = content.rstrip("\n").split("\n")
    if comment:
        lines = [f"{ln}  {comment}" if ln.strip() else ln for ln in lines]
    return f"DO {_TAG} BEGIN\n" + "\n".join(lines) + f"\nEND {_TAG};\n"


def _applying_guards() -> list[Guard]:
    # Collection-time selection stays cheap (one detect, no guard run): every guard with a pragma
    # that applies to the plants' stack. Whether its plain plants FIRE is decided in the test body,
    # so a collection never pays a run of every guard (#1125 round 1, M3).
    with tempfile.TemporaryDirectory() as d:
        profile = _plant(Path(d), _SQL_PLANTS)
        return [g for g in ALL_GUARDS if _pragma_tokens(g) and g.applies(profile)]


_APPLYING = _applying_guards()
_SWEEP_ANCHORS = {"pg-role-bypassrls", "rls-permissive-policy", "policy-no-role-scope", "storage-no-rls"}


def test_the_do_body_sweep_reaches_the_sql_guards() -> None:
    # Not vacuous: the sweep below returns early for a guard none of whose plain plants fires, so
    # pin that the plant set really holds a firing violation for these SQL guards.
    by_id = {g.id: g for g in _APPLYING}
    for gid in sorted(_SWEEP_ANCHORS | set(_NO_DO_BODY_DETECTION)):
        assert gid in by_id, f"{gid} no longer applies to the SQL plants' stack"
        assert _sql_findings(by_id[gid], _SQL_PLANTS), f"{gid}: its plain SQL plants no longer fire"


@pytest.mark.slow
@pytest.mark.parametrize("guard", _APPLYING, ids=[g.id for g in _APPLYING])
def test_a_real_comment_inside_a_do_body_suppresses_every_sql_guard(guard: Guard) -> None:
    if not _sql_findings(guard, _SQL_PLANTS):
        # No plain SQL plant of this guard fires: it does not detect in SQL, so nothing to wrap.
        assert guard.id not in _NO_DO_BODY_DETECTION and guard.id not in _SWEEP_ANCHORS
        return
    comment = "-- " + _body(_pragma_tokens(guard))
    wrapped = _sql_findings(guard, {p: _wrap(c, "") for p, c in _SQL_PLANTS.items()})
    if guard.id in _NO_DO_BODY_DETECTION:
        assert wrapped == 0, f"{guard.id} now reads a DO body: drop it from _NO_DO_BODY_DETECTION"
        return
    assert wrapped, f"{guard.id}: no finding from the wrapped plants; pin it in _NO_DO_BODY_DETECTION with why"
    commented = _sql_findings(guard, {p: _wrap(c, comment) for p, c in _SQL_PLANTS.items()})
    assert commented == 0, f"{guard.id}: a real pragma comment inside the DO body left {commented} of {wrapped}"
