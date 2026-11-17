"""Guard: policy EXISTS sub-select against auth.users has no caller binding (pgrls SEC036).

The exploit is a one-line omission. The correct shape:

    USING (EXISTS (SELECT 1 FROM auth.users
                   WHERE id = auth.uid()
                     AND raw_app_meta_data ->> 'role' = 'admin'))

— a per-user admin check. The buggy variant drops the `id = auth.uid()` clause:

    USING (EXISTS (SELECT 1 FROM auth.users
                   WHERE raw_app_meta_data ->> 'role' = 'admin'))

— which evaluates to "is there ANY admin in the system?" rather than "is the CALLING user an
admin." If there's any admin at all, every authenticated user passes. The SQL still parses, the
test passes when an admin is present in the test DB, the production exploit is silent and
deterministic.

Fires when a policy's `USING`/`WITH CHECK` clause contains an `EXISTS (SELECT ... FROM
auth.users ...)` sub-select whose body carries no caller-binding signal — a call to `auth.uid()`,
`auth.role()`, `auth.jwt()`, `current_user`, `session_user`, or `current_setting(...)` anywhere
inside the sub-select.

Suppress: `-- security: allow-auth-users-unbound-exists` on the statement's own line (or anywhere
in the same file).

OWASP:A01.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_view,
    iter_files,
    iter_statement_spans,
    matching_close_paren,
    pg_auth_call_pattern,
    read,
    rel,
    strip_sql_comments,
)
from .rls_inverted_auth_check import _USING_HEAD, _WITH_CHECK_HEAD, _clause_body
from .rls_permissive_policy import _CREATE_POLICY_HEAD

_EXISTS_HEAD = re.compile(r"\bexists\s*\(", re.IGNORECASE)
# H6 (Dean's review, PR #893 review): bare `from auth.users` was an FN on pg_dump's quoted
# `FROM "auth"."users"` spelling — the real unbound-EXISTS violation on the flagship's own
# schema shape went completely undetected.
_FROM_AUTH_USERS = re.compile(r'\bfrom\s+"?auth"?\s*\.\s*"?users"?\b', re.IGNORECASE)
# H3 (Dean's review, PR #893 review): same quoted-identifier gap, opposite direction — a
# CORRECTLY caller-bound policy using the quoted `"auth"."uid"()` spelling was misread as
# unbound and fired HIGH on safe code, since only the bare form counted as a binding signal.
_BINDING_SIGNAL = re.compile(
    pg_auth_call_pattern("uid", "role", "jwt")
    + r"|\bcurrent_user\b|\bsession_user\b|\bcurrent_setting\s*\(",
    re.IGNORECASE,
)
_PRAGMA = re.compile(r"--\s*security:\s*allow-auth-users-unbound-exists")


def _has_unbound_exists_over_auth_users(clause: str) -> bool:
    for m in _EXISTS_HEAD.finditer(clause):
        open_idx = m.end() - 1
        close_idx = matching_close_paren(clause, open_idx)
        if close_idx is None:
            continue
        body = clause[open_idx + 1 : close_idx]
        if not _FROM_AUTH_USERS.search(body):
            continue
        if not _BINDING_SIGNAL.search(body):
            return True
    return False


class RlsAuthUsersUnboundExistsGuard(Guard):
    id = "rls-auth-users-unbound-exists"
    title = "Policy EXISTS-checks auth.users with no caller binding — passes for every authenticated user if anyone matches"
    area = "Database"
    schema_state = True

    canary_plant = CanaryPlant(
        files={
            "sql/rls_auth_users_unbound_exists.sql": (
                "CREATE TABLE public.canary_unbound_exists (id uuid PRIMARY KEY, body text);\n"
                "ALTER TABLE public.canary_unbound_exists ENABLE ROW LEVEL SECURITY;\n"
                "CREATE POLICY canary_unbound_exists_p ON public.canary_unbound_exists "
                "USING (EXISTS (SELECT 1 FROM auth.users "
                "WHERE raw_app_meta_data ->> 'role' = 'admin'));\n"
            ),
        },
        expects=frozenset({"rls-auth-users-unbound-exists/no-caller-binding"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "sql" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        sql_dir = root / profile.sql_dir if profile.sql_dir else root
        out: list[Finding] = []
        for f in iter_files(sql_dir, (".sql",)):
            text = read(f)
            view_lines = comment_view(text, "sql").splitlines()  # same lines: the pragma reads comments only (#1040)
            blanked = strip_sql_comments(text, blank=True)
            for start, end in iter_statement_spans(blanked, _CREATE_POLICY_HEAD):
                stmt = blanked[start:end]
                s_line = blanked.count("\n", 0, start)
                e_line = blanked.count("\n", 0, end)
                window = "\n".join(view_lines[max(0, s_line - 1) : e_line + 1])
                if _PRAGMA.search(window):
                    continue
                using_body = _clause_body(stmt, _USING_HEAD) or ""
                check_body = _clause_body(stmt, _WITH_CHECK_HEAD) or ""
                if not (
                    _has_unbound_exists_over_auth_users(using_body)
                    or _has_unbound_exists_over_auth_users(check_body)
                ):
                    continue
                loc = f"{rel(root, f)}:{s_line + 1}"
                out.append(self._finding(loc))
        return out

    def _finding(self, loc: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=loc,
            message=(
                "This RLS policy's clause contains `EXISTS (SELECT ... FROM auth.users ...)` "
                "with no caller-binding condition (no `auth.uid()`, `auth.role()`, `auth.jwt()`, "
                "`current_user`, `session_user`, or `current_setting(...)` inside the sub-select). "
                "It evaluates to 'does ANY row in auth.users match this condition' rather than "
                "'does the CALLING user match it' — if any user in the system satisfies the "
                "sub-select's condition (e.g. any admin exists), the policy passes for every "
                "authenticated user."
            ),
            remediation=(
                "Bind the sub-select to the caller, e.g. add `AND id = auth.uid()` to the WHERE "
                "clause. If this is intentional (a genuinely system-wide check), suppress with "
                "`-- security: allow-auth-users-unbound-exists`."
            ),
            rule="rls-auth-users-unbound-exists/no-caller-binding",
            standards=["OWASP:A01"],
        )
