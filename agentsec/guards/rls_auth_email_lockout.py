"""Guard: RLS policy gates on auth.email() (pgrls SEC034).

A policy that scopes rows by email — `USING (owner_email = auth.email())` — ships with three
subtle failure modes that are not exploits but are footguns. The cumulative behavior is silent
data lockout, not privilege escalation:

1. **Email change flow.** Supabase auth supports user-initiated email change. The new email
   lands in the JWT after verification; rows owned by the old email are now invisible to the
   user who owns them. Repair requires a manual UPDATE on every email-keyed table.
2. **Case sensitivity.** SQL `=` is case-sensitive; email handling is conventionally
   case-insensitive. `User@Example.com` stored vs `user@example.com` in the JWT never matches —
   silent deny.
3. **Plus-addressing / aliasing.** `user+tag@gmail.com` and `user@gmail.com` reach the same
   inbox but compare unequal.

The canonical fix is to scope by `auth.uid()` (immutable per user, normalized) and treat email as
a display value only, never a row-matching key.

Fires on any policy `USING`/`WITH CHECK` clause containing `auth.email()`.

Suppress: `-- security: allow-auth-email-lockout` on the statement's own line (or anywhere in the
same file).

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
    pg_auth_call_pattern,
    read,
    rel,
    strip_sql_comments,
)
from .rls_inverted_auth_check import _USING_HEAD, _WITH_CHECK_HEAD, _clause_body
from .rls_permissive_policy import _CREATE_POLICY_HEAD

# Was anchored to the bare `auth.email()` spelling only, so a pg_dump/migration-tool
# `"auth"."email"()` quoted form (the flagship's own shape) was silent — the same H3/H5/H6
# root cause Dean's review found in 3 other guards (Dean's follow-up review, PR #893).
_AUTH_EMAIL = re.compile(pg_auth_call_pattern("email"), re.IGNORECASE)
_PRAGMA = re.compile(r"--\s*security:\s*allow-auth-email-lockout")


class RlsAuthEmailLockoutGuard(Guard):
    id = "rls-auth-email-lockout"
    title = "RLS policy gates on auth.email() — email-change / case / plus-addressing silent lockout"
    area = "Database"
    schema_state = True

    canary_plant = CanaryPlant(
        files={
            "sql/rls_auth_email_lockout.sql": (
                "CREATE TABLE public.canary_email_gated (id uuid PRIMARY KEY, owner_email text);\n"
                "ALTER TABLE public.canary_email_gated ENABLE ROW LEVEL SECURITY;\n"
                "CREATE POLICY canary_email_gated_p ON public.canary_email_gated "
                "USING (owner_email = auth.email());\n"
            ),
        },
        expects=frozenset({"rls-auth-email-lockout/gated-on-email"}),
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
                if not (_AUTH_EMAIL.search(using_body) or _AUTH_EMAIL.search(check_body)):
                    continue
                loc = f"{rel(root, f)}:{s_line + 1}"
                out.append(self._finding(loc))
        return out

    def _finding(self, loc: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="medium",
            title=self.title,
            location=loc,
            message=(
                "This RLS policy gates row visibility on `auth.email()`. Three silent lockout "
                "modes: (1) after a user-initiated email change, rows owned by the old email "
                "become invisible to the user who owns them; (2) SQL `=` is case-sensitive while "
                "email handling conventionally isn't, so a stored/JWT case mismatch silently "
                "denies; (3) plus-addressing (`user+tag@x.com` vs `user@x.com`) compares unequal "
                "though both reach the same inbox. This is data lockout, not privilege "
                "escalation, but it's silent and easy to miss in review."
            ),
            remediation=(
                "Scope by `auth.uid()` instead (immutable per user, normalized) and treat email "
                "as a display value only, never a row-matching key. If this is intentional, "
                "suppress with `-- security: allow-auth-email-lockout`."
            ),
            rule="rls-auth-email-lockout/gated-on-email",
            standards=["OWASP:A01"],
        )
