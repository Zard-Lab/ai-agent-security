"""Guard: RLS policy keys a row comparison off current_user/session_user (pgrls SEC018).

A policy whose `USING` or `WITH CHECK` clause compares a column against `current_user` or
`session_user` is using *the Postgres role the session runs as* as the row-matching key —
`owner_role = current_user`, for example. That isolates tenants only when every tenant connects
as — or `SET ROLE`s to — a **distinct** Postgres role.

Application architectures almost never do that. A connection pool authenticates as one shared
database role and serves every tenant's requests over it; `current_user` is then identical for
every tenant, so a policy like `USING (owner_role = current_user)` matches the same way for
everyone and provides no isolation at all. The policy looks like access control and reads
correctly in review, but the discriminator is a constant across every request that shares the
pooled connection role.

`session_user` (the original login role, unchanged by `SET ROLE`) has the same problem, and is
strictly worse for the `SET ROLE` pattern: even a deployment that does `SET ROLE tenant_x` per
request leaves `session_user` pinned to the pool's login role.

**Regex-based, not a real parser** — a deliberately narrower approximation of pgrls's real
AST-based SEC018, which resolves the compared column against the table's actual own-column list
and distinguishes a comparison operand from a function argument. This guard fires on a direct
`<identifier> = current_user` / `current_user = <identifier>` (or `session_user`) adjacency —
requiring an `=` comparison excludes the common non-finding shapes on its own: a function-argument
use (`pg_has_role(current_user, ...)`) never has `=` directly adjacent to the identifier, and a
literal comparison (`current_user = 'postgres'`) doesn't match `<identifier>` (a bare word, not a
quoted string). It does NOT verify the compared identifier is actually a column of the policy's
own table (could be a catalog/membership-table column reached through a sub-select, which pgrls's
own-table check excludes) — a disclosed, coarser scope than the source pattern.

Deliberately excludes the `current_role` / bare `user` aliases pgrls also covers: `user` in
particular collides with an ordinary column literally named `user`, and neither is common enough
in practice to be worth that false-positive risk in a text-only guard.

`current_user`-based policies are **not** universally wrong — the "role-per-tenant" RLS pattern
(one Postgres role per tenant, `SET ROLE` per request) is a legitimate, documented design, and
there `current_user` is exactly the right discriminator. This guard cannot tell which deployment
model is in use, so it is MEDIUM, not HIGH, and suppressible per-statement.

Suppress: `-- security: allow-current-user-tenant-key` on the statement's own line (or anywhere
in the same file) for a policy that genuinely uses the role-per-tenant pattern.

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
    read,
    rel,
    strip_sql_comments,
)
from .rls_inverted_auth_check import _USING_HEAD, _WITH_CHECK_HEAD, _clause_body
from .rls_permissive_policy import _CREATE_POLICY_HEAD

_ROLE_IDENTITY = r"(?:current_user|session_user)"
_IDENT = r"[A-Za-z_][\w.]*"
_COMPARISON = re.compile(
    rf"\b(?P<lhs>{_IDENT})\s*(?:=|<>|!=)\s*(?P<rhs>{_ROLE_IDENTITY})\b"
    rf"|\b(?P<lhs2>{_ROLE_IDENTITY})\s*(?:=|<>|!=)\s*(?P<rhs2>{_IDENT})\b",
    re.IGNORECASE,
)
_PRAGMA = re.compile(r"--\s*security:\s*allow-current-user-tenant-key")


def _has_identity_comparison(clause: str) -> bool:
    return bool(_COMPARISON.search(clause))


class RlsCurrentUserTenantKeyGuard(Guard):
    id = "rls-current-user-tenant-key"
    title = "RLS policy keys row visibility off current_user/session_user — no isolation over a pooled connection"
    area = "Database"
    schema_state = True

    canary_plant = CanaryPlant(
        files={
            "sql/rls_current_user_tenant_key.sql": (
                "CREATE TABLE public.canary_current_user_key (id uuid PRIMARY KEY, owner_role text);\n"
                "ALTER TABLE public.canary_current_user_key ENABLE ROW LEVEL SECURITY;\n"
                "CREATE POLICY canary_current_user_key_p ON public.canary_current_user_key "
                "USING (owner_role = current_user);\n"
            ),
        },
        expects=frozenset({"rls-current-user-tenant-key/role-identity-comparison"}),
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
                using_body = _clause_body(stmt, _USING_HEAD)
                check_body = _clause_body(stmt, _WITH_CHECK_HEAD)
                hit = (using_body and _has_identity_comparison(using_body)) or (
                    check_body and _has_identity_comparison(check_body)
                )
                if not hit:
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
                "This RLS policy's USING/WITH CHECK clause compares a column against "
                "`current_user`/`session_user` — the Postgres role the session runs as. That "
                "only isolates tenants when every tenant connects as (or SET ROLEs to) a "
                "distinct Postgres role. A pooled application connection authenticates as one "
                "shared role, so `current_user` is identical for every tenant and the "
                "comparison matches the same way for everyone — no per-tenant isolation, even "
                "though the policy looks correct and passes review."
            ),
            remediation=(
                "Key the policy off a per-request session value instead — a GUC read with "
                "`current_setting('app.tenant_id')`, or a JWT claim (`auth.uid()`/`auth.jwt()`). "
                "If this project genuinely uses the role-per-tenant pattern (one Postgres role "
                "per tenant, SET ROLE per request), `current_user` is the right key here — "
                "suppress with `-- security: allow-current-user-tenant-key`."
            ),
            rule="rls-current-user-tenant-key/role-identity-comparison",
            standards=["OWASP:A01"],
        )
