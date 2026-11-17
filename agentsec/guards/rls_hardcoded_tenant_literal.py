"""Guard: RLS policy pins an identity column to a hardcoded literal (pgrls SEC021).

A row-level security policy isolates tenants by keying row visibility off a *per-request* value —
read from session context the application sets on every connection (`current_setting
('app.tenant_id')`, a JWT claim). The footgun this flags is a policy whose entire USING/WITH CHECK
clause instead compares an identity-named column (`tenant_id`, `org_id`, `owner_id`, ...) against
a **literal constant** — `USING (tenant_id = 1)`. A literal pins the policy to one specific
tenant: every session, including an unrelated tenant or an anonymous request, is handed the same
fixed slice of rows. It is almost always a scaffolding value (`tenant_id = 1` while developing
against a seed tenant) that was never swapped for the real session lookup before the policy
shipped.

**Detection is a name heuristic, INFO severity — a review nudge, not a hard finding.** It cannot
know a project's column conventions or whether the fixed value is genuinely intentional (a table
pinned to one tenant, an admin-only policy). The identity-ish column NAME is what separates the
anti-pattern from a legitimate `column = literal` policy such as `USING (is_public = true)`, which
compares an attribute column to a constant on purpose.

**Narrower than pgrls's real AST version by design: only fires when the comparison IS the entire
clause**, not merely present somewhere inside a larger boolean expression. pgrls's own docs note
the identity-literal comparison is legitimate as an *additive sentinel* alongside a real
per-request scope — `USING (tenant_id = 1 OR tenant_id = current_setting('app.tenant_id')::int)`
marks shared/public rows without being the sole discriminator. A regex tool cannot reliably tell
"the sole discriminator" from "one disjunct of many" the way a real expression-tree walk can, so
this guard only fires on the unambiguous case (the comparison alone, optionally wrapped in outer
parens) and stays silent on anything more complex — a disclosed false-negative trade, not a
promise of the same recall as the source AST rule.

Suppress: `-- security: allow-hardcoded-tenant-literal` on the statement's own line (or anywhere
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
    read,
    rel,
    strip_sql_comments,
)
from .rls_inverted_auth_check import _USING_HEAD, _WITH_CHECK_HEAD, _clause_body
from .rls_permissive_policy import _CREATE_POLICY_HEAD

_IDENTITY_COLUMNS = frozenset({
    "account", "account_id", "client_id", "company_id", "customer_id", "group_id",
    "member_id", "org", "org_id", "organisation_id", "organization_id", "owner",
    "owner_id", "project_id", "site_id", "team_id", "tenant", "tenant_id", "user_id",
    "workspace_id",
})

_LITERAL = r"(?:'[^']*'|\d+(?:\.\d+)?|true|false)(?:\s*::\s*\w+)?"
_WHOLE_CLAUSE = re.compile(
    rf"^\(*\s*(?:\w+\.)?(?P<col_lhs>\w+)\s*=\s*{_LITERAL}\s*\)*$"
    rf"|^\(*\s*{_LITERAL}\s*=\s*(?:\w+\.)?(?P<col_rhs>\w+)\s*\)*$",
    re.IGNORECASE,
)
_PRAGMA = re.compile(r"--\s*security:\s*allow-hardcoded-tenant-literal")


def _pins_identity_column(clause: str) -> bool:
    m = _WHOLE_CLAUSE.match(clause.strip())
    if not m:
        return False
    col = m.group("col_lhs") or m.group("col_rhs")
    return col is not None and col.lower() in _IDENTITY_COLUMNS


class RlsHardcodedTenantLiteralGuard(Guard):
    id = "rls-hardcoded-tenant-literal"
    title = "RLS policy pins an identity column to a hardcoded literal, not a per-request value"
    area = "Database"
    schema_state = True

    canary_plant = CanaryPlant(
        files={
            "sql/rls_hardcoded_tenant_literal.sql": (
                "CREATE TABLE public.canary_tenant_literal (id uuid PRIMARY KEY, tenant_id int);\n"
                "ALTER TABLE public.canary_tenant_literal ENABLE ROW LEVEL SECURITY;\n"
                "CREATE POLICY canary_tenant_literal_p ON public.canary_tenant_literal "
                "USING (tenant_id = 1);\n"
            ),
        },
        expects=frozenset({"rls-hardcoded-tenant-literal/identity-column-pinned"}),
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
                hit = (using_body and _pins_identity_column(using_body)) or (
                    check_body and _pins_identity_column(check_body)
                )
                if not hit:
                    continue
                loc = f"{rel(root, f)}:{s_line + 1}"
                out.append(self._finding(loc))
        return out

    def _finding(self, loc: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="info",
            title=self.title,
            location=loc,
            message=(
                "This RLS policy's USING/WITH CHECK clause compares an identity-named column "
                "(a tenant/owner-style column) against a hardcoded literal — e.g. `tenant_id = "
                "1`. If that literal is the policy's only discriminator, every session is "
                "handed the same fixed slice of rows instead of being scoped to its own "
                "tenant — almost always a scaffolding value left in place of the real "
                "per-request session lookup."
            ),
            remediation=(
                "Key the comparison off a value the application sets per request — "
                "`current_setting('app.tenant_id')`, or a JWT claim (`auth.uid()`/`auth.jwt()`). "
                "If the fixed value is intentional (a table pinned to one tenant, an admin-only "
                "policy), suppress with `-- security: allow-hardcoded-tenant-literal`."
            ),
            rule="rls-hardcoded-tenant-literal/identity-column-pinned",
            standards=["OWASP:A01"],
        )
