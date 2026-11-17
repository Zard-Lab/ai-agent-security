"""Guard: inverted auth check in an RLS policy — the "Lovable CVE" pattern (pgrls SEC004).

The shape: `USING (auth.uid() IS NULL OR <real check>)`. `auth.uid()` (and its siblings
`auth.role()`, `auth.jwt()`, and `current_setting(name, true)`) returns NULL for a token-less
(anonymous) connection — so for that connection the `IS NULL` disjunct is true, the OR is
satisfied, and `<real check>` is never evaluated. Every row is visible to every anonymous
caller, even though the policy reads as if it were scoped.

The same inversion in **WITH CHECK** is the write-side twin: for a token-less session the
disjunct is true, so the policy accepts any row that session writes — including rows stamped
for another tenant. Both clauses are inspected independently; a policy carrying the hole in
both gets one finding naming both clauses.

Only an **explicit** `WITH CHECK` is inspected separately from `USING`. Postgres reuses `USING`
as the implicit `WITH CHECK` on UPDATE/ALL when `WITH CHECK` is omitted, so an absent clause
adds no hole the USING finding hasn't already reported.

**Regex-based, not a real parser** (mirrors this codebase's other RLS clause guards, e.g.
`rls_permissive_policy.py`). The `IS NULL` disjunct must sit immediately adjacent to an `OR`
keyword (optionally through parens) on either side — `<auth> IS NULL OR <x>` or
`<x> OR <auth> IS NULL` — approximating "top-level OR disjunct" without a real expression
tree. A disjunct several tokens away from its `OR` (e.g. buried behind an intervening
function call before reaching the keyword) can be missed; a known, disclosed limitation, not a
promise of full boolean-algebra coverage — same trade the sibling guards in this file's area
already make.

Nullable auth functions: `auth.uid()`, `auth.role()`, `auth.jwt()`, and the two-argument
`current_setting(name, true)` form (the `missing_ok=true` overload, which returns NULL instead
of raising). Deliberately EXCLUDES `current_user` / `session_user` / `current_role` / `user` —
Postgres has no unauthenticated backend, so these SQLValueFunctions always return the session
role name and are never NULL; `<col> = current_user IS NULL` would be a false positive. Also
excludes the one-argument `current_setting(name)` form, which raises rather than returning NULL
for an unset GUC — an `IS NULL` disjunct built on it can never actually be satisfied.

Severity: HIGH when the policy is reachable by an anonymous/token-less session (`anon`/PUBLIC/
no `TO` clause — same role vocabulary as `rls_permissive_policy.py`). MEDIUM when the policy is
restricted to a named non-anon role: the disjunct is still a latent hole (it fires for any
session in that role whose auth context happens to be NULL, and becomes a full anonymous hole
if the role restriction is ever loosened or `anon` is granted membership in it), but this guard
does not verify Postgres role-inheritance chains, so it does not claim the same anonymous-read
severity a direct anon-reachable policy gets.

Suppress an audited statement with `-- security: allow-inverted-auth-check`.

OWASP:A01 (Broken Access Control).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity

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
from .rls_permissive_policy import _CREATE_POLICY_HEAD, _target_roles

_USING_HEAD = re.compile(r"\busing\s*\(", re.IGNORECASE)
_WITH_CHECK_HEAD = re.compile(r"\bwith\s+check\s*\(", re.IGNORECASE)
_PRAGMA = re.compile(r"--\s*security:\s*allow-inverted-auth-check")

# H5 (Dean's review, PR #893 review): was anchored to the bare `auth.uid()` spelling only, so
# a pg_dump/migration-tool `"auth"."uid"()` quoted form (the flagship's own shape) was silent —
# this HIGH "Lovable CVE" pattern neutered on exactly the schema style it targets.
_AUTH_CALL = pg_auth_call_pattern("uid", "role", "jwt")
# Only the two-arg `current_setting(name, true)` form is genuinely nullable — the one-arg form
# and an explicit `missing_ok=false`/`false` raise instead of returning NULL.
_CS_NULLABLE = r"current_setting\s*\(\s*[^()]*?,\s*true\s*\)"
_NULLABLE_AUTH = rf"(?:{_AUTH_CALL}|{_CS_NULLABLE})"
_INVERTED_AUTH_DISJUNCT = re.compile(
    rf"\bor\s*\(*\s*{_NULLABLE_AUTH}\s+is\s+null\b"
    rf"|{_NULLABLE_AUTH}\s+is\s+null\s*\)*\s*\bor\b",
    re.IGNORECASE,
)

# Roles a token-less / unauthenticated session can act as — mirrors rls_permissive_policy.py's
# own anon-reachability vocabulary (that guard reasons about "authorizes everyone"; this one
# reasons about "anonymous session hits a NULL auth context", the same reachable-role set).
_ANON_ROLES = frozenset({"anon", "public"})


def _clause_body(stmt: str, head: re.Pattern[str]) -> str | None:
    m = head.search(stmt)
    if not m:
        return None
    open_idx = m.end() - 1
    close_idx = matching_close_paren(stmt, open_idx)
    if close_idx is None:
        return None
    return stmt[open_idx + 1 : close_idx]


class RlsInvertedAuthCheckGuard(Guard):
    id = "rls-inverted-auth-check"
    title = "RLS policy has an inverted auth check — anonymous callers hit a NULL short-circuit"
    area = "Database"
    schema_state = True  # policies/grants/objects a schema dump reproduces

    canary_plant = CanaryPlant(
        files={
            "sql/rls_inverted_auth_check.sql": (
                "CREATE TABLE public.canary_inverted_auth (id uuid PRIMARY KEY, owner_id uuid);\n"
                "ALTER TABLE public.canary_inverted_auth ENABLE ROW LEVEL SECURITY;\n"
                "CREATE POLICY canary_inverted_auth_p ON public.canary_inverted_auth "
                "USING (auth.uid() IS NULL OR owner_id = auth.uid());\n"
            ),
        },
        expects=frozenset({"rls-inverted-auth-check/is-null-or-bypass"}),
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
                loc = f"{rel(root, f)}:{s_line + 1}"

                using_body = _clause_body(stmt, _USING_HEAD)
                check_body = _clause_body(stmt, _WITH_CHECK_HEAD)
                in_using = bool(using_body and _INVERTED_AUTH_DISJUNCT.search(using_body))
                in_check = bool(check_body and _INVERTED_AUTH_DISJUNCT.search(check_body))
                if not in_using and not in_check:
                    continue

                roles = _target_roles(stmt)
                out.append(self._finding(loc, roles, in_using, in_check))
        return out

    def _finding(self, loc: str, roles: set[str], in_using: bool, in_check: bool) -> Finding:
        if in_using and in_check:
            clauses, plural = "USING and WITH CHECK", "s"
        elif in_using:
            clauses, plural = "USING", ""
        else:
            clauses, plural = "WITH CHECK", ""

        anon_reachable = bool(roles & _ANON_ROLES)
        target = "PUBLIC" if roles == {"public"} else ", ".join(sorted(roles))
        severity: Severity
        if anon_reachable:
            severity = "high"
            impact = (
                "For a token-less (anonymous) connection that disjunct is true, so the OR is "
                "satisfied without ever evaluating the real check — every row is exposed to, "
                "and every write accepted from, an anonymous caller."
                if in_using and in_check
                else (
                    "For a token-less (anonymous) connection that disjunct is true, exposing "
                    "every row to anonymous callers."
                    if in_using
                    else (
                        "For a token-less (anonymous) connection that disjunct is true, accepting "
                        "every write from an anonymous caller, including rows stamped for another "
                        "tenant."
                    )
                )
            )
        else:
            severity = "medium"
            impact = (
                f"The policy targets `{target}`, not anon/PUBLIC, so a token-less request "
                "cannot reach it directly — but the disjunct is a latent hole for any session "
                "in that role whose auth context happens to be NULL, and becomes a full "
                "anonymous hole if the role restriction is ever loosened."
            )

        return Finding(
            check_id=self.id,
            severity=severity,
            title=self.title,
            location=loc,
            message=(
                f"This RLS policy's {clauses} clause{plural} has a top-level "
                "`<auth function> IS NULL OR <real check>` disjunct (or the reverse order). "
                f"{impact}"
            ),
            remediation=(
                "Remove the `IS NULL` disjunct, or replace it with an explicit deny for the "
                "anonymous case (e.g. drop the OR entirely and let a missing role membership "
                "fail closed). If this disjunct is genuinely intentional, suppress with "
                "`-- security: allow-inverted-auth-check`."
            ),
            rule="rls-inverted-auth-check/is-null-or-bypass",
            standards=["OWASP:A01"],
        )
