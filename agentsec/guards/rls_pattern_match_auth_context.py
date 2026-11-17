"""Guard: policy predicate pattern-matches against an auth-context value (pgrls SEC026).

A policy whose `USING`/`WITH CHECK` expression compares a column against an auth-context value
(`auth.uid()`, `auth.role()`, `auth.jwt()`, `current_setting(...)`, `current_user`,
`current_role`, `session_user`) using a pattern-matching operator — `LIKE`/`ILIKE`/`SIMILAR TO`
or a POSIX regex operator (`~`/`~*`/`!~`/`!~*`) — makes the predicate's tightness depend on the
*shape* of the auth-context value rather than its identity:

    CREATE POLICY p ON documents USING (user_email ILIKE current_setting('app.email'));

`LIKE`/`ILIKE` interpret `%`/`_` as wildcards. If the session GUC is ever set to `%` (or any
wildcard shape), every row matches — total bypass. The same hole opens for POSIX regex: a session
value of `.*` matches every value. The fix is a plain `=` comparison instead — the intended
case-insensitivity, if genuinely needed, belongs on a normalized column, not on the comparison
operator.

Fires on either operand direction (`column LIKE <auth call>` or `<auth call> LIKE column`) — the
vulnerability is symmetric, whichever side carries the auth value drives the predicate's shape.
**Deliberately excludes an auth value compared to a literal pattern** (`current_user LIKE
'admin%'` — the author wrote the wildcard, nothing session-controlled) by requiring the non-auth
operand to be a bare identifier, not a quoted string.

Suppress: `-- security: allow-pattern-match-auth-context` on the statement's own line (or
anywhere in the same file).

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

_IDENT = r"[A-Za-z_][\w.]*"
# H2 (Dean's review, PR #893 review): the 3 bare words lacked \b anchors, so `re.search`
# matched them as a SUBSTRING of an ordinary column name — `current_username`,
# `mycurrent_role`, `custom_session_user` all fired as if they were the real identity
# function. Word-boundaried on both sides now.
# review follow-up: `auth.uid()`/`auth.role()`/`auth.jwt()` were ALSO anchored to the bare
# spelling only, missing the pg_dump/migration-tool `"auth"."uid"()` quoted form — the same
# H3/H5/H6 root cause 3 other guards already had fixed. `pg_auth_call_pattern` covers both.
_AUTH_CALL = (
    rf"(?:{pg_auth_call_pattern('uid', 'role', 'jwt')}|"
    r"current_setting\s*\([^()]*\)|\bcurrent_user\b|\bcurrent_role\b|\bsession_user\b)"
)
_PATTERN_OP = r"(?:not\s+)?(?:i?like|similar\s+to)|!~\*|~\*|!~|~"
_PATTERN_MATCH = re.compile(
    rf"\b(?P<lhs>{_IDENT})\s+(?P<op1>{_PATTERN_OP})\s+{_AUTH_CALL}"
    rf"|{_AUTH_CALL}\s+(?P<op2>{_PATTERN_OP})\s+(?P<rhs>{_IDENT})",
    re.IGNORECASE,
)
_PRAGMA = re.compile(r"--\s*security:\s*allow-pattern-match-auth-context")


def _has_pattern_match(clause: str) -> bool:
    return bool(_PATTERN_MATCH.search(clause))


class RlsPatternMatchAuthContextGuard(Guard):
    id = "rls-pattern-match-auth-context"
    title = "RLS policy pattern-matches a column against an auth-context value — a wildcard session value bypasses it"
    area = "Database"
    schema_state = True

    canary_plant = CanaryPlant(
        files={
            "sql/rls_pattern_match_auth_context.sql": (
                "CREATE TABLE public.canary_pattern_match (id uuid PRIMARY KEY, user_email text);\n"
                "ALTER TABLE public.canary_pattern_match ENABLE ROW LEVEL SECURITY;\n"
                "CREATE POLICY canary_pattern_match_p ON public.canary_pattern_match "
                "USING (user_email ILIKE current_setting('app.email'));\n"
            ),
        },
        expects=frozenset({"rls-pattern-match-auth-context/wildcard-shape-controlled"}),
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
                hit = (using_body and _has_pattern_match(using_body)) or (
                    check_body and _has_pattern_match(check_body)
                )
                if not hit:
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
                "This RLS policy's USING/WITH CHECK clause pattern-matches a column against an "
                "auth-context value (current_setting/auth.uid/auth.role/auth.jwt/current_user/"
                "session_user) using LIKE/ILIKE/SIMILAR TO or a POSIX regex operator. The "
                "predicate's tightness now depends on the SHAPE of the session value, not its "
                "identity — if that value is ever a wildcard pattern (`%`, `.*`), every row "
                "matches, a total bypass."
            ),
            remediation=(
                "Use a plain `=` comparison instead of a pattern operator. If case-insensitive "
                "matching is genuinely needed, normalize the column value (store/compare "
                "lowercased) rather than using ILIKE against a session-controlled value. If this "
                "is intentional, suppress with `-- security: allow-pattern-match-auth-context`."
            ),
            rule="rls-pattern-match-auth-context/wildcard-shape-controlled",
            standards=["OWASP:A01"],
        )
