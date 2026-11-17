"""Guard: permissive policy grants the named anon role write access (pgrls SEC039).

Supabase (and any PostgREST deployment) exposes the database through two built-in roles: `anon`
for requests carrying no JWT and `authenticated` for signed-in users. A permissive policy whose
role list includes `anon` for a write command (INSERT, UPDATE, DELETE, or ALL) lets an
*unauthenticated* client modify rows — anonymous data tampering, insertion, or deletion, gated by
that policy's clause and by the table's own GRANT (without a matching `GRANT INSERT`/etc. the
write is `permission denied`, which is why the remediation revokes the grant, not just the
policy). `anon` *read* (SELECT) policies are a deliberate, common public-data pattern and are NOT
flagged — only the write side is.

This is the write-side analog of `policy-no-role-scope`'s PUBLIC check, for the NAMED `anon`
role specifically — Supabase's `anon` is a real role, not the PUBLIC pseudo-role, so a
PUBLIC-scoped check does not catch a policy explicitly scoped `TO anon`.

Fires on a PERMISSIVE policy (not `AS RESTRICTIVE`) whose `TO` clause includes `anon` and whose
command (from an explicit `FOR` clause, or `ALL` when `FOR` is omitted — Postgres's own default)
covers a write: `INSERT`, `UPDATE`, `DELETE`, or `ALL`. `FOR SELECT` policies are excluded.

Suppress: `-- security: allow-anon-write-access` on the statement's own line (or anywhere in the
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
    read,
    rel,
    strip_sql_comments,
)
from .rls_permissive_policy import _AS_RESTRICTIVE, _CREATE_POLICY_HEAD, _target_roles

# H7 (Dean's review, PR #893 review): an unanchored `_FOR_COMMAND` matched INSIDE the
# quoted policy name too — Supabase's own default policy names ship as
# `"Enable read access for all users"` / `"Enable insert for authenticated users only"`, so
# "for all"/"for select" is literally the common case, and a policy with NO real FOR clause
# (implicit ALL, which covers writes) was misread as read-only. The lookahead anchors the
# match to what must syntactically FOLLOW a real FOR clause (TO/USING/WITH CHECK/statement
# end) so a quoted string's prose can never satisfy it.
_FOR_COMMAND = re.compile(
    r"\bfor\s+(all|select|insert|update|delete)\s*(?=\bto\b|\busing\b|\bwith\s+check\b|;|$)",
    re.IGNORECASE,
)
_WRITE_COMMANDS = frozenset({"all", "insert", "update", "delete"})
_PRAGMA = re.compile(r"--\s*security:\s*allow-anon-write-access")


def _covers_write(stmt: str) -> bool:
    m = _FOR_COMMAND.search(stmt)
    if not m:
        return True  # no FOR clause -> defaults to ALL commands (Postgres's own default)
    return m.group(1).lower() in _WRITE_COMMANDS


class RlsAnonWriteAccessGuard(Guard):
    id = "rls-anon-write-access"
    title = "Permissive policy grants the anon role write access — unauthenticated data tampering"
    area = "Database"
    schema_state = True

    canary_plant = CanaryPlant(
        files={
            "sql/rls_anon_write_access.sql": (
                "CREATE TABLE public.canary_anon_write (id uuid PRIMARY KEY, body text);\n"
                "ALTER TABLE public.canary_anon_write ENABLE ROW LEVEL SECURITY;\n"
                "CREATE POLICY canary_anon_write_p ON public.canary_anon_write "
                "FOR INSERT TO anon WITH CHECK (true);\n"
            ),
        },
        expects=frozenset({"rls-anon-write-access/anon-write-permitted"}),
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
                if _AS_RESTRICTIVE.search(stmt):
                    continue
                roles = _target_roles(stmt)
                if "anon" not in roles:
                    continue
                if not _covers_write(stmt):
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
                "This PERMISSIVE policy's `TO` clause includes `anon` and its command covers a "
                "write (INSERT/UPDATE/DELETE/ALL). Any unauthenticated client can modify rows "
                "through this policy, gated only by its own USING/WITH CHECK clause and the "
                "table's GRANT. `anon` read (SELECT) access is a common, deliberate public-data "
                "pattern — write access rarely is."
            ),
            remediation=(
                "Restrict the policy `TO authenticated` (or a privileged role) and revoke the "
                "table's write GRANT to `anon` if present. If anonymous write access is genuinely "
                "intentional (e.g. a public contact-form insert), suppress with "
                "`-- security: allow-anon-write-access`."
            ),
            rule="rls-anon-write-access/anon-write-permitted",
            standards=["OWASP:A01"],
        )
