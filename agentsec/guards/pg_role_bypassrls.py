"""Guard: role granted the BYPASSRLS attribute (pgrls SEC016).

A Postgres role granted `BYPASSRLS` skips **every** row-level security policy on **every**
table, cluster-wide — RLS is not weakened for that role, it is simply off. Nothing in a table
definition, a policy, or a GRANT reveals that a particular role ignores all of them: the bypass
is invisible at the policy layer entirely. An application that authenticates as a BYPASSRLS role
gets zero tenant isolation while every policy in the schema still reads as airtight.

Fires on `CREATE ROLE ... BYPASSRLS` or `ALTER ROLE ... BYPASSRLS`. Skipped when the same
statement also grants `SUPERUSER` — a superuser already bypasses RLS unconditionally via
`rolsuper`, so `BYPASSRLS` on one is redundant noise, not an additional exposure (mirrors
pgrls's own superuser exclusion — this guard cannot see a role's live superuser status if it was
granted in a separate, earlier statement, a disclosed static-analysis limitation).

`NOBYPASSRLS` (with or without a space) is the explicit negation and never fires.

Suppress: `-- security: allow-role-bypassrls` on the statement's own line (or anywhere in the
same file), for a role that legitimately needs the attribute (backup, logical-replication, or
ETL roles are the common legitimate case, per pgrls's own documentation of this pattern).

OWASP:A01, CWE-284.
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

_ROLE_HEAD = re.compile(r"\b(?:create|alter)\s+role\s+\"?(?P<name>\w+)\"?", re.IGNORECASE)
_BYPASSRLS = re.compile(r"\bbypassrls\b", re.IGNORECASE)
_NO_BYPASSRLS = re.compile(r"\bno\s*bypassrls\b", re.IGNORECASE)
_SUPERUSER = re.compile(r"\bsuperuser\b", re.IGNORECASE)
_PRAGMA = re.compile(r"--\s*security:\s*allow-role-bypassrls")


class PgRoleBypassrlsGuard(Guard):
    id = "pg-role-bypassrls"
    title = "Role granted BYPASSRLS — skips every RLS policy, cluster-wide"
    area = "Database"
    # schema_state defaults to False (gating) — deliberately NOT overridden to True. Roles are
    # cluster-level objects (CREATE ROLE/ALTER ROLE is not scoped to one database), so a standard
    # per-database schema dump (schema.sql, `supabase db dump`) structurally cannot reproduce a
    # role's BYPASSRLS grant at all — only `pg_dumpall --roles-only` can, and this project's own
    # dump detection (`sql_state.py::find_dumps`) never looks for one. Setting True here
    # would silently demote a real, live BYPASSRLS grant to non-gating the moment ANY schema dump
    # exists in the repo, even though that dump never actually speaks for this finding — exactly
    # CLAUDE.md's own "cluster roles" example of what schema_state=True must never apply to
    # (Dean's review, PR #893 review).

    canary_plant = CanaryPlant(
        files={
            "sql/pg_role_bypassrls.sql": (
                "CREATE ROLE canary_bypass_role LOGIN BYPASSRLS PASSWORD 'x';\n"
            ),
        },
        expects=frozenset({"pg-role-bypassrls/attribute-granted"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "supabase" in profile.features or "postgres" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        sql_dir = root / profile.sql_dir if profile.sql_dir else root
        out: list[Finding] = []
        for f in iter_files(sql_dir, (".sql",)):
            text = read(f)
            view_lines = comment_view(text, "sql").splitlines()  # same length: the window below is the same slice (#424)
            stripped = strip_sql_comments(text)
            for start, end in iter_statement_spans(stripped, _ROLE_HEAD):
                stmt = stripped[start:end]
                head = _ROLE_HEAD.search(stmt)
                if not head:
                    continue
                # Blank out any NOBYPASSRLS span first so the bare BYPASSRLS search below
                # can't re-match inside it (the two share the substring "bypassrls").
                without_negation = _NO_BYPASSRLS.sub(lambda m: " " * len(m.group(0)), stmt)
                if not _BYPASSRLS.search(without_negation):
                    continue
                if _SUPERUSER.search(stmt):
                    continue
                s_line = stripped.count("\n", 0, start)
                e_line = stripped.count("\n", 0, end)
                window = "\n".join(view_lines[max(0, s_line - 1) : e_line + 1])
                if _PRAGMA.search(window):
                    continue
                loc = f"{rel(root, f)}:{s_line + 1}"
                name = head.group("name")
                out.append(self._finding(loc, name))
        return out

    def _finding(self, loc: str, name: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=loc,
            message=(
                f"Role `{name}` is granted the BYPASSRLS attribute. A role with BYPASSRLS "
                "skips every row-level security policy on every table, cluster-wide — RLS "
                "is effectively off for it, unconditionally. Nothing in a table definition, "
                "a policy, or a GRANT reveals this: the bypass is invisible at the policy "
                "layer entirely, so a schema whose policies all read as airtight can still "
                "leak completely through this role."
            ),
            remediation=(
                f"If `{name}` does not genuinely need to bypass RLS, remove the attribute: "
                f"`ALTER ROLE {name} NOBYPASSRLS`. BYPASSRLS is typically needed only by "
                "backup, logical-replication, or ETL roles. If the bypass is intentional, "
                "suppress with `-- security: allow-role-bypassrls`."
            ),
            rule="pg-role-bypassrls/attribute-granted",
            standards=["OWASP:A01"],
        )
