"""Guard: role can SET ROLE to a BYPASSRLS role via membership (pgrls SEC029).

`BYPASSRLS` is a role *attribute*. Role attributes — unlike object privileges — are never
inherited through role membership, even with `INHERIT`. So being a member of a BYPASSRLS role
does not make you bypass RLS automatically, and the member's own attributes look clean.

But membership grants `SET ROLE`. A role that is a member of a BYPASSRLS role can run
`SET ROLE <that role>` and, from that point in the session, bypass every row-level security
policy on every table — an RLS-bypass path invisible from the member's own attributes:

    CREATE ROLE admin BYPASSRLS NOLOGIN;
    CREATE ROLE app LOGIN;
    GRANT admin TO app;        -- app can `SET ROLE admin`, then bypass RLS

`app` here has no BYPASSRLS of its own (`pg-role-bypassrls` stays silent on it), yet a single
`SET ROLE admin` turns RLS off for the rest of the session.

Two-pass, same-file-or-cross-file: collects every role name granted `BYPASSRLS` via
`CREATE ROLE`/`ALTER ROLE` (reusing the same detection `pg-role-bypassrls` uses), then scans for
role-membership `GRANT <role> TO <member>` statements (distinguished from a privilege grant by
the absence of an `ON <object>` clause between `GRANT` and `TO`) naming one of those roles as the
grantee side. Direct membership only — does not resolve a *transitive* chain (a member of a
member of a BYPASSRLS role), a disclosed narrower scope than pgrls's full `pg_auth_members`
closure.

Suppress: `-- security: allow-role-bypassrls-membership` on the GRANT statement's own line, or the
line immediately before or after it (L1: NOT anywhere in the file — the check is a
narrow 3-line window centered on the GRANT statement, matching what the code actually does).

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
    blank_sql_literals,
    comment_view,
    find_statement_end,
    iter_files,
    read,
    rel,
    strip_sql_comments,
)

_ROLE_HEAD = re.compile(r"\b(?:create|alter)\s+role\s+\"?(?P<name>\w+)\"?", re.IGNORECASE)
_BYPASSRLS = re.compile(r"\bbypassrls\b", re.IGNORECASE)
_NO_BYPASSRLS = re.compile(r"\bno\s*bypassrls\b", re.IGNORECASE)
_SUPERUSER = re.compile(r"\bsuperuser\b", re.IGNORECASE)

_GRANT = re.compile(r"\bgrant\b", re.IGNORECASE)
_TO = re.compile(r"\bto\b", re.IGNORECASE)
_ON_KEYWORD = re.compile(r"\bon\b", re.IGNORECASE)
_PRAGMA = re.compile(r"--\s*security:\s*allow-role-bypassrls-membership")


def _collect_bypassrls_roles(stripped: str) -> set[str]:
    roles: set[str] = set()
    for head_m in _ROLE_HEAD.finditer(stripped):
        semi = find_statement_end(stripped, head_m.end())
        bound = semi if semi != -1 else len(stripped)
        stmt = stripped[head_m.start() : bound]
        without_negation = _NO_BYPASSRLS.sub(lambda m: " " * len(m.group(0)), stmt)
        if _BYPASSRLS.search(without_negation) and not _SUPERUSER.search(stmt):
            roles.add(head_m.group("name"))
    return roles


class PgRoleBypassrlsMembershipGuard(Guard):
    id = "pg-role-bypassrls-membership"
    title = "Role can SET ROLE to a BYPASSRLS role — an RLS-bypass path invisible from its own attributes"
    area = "Database"
    # schema_state defaults to False (gating) — deliberately NOT overridden to True. This guard
    # flags role membership (GRANT <role> TO <member>), same as `pg_role_bypassrls.py` flags the
    # BYPASSRLS attribute itself — both are cluster-level objects a standard per-database schema
    # dump structurally cannot reproduce, so a dump's mere presence must not demote either to
    # non-gating (Dean's review, PR #893 review — same fix as the sibling guard).

    canary_plant = CanaryPlant(
        files={
            "sql/pg_role_bypassrls_membership.sql": (
                "CREATE ROLE canary_bypass_admin BYPASSRLS NOLOGIN;\n"
                "CREATE ROLE canary_bypass_member LOGIN;\n"
                "GRANT canary_bypass_admin TO canary_bypass_member;\n"
            ),
        },
        expects=frozenset({"pg-role-bypassrls-membership/set-role-path"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "supabase" in profile.features or "postgres" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        sql_dir = root / profile.sql_dir if profile.sql_dir else root
        texts: list[tuple[Path, str]] = [
            (f, strip_sql_comments(read(f))) for f in iter_files(sql_dir, (".sql",))
        ]
        if not texts:
            return []

        bypassrls_roles: set[str] = set()
        for _f, stripped in texts:
            bypassrls_roles |= _collect_bypassrls_roles(stripped)
        if not bypassrls_roles:
            return []
        bypassrls_lower = {r.lower() for r in bypassrls_roles}

        out: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for f, stripped in texts:
            raw = read(f)
            view_lines = comment_view(raw, "sql").splitlines()  # same lines: the pragma reads comments only (#1040)
            for grant_m in _GRANT.finditer(stripped):
                semi = find_statement_end(stripped, grant_m.end())
                bound = semi if semi != -1 else len(stripped)
                to_m = _TO.search(stripped, grant_m.end(), bound)
                if not to_m:
                    continue
                roles_span = stripped[grant_m.end() : to_m.start()]
                # L2: classify on a QUOTED-IDENTIFIER-masked view, not the raw span —
                # a legal (if exotic) quoted role name containing "on" as its own standalone
                # word (`GRANT "role on call" TO app;`) otherwise reads as a privilege grant's
                # `ON <object>` clause and this membership grant goes undetected. Only the
                # classification check uses the masked view; `roles_span` itself (with real
                # quotes) is still used below to extract the actual role name.
                if _ON_KEYWORD.search(blank_sql_literals(roles_span, identifiers=True)):
                    continue  # a privilege grant (GRANT ... ON ... TO ...), not membership
                granted_roles = {
                    t.strip().strip('"') for t in re.split(r"\s*,\s*", roles_span) if t.strip()
                }
                matched = {r for r in granted_roles if r.lower() in bypassrls_lower}
                if not matched:
                    continue
                members_span = stripped[to_m.end() : bound]
                members_span = re.split(r"\bwith\b", members_span, maxsplit=1, flags=re.IGNORECASE)[0]
                members = {
                    t.strip().strip('"') for t in re.split(r"\s*,\s*", members_span) if t.strip()
                }
                s_line = stripped.count("\n", 0, grant_m.start())
                window = "\n".join(view_lines[max(0, s_line - 1) : s_line + 2])
                if _PRAGMA.search(window):
                    continue
                loc = f"{rel(root, f)}:{s_line + 1}"
                for member in sorted(members):
                    for bypassrls_role in sorted(matched):
                        key = (member.lower(), bypassrls_role.lower())
                        if key in seen:
                            continue
                        seen.add(key)
                        out.append(self._finding(loc, member, bypassrls_role))
        return out

    def _finding(self, loc: str, member: str, bypassrls_role: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=loc,
            message=(
                f"Role `{member}` is granted membership in `{bypassrls_role}`, which carries the "
                f"BYPASSRLS attribute. Attributes are never inherited through membership, so "
                f"`{member}`'s own attributes look clean — but membership grants SET ROLE, and "
                f"`SET ROLE {bypassrls_role}` turns off RLS entirely for the rest of the session. "
                "An application authenticating as this role has a silent RLS-bypass path invisible "
                "from its own role definition."
            ),
            remediation=(
                f"Revoke the membership if `{member}` does not genuinely need this escalation path "
                f"(`REVOKE {bypassrls_role} FROM {member};`), or confirm it is an intended "
                "admin/operator login and suppress with "
                "`-- security: allow-role-bypassrls-membership`."
            ),
            rule="pg-role-bypassrls-membership/set-role-path",
            standards=["OWASP:A01"],
        )
