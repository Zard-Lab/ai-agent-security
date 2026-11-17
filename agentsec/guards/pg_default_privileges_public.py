"""Guard: default table privileges granted to PUBLIC (pgrls SEC044).

`ALTER DEFAULT PRIVILEGES [IN SCHEMA s] [FOR ROLE r] GRANT <priv> ON TABLES TO PUBLIC` does not
touch any existing table — it records a standing rule that **every table created after it** is
automatically granted `<priv>`. When the grantee is PUBLIC and the privilege is a row-access one
(`SELECT`/`INSERT`/`UPDATE`/`DELETE`), the default becomes a defense-in-depth footgun: a developer
who later adds a table and forgets `ENABLE ROW LEVEL SECURITY` has silently exposed it to every
role — including `anon` in a PostgREST/Supabase deployment — without writing a single `GRANT`.
Default privileges are not retroactive, so this is a standing config posture finding, not a
per-table one: it fires regardless of whether any table has been created under it yet.

**Only `PUBLIC` fires.** `anon`/`authenticated` are deliberately excluded — granting future
tables to those named roles is the deliberate, RLS-gated Supabase pattern (Supabase ships default
privileges to those roles precisely so PostgREST can see new tables; RLS, not the grant, is what
scopes access). Flagging that would fire on essentially every Supabase project.

**Only row-access privileges count**: `SELECT`/`INSERT`/`UPDATE`/`DELETE`. A default of only
`REFERENCES`/`TRIGGER`/`TRUNCATE` neither reads nor writes row contents.

Regex-based, not a real parser: parses `ALTER DEFAULT PRIVILEGES ... ;` statements and requires
`GRANT <priv-list> ON TABLES TO <role-list>` within the statement, where `<priv-list>` contains at
least one row-access privilege and `<role-list>` contains `PUBLIC`. Does not model
`pg_default_acl`'s real per-grantor identity the way pgrls does (a real linter dedupes/keys on
`(schema, grantee, grantor)`); this guard reports one finding per matching statement.

**Three sequential bounded searches, not one combined regex** (issue #419's ReDoS class — an
earlier single-regex version combining a bounded lazy character-class group with a required
suffix measured cubic-or-worse growth under `tests/test_regex_redos_safety.py`, even with the
group's length bounded, because the lazy group still backtracks combinatorially against a long
non-matching run before giving up). Locates `GRANT`, then `ON TABLES`, then `TO <roles>` as
three separate, simple, statement-bounded searches (mirrors `iter_bounded_matches`'s own linear
approach — see `base.py`), with the privilege list read by plain string slicing between the
first two matches rather than captured by a backtracking-prone group.

Suppress: `-- security: allow-default-privileges-public` on the statement's own line (or
anywhere in the same file).

OWASP:A01, CWE-732.
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
    find_statement_end,
    iter_files,
    read,
    rel,
    strip_sql_comments,
)

_ALTER_DEFAULT_PRIVILEGES_HEAD = re.compile(r"\balter\s+default\s+privileges\b", re.IGNORECASE)
_GRANT = re.compile(r"\bgrant\b", re.IGNORECASE)
_ON_TABLES = re.compile(r"\bon\s+tables\b", re.IGNORECASE)
_TO_ROLES = re.compile(r"\bto\s+(?P<roles>[^;]+)", re.IGNORECASE)
_ROW_ACCESS_PRIVILEGES = frozenset({"select", "insert", "update", "delete"})
_PRAGMA = re.compile(r"--\s*security:\s*allow-default-privileges-public")


def _has_row_access_privilege(privs: str) -> bool:
    tokens = {t.strip().lower() for t in privs.split(",")}
    return bool(tokens & _ROW_ACCESS_PRIVILEGES)


def _grants_public(roles: str) -> bool:
    tokens = {t.strip().strip('"').lower() for t in re.split(r"\s*,\s*", roles) if t.strip()}
    return "public" in tokens


class PgDefaultPrivilegesPublicGuard(Guard):
    id = "pg-default-privileges-public"
    title = "Default table privileges granted to PUBLIC — every future table exposed until RLS is remembered"
    area = "Database"
    schema_state = True

    canary_plant = CanaryPlant(
        files={
            "sql/pg_default_privileges_public.sql": (
                "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO PUBLIC;\n"
            ),
        },
        expects=frozenset({"pg-default-privileges-public/row-access-to-public"}),
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
            for head_m in _ALTER_DEFAULT_PRIVILEGES_HEAD.finditer(stripped):
                semi = find_statement_end(stripped, head_m.end())
                bound = semi if semi != -1 else len(stripped)
                grant_m = _GRANT.search(stripped, head_m.end(), bound)
                if not grant_m:
                    continue
                on_m = _ON_TABLES.search(stripped, grant_m.end(), bound)
                if not on_m:
                    continue
                to_m = _TO_ROLES.search(stripped, on_m.end(), bound)
                if not to_m:
                    continue
                privs = stripped[grant_m.end() : on_m.start()]
                if not _has_row_access_privilege(privs):
                    continue
                if not _grants_public(to_m.group("roles")):
                    continue
                s_line = stripped.count("\n", 0, head_m.start())
                e_line = stripped.count("\n", 0, bound)
                window = "\n".join(view_lines[max(0, s_line - 1) : e_line + 1])
                if _PRAGMA.search(window):
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
                "This `ALTER DEFAULT PRIVILEGES` statement auto-grants a row-access privilege "
                "(SELECT/INSERT/UPDATE/DELETE) on every FUTURE table to PUBLIC. Default "
                "privileges are not retroactive, so this is a standing posture, not a one-time "
                "grant: any new table created after this statement, without ENABLE ROW LEVEL "
                "SECURITY, is immediately exposed to every role — including `anon` in a "
                "PostgREST/Supabase deployment — with no per-table GRANT and nothing but the "
                "author remembering RLS standing in the way."
            ),
            remediation=(
                "Revoke the default and rely on RLS instead: "
                "`ALTER DEFAULT PRIVILEGES [FOR ROLE <grantor>] [IN SCHEMA <schema>] REVOKE "
                "<privilege> ON TABLES FROM PUBLIC;` (the `FOR ROLE` clause must name the same "
                "role the default was created for — a bare REVOKE only clears the running "
                "role's own default). If this default is deliberate, suppress with "
                "`-- security: allow-default-privileges-public`."
            ),
            rule="pg-default-privileges-public/row-access-to-public",
            standards=["OWASP:A01"],
        )
