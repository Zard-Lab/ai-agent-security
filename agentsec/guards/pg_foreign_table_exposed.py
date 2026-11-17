"""Guard: foreign table exposed to a low-trust role (pgrls SEC053).

A foreign table (`postgres_fdw`/`file_fdw`, or a Supabase Wrapper over Stripe/S3/an external DB)
**cannot carry RLS** — Postgres rejects `ALTER TABLE <ft> ENABLE ROW LEVEL SECURITY` outright
("not supported for foreign tables"). So a foreign table that grants a row-reading privilege to a
low-trust role (`anon`/`authenticated`/`PUBLIC`) is directly readable at
`GET /rest/v1/<ft>` with **no row filtering possible** — every remote row is returned to any
caller, even an unauthenticated one:

    CREATE FOREIGN TABLE public.stripe_customers (...) SERVER stripe;
    GRANT SELECT ON public.stripe_customers TO anon;   -- GET /rest/v1/stripe_customers -> all rows

This is the foreign-table sibling of `pg-rls-no-policy`: the same "exposed schema + low-trust
grant = HTTP-reachable, unfiltered" conjunction, for the one relation type that structurally
cannot have RLS at all — a pure exposure test, no policy analysis needed or possible.

Fires when a table declared `CREATE FOREIGN TABLE` is granted `SELECT` (directly — a grant to a
group role a low-trust role merely inherits is not expanded) to `anon`, `authenticated`, or
`PUBLIC` anywhere in the scanned SQL.

Suppress: `-- security: allow-foreign-table-exposed` anywhere in the file granting the table.

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
    find_statement_end,
    iter_files,
    pragma_present,
    read,
    rel,
    strip_sql_comments,
)

_FOREIGN_TABLE_HEAD = re.compile(
    r"\bcreate\s+foreign\s+table\s+(?:if\s+not\s+exists\s+)?"
    r"(?:(?P<schema>\"?\w+\"?)\.)?\"?(?P<name>\w+)\"?",
    re.IGNORECASE,
)
_GRANT = re.compile(r"\bgrant\b", re.IGNORECASE)
_ON = re.compile(r"\bon\s+(?:table\s+)?(?:(?P<schema>\"?\w+\"?)\.)?\"?(?P<name>\w+)\"?", re.IGNORECASE)
_TO_ROLES = re.compile(r"\bto\s+(?P<roles>[^;]+)", re.IGNORECASE)
_LOW_TRUST_ROLES = frozenset({"anon", "authenticated", "public"})
_PRAGMA = "security: allow-foreign-table-exposed"


def _norm(token: str | None) -> str:
    return (token or "").strip('"').lower()


def _qual(schema: str | None, name: str) -> str:
    return f"{_norm(schema) or 'public'}.{_norm(name)}"


class PgForeignTableExposedGuard(Guard):
    id = "pg-foreign-table-exposed"
    title = "Foreign table granted to a low-trust role — no RLS is possible on it, ever"
    area = "Database"
    schema_state = True

    canary_plant = CanaryPlant(
        files={
            "sql/pg_foreign_table_exposed.sql": (
                "CREATE FOREIGN TABLE public.canary_stripe_customers (id text, email text) "
                "SERVER stripe;\n"
                "GRANT SELECT ON public.canary_stripe_customers TO anon;\n"
            ),
        },
        expects=frozenset({"pg-foreign-table-exposed/granted-to-low-trust-role"}),
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

        foreign_tables: set[str] = set()
        for _f, stripped in texts:
            for m in _FOREIGN_TABLE_HEAD.finditer(stripped):
                # H4 (Dean's review, PR #893 review): this used to ALSO always add a
                # forced `public.<name>` entry regardless of the foreign table's real
                # schema, so `external.stripe_customers` collided with an unrelated,
                # correctly-RLS'd `public.stripe_customers` and reported it as exposed.
                # Store only the real qualified name, matching `pg_rls_not_forced.py` /
                # `pg_rls_no_policy.py`'s own established pattern.
                foreign_tables.add(_qual(m.group("schema"), m.group("name")))

        out: list[Finding] = []
        seen: set[str] = set()
        for f, stripped in texts:
            raw = read(f)
            suppressed = pragma_present(_PRAGMA, raw, dialect="sql")  # once per file (#424)
            for grant_m in _GRANT.finditer(stripped):
                semi = find_statement_end(stripped, grant_m.end())
                bound = semi if semi != -1 else len(stripped)
                on_m = _ON.search(stripped, grant_m.end(), bound)
                if not on_m:
                    continue
                table = _qual(on_m.group("schema"), on_m.group("name"))
                if table not in foreign_tables:
                    continue
                to_m = _TO_ROLES.search(stripped, on_m.end(), bound)
                if not to_m:
                    continue
                # H8 (Dean's review, PR #893 review): `TO anon WITH GRANT OPTION` left the
                # `WITH ...` tail attached, so the role parsed as "anon with grant option" and
                # never matched _LOW_TRUST_ROLES. Strip it first, matching
                # `pg_role_bypassrls_membership.py`'s own established pattern.
                roles_text = re.split(r"\bwith\b", to_m.group("roles"), maxsplit=1, flags=re.IGNORECASE)[0]
                roles = {
                    t.strip().strip('"').lower()
                    for t in re.split(r"\s*,\s*", roles_text)
                    if t.strip()
                }
                if not (roles & _LOW_TRUST_ROLES):
                    continue
                if table in seen or suppressed:
                    continue
                seen.add(table)
                s_line = stripped.count("\n", 0, grant_m.start())
                loc = f"{rel(root, f)}:{s_line + 1}"
                out.append(self._finding(loc, table))
        return out

    def _finding(self, loc: str, table: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=loc,
            message=(
                f"`{table}` is a FOREIGN TABLE granted SELECT to a low-trust role "
                "(anon/authenticated/PUBLIC). Foreign tables structurally cannot carry RLS — "
                "Postgres rejects ENABLE ROW LEVEL SECURITY on them outright — so this grant "
                "means every remote row is returned to any caller with no row filtering "
                "possible, via `GET /rest/v1/<table>` in a PostgREST/Supabase deployment."
            ),
            remediation=(
                f"Revoke the grant (`REVOKE SELECT ON {table} FROM <role>;`) and reach the "  # nosec B608 (example SQL in remediation prose, not a real query)
                "remote data only through a SECURITY DEFINER function that applies its own "
                "row-scoping logic, never a direct grant on the foreign table itself. If direct "
                "access is intentional, suppress with `-- security: allow-foreign-table-exposed`."
            ),
            rule="pg-foreign-table-exposed/granted-to-low-trust-role",
            standards=["OWASP:A01"],
        )
