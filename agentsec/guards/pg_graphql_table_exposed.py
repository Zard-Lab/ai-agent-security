"""Guard: table/view visible in the pg_graphql schema to anon/authenticated
(checklist §7 — Database Security).

`pg_graphql` introspection reflects the calling role's Postgres privileges directly: if
`anon` (or `authenticated`) can `SELECT` a table, view, materialized view, or foreign
table, that object's name, columns, and relationships are visible through
`/graphql/v1` to anyone holding the corresponding key — **even when Row Level Security
is enabled and correctly scoped.** RLS restricts which *rows* a query returns; it does
nothing to hide that the table exists, what its columns are called, or how it relates to
other tables. A developer who confirms "RLS is on, so this table is protected" can still
be leaking their entire schema shape — table names, column names, foreign-key
relationships — to an unauthenticated caller, which is itself useful reconnaissance and,
for a table whose very *name* is sensitive (`refunds_flagged_for_fraud`,
`internal_admin_notes`), a disclosure regardless of row-level access.

Mirrors Supabase Splinter's paired `pg_graphql_anon_table_exposed` /
`pg_graphql_authenticated_table_exposed` lints (0026/0027), which run live against
`pg_catalog.has_column_privilege(...)`. This guard reads the same combination from
`.sql` source: the extension being installed, plus an explicit `GRANT SELECT` (or
broader) to `anon`/`authenticated` on a table or view elsewhere in the scanned SQL.

**Detection — two rule variants, one per role, both requiring `pg_graphql` installed.**
Statement-bound, not line-bound: a `GRANT ... ON ... TO ...` split across several lines
(a common SQL-formatter style) is still found, since each `GRANT` keyword's search
window runs to the statement's own terminating `;`.
  - `pg-graphql-table-exposed/anon` (MEDIUM): `CREATE EXTENSION pg_graphql` is present
    AND a `GRANT ... ON <table> TO anon` (or `PUBLIC`, which `anon` inherits) exists.
  - `pg-graphql-table-exposed/authenticated` (MEDIUM): same, but the grant is `TO
    authenticated`.

Scoped to table/view grants only — a `GRANT EXECUTE ON FUNCTION` is a different exposure
path (already covered by `pg-anon-grant`/`definer-function-grants`), and a bare `GRANT
USAGE ON SCHEMA` grants no column privilege at all, so pg_graphql would show nothing for
it. Severity is MEDIUM, not HIGH: this is schema/metadata visibility, not the row-data
access a missing-RLS finding represents — the two are complementary, not the same claim.

**Suppress:** `-- security: allow-pg-graphql-table-exposed` anywhere in a `.sql` file
opts the whole file out (the same file-level pragma shape `pg-anon-grant` uses).
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
    is_reference_sql_path,
    iter_files,
    pragma_present,
    read,
    rel,
    strip_sql_comments,
)

_PRAGMA = "security: allow-pg-graphql-table-exposed"
_STANDARDS = ["OWASP:A01"]

_CREATE_EXT_GRAPHQL = re.compile(
    r'CREATE\s+EXTENSION(?:\s+IF\s+NOT\s+EXISTS)?\s+"?pg_graphql"?',
    re.IGNORECASE,
)

# Statement-bound, not line-bound: a `GRANT ... ON ... TO ...` split across multiple
# lines (a common SQL-formatter style) must still be found, so each `GRANT` keyword's
# search window runs to `find_statement_end`'s terminating `;` — the same bounded,
# quote-aware span every other multi-line-tolerant guard in this codebase uses, never
# one combined backtracking-prone regex spanning the gap (issue #419's lesson).
_GRANT_KW = re.compile(r"\bGRANT\s", re.IGNORECASE)
_ON_TOKEN = re.compile(r"\sON\s+(?:TABLE\s+)?(\S+)", re.IGNORECASE)
_TO_ANON = re.compile(r"\sTO\s+(?:anon|public)\b", re.IGNORECASE)
_TO_AUTHENTICATED = re.compile(r"\sTO\s+authenticated\b", re.IGNORECASE)
# Excluded object kinds: a function/procedure/routine grant is a different exposure
# path (RPC-call, not table introspection), and schema-level USAGE carries no column
# privilege pg_graphql's own introspection query checks.
_ON_FUNCTION_OR_SCHEMA = re.compile(
    r"\bON\s+(?:ALL\s+)?(?:FUNCTION|ROUTINE|PROCEDURE|SCHEMA)S?\b", re.IGNORECASE
)


def _grant_target(text: str, start: int, end: int, to_pattern: re.Pattern[str]) -> str | None:
    """The granted object's bare name if `text[start:end]` (one GRANT statement's span)
    is a `GRANT ... ON <obj> TO <role>` (matching `to_pattern`) on a table/view, else
    None. Ordered, bounded searches — never one combined regex over the whole span."""
    if _ON_FUNCTION_OR_SCHEMA.search(text, start, end):
        return None
    o = _ON_TOKEN.search(text, start, end)
    if o is None:
        return None
    if to_pattern.search(text, o.end(), end) is None:
        return None
    return o.group(1).strip('"').strip(";").strip(",")


class PgGraphqlTableExposedGuard(Guard):
    id = "pg-graphql-table-exposed"
    title = "Table visible in the pg_graphql schema to anon/authenticated"
    area = "Database"
    schema_state = True  # extension + grants a schema dump reproduces

    # sql/graphql_exposure.sql: pg_graphql installed + GRANT SELECT ... TO anon on a
    # table -> fires pg-graphql-table-exposed/anon.
    canary_plant = CanaryPlant(
        files={
            "sql/graphql_exposure.sql": (
                "CREATE EXTENSION IF NOT EXISTS pg_graphql;\n"
                "GRANT SELECT ON TABLE internal_notes TO anon;\n"
            ),
        },
        expects=frozenset({"pg-graphql-table-exposed/anon"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "supabase" in profile.features or "graphql" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        sql_files = list(iter_files(root, (".sql",)))

        graphql_installed = False
        for f in sql_files:
            raw = read(f)
            if raw and _CREATE_EXT_GRAPHQL.search(strip_sql_comments(raw)):
                graphql_installed = True
                break
        if not graphql_installed:
            return []

        out: list[Finding] = []
        for f in sql_files:
            # L6 (the PR #904 review): scope to product SQL only, matching this
            # PR's own sibling `rls_fkey_to_auth_non_primary.py` — an example/reference .sql
            # file must not fire a real GRANT-exposure finding.
            if is_reference_sql_path(rel(root, f)):
                continue
            raw = read(f)
            if not raw or pragma_present(_PRAGMA, raw, dialect="sql"):
                continue
            cleaned = strip_sql_comments(raw)
            for g in _GRANT_KW.finditer(cleaned):
                stmt_end = find_statement_end(cleaned, g.start())
                end = len(cleaned) if stmt_end == -1 else stmt_end
                lineno = cleaned.count("\n", 0, g.start()) + 1
                for role, to_pattern, rule_suffix in (
                    ("anon", _TO_ANON, "anon"),
                    ("authenticated", _TO_AUTHENTICATED, "authenticated"),
                ):
                    target = _grant_target(cleaned, g.end(), end, to_pattern)
                    if target is None:
                        continue
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="medium",
                            title=self.title,
                            location=f"{rel(root, f)}:{lineno}",
                            message=(
                                f"`{target}` is granted to `{role}`, and `pg_graphql` is "
                                "installed in this project. That combination makes "
                                f"`{target}`'s name, columns, and relationships visible "
                                "through `/graphql/v1` introspection to anyone holding the "
                                f"{'public anon key' if role == 'anon' else 'authenticated key (any signed-up user)'}"
                                " — regardless of what Row Level Security policies restrict "
                                "at the row level. RLS hides row data; it does not hide "
                                "schema shape."
                            ),
                            remediation=(
                                f"If `{target}` should not be discoverable via GraphQL to "  # nosec B608 (example SQL in remediation prose, not a real query)
                                f"{'unauthenticated callers' if role == 'anon' else 'every signed-up user'}, "
                                f"`REVOKE SELECT ON {target} FROM {role};`. If the exposure "
                                "is intentional (the table is meant to be publicly "
                                "queryable), add "
                                f"`-- {_PRAGMA}` to this file."
                            ),
                            rule=f"pg-graphql-table-exposed/{rule_suffix}",
                            standards=list(_STANDARDS),
                        )
                    )
        return out
