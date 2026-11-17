---
type: Guard
title: "pg-graphql-table-exposed"
description: "Table visible in the pg_graphql schema to anon/authenticated."
timestamp: "2026-09-19T00:00:00+00:00"
guard_id: "pg-graphql-table-exposed"
checklist_section: ["7"]
standards: ["OWASP:A01"]
---

# Table visible in the pg_graphql schema to anon/authenticated

_Author — 2026-09-19_

**Guard ID:** `pg-graphql-table-exposed`
**File:** `agentsec/guards/pg_graphql_table_exposed.py`
**Checklist item:** `7-pg-graphql-no-anon-authenticated-table-exposure` (covered)
**Standards:** OWASP:A01
**Severity:** MEDIUM
**Applies when:** `supabase` or `graphql` in detected features

---

## The threat

`pg_graphql` introspection reflects the calling role's Postgres privileges directly: if `anon`
(or `authenticated`) can `SELECT` a table, view, materialized view, or foreign table, that
object's name, columns, and relationships are visible through `/graphql/v1` to anyone holding the
corresponding key — **even when Row Level Security is enabled and correctly scoped.** RLS
restricts which *rows* a query returns; it does nothing to hide that the table exists, what its
columns are called, or how it relates to other tables. A developer who confirms "RLS is on, so
this table is protected" can still be leaking their entire schema shape to an unauthenticated
caller — useful reconnaissance on its own, and for a table whose very *name* is sensitive
(`refunds_flagged_for_fraud`, `internal_admin_notes`), a disclosure regardless of row-level access.

Mirrors Supabase Splinter's paired `pg_graphql_anon_table_exposed` / `pg_graphql_authenticated_table_exposed`
lints (`0026`/`0027`), which run live against `pg_catalog.has_column_privilege(...)`.

## Detection logic

1. **Scope gate:** `applies()` returns True when `supabase` or `graphql` is in `profile.features`.
2. **Extension check:** `CREATE EXTENSION pg_graphql` must be present somewhere in the scanned SQL
   — if not, the guard returns no findings at all (this exact GRANT shape without the extension is
   `pg-anon-grant`'s territory, not this guard's).
3. **GRANT scan, statement-bound not line-bound:** for each `GRANT` keyword, the search window
   runs to that statement's own terminating `;` (via `find_statement_end`), so a `GRANT ... ON ...
   TO ...` split across multiple lines (a common SQL-formatter style) is still found.
4. **Two rule variants, one per role:** `pg-graphql-table-exposed/anon` when the grant targets
   `anon`/`public`; `pg-graphql-table-exposed/authenticated` when it targets `authenticated`.
5. **Excluded:** a `GRANT EXECUTE ON FUNCTION/ROUTINE/PROCEDURE` (a different exposure path, RPC-
   call not table introspection — already covered by `pg-anon-grant`/`definer-function-grants`),
   and a bare `GRANT USAGE ON SCHEMA` (no column privilege, which is what pg_graphql's own
   introspection query actually checks).

Severity is MEDIUM, not HIGH: this is schema/metadata visibility, not the row-data access a
missing-RLS finding represents — complementary, not the same claim.

**Suppress:** `-- security: allow-pg-graphql-table-exposed` anywhere in a `.sql` file.

---

## Examples

```sql
-- Fires MEDIUM: pg-graphql-table-exposed/anon
CREATE EXTENSION IF NOT EXISTS pg_graphql;
GRANT SELECT ON TABLE internal_notes TO anon;
```

```sql
-- Fires MEDIUM: pg-graphql-table-exposed/authenticated (multi-line GRANT, statement-bound)
CREATE EXTENSION pg_graphql;
GRANT SELECT
  ON internal_notes
  TO authenticated;
```

---

## FP-bait (must stay silent)

- The identical GRANT with `pg_graphql` never installed.
- `GRANT EXECUTE ON FUNCTION do_thing() TO anon` (function grant, different exposure path).
- `GRANT USAGE ON SCHEMA app TO anon` (namespace access, no column privilege).
- `GRANT SELECT ON internal_notes TO service_role` (privileged server-side role, not anon/authenticated).
- The pragma comment present.

---

## Adversarial self-test

**Bypass attempt (2026-09-19):** can a multi-line GRANT statement evade the check by splitting the
`ON`/`TO` keywords across lines? No — the search window is statement-bound via `find_statement_end`,
not line-bound, so `GRANT SELECT\n  ON t\n  TO anon;` still fires. This was fixed during the
guard's own build (an initial line-bound version missed exactly this shape, caught by an
adversarial self-test before the guard shipped).

---

## Canary plant

`sql/graphql_exposure.sql`: `CREATE EXTENSION pg_graphql;` + `GRANT SELECT ON TABLE internal_notes
TO anon;` → fires `pg-graphql-table-exposed/anon` (MEDIUM).

---

## Checklist coverage

| Item | Before | After |
|---|---|---|
| `7-pg-graphql-no-anon-authenticated-table-exposure` | manual | **covered** |

---

# Citations

- Supabase Splinter, `pg_graphql_anon_table_exposed` (`0026`):
  https://github.com/supabase/splinter/blob/main/lints/0026_pg_graphql_anon_table_exposed.sql
- Supabase Splinter, `pg_graphql_authenticated_table_exposed` (`0027`):
  https://github.com/supabase/splinter/blob/main/lints/0027_pg_graphql_authenticated_table_exposed.sql
