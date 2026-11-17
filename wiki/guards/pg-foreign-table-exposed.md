---
type: Guard
title: "pg-foreign-table-exposed"
description: "Foreign table granted to a low-trust role - no RLS is possible on it, ever."
timestamp: "2026-09-18T00:00:00Z"
guard_id: "pg-foreign-table-exposed"
checklist_section: ["7"]
standards: ["OWASP:A01"]
---

# Foreign table granted to a low-trust role

Flags a `CREATE FOREIGN TABLE` granted `SELECT` to `anon`, `authenticated`, or `PUBLIC`. Closes
checklist item `7-foreign-table-exposed`. Mined from `pgrls`'s SEC053. OWASP:A01.

## The threat

A foreign table (`postgres_fdw`/`file_fdw`, or a Supabase Wrapper over Stripe/S3/an external DB)
cannot carry RLS at all — Postgres rejects `ALTER TABLE <ft> ENABLE ROW LEVEL SECURITY` outright.
So a foreign table in a PostgREST-exposed schema that grants a row-reading privilege to a
low-trust role is directly readable at `GET /rest/v1/<ft>` with no row filtering possible —
every remote row is returned to any caller, even unauthenticated. This is the same "exposed
schema + low-trust grant = HTTP-reachable, unfiltered" conjunction `pg-rls-no-policy` covers, for
the one relation type where RLS structurally cannot be the answer.

## What counts as a hit (and what doesn't)

Collects every `CREATE FOREIGN TABLE` name, then scans `GRANT` statements for a `SELECT` grant on
one of those names whose grantee list includes `anon`, `authenticated`, or `PUBLIC` (case-folded,
direct grant only — a grant to a group role a low-trust role merely inherits is not expanded, the
same conservative scope pgrls's own SEC053 documents).

Suppress with `-- security: allow-foreign-table-exposed` for an intentional direct-access design.

## What this guard does NOT prove

It is a pure exposure test — no policy/predicate analysis is needed or possible for a relation
type that can never carry RLS. It does not verify the schema is actually PostgREST-exposed (this
guard doesn't currently model a configurable exposed-schema list the way pgrls's SEC049/SEC053
do) — any `GRANT` to a low-trust role on a foreign table fires, regardless of schema.

## Related

The foreign-table sibling of `pg-rls-no-policy` — the recommended mitigation is the same pattern
`definer-function-grants` already establishes: reach the remote data only through a SECURITY
DEFINER function that applies its own row-scoping logic, never a direct grant on the table.

# Citations

[1] agentsec checklist item `7-foreign-table-exposed` (§7)
[2] OWASP:A01
[3] pgrls SEC053 — the source pattern this guard mirrors
