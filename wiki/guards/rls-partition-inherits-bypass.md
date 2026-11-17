---
type: Guard
title: "rls-partition-inherits-bypass"
description: "Partition/inheritance child bypasses the parent's RLS when queried directly."
timestamp: "2026-09-18T00:00:00Z"
guard_id: "rls-partition-inherits-bypass"
checklist_section: ["7"]
standards: ["OWASP:A01"]
---

# Partition/inheritance child bypasses the parent's RLS

Flags a declarative-partition or classic-`INHERITS` child table whose parent has RLS enabled but
the child does not have its own. Closes checklist item `7-rls-partition-inherits-bypass`. Mined
from `pgrls`'s SEC041 (partition) and SEC043 (inheritance). OWASP:A01.

## The threat

Postgres does not propagate row-level security from a table down to a child that reaches it via
declarative partitioning (`CREATE TABLE child PARTITION OF parent ...`) or classic `INHERITS
(parent)` — `relrowsecurity` is per-table. A query routed *through the parent* applies the
parent's policies, but a query naming the **child directly** is governed by the child's own RLS
— and if the child has none, it returns every row, ignoring the parent entirely. This matters
wherever the child is reachable by name, notably PostgREST/Supabase (which exposes every granted
table in the schema — `GET /events_t1`) and any ORM or job that targets a partition/child
directly.

## What counts as a hit (and what doesn't)

Two-pass, cross-file: collects every table's RLS-enabled status (reusing the same
`ENABLE ROW LEVEL SECURITY` detection `pg-rls-no-policy`/`pg-rls-not-forced` use), then scans
`CREATE TABLE` statements for a `PARTITION OF <parent>` or `INHERITS (<parent>)` clause. Fires
when the parent has RLS enabled and the child does not have its own separate `ENABLE ROW LEVEL
SECURITY` statement anywhere in the scanned SQL.

Two rule variants sharing one guard: `partition-child-no-rls` for a declarative partition child,
`inherits-child-no-rls` for a classic-inheritance child — the same underlying Postgres behavior,
reached through two different table-creation syntaxes.

Suppress with `-- security: allow-partition-inherits-bypass` in the file defining the child, for
a case where direct access to the child is intentionally blocked at the GRANT layer instead.

## What this guard does NOT prove

It requires the parent's `ENABLE ROW LEVEL SECURITY` and the child's `PARTITION OF`/`INHERITS`
clause to both appear in scanned SQL — a child created against a live database without a
corresponding migration is invisible. It also does not verify the child's GRANT structure (a
child with no client-role grant at all is unreachable regardless of RLS, the same "who can even
query this" nuance `pg-rls-no-policy` accounts for with its severity split — this guard doesn't
attempt that here, since the underlying Postgres behavior is the same regardless of reachability).

## Related

Complements `pg-rls-not-forced` and `pg-role-bypassrls`/`pg-role-bypassrls-membership` — all four
cover a way RLS can be silently absent for a specific access path even though the "main" table
looks fully protected.

# Citations

[1] agentsec checklist item `7-rls-partition-inherits-bypass` (§7)
[2] OWASP:A01
[3] pgrls SEC041 (partition) / SEC043 (inheritance) — the source patterns this guard mirrors
