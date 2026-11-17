---
type: Guard
title: "pg-role-bypassrls"
description: "Role granted BYPASSRLS - skips every RLS policy, cluster-wide."
timestamp: "2026-09-18T00:00:00Z"
guard_id: "pg-role-bypassrls"
checklist_section: ["7"]
standards: ["OWASP:A01"]
---

# Role granted BYPASSRLS — skips every RLS policy, cluster-wide

Flags `CREATE ROLE ... BYPASSRLS` or `ALTER ROLE ... BYPASSRLS`. Closes checklist item
`7-role-bypassrls`. Mined from `pgrls`'s SEC016. OWASP:A01.

## The threat

A Postgres role granted the `BYPASSRLS` attribute skips **every** row-level security policy on
**every** table, cluster-wide. This is not a weakened policy — RLS is simply off for that role.
Nothing in a table definition, a policy, or a GRANT reveals that a particular role ignores all of
them: the bypass is invisible at every layer this codebase's other RLS guards inspect. An
application that authenticates as a BYPASSRLS role gets zero tenant isolation while every policy
in the schema still reads as airtight.

## What counts as a hit (and what doesn't)

Parses `CREATE ROLE` / `ALTER ROLE` statements (via the shared `iter_statement_spans`) and fires
when the statement contains the bare `BYPASSRLS` keyword — with the `NOBYPASSRLS` /
`NO BYPASSRLS` negation blanked out first so it can never satisfy the same regex (the two forms
share the substring `bypassrls`).

**Skipped when the same statement also grants `SUPERUSER`.** A superuser already bypasses RLS
unconditionally via `rolsuper`; `BYPASSRLS` on one is redundant noise, not an additional
exposure — mirrors pgrls's own superuser exclusion. This is a disclosed static-analysis
limitation: this guard cannot see a role's live superuser status if it was granted in a separate,
earlier `ALTER ROLE` statement in a different file — only same-statement co-occurrence is
checked.

Suppress with `-- security: allow-role-bypassrls` for a role that legitimately needs the
attribute — backup, logical-replication, or ETL roles are the common legitimate case (per
pgrls's own documentation of this pattern).

## What this guard does NOT prove

It sees the literal grant statement in migration SQL; it does not introspect the live cluster's
actual role attributes (a role could be granted BYPASSRLS outside any scanned migration, e.g.
via `psql` directly against a managed database console). It also does not follow the `SET ROLE`
escalation path — a role that is a *member* of a BYPASSRLS-carrying role does not itself bypass
RLS unless it actually `SET ROLE`s to it; that reachability question is a separate, unbuilt
pattern (pgrls's own SEC029).

## Related

Complements `pg-rls-not-forced` (the table-owner bypass, closed by `FORCE`) — together they cover
the two role-level ways a session can end up exempt from RLS regardless of how correct the
policies themselves are: ownership (until FORCE'd) and the BYPASSRLS attribute (unconditional,
FORCE does not touch it).

# Citations

[1] agentsec checklist item `7-role-bypassrls` (§7)
[2] OWASP:A01
[3] pgrls SEC016 — the source pattern this guard mirrors
