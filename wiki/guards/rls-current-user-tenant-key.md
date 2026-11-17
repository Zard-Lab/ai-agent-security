---
type: Guard
title: "rls-current-user-tenant-key"
description: "RLS policy keys row visibility off current_user/session_user - no isolation over a pooled connection."
timestamp: "2026-09-18T00:00:00Z"
guard_id: "rls-current-user-tenant-key"
checklist_section: ["7"]
standards: ["OWASP:A01"]
---

# RLS policy keys row visibility off current_user/session_user

Flags an RLS policy whose `USING`/`WITH CHECK` clause compares a column against
`current_user` or `session_user`. Closes checklist item `7-rls-current-user-tenant-key`. Mined
from `pgrls`'s SEC018. OWASP:A01.

## The threat

A policy shaped `USING (owner_role = current_user)` uses the Postgres role the session runs as
as the row-matching key. That isolates tenants only when every tenant connects as — or `SET
ROLE`s to — a distinct Postgres role. Application architectures almost never do that: a
connection pool authenticates as one shared database role and serves every tenant's requests
over it, so `current_user` is identical for every tenant and the comparison matches the same
way for everyone. The policy looks like access control and reads correctly in review, but the
discriminator is a constant. `session_user` (the login role, unchanged by `SET ROLE`) has the
same problem and is worse for a `SET ROLE`-per-request deployment, since it stays pinned to the
pool's login role regardless.

## What counts as a hit (and what doesn't)

Regex-based, a deliberately narrower approximation of pgrls's real AST-based SEC018 (which
resolves the compared column against the table's own-column list and distinguishes an operand
from a function argument). Extracts each `CREATE POLICY` statement's `USING`/`WITH CHECK` clause
body (via the shared `matching_close_paren`-based extraction this file's sibling
`rls-inverted-auth-check` already uses) and fires on a direct `<identifier> = current_user` /
`current_user = <identifier>` adjacency (or `<>`/`!=`).

Requiring the `=`/`<>`/`!=` operator directly adjacent excludes the two common non-findings on
its own:

- **A function argument** — `pg_has_role(current_user, 'pg_read_all_data', 'MEMBER')` never has
  a comparison operator directly next to `current_user`; it's an admin/role-privilege check, the
  standard escape branch of a policy, not a tenant key.
- **A literal comparison** — `current_user = 'postgres'` doesn't match `<identifier>` (a bare
  word, not a quoted string), so a single-role admin check stays silent.

**Deliberately excludes `current_role` and the bare `user` alias** that pgrls's SEC018 also
covers: `user` collides with an ordinary column literally named `user`, and neither alias is
common enough in real-world Supabase/PostgREST schemas to be worth that false-positive risk in a
text-only guard.

**Does NOT verify the compared identifier is actually a column of the policy's own table** — a
disclosed, coarser scope than pgrls's own-table check, which excludes a catalog/membership-table
lookup (`pg_roles.rolname = current_user`) reached through a sub-select. A guard operating on
text alone cannot resolve table membership the way a real schema-aware linter can; that
imprecision is accepted here rather than attempting a brittle heuristic.

Severity: MEDIUM. `current_user`-based policies are not universally wrong — the "role-per-tenant"
pattern (one Postgres role per tenant, `SET ROLE` per request) is a legitimate, documented design
where `current_user` is exactly the right discriminator. This guard cannot tell which deployment
model is in use.

Suppress with `-- security: allow-current-user-tenant-key` for a policy that genuinely uses the
role-per-tenant pattern.

## What this guard does NOT prove

It flags the structural comparison shape; it cannot determine the actual deployment model (pooled
vs. role-per-tenant) from the SQL alone — that is application/infrastructure context absent from
the schema. It also cannot see a catalog/membership-table variant of the pattern reached through a
sub-select (the same own-table-only scope pgrls's own SEC018 accepts, and this guard inherits it
without even the table-column verification pgrls has).

## Related

Sibling of `rls-inverted-auth-check` — both mine deeper RLS-policy anti-patterns from `pgrls`
beyond the constant-clause shapes `rls-permissive-policy` already covers, and share the same
clause-body extraction infrastructure.

# Citations

[1] agentsec checklist item `7-rls-current-user-tenant-key` (§7)
[2] OWASP:A01
[3] pgrls SEC018 — the source pattern this guard mirrors (narrowed scope, see above)
