---
type: Guard
title: "pg-rls-not-forced"
description: "RLS enabled but not FORCE'd - the table owner role still bypasses every policy."
timestamp: "2026-09-18T00:00:00Z"
guard_id: "pg-rls-not-forced"
checklist_section: ["7"]
standards: ["OWASP:A01"]
---

# RLS enabled but not FORCE'd — the table owner role still bypasses every policy

Flags a table with `ENABLE ROW LEVEL SECURITY` but no matching `FORCE ROW LEVEL SECURITY`
anywhere in the scanned SQL. Closes checklist item `7-rls-not-forced`. Mined from `pgrls`'s
SEC002. OWASP:A01.

## The threat

`ALTER TABLE ... ENABLE ROW LEVEL SECURITY` does not bind the table's OWNER role. An owner —
commonly the migration/deploy role, and the role most local dev and CI setups connect as —
bypasses every policy on the table unless `ALTER TABLE ... FORCE ROW LEVEL SECURITY` is also
set. Without FORCE, a policy that reads as correct in review, and that passes every test run
locally, can genuinely fail to scope anything for a non-owner client role in production. The gap
is invisible at the policy layer: the policies themselves can be entirely correct, and the
missing FORCE is a separate, easy-to-forget statement.

## What counts as a hit (and what doesn't)

Cross-file, same collection shape as the sibling `pg-rls-no-policy` guard: scans all `.sql`
files, collects every table with an `ENABLE ROW LEVEL SECURITY` statement and every table with a
`FORCE ROW LEVEL SECURITY` statement (both qualified and bare-name indexed, so an unqualified
`ALTER TABLE docs FORCE ...` still matches a schema-qualified `public.docs ENABLE ...` via
search-path resolution), and reports ENABLE-without-FORCE. A `FORCE` in ANY file (not just the
one containing the ENABLE) closes the gap.

An auto-generated SQL dump (`pg_dump`/`supabase db dump`, detected the same way
`pg_rls_no_policy.py` does — a structured header comment line, not prose mentioning a dump) is
excluded from the ENABLE-scanning pass, for the same reason: it mirrors live state, and an
un-pragma'd dump could otherwise re-surface a table whose FORCE the author deliberately omitted
and pragma'd in the hand-authored migration.

Suppress with `-- security: allow-rls-not-forced` anywhere in the file containing the ENABLE
statement — for the rare case where the owner genuinely needs an unrestricted path (e.g. a
maintenance script that intentionally runs as owner).

## What this guard does NOT prove

It does not evaluate whether the table's policies are themselves correct — only whether the
owner role is bound by them at all. A table can pass this guard (FORCE is set) and still have a
badly scoped policy (`rls-permissive-policy`'s job), or fail this guard and have perfectly
correct policies that simply never get exercised against a non-owner role in dev/CI.

## Related

Sibling of `pg-rls-no-policy` (RLS enabled, zero policies) — both are cross-file aggregation
guards over the same `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` signal, checking a different
axis of "does RLS actually do anything here."

# Citations

[1] agentsec checklist item `7-rls-not-forced` (§7)
[2] OWASP:A01
[3] pgrls SEC002 — the source pattern this guard mirrors
