---
type: Guard
title: "rls-restrictive-only"
description: "Table has only RESTRICTIVE policies - silent deny-all."
timestamp: "2026-09-18T00:00:00Z"
guard_id: "rls-restrictive-only"
checklist_section: ["7"]
standards: ["OWASP:A01"]
---

# Table has only RESTRICTIVE policies — silent deny-all

Flags a table with RLS enabled, at least one policy, and zero PERMISSIVE policies among them.
Closes checklist item `7-rls-restrictive-only`. Mined from `pgrls`'s SEC012. OWASP:A01.

## The threat

Postgres composes RLS policies as `(permissive policies OR'd together) AND (restrictive
policies AND'd together)`: a row is visible iff at least one PERMISSIVE policy matches AND every
RESTRICTIVE policy matches. With zero PERMISSIVE policies, the OR-group is empty — no row
passes, regardless of how many RESTRICTIVE policies exist or what they say. A developer who adds
a RESTRICTIVE policy expecting it to "layer on top of" an implicit permissive default has instead
made the table silently deny-all — there is no implicit default. This is the same effective shape
as `pg-rls-no-policy` (RLS enabled, zero policies) and `rls-permissive-policy`'s `always-false`
(`USING (false)`), achieved through a subtler, easier-to-miss mechanism.

## What counts as a hit (and what doesn't)

Cross-file aggregation, the same shape as `pg-rls-no-policy`/`pg-rls-not-forced`: collects every
table's RLS-enabled status and every `CREATE POLICY` for that table across all scanned files,
tracking whether each policy is PERMISSIVE (the default) or `AS RESTRICTIVE`. Fires when a table
has RLS enabled, at least one policy exists, and none of them is PERMISSIVE.

`AS { PERMISSIVE | RESTRICTIVE }` follows the `ON <table>` clause in `CREATE POLICY`'s own
grammar (not precedes it) — the search for it is scoped from the end of the `ON`-clause match to
the statement's own end, so a later statement's `AS RESTRICTIVE` can never leak backward into an
earlier one's classification.

A table with RLS enabled and zero policies at all stays silent here — that's
`pg-rls-no-policy`'s domain.

Suppress with `-- security: allow-restrictive-only` in a file defining the table's policies, for
a deliberate "shadow" table meant to be queried only via a SECURITY DEFINER function, never
directly.

## What this guard does NOT prove

It does not evaluate whether the deny-all is actually reached by any client role (unlike
`pg-rls-no-policy`, which grades severity by client-grant reachability) — every restrictive-only
table fires at the same MEDIUM severity, since even a deny-all reachable only by `service_role`
is more likely an authoring mistake here than the deliberate design `pg-rls-no-policy`'s INFO
tier accounts for.

## Related

Sibling of `pg-rls-no-policy` and `rls-permissive-policy`'s `always-false` — all three are static
mirrors of the different ways an RLS-enabled table ends up silently deny-all.

# Citations

[1] agentsec checklist item `7-rls-restrictive-only` (§7)
[2] OWASP:A01
[3] pgrls SEC012 — the source pattern this guard mirrors
