---
type: Guard
title: "rls-anon-write-access"
description: "Permissive policy grants the anon role write access - unauthenticated data tampering."
timestamp: "2026-09-18T00:00:00Z"
guard_id: "rls-anon-write-access"
checklist_section: ["7"]
standards: ["OWASP:A01"]
---

# Permissive policy grants the anon role write access

Flags a PERMISSIVE policy whose `TO` clause includes the named `anon` role and whose command
covers a write (INSERT/UPDATE/DELETE/ALL). Closes checklist item `7-rls-anon-write-access`.
Mined from `pgrls`'s SEC039. OWASP:A01.

## The threat

Supabase (and any PostgREST deployment) exposes the database through two built-in roles: `anon`
for requests carrying no JWT and `authenticated` for signed-in users. A permissive policy whose
role list includes `anon` for a write command lets an unauthenticated client modify rows —
anonymous data tampering, insertion, or deletion, gated by that policy's own clause and by the
table's GRANT (without a matching `GRANT INSERT`/etc. the write is `permission denied`, which is
why the remediation revokes the grant too, not just the policy scope). `anon` *read* (SELECT)
access is a deliberate, common public-data pattern and is not flagged — only the write side is.

## What counts as a hit (and what doesn't)

Reuses `rls-permissive-policy`'s role-target and `AS RESTRICTIVE` detection: fires when a policy
is PERMISSIVE (not `AS RESTRICTIVE`), its `TO` clause includes `anon`, and its command — read from
an explicit `FOR` clause, or `ALL` when `FOR` is omitted (Postgres's own default when no `FOR` is
given) — covers `INSERT`/`UPDATE`/`DELETE`/`ALL`. `FOR SELECT` policies are excluded.

This is the write-side analog of `policy-no-role-scope`'s PUBLIC check, for the *named* `anon`
role specifically — `policy-no-role-scope` catches a missing `TO` clause (defaulting to PUBLIC),
but Supabase's `anon` is a real, named role, not the PUBLIC pseudo-role, so a PUBLIC-scoped check
alone does not catch a policy explicitly scoped `TO anon`.

Suppress with `-- security: allow-anon-write-access` for an intentional anonymous-write design
(e.g. a public contact-form insert).

## What this guard does NOT prove

It does not verify the table actually has a matching `GRANT INSERT`/`UPDATE`/`DELETE` to `anon` —
a policy this broad with no matching grant is currently inert (the write is `permission denied`
at the GRANT layer), but flagging the policy regardless is the fail-safe direction: a grant added
later without revisiting the policy would otherwise go unnoticed.

## Related

Sibling of `policy-no-role-scope` — both flag an RLS policy reachable by a low-trust/anonymous
caller, on the missing-scope axis (`policy-no-role-scope`) vs. the named-anon-write axis (this
guard).

# Citations

[1] agentsec checklist item `7-rls-anon-write-access` (§7)
[2] OWASP:A01
[3] pgrls SEC039 — the source pattern this guard mirrors
