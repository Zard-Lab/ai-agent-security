---
type: Guard
title: "rls-auth-email-lockout"
description: "RLS policy gates on auth.email() - email-change / case / plus-addressing silent lockout."
timestamp: "2026-09-18T00:00:00Z"
guard_id: "rls-auth-email-lockout"
checklist_section: ["7"]
standards: ["OWASP:A01"]
---

# RLS policy gates on auth.email()

Flags any RLS policy clause containing `auth.email()`. Closes checklist item
`7-rls-auth-email-lockout`. Mined from `pgrls`'s SEC034. OWASP:A01.

## The threat

A policy that scopes rows by email — `USING (owner_email = auth.email())` — carries three
subtle failure modes that are footguns rather than exploits, all leading to silent
denial-of-service-to-self rather than privilege escalation:

1. **Email change flow.** Supabase supports user-initiated email change; rows owned by the old
   email become invisible to the user who owns them until a manual repair UPDATE.
2. **Case sensitivity.** SQL `=` is case-sensitive; email handling is conventionally
   case-insensitive — a stored/JWT case mismatch silently denies.
3. **Plus-addressing.** `user+tag@gmail.com` and `user@gmail.com` reach the same inbox but
   compare unequal.

## What counts as a hit (and what doesn't)

Fires on any `auth.email()` call anywhere inside a policy's `USING`/`WITH CHECK` clause — no
further qualification needed, since every use of this function as a row-matching key carries the
same three failure modes regardless of the surrounding expression shape.

Both the bare `auth.email()` spelling and the `pg_dump`/migration-tool quoted form
`"auth"."email"()` (the shape a Supabase schema dump ships) are matched, via the shared
`pg_auth_call_pattern` helper; a same-shaped call on another schema stays silent.

Suppress with `-- security: allow-auth-email-lockout` for an intentional use.

## What this guard does NOT prove

It does not distinguish `auth.email()` used as the primary discriminator from a secondary,
display-only reference that happens to sit inside the policy clause for an unrelated reason —
any occurrence fires.

## Related

A narrower, Supabase-specific companion to `rls-current-user-tenant-key` — both flag a
discriminator choice that looks correct but silently fails to do what the author intended.

# Citations

[1] agentsec checklist item `7-rls-auth-email-lockout` (§7)
[2] OWASP:A01
[3] pgrls SEC034 — the source pattern this guard mirrors
