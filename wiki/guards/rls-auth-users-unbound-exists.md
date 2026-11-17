---
type: Guard
title: "rls-auth-users-unbound-exists"
description: "Policy EXISTS-checks auth.users with no caller binding - passes for every authenticated user if anyone matches."
timestamp: "2026-09-18T00:00:00Z"
guard_id: "rls-auth-users-unbound-exists"
checklist_section: ["7"]
standards: ["OWASP:A01"]
---

# Policy EXISTS-checks auth.users with no caller binding

Flags a policy clause containing `EXISTS (SELECT ... FROM auth.users ...)` whose sub-select
carries no caller-binding condition. Closes checklist item `7-rls-auth-users-unbound-exists`.
Mined from `pgrls`'s SEC036. OWASP:A01.

## The threat

The exploit is a one-line omission. The correct shape:

```sql
USING (EXISTS (SELECT 1 FROM auth.users
               WHERE id = auth.uid()
                 AND raw_app_meta_data ->> 'role' = 'admin'))
```

is a per-user admin check. The buggy variant drops `id = auth.uid()`:

```sql
USING (EXISTS (SELECT 1 FROM auth.users
               WHERE raw_app_meta_data ->> 'role' = 'admin'))
```

— which evaluates to "is there ANY admin in the system?" rather than "is the CALLING user an
admin." If there's any admin at all, every authenticated user passes the policy. The SQL still
parses, tests pass when an admin exists in the test DB, and the production exploit is silent and
deterministic.

## What counts as a hit (and what doesn't)

Finds `EXISTS (...)` sub-selects inside a policy's `USING`/`WITH CHECK` clause via balanced-paren
extraction (`matching_close_paren`), checks whether the sub-select's body references
`auth.users`, and — if it does — checks whether the body contains a caller-binding signal
anywhere inside it: `auth.uid()`, `auth.role()`, `auth.jwt()`, `current_user`, `session_user`, or
`current_setting(...)`. Fires only when `auth.users` is referenced AND no binding signal is
present.

Suppress with `-- security: allow-auth-users-unbound-exists` for a genuinely system-wide check
(rare — most `auth.users` EXISTS checks are meant to be per-caller).

## What this guard does NOT prove

It requires the binding signal to be textually present anywhere inside the sub-select body, not
necessarily correctly wired into the WHERE clause comparing against `auth.users.id` — a binding
call present but logically disconnected (e.g. comparing against an unrelated column) would still
silence this guard, a coarser check than a real expression-tree analysis of which condition
actually correlates the sub-select to the caller.

## Related

A HIGH-value, narrowly-scoped complement to `rls-inverted-auth-check` — both catch a missing
per-caller binding, in different clause shapes (an `IS NULL OR` disjunct vs. an unbound `EXISTS`
sub-select).

# Citations

[1] agentsec checklist item `7-rls-auth-users-unbound-exists` (§7)
[2] OWASP:A01
[3] pgrls SEC036 — the source pattern this guard mirrors
