---
type: Guard
title: "rls-fkey-to-auth-non-primary"
description: "Foreign key into the auth schema references a non-primary-key column."
timestamp: "2026-09-19T00:00:00+00:00"
guard_id: "rls-fkey-to-auth-non-primary"
checklist_section: ["7"]
standards: ["OWASP:A01"]
---

# Foreign key into auth schema references a non-primary-key column

_Author — 2026-09-19_

**Guard ID:** `rls-fkey-to-auth-non-primary`
**File:** `agentsec/guards/rls_fkey_to_auth_non_primary.py`
**Checklist item:** `7-fkey-to-auth-references-primary-key` (covered)
**Standards:** OWASP:A01
**Severity:** MEDIUM
**Applies when:** `supabase` or `sql` in detected features

---

## The threat

Supabase's `auth.users.id` is the one stable, immutable identity anchor in the `auth` schema — it
is the table's primary key and never changes for the life of the account. A foreign key that
instead references a DIFFERENT unique constraint in `auth` — most commonly `auth.users(email)`, or
`auth.identities`' own `(provider_id, provider)` unique constraint — ties application data to a
value that is NOT the stable identity: an email address can be changed by the user (or reused
after an old account is deleted and a new one signs up with the same address), and an identity row
belongs to one linked provider, not the account itself. Either shape lets application data
silently point at the wrong person, or at nobody, after a change that has nothing to do with the
application's own logic.

Mirrors Supabase Splinter's `fkey_to_auth_unique` lint (`0021`), which runs live against
`pg_constraint`/`pg_index` (`indisunique AND NOT indisprimary`).

Verified against the real Supabase Auth (GoTrue) schema before building this guard, not assumed:
`auth.users.id` is the table's declared `PRIMARY KEY`; `auth.users.email` is a separate `UNIQUE`
column; `auth.identities` carries its own `identities_provider_id_provider_unique` constraint on
`(provider_id, provider)`, distinct from its primary key.

## Detection logic

1. **Scope gate:** `applies()` returns True when `supabase` or `sql` is in `profile.features`.
2. **Scan `.sql` files** (comment-stripped, reference/example paths skipped) for
   `REFERENCES auth.<table>` optionally followed by `(<column>)`.
3. **Safe, silent:** `auth.users(id)` explicitly, or a bare `auth.users` with no column (implicit
   primary-key reference).
4. **Fire MEDIUM:** any other explicit `auth.<table>(<column>)` pairing — a named column that
   is not the confirmed-safe `users(id)` anchor.
5. A bare `REFERENCES auth.<other_table>` with **no column** is left silent — it implicitly
   targets that table's own primary key, which this guard has no evidence is unsafe (only
   `auth.users(email)` and the `identities` composite unique constraint are confirmed
   non-primary shapes from the real schema).

**Suppress:** `-- security: allow-fkey-to-auth-non-primary` on the same line, or anywhere in the
file to opt the whole file out.

---

## Examples

```sql
-- Fires MEDIUM — email can change or be reused
CREATE TABLE public.newsletter_subscribers (
    user_email text REFERENCES auth.users(email)
);
```

```sql
-- Silent — the stable, correct pattern
CREATE TABLE public.profiles (
    user_id uuid REFERENCES auth.users(id)
);
```

---

## FP-bait (must stay silent)

- `REFERENCES auth.users(id)` explicitly.
- A bare `REFERENCES auth.users` with no column at all.
- An ordinary FK to a non-`auth` table (`REFERENCES public.customers(id)`).
- The pragma comment present.

---

## Canary plant

`sql/fkey_to_auth.sql`: a table with `user_email text REFERENCES auth.users(email)` → fires
`rls-fkey-to-auth-non-primary/non-primary-reference` (MEDIUM).

---

## Checklist coverage

| Item | Before | After |
|---|---|---|
| `7-fkey-to-auth-references-primary-key` | manual | **covered** |

---

# Citations

- Supabase Splinter, `fkey_to_auth_unique` (`0021`):
  https://github.com/supabase/splinter/blob/main/lints/0021_fkey_to_auth_unique.sql
- Supabase Auth (GoTrue) schema migrations: https://github.com/supabase/auth/tree/master/migrations
