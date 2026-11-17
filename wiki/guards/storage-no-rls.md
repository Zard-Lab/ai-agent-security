---
type: Guard
title: "storage-no-rls"
description: "Private-looking Supabase storage bucket has no storage.objects RLS policy referencing it."
timestamp: "2026-08-23T01:40:23Z"
guard_id: "storage-no-rls"
checklist_section: ["7"]
standards: ["OWASP:A01", "CIS:6.3"]
---

# Private Supabase storage bucket with no storage.objects RLS policy

_Author — 2026-08-23. Built from our research notes (source:
[database-sentinel](https://github.com/Farenhytee/database-sentinel), `STORAGE_NO_RLS`)._

---

## The threat

Supabase Storage keeps two independent access controls: the bucket's own `public`/`private`
flag, and Row Level Security on the `storage.objects` table — the table that actually backs
every file's row (`bucket_id`, `name`, `owner`, metadata). `supabase_storage_public.py` already
catches the first gap (a bucket shipped with `public = true`). This guard catches the second,
distinct one: a bucket marked `public = false` that LOOKS locked down, but carries **zero**
`CREATE POLICY` statements on `storage.objects` referencing it.

That has two possible bad outcomes, both real:

* Supabase migrations enable RLS on `storage.objects` by default. With RLS on and no matching
  policy, Postgres denies **every** SELECT/INSERT/UPDATE/DELETE — an accidental lockout. The
  bucket looks "secured" in review (`public = false`) while the app itself cannot read or write
  to it, which gets "fixed" under time pressure by loosening the wrong control.
* If RLS is somehow not enforced on that table, the opposite holds: `public = false` is
  cosmetic and the bucket is wide open to anyone who can reach `storage.objects` directly.

Findings carry **OWASP A01 (Broken Access Control)** and **CIS 6.3**; severity **high** — this
is a real RLS-coverage gap, not a style nit, and it sits on the same "silently blocks or leaks
everything" axis as `pg_rls_no_policy.py`'s table-level check, scoped to Storage's one special
table.

## Why it's often introduced

`public = false` reads as "done" — it is the setting most tutorials and the Supabase dashboard
surface first, and it genuinely does stop the unauthenticated public-URL shortcut. Writing the
matching `storage.objects` policy is a separate, easy-to-forget step, especially because the
policy syntax (`bucket_id = 'x'` inside a `USING` clause on a table most developers never
touch directly) is much less discoverable than the bucket's own `public` toggle.

## Detection design

1. **`applies()` gate** — `"supabase" in profile.features`.
2. **Scan** — every `.sql` file under `profile.sql_dir` (or root), skipping reference/example/
   test paths via `is_reference_sql_path` (migrations are NOT skipped — they are the deployed
   schema, same convention as `pg_rls_no_policy.py`).
3. **Bucket definitions** — an `INSERT INTO storage.buckets (...) VALUES (...)` is read
   **positionally** (same technique and same limitations as `supabase_storage_public.py`'s
   `_insert_public_value`: no nested parens, no multi-row insert, no select-based insert) to
   extract the bucket's `id` and `public` column values. An `UPDATE storage.buckets SET
   public = false ... WHERE id = 'x'` is also recognized. A bucket whose `public` value is
   contradicted across migrations (`false` in one, `true` in another) is treated as ambiguous
   and never flagged.
4. **Object policies** — every `CREATE POLICY ... ON storage.objects` statement (found via
   `iter_statement_spans`, the linear O(419)-safe replacement for a scan-to-`;` regex) is read
   for the bucket(s) it scopes itself to: `bucket_id = '<id>'`, `bucket_id IN (...)`, or the
   folder-path convention `(storage.foldername(name))[1] = '<id>'`. A policy with **no**
   `bucket_id` filter at all is global — it covers every bucket and silences the whole guard.
5. **Cross-reference** — a private bucket (`public = false`, unambiguous) whose id never
   appears in any object-policy's bucket set, and no global policy exists, is flagged. One
   finding per bucket, at the location of the file that first declared it.
6. **Suppress** — `-- security: allow-storage-no-rls` anywhere in the file declaring the
   bucket. Severity **high**, rule `storage-no-rls/private-bucket-no-object-policy`, standards
   `["OWASP:A01", "CIS:6.3"]`.

### Deliberate narrowing vs. the source candidate

The candidate description also floated cross-referencing bucket-client SDK calls
(`storage.createBucket(...)`/`create_bucket(...)`) in Python/JS/TS, the way
`supabase_storage_public.py` does for its own (different) check. This guard stays **SQL-only**.
A bucket created via a client SDK call has no reliable, low-FP way to line up its name/id
against a SQL policy's `bucket_id` literal — they live in different files, often different
languages, and the id is frequently a runtime variable rather than a literal. Since this is a
"prove the mitigation is ABSENT" check, that ambiguity would either miss real gaps (a variable
bucket id never matches anything, so nothing is ever flagged) or over-fire (guessing a name
match that isn't the same bucket). SQL migrations keep both signals — bucket definition and
policy scope — in the same well-structured, statically-parseable source.

## When NOT to flag

* The bucket is public (`public = true`) — that is `supabase_storage_public.py`'s concern, not
  this guard's.
* A `CREATE POLICY ... ON storage.objects` anywhere in the scanned SQL references the bucket's
  id, directly or via the folder-path convention.
* A bucket-unscoped `storage.objects` policy exists — a deliberate, broad grant.
* The bucket's `public` value is contradicted across migrations — ambiguous, stays silent
  rather than guessing which value is current.
* The pragma is present in the file that declares the bucket.

## Tests

| Test | What it checks |
|---|---|
| `test_storage_no_rls_fires_on_private_bucket_no_policy` | private bucket, zero object policies → HIGH |
| `test_storage_no_rls_silent_when_policy_references_bucket` | FP-bait: a matching `bucket_id = '...'` policy exists → silent |
| `test_storage_no_rls_silent_when_policy_via_foldername` | FP-bait: folder-path-convention policy covers the bucket → silent |
| `test_storage_no_rls_silent_for_public_bucket` | `public = true` bucket → not this guard's concern, silent |
| `test_storage_no_rls_silent_via_global_policy` | bucket-unscoped `storage.objects` policy → silent |
| `test_storage_no_rls_silent_on_contradictory_public_value` | `public` flips false→true across migrations → ambiguous, silent |
| `test_storage_no_rls_fires_via_update_statement` | `UPDATE storage.buckets SET public = false WHERE id = ...` form → HIGH |
| `test_storage_no_rls_pragma_suppresses` | `-- security: allow-storage-no-rls` → silent |
| `test_storage_no_rls_applies_gate` | fires only when `supabase` is a detected feature |
| `test_storage_no_rls_no_sql_files` | no `.sql` files → empty, no crash |
| `test_storage_no_rls_skips_examples_dir` | a bucket def under `examples/` → silent (reference SQL) |
| `test_storage_no_rls_hostile_headless_sql_is_linear` | 30k head-repeats, no `;` → completes in well under 5s (issue #419 DoS class) |

## Known bypasses

* **Non-literal bucket id** — a bucket id built from a variable, function call, or
  `ON CONFLICT` upsert whose id comes from a subquery is not read (the positional extractor
  requires a literal in the `VALUES` tuple).
* **Multi-row / select-based INSERT** — only the first row of a multi-row `VALUES (...), (...)`
  insert is read positionally, the same documented limitation as `supabase_storage_public.py`.
* **Dashboard-created buckets** — a bucket created through the Supabase Dashboard UI rather
  than a committed migration is invisible to a static scan.
* **Policy defined via the Dashboard Policy Editor** — same blind spot in the other direction:
  a real policy that never made it into a `.sql` file looks like a gap here.

## What this guard does NOT prove

That the policies which DO exist are correctly scoped (e.g. that `bucket_id = 'docs'` is paired
with a sane `USING`/`WITH CHECK` predicate, or that RLS is actually enabled on
`storage.objects` in the first place) — only that at least one policy statement references the
bucket, or that a global policy exists. It reasons about `.sql` files, not live database state.

# Citations

[1] agentsec checklist item `7-storage-objects-no-rls` (§7)
[2] research notes (private, not in this repo)
[3] OWASP:A01
[4] CIS:6.3
