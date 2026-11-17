---
type: Guard
title: "pgmq-queue-exposed-in-api"
description: "Supabase pgmq message queue exposed via the Data API."
timestamp: "2026-09-19T00:00:00+00:00"
guard_id: "pgmq-queue-exposed-in-api"
checklist_section: ["7"]
standards: ["OWASP:A01"]
---

# Supabase pgmq queue exposed via the Data API

_Author — 2026-09-19_

**Guard ID:** `pgmq-queue-exposed-in-api`
**File:** `agentsec/guards/pgmq_queue_exposed_in_api.py`
**Checklist item:** `7-pgmq-queue-not-exposed-via-api` (covered)
**Standards:** OWASP:A01
**Severity:** HIGH
**Applies when:** `supabase` in detected features

---

## The threat

`pgmq` (Postgres Message Queue) is Supabase's built-in queueing extension. Its queue tables live
in the `pgmq` schema, which is never itself part of the PostgREST Data API — but Supabase ships a
companion `pgmq_public` schema of thin wrapper views/functions specifically so a queue CAN be
reached over the Data API. Adding `pgmq_public` to the project's exposed API schema list is a
deliberate, one-line opt-in, and it is also the entire exposure: once reachable, any caller
holding the `anon` or `authenticated` key can read, send, and pop messages through `/rest/v1/`,
since queue tables are not RLS-scoped the way an application table would be.

Mirrors Supabase Splinter's `insecure_queue_exposed_in_api` lint (`0019`), which runs live against
`pg_catalog.has_table_privilege('anon'/'authenticated', ...)` on `pgmq.q_*` tables. This guard
reads the artifact that actually decides the exposure without a live connection: the project's own
`supabase/config.toml`.

## Detection logic

1. **Scope gate:** `applies()` returns True when `supabase` is in `profile.features`.
2. **Parse `supabase/config.toml`** (the Supabase CLI's own project config file) with the stdlib
   `tomllib` — not a regex, since a TOML array can span multiple lines and quoting varies.
3. **Fire HIGH** if `[api].schemas` includes `"pgmq_public"`. No secondary "is RLS enabled" check:
   exposure is controlled entirely at the schema-list level, and pgmq queue tables are not designed
   to carry per-row RLS the way a normal `public` table is.
4. A malformed or unparseable `config.toml`, or one with no `[api]` table at all, is silently
   skipped — never a crash.

**What this does NOT do:** it does not scan for `pgmq.create(...)` calls to confirm a queue
actually exists — the config line alone is sufficient, since exposure applies to every queue in
the project, not per-queue. It also does not scan for a SQL-GRANT-shaped alternative some projects
might use instead of the CLI config — a documented, narrower scope, not an oversight.

**Suppress:** `# security: allow-pgmq-queue-exposed` as a comment anywhere in `config.toml`.

---

## Examples

```toml
# Fires HIGH — pgmq_public added to the exposed schema list
[api]
schemas = ["public", "pgmq_public"]
```

```toml
# Silent — pgmq_public not exposed
[api]
schemas = ["public", "graphql_public"]
```

---

## FP-bait (must stay silent)

- A `config.toml` with no `[api]` table at all (e.g. only `[db]`) — must not crash, must stay silent.
- A malformed/unparseable `config.toml` — must not crash, must stay silent.
- The pragma comment present anywhere in the file.

---

## Canary plant

`supabase/config.toml` with `[api] schemas = ["public", "pgmq_public"]` → fires
`pgmq-queue-exposed-in-api/schema-exposed` (HIGH).

---

## Checklist coverage

| Item | Before | After |
|---|---|---|
| `7-pgmq-queue-not-exposed-via-api` | manual | **covered** |

---

# Citations

- Supabase Splinter, `insecure_queue_exposed_in_api` (`0019`):
  https://github.com/supabase/splinter/blob/main/lints/0019_insecure_queue_exposed_in_api.sql
- Supabase `pgmq` docs: https://supabase.com/docs/guides/queues
