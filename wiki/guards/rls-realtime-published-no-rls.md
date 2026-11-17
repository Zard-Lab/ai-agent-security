---
type: Guard
title: "rls-realtime-published-no-rls"
description: "Table published to Realtime with RLS disabled - every change broadcast unfiltered."
timestamp: "2026-09-18T00:00:00Z"
guard_id: "rls-realtime-published-no-rls"
checklist_section: ["7"]
standards: ["OWASP:A01"]
---

# Table published to Realtime with RLS disabled

Flags a table added to a Realtime publication (`ALTER PUBLICATION supabase_realtime ADD TABLE
...`) that does not have RLS enabled. Closes checklist item `7-rls-realtime-published-no-rls`.
Mined from `pgrls`'s SEC051. OWASP:A01.

## The threat

In Supabase Realtime, a table added to the `supabase_realtime` publication has its row changes
streamed to subscribed clients over the Realtime websocket. Realtime's "Postgres Changes" feature
applies the table's RLS policies to each change — evaluated as the *subscribed* role — before
delivering it, but only when RLS is enabled. A published table with RLS off has no policy to
apply, so every INSERT/UPDATE/DELETE is broadcast to every subscriber verbatim, regardless of
tenant — a side channel that bypasses the row filtering the REST API would enforce on the same
table.

## What counts as a hit (and what doesn't)

Collects every table's RLS-enabled status (reusing the same detection
`pg-rls-no-policy`/`pg-rls-not-forced` use) and every table named in an `ALTER PUBLICATION
<name> ADD TABLE ...` statement (a comma-separated list in one statement is expanded — each
table checked independently). Fires when a published table is not in the RLS-enabled set.

Suppress with `-- security: allow-realtime-published-no-rls` for an intentional public
presence/chat-style channel.

## What this guard does NOT prove

It only recognizes explicit `ADD TABLE` membership — a `FOR ALL TABLES` or (PG15+) `FOR TABLES IN
SCHEMA` publication, which implicitly includes every table without naming any individually, is
not expanded by this text-only scan (a disclosed narrower scope than pgrls's own
`pg_publication_tables`-based introspection).

## Related

The Realtime-channel analog of `public-table-rls`/`pg-rls-no-policy` — sharpened to name the
broadcast consequence specifically, the same relationship `rls-anon-write-access` has to
`policy-no-role-scope` for the write side.

# Citations

[1] agentsec checklist item `7-rls-realtime-published-no-rls` (§7)
[2] OWASP:A01
[3] pgrls SEC051 — the source pattern this guard mirrors
