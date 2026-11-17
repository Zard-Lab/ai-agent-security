---
type: Guard
title: "pg-function-immutable-reads-session"
description: "Function marked IMMUTABLE reads session state - a reused/cached plan serves a different user's value."
timestamp: "2026-09-18T00:00:00Z"
guard_id: "pg-function-immutable-reads-session"
checklist_section: ["7"]
standards: ["OWASP:A01"]
---

# Function marked IMMUTABLE reads session state

Flags `CREATE FUNCTION`/`ALTER FUNCTION` carrying `IMMUTABLE` whose body reads session/identity
state. Closes checklist item `7-function-immutable-reads-session`. Mined from `pgrls`'s SEC046.
OWASP:A01.

## The threat

`IMMUTABLE` promises the planner a function returns the same result for the same arguments
forever, so the planner may constant-fold the call at plan time — evaluate it once and bake the
literal into the plan. When the body actually reads `current_setting(...)`, an `auth.*` helper,
or `current_user`/`session_user`, that promise is false: the value frozen for the connection that
first planned the statement is reused for every later caller of any reused or cached plan. Plans
are reused all over a Postgres deployment — a connection pooler handing a backend to a different
user (Supavisor/PgBouncer), PostgREST, a prepared statement, a PL/pgSQL function's plan cache.
Used in an RLS policy, this is a silent cross-user data leak: a later caller on the same cached
plan is served the first caller's session value, not their own.

## What counts as a hit (and what doesn't)

Parses `CREATE FUNCTION`/`ALTER FUNCTION` statements and fires when the statement carries the
bare `IMMUTABLE` keyword (with `NOT IMMUTABLE` blanked out first) AND the statement text contains
a session read (`current_setting(`, `auth.<anything>(`, `current_user`, `session_user`).

Suppress with `-- security: allow-function-immutable-reads-session` for a case this guard's text
scan mis-detects (e.g. the session-read text sits in a comment inside the function body that
`strip_sql_comments` didn't fully neutralize, or dead code that's never actually reached).

## What this guard does NOT prove

It requires the session-read call to be textually present anywhere in the `CREATE FUNCTION`
statement, not necessarily in a path that's actually executed — a function body with an unreached
branch containing the call would still fire. The fix (declare STABLE) is safe either way, so this
is a disclosed over-approximation, not an under-approximation.

## Related

A niche but concrete companion to `pg-function-leakproof` and `pg-function-search-path` — all
three cover ways a function's declared attributes can silently defeat the correctness/isolation
guarantees Postgres's planner otherwise relies on them for.

# Citations

[1] agentsec checklist item `7-function-immutable-reads-session` (§7)
[2] OWASP:A01
[3] pgrls SEC046 — the source pattern this guard mirrors
