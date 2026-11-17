---
type: Guard
title: "rls-pattern-match-auth-context"
description: "RLS policy pattern-matches a column against an auth-context value - a wildcard session value bypasses it."
timestamp: "2026-09-18T00:00:00Z"
guard_id: "rls-pattern-match-auth-context"
checklist_section: ["7"]
standards: ["OWASP:A01"]
---

# RLS policy pattern-matches against an auth-context value

Flags a policy predicate that compares a column against an auth-context value
(`current_setting`/`auth.uid()`/`auth.role()`/`auth.jwt()`/`current_user`/`current_role`/
`session_user`) using a pattern-matching operator instead of `=`. Closes checklist item
`7-rls-pattern-match-auth-context`. Mined from `pgrls`'s SEC026. OWASP:A01.

## The threat

`USING (user_email ILIKE current_setting('app.email'))` makes the predicate's tightness depend
on the *shape* of the session value, not its identity. `LIKE`/`ILIKE` interpret `%`/`_` as
wildcards — if the GUC is ever set to `%` (or any wildcard shape), every row matches, a total
bypass. The same hole opens for POSIX regex operators: a session value of `.*` matches
everything. The author usually wanted case-insensitive matching; the fix is a plain `=`
comparison, with normalization (store/compare lowercased) if case-insensitivity is genuinely
needed — never a pattern operator against a value the session controls.

## What counts as a hit (and what doesn't)

Extracts each `CREATE POLICY` statement's clause body and matches a pattern operator
(`LIKE`/`ILIKE`/`SIMILAR TO`/`~`/`~*`/`!~`/`!~*`, with `NOT` variants) adjacent to an auth-context
call on either side. Fires in both operand orders — `column LIKE <auth>` and `<auth> LIKE
column` — since the vulnerability is symmetric.

The auth-context calls `auth.uid()`/`auth.role()`/`auth.jwt()` are matched in both the bare
spelling and the `pg_dump`/migration-tool quoted form `"auth"."uid"()` (the shape a Supabase
schema dump ships), via the shared `pg_auth_call_pattern` helper; a same-shaped call on
another schema (`"public"."uid"()`) is not an auth-context value and stays silent.

**Deliberately excludes an auth value compared to a literal pattern** (`current_user LIKE
'admin%'`) — the non-auth operand must be a bare identifier (a column reference), not a quoted
string, so an author-written wildcard against a fixed string isn't flagged. This falls out
naturally from the identifier regex requiring the operand to start with a letter/underscore,
which a quoted literal never does.

Suppress with `-- security: allow-pattern-match-auth-context` for an intentional pattern match.

## What this guard does NOT prove

It matches by operator adjacency, not a real expression tree — a pattern operator several tokens
away from the auth call inside a more complex sub-expression can be missed. It also does not
attempt pgrls's SubLink-wrapped-value nuance (`col LIKE (SELECT current_setting(...))` vs a real
lookup sub-select with a FROM clause); this guard's clause-level scan would treat both the same,
a coarser approximation than the source rule's AST distinction.

## Related

Sibling of `rls-current-user-tenant-key`/`rls-hardcoded-tenant-literal` — all three flag ways a
policy's comparison operator, not its discriminator column choice, silently defeats the intended
scoping.

# Citations

[1] agentsec checklist item `7-rls-pattern-match-auth-context` (§7)
[2] OWASP:A01
[3] pgrls SEC026 — the source pattern this guard mirrors
