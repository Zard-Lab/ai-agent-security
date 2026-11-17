---
type: Guard
title: "rls-inverted-auth-check"
description: "RLS policy has an inverted auth check (auth function IS NULL OR ...) - anonymous callers hit a NULL short-circuit."
timestamp: "2026-09-18T00:00:00Z"
guard_id: "rls-inverted-auth-check"
checklist_section: ["7"]
standards: ["OWASP:A01"]
---

# RLS policy has an inverted auth check — anonymous callers hit a NULL short-circuit

Flags a Row Level Security policy whose `USING` or `WITH CHECK` clause carries a top-level
`<auth function> IS NULL OR <real check>` disjunct — the "Lovable CVE" pattern, mined from
`pgrls`'s SEC004 rule. Closes checklist item `7-rls-inverted-auth-check`. OWASP:A01.

## The threat

`auth.uid()` (and its siblings `auth.role()`, `auth.jwt()`, and the two-argument
`current_setting(name, true)` form) returns NULL for a token-less connection. A policy shaped
`USING (auth.uid() IS NULL OR owner_id = auth.uid())` reads, at a glance, like a scoped
per-owner policy — but for an anonymous caller the first disjunct is true, the `OR` is
satisfied, and `owner_id = auth.uid()` is never evaluated. Every row is exposed to every
anonymous caller, through a policy that looks like it does the right thing.

The write-side twin is the same shape in `WITH CHECK`: a token-less session's disjunct is true,
so the policy accepts any row that session writes — including rows stamped for another tenant.

This is a real-world footgun, not a theoretical construct — the pattern is named for a class of
CVEs found in Lovable-generated Supabase schemas, where an AI code generator wrote exactly this
"handle the anonymous case" branch without realizing it defeats the policy entirely.

## What counts as a hit (and what doesn't)

Regex-based, not a real parser (mirrors this codebase's other RLS clause guards, e.g.
`rls-permissive-policy`). Parses `CREATE POLICY ... ;` statements, extracts the `USING(...)` and
explicit `WITH CHECK(...)` clause bodies via a balanced-paren scan (`matching_close_paren`), and
searches each body for a nullable auth function's `IS NULL` immediately adjacent to an `OR`
keyword on either side (`<auth> IS NULL OR <x>` or `<x> OR <auth> IS NULL`, optionally through
parens) — approximating "top-level OR disjunct" without a real expression tree.

**Nullable auth functions:** `auth.uid()`, `auth.role()`, `auth.jwt()`, and
`current_setting(name, true)` (the two-arg `missing_ok=true` overload). Deliberately excludes:

- `current_user` / `session_user` / `current_role` / `user` — Postgres has no unauthenticated
  backend, so these always return the session role name and are never NULL. A policy comparing
  a column against `current_user` with an unrelated `IS NULL` disjunct elsewhere is not this bug.
- The one-argument `current_setting(name)` form — it *raises* on an unset GUC rather than
  returning NULL, so an `IS NULL` disjunct built on it can never actually be satisfied.
- An `IS NULL` disjunct gated by `AND`, not `OR` (e.g. `is_archived = false AND auth.uid() IS
  NULL`) — that narrows the policy rather than opening it, the opposite failure mode.

Only an **explicit** `WITH CHECK` is inspected separately from `USING`. Postgres reuses `USING`
as the implicit `WITH CHECK` on UPDATE/ALL when `WITH CHECK` is omitted, so an absent clause adds
no hole the USING finding hasn't already reported. A policy carrying the hole in both clauses
gets one finding naming both.

## Severity

HIGH when the policy is reachable by an anonymous/token-less session — `anon`/`PUBLIC`/no `TO`
clause, the same role vocabulary `rls-permissive-policy` uses. MEDIUM when the policy is
restricted to a named non-anon role (e.g. `TO authenticated`): the disjunct is still a latent
hole — it fires for any session in that role whose auth context happens to be NULL, and becomes
a full anonymous hole if the role restriction is ever loosened or `anon` is granted membership
in it — but this guard does not verify Postgres role-inheritance chains, so it does not claim the
same severity a direct anon-reachable policy gets.

Suppress an audited statement with `-- security: allow-inverted-auth-check`.

## What this guard does NOT prove

The `OR`-adjacency check is a regex heuristic, not boolean-algebra evaluation — a disjunct several
tokens away from its `OR` (behind an intervening function call before reaching the keyword) can be
missed, a disclosed false-negative direction shared with this codebase's other clause-shape RLS
guards. It also does not attempt pgrls's full nullability analysis for every possible auth-context
function; the four covered here (`auth.uid`/`auth.role`/`auth.jwt`/two-arg `current_setting`) are
the common Supabase/PostgREST auth-context surface, not an exhaustive list.

## Related

Sibling of `rls-permissive-policy` (constant-`true`/`false` clauses) and `policy-no-role-scope`
(missing `TO` clause) — all three are static mirrors of real RLS misconfiguration classes mined
from `pgrls`, agentsec's own Database Security area's deepest coverage gap relative to a dedicated
Postgres RLS linter.

# Citations

[1] agentsec checklist item `7-rls-inverted-auth-check` (§7)
[2] OWASP:A01
[3] pgrls SEC004 — the source pattern this guard mirrors
