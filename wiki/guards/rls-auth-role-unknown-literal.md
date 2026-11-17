---
type: Guard
title: "rls-auth-role-unknown-literal"
description: "Policy compares auth.role() to a role name it never returns - a lockout when equal, admit-all when negated."
timestamp: "2026-10-06T00:00:00Z"
guard_id: "rls-auth-role-unknown-literal"
checklist_section: ["7"]
standards: ["OWASP:A01"]
---

# Policy compares auth.role() to a role name it never returns

Flags an RLS policy that compares `auth.role()` with a literal outside the fixed set of names
`auth.role()` can actually return. Such a comparison has a fixed truth value, and the guard
reports both directions: the equality never holds (`not-a-real-role`, a lockout), and its
negation always holds (`negated-always-true`, admit-all). Closes checklist item
`7-rls-auth-role-unknown-literal`. The lockout rule was mined from `pgrls`'s SEC037, and the
admit-all rule is its mirror (#924). OWASP:A01.

## The threat

In the Supabase/PostgREST auth model, `auth.role()` returns one of a small, fixed set of names
from the JWT. By default those are `anon`, `authenticated` and `service_role`.

**Lockout (`not-a-real-role`, MEDIUM).** A policy that tests equality against a string outside
that set (`auth.role() = 'admin'`) silently denies every row, because the equality never holds.
The result set is always empty, which hides the broken policy: a test seeded with "admin" data
sees no rows, a developer assumes the policy works, and the table becomes inaccessible in
production.

**Admit-all (`negated-always-true`, HIGH).** The negated comparison
(`auth.role() NOT IN ('admin')`, `<> 'admin'`, `IS DISTINCT FROM 'admin'`,
`NOT (auth.role() = 'admin')`) always holds, so the policy admits every row to every role it
targets. `TO authenticated USING (auth.role() <> 'admin')` lets every signed-in user read every
tenant's rows. `TO anon` makes that an unauthenticated read of the whole table. This is the same
exposure as `USING (true)`, which `rls-permissive-policy/always-true` grades HIGH. But it reads
like a real gate, and no other guard knows the `auth.role()` value domain. Before #924 the
role-scoped spellings were silent across every guard.

## What counts as a hit (and what doesn't)

**`not-a-real-role`** fires on `auth.role() = '<literal>'` in either operand order and on
`auth.role() IN ('<literal>', ...)`. Each literal is checked against the known-role set. There is
one finding per distinct unknown literal per statement: two comparisons with the same unknown
literal collapse to one finding, and two with different literals give two, since each is usually
a distinct typo or intent with a distinct fix. A match that an odd number of `NOT`s reach is
skipped, because negated, the never-true comparison is always true, which is the opposite of the
lockout claim (#893 #B, #924). `NOT` binds below every comparison and above `AND` / `OR`, so a
`NOT` reaches to the next `AND` / `OR` in its own group, or to the end of that group. That
covers `NOT (...)`, `NOT EXISTS (...)`, `x NOT IN (...)`, `NOT x IN (...)` and a bare leading
`NOT`. A paren group and a `CASE ... END` are each a group, so `NOT CASE ... END` negates the
whole `CASE`. A `NOT` inside a `CASE` ends at the next `WHEN` / `THEN` / `ELSE` (a branch
boundary), and one inside an argument list ends at the next comma. Two negations cancel:
`NOT NOT (auth.role() = 'admin')` is a lockout again and still fires. A literal in a clause the admit-all rule proves always true is skipped too. A dead
`= 'moderator'` disjunct next to an always-true one is not a lockout.

**`negated-always-true`** is a claim made only where it is provable:

1. **The atom.** A whole expression that is one of `auth.role() <> 'L'`, `!= 'L'` or
   `IS DISTINCT FROM 'L'` (either operand order), `auth.role() NOT IN ('L', ...)`, pg_dump's
   `auth.role() <> ALL (ARRAY['L'::text, ...])`, or an odd run of `NOT` over
   `auth.role() = 'L'` / `auth.role() IN ('L', ...)`. An even run of `NOT` cancels and leaves the
   atom as written. Casts like `'L'::text` are accepted. **Every** literal must be
   unknown: `NOT IN ('admin', 'anon')` excludes `anon`, so it is a real gate and stays silent.
   So does a list with a non-literal member.
2. **The clause.** The atom must be the whole `USING` / `WITH CHECK` body or a depth-0 `OR`
   disjunct of it (nested disjuncts included). SQL's `AND` binds tighter than `OR`, so in
   `owner_id = auth.uid() AND auth.role() <> 'admin'` the atom is only a conjunct and the policy
   is scoped. That stays silent, as do a `CASE WHEN auth.role() <> 'admin' THEN ...` branch and
   `(auth.role() <> 'admin') = false`. An `OR` inside a `CASE ... END` body belongs to a branch
   or a `WHEN` condition, never to the clause, so `CASE WHEN p OR auth.role() <> 'admin' THEN
   owner_id = auth.uid() END` stays silent too. Structure is read on a view with literal and identifier
   content blanked, using `policy_no_role_scope`'s paren map and depth-0 split, so a quoted `or`
   never splits a clause.
3. **The policy.** The gating mirrors `rls-permissive-policy/always-true`. The `USING` clause
   decides, or `WITH CHECK` when there is no `USING` at all (a `FOR INSERT` policy). An
   `AS RESTRICTIVE` policy is skipped because it is a no-op floor, not a grant. A policy scoped
   only to `service_role` is skipped because that role bypasses RLS. The message names the
   targeted roles and adds "reachable by unauthenticated callers" for `anon` / PUBLIC.

Both rules match the bare `auth.role()` spelling and the `pg_dump`/migration-tool quoted form
`"auth"."role"()` (the shape a Supabase schema dump ships) through the shared
`pg_auth_call_pattern` helper. A call on any other schema (`"public"."role"()`) is not
`auth.role()` and stays silent. The quoted policy name is space-filled before any clause is read
(`blank_policy_names`), so a name like `"mark as restrictive"` or `"x using (y)"` can neither skip
nor fake a clause (#893 #C).

Suppress both rules with a `-- security: allow-auth-role-unknown-literal` comment on the
statement's own lines or on the line just before it. Use it for a deployment whose custom
access-token hook really issues a role name this guard's fixed set doesn't recognize: a real
role makes both the lockout claim and the admit-all claim false.

## What this guard does NOT prove

- The lockout rule only matches the literal-equality and `IN`-list shapes. It does not match
  `auth.role() = ANY(ARRAY[...])` or the other array-quantified comparisons that pgrls's real AST
  rule also covers.
- The lockout rule still overclaims when an unknown-literal equality is one `OR` disjunct beside
  a real check. `owner_id = auth.uid() OR auth.role() = 'admin'` admits owner rows, and only the
  admin branch is dead (a follow-up to #924).
- The admit-all rule reports nothing for a scoped `USING` paired with an always-true
  `WITH CHECK` (the `write-check-open` shape: the read side is gated, the write side open). It
  also does not cover `auth.jwt() ->> 'role' <> 'x'` (a different function with the same
  semantics), `ALTER POLICY`, or always-true shapes beyond the atoms above, such as
  `NOT (auth.role() = 'admin' AND ...)`.
- `<>` / `NOT IN` evaluate to NULL, not true, when `auth.role()` itself is NULL (a direct
  database connection with no JWT). "Admits every row" is the PostgREST-request claim, and every
  PostgREST request carries a role. `IS DISTINCT FROM` is true even then.
- The `<> ALL (ARRAY[...])` shape is the standard Postgres deparse of a multi-literal `NOT IN`,
  but it has not been checked against a live `pg_get_expr` here.

## Related

Companion to `rls-current-user-tenant-key`/`rls-hardcoded-tenant-literal`. All three flag a
comparison that reads as correct but silently fails to scope anything the way it appears to. The
admit-all rule is the domain-aware twin of `rls-permissive-policy/always-true`, which is
literal-only by design. An unscoped admit-all policy also draws
`policy-no-role-scope/no-to-clause` for its missing `TO` clause, which is a separate defect, the
same way an unscoped `USING (true)` does.

# Examples

```sql
-- not-a-real-role (MEDIUM): never true, the policy denies every row
CREATE POLICY p ON public.docs USING (auth.role() = 'admin');

-- negated-always-true (HIGH): always true, every signed-in user reads every row
CREATE POLICY p ON public.docs FOR SELECT TO authenticated
  USING (auth.role() NOT IN ('admin'));

-- negated-always-true (HIGH): one always-true OR disjunct opens the whole clause
CREATE POLICY p ON public.docs FOR SELECT TO anon
  USING (owner_id = auth.uid() OR auth.role() <> 'admin');

-- silent: a real gate (anon is a role auth.role() does return)
CREATE POLICY p ON public.docs USING (auth.role() NOT IN ('admin', 'anon'));

-- silent: the dead conjunct cannot widen a scoped policy
CREATE POLICY p ON public.docs FOR SELECT TO authenticated
  USING (owner_id = auth.uid() AND auth.role() <> 'admin');

-- the fix: scope by identity, or gate on the application role that IS allowed
CREATE POLICY p ON public.docs FOR SELECT TO authenticated
  USING (owner_id = auth.uid());
CREATE POLICY p ON public.docs FOR SELECT TO authenticated
  USING ((auth.jwt() -> 'app_metadata' ->> 'role') = 'editor');
```

# Citations

[1] agentsec checklist item `7-rls-auth-role-unknown-literal` (§7)
[2] OWASP:A01
[3] pgrls SEC037, the source pattern the lockout rule mirrors
[4] Issue #924, the negated (admit-all) polarity
