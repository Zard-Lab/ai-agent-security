---
type: Guard
title: "rls-multiple-permissive-policies"
description: "Multiple permissive RLS policies on one table — access is the union."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "rls-multiple-permissive-policies"
checklist_section: ["7"]
standards: ["OWASP:A01"]
---

# Multiple permissive RLS policies on one table — access is the union

Flags a table with **2+ PERMISSIVE RLS policies for the same (role, command)**. Closes checklist item
`7-rls-multiple-permissive-policies`. OWASP:A01. Mirrors Supabase Splinter's `multiple_permissive_policies`.

## The threat

Permissive RLS policies are **OR'd**: a row is allowed if **any** permissive policy passes. So adding a
permissive policy only ever *widens* access — only a `RESTRICTIVE` policy narrows it. A developer who stacks
a second permissive policy on a table (often expecting to add a *restriction*) instead grants the **union** of
both conditions, frequently broader than intended. It's the second-most-common RLS mistake after the
always-true policy, and on a real Supabase schema it was the single largest issue the live Splinter run found
that the static guards had no equivalent for.

## Severity rationale

**MEDIUM (a smell to review, not a proven bug).** Multiple permissive policies is sometimes intentional —
distinct legitimate access paths OR'd on purpose. So this surfaces for review rather than asserting a bug.
(Contrast `rls-permissive-policy`, which is HIGH because `USING (true)` is almost never intentional.)

Note: Splinter categorizes its `multiple_permissive_policies` lint as **PERFORMANCE** (each policy is evaluated
per row). This guard adds the **security** framing — access-union breadth — and catches it **statically,
pre-deploy**, where Splinter only catches it live.

## Detection design

Parse every `CREATE POLICY … ;` statement (comment-blanked, multiline). For each **permissive** policy (i.e.
NOT `AS RESTRICTIVE`), extract the table (`ON <obj>`), the command (`FOR <cmd>`, default `ALL`), and the role
list (`TO …`, default PUBLIC). Group by `(table, command, role)` — expanding `FOR ALL` to all four commands
and the role list to its members, **excluding `service_role`** (it bypasses RLS, so stacking policies on it is
moot). Count **distinct policy names** per group (so a policy dropped-and-recreated across migrations counts
once). A group with **≥2** distinct names → one MEDIUM finding naming the table, role, command, and count.

The reported location is the last (sorted file order) contributing `CREATE POLICY` — which tends to be the
schema snapshot / latest migration, so the live policy set is cited.

## When NOT to flag (and the pragma)

- A second policy that is `AS RESTRICTIVE` → not counted (restrictive narrows; it doesn't union).
- Policies for *different* roles or *different* commands → no shared group, no finding.
- A group targeting only `service_role` → silent (RLS-bypassed).
- A single policy, or the same policy name re-created → not a "second policy."
- Intentional → `-- security: allow-multiple-permissive` anywhere in the `.sql` file.

## Known bypasses / limits

- **Migration over-count.** The scan is per-file across all migrations; a policy created and later `DROP`ped
  (without a same-name re-create) still contributes its name, so a table that *historically* had two policies
  but now has one can over-count. The superseded-migration demotion (`sql_state`) sinks history findings, and
  the live Splinter cross-check upgrades the genuinely-live ones to `confirmed-live` — so the report still
  leads correctly. (Per-file static analysis can't resolve net live state; that's Splinter's lane — see
  the SQL-guards-vs-Splinter division of labour.)
- **Role expansion is literal.** A custom role that *inherits* `authenticated` isn't expanded; only the named
  roles are grouped.
- **`FOR ALL` overlap** IS handled (expanded to each command), so a `FOR ALL` + `FOR SELECT` pair flags on SELECT.

## Comment blanking (issue #500)

This guard carried a **byte-identical** copy of `rls-permissive-policy`'s private, string-unaware
`re.sub(r"/\*.*?\*/", …, re.DOTALL)` and inherited all three of its silent-miss shapes: a `/*` inside an
ordinary literal, a `/* note -- superseded */` whose `*/` the line-comment pass ate first, and a Postgres
`E'…'` literal that mis-closed at its escaped quote. See
[[rls-permissive-policy]] for the full table and the measurements.

The failure mode here is one step removed and easier to miss: this guard reports on a **group**, so
blanking just one of two policies drops the group below the 2-policy threshold and the guard goes silent
without ever losing a statement it would have reported on. Both guards then moved to
`blank_block_comments(sql, dialect="sql")` with the `--` pass running **after** it — an ordering that is
load-bearing, not cosmetic.

Since #442 phase 2b, both guards read the shared `strip_sql_comments(sql, blank=True)`, the length- and newline-preserving lexer the other SQL guards use, with no private copy left. It is one scan with no
ordering to get wrong. It also treats a `--` inside a literal as data, a comment inside a `DO` body as a
comment, and a `COPY` data row as data. See [[rls-permissive-policy]].

## Checklist mapping

`7-rls-multiple-permissive-policies` (covered) → `test_rls_multiple_permissive_flags_two_permissive`.

## Cross-check

Mapped in `crosscheck._RULE_MAP` to Splinter's `multiple_permissive_policies`, so on a `live` run the static
findings that the DB confirms become `confirmed-live` (and the duplicate Splinter entity finding is folded out)
rather than appearing as static-only / splinter-only.

## Related

`rls-permissive-policy` (always-true, HIGH) and `policy-exists-rls-disabled` (RLS on, no policy) are the other
§7 RLS guards; together they cover the permissive-policy failure modes. This is the static, pre-deploy mirror
of Splinter's `multiple_permissive_policies`.

# Citations

[1] agentsec checklist item `7-rls-multiple-permissive-policies` (§7)
[2] OWASP:A01
