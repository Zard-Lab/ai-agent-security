---
type: Guard
title: "rls-auth-uid-unwrapped"
description: "auth.uid()/auth.jwt() called unwrapped inside an RLS policy's USING/WITH CHECK clause, re-evaluated once per row instead of once per statement."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "rls-auth-uid-unwrapped"
checklist_section: ["7"]
standards: ["OWASP:A04"]
---

# auth.uid()/auth.jwt() called unwrapped in an RLS policy — re-evaluated per row

_Author — 2026-08-23_

---

## The threat

This is a **performance**, not a bypass, finding — it never grants access RLS didn't already
intend, so it is deliberately graded lower than this project's other RLS guards. Postgres's query
planner treats a bare function call inside a policy's `USING`/`WITH CHECK` expression as volatile
with respect to the current row, so it re-evaluates `auth.uid()`/`auth.jwt()` **once per row
scanned**, not once per statement:

```sql
-- re-evaluated once per row — a full-table scan pays this cost N times
USING (auth.uid() = user_id)

-- wrapped: the planner recognizes no correlation to the outer row and caches it as an
-- initplan, evaluated exactly once per statement
USING ((select auth.uid()) = user_id)
```

WHO reaches this: nobody attacker-side — this is not an access-control question. WHAT effect: on
a table with real row counts, every SELECT/UPDATE/DELETE that RLS filters through this policy pays
a JWT-claim-lookup cost proportional to the number of rows scanned rather than a constant cost per
statement — a real, measurable latency and CPU cost amplifier, and DoS-adjacent at the extreme (a
large or unindexed table under load). This is Supabase's own documented RLS performance guidance
([Row Level Security — Call functions with SELECT](https://supabase.com/docs/guides/database/postgres/row-level-security#call-functions-with-select)).
Findings carry `OWASP:A04` (Insecure Design) — the same standard this codebase already uses for
its other DoS-adjacent, non-bypass performance findings (see "Severity precedent" below), not
`OWASP:A01` (Broken Access Control), because nothing here widens or narrows who can read what.

## Why it's often introduced

Every Supabase quickstart, tutorial, and the dashboard's own policy editor template writes the
unwrapped form first, because it reads naturally as "the current user's id equals this row's
owner":

```sql
create policy "individuals can view their own todos"
on todos for select
using ( auth.uid() = user_id );
```

This is correct and safe — it is exactly what Supabase's own docs teach as the *first* pattern to
learn. The wrapped form is a *later*, opt-in performance optimization documented on Supabase's
"RLS performance" page, not the introductory example, so most policies never get the second pass
that would add the `(select ...)` wrapper — especially ones written early in a project, before the
table has enough rows for the cost to be visible in testing.

## Detection design

1. **`applies()` gate** — `"supabase" in profile.features`. `auth.uid()`/`auth.jwt()` are
   Supabase Auth helper functions with no equivalent in a hand-rolled Postgres app.
2. **Files scanned** — every `.sql` file under `profile.sql_dir` (or `root`), excluding
   `is_reference_sql_path` matches (examples/tutorials/test fixtures) — same filter every sibling
   guard in this batch applies (`policy_no_role_scope.py`, `storage_no_rls.py`,
   `matview_exposed.py`, `sensitive_columns.py`) and `pg_rls_no_policy.py` itself. **Fixed
   2026-08-25** — this guard originally omitted the filter and fired on example/tutorial SQL every
   sibling stays silent on; the omission was this doc's own error, not a deliberate scope cut.
3. **Statement-bounded parsing** — each `CREATE POLICY` statement's span (`;`-terminated) is found
   via the shared `iter_statement_spans` helper (the linear replacement for a
   `head … [^;]*? tail` scan-to-terminator regex — issue #419's fix, reused here rather than
   re-implemented). `auth.uid()`/`auth.jwt()` only ever appears meaningfully inside a policy's
   `USING`/`WITH CHECK` expression, so the whole statement span is scanned directly — no separate
   clause-boundary extraction is needed.
4. **The call, in both spellings** — `pg_auth_call_pattern("uid", "jwt")` matches the bare
   `auth.uid()` and the quote-all `"auth"."uid"()` that `supabase db dump` emits. Calls are found on
   a `blank_sql_literals` view of the statement, so the spelling inside a string literal is not a
   call, and a match that starts inside a quoted identifier (a policy NAMED
   `"owner: auth.uid() = user_id"`) is dropped too.
5. **Wrapped is a property, not a spelling (#855)** — a call is wrapped iff its NEAREST enclosing
   `( select` group is a self-contained scalar sub-SELECT, which is what lets the planner hoist it
   to an initplan. One linear pass per statement pairs parens on a second view (identifier contents
   blanked too, so a paren inside a name or a literal is inert) and records each call's nearest
   `( select`. Its body (the text after `select`, up to the matching paren) is self-contained iff,
   after stripping the auth calls, a trailing `AS <alias>`, `::<type>` casts, string literals,
   function names before `(` (schema-qualified ones included), numbers and `null`/`true`/`false`,
   no identifier character or `"` is left. Anything left over is a column reference (pg_dump
   qualifies outer ones, `t.id`), a `FROM`, or text the strip list does not know, and every one
   of those keeps the call firing. Only the nearest sub-SELECT decides: an outer wrapper never makes
   a call inside `EXISTS (SELECT 1 FROM … WHERE … = auth.uid())` per-statement. A sub-SELECT that
   contains another sub-SELECT is never self-contained (the inner `select` is residue), so only the
   innermost ones are residue-tested; they are disjoint, which keeps the pass linear. The verdict is
   memoised per sub-SELECT.
6. **Views per statement, not per file** — `blank_sql_literals` space-fills a whole `DO $$ … $$`
   body, and the idempotent `DO $$ BEGIN IF NOT EXISTS … THEN CREATE POLICY …` migration idiom
   puts the policy inside one. Built per file, the views hid 61 of 334 calls (51 policies) across
   the corpus-scan cache and two local Supabase app checkouts, correlated `EXISTS` true positives
   among them. Built per statement span (the spans are disjoint, so it stays linear), the policy text
   reads as code, and so does a policy built in an `EXECUTE '…'` literal.
7. **Inline opt-out pragma** — `-- security: allow-rls-auth-uid-unwrapped`, anywhere in the `.sql`
   file (file-level — see "When NOT to flag" for why file-level is an accepted trade-off here).
8. **Severity/rule/standards** — MEDIUM. Rule id `rls-auth-uid-unwrapped/uid-unwrapped` or
   `rls-auth-uid-unwrapped/jwt-unwrapped` depending on which function fired. Standards
   `["OWASP:A04"]`.

**Severity precedent.** MEDIUM was chosen against two comparable non-bypass, DoS-adjacent findings
already in this codebase's checklist, both also `OWASP:A04` and also MEDIUM:
`8-async-route-no-blocking-io` ("event-loop stall = single-request DoS") and `3a-upload-size-cap`
("memory-DoS protection"). All three share the same shape — a real availability/cost concern that
never bypasses access control — so the same severity tier applies. This is deliberately lower than
this codebase's other RLS guards (`policy-exists-rls-disabled`, `rls-permissive-policy`: CRITICAL/
HIGH), which are genuine access-control bypasses.

## When NOT to flag

- **`(select auth.uid())` / `(SELECT auth.jwt())`**, any case and any whitespace, stays silent: the
  wrapped form is exactly the fix this guard is recommending. So does every deparsed spelling of
  it (`( SELECT auth.uid() AS uid)`, `( SELECT (auth.jwt() ->> 'org'::text))`,
  `( SELECT ((auth.jwt() ->> 'sub'::text))::uuid AS uuid)` and their quote-all twins), and a
  hand-written sub-SELECT that carries more than the bare call but nothing correlated:
  `(select auth.jwt()->>'org_role')`, `(select auth.uid()::text)`,
  `(select coalesce(auth.jwt()->>'org_id', auth.jwt()->'o'->>'id'))`,
  `(select public.is_org_member(auth.uid()))`.
- **`auth.uid()` used OUTSIDE a `CREATE POLICY` statement** (a trigger function body, an ordinary
  `SELECT`) is out of scope — the per-row re-evaluation cost this guard is about is specific to
  the RLS planner path, not a general "don't call auth.uid() unwrapped" style rule.
- **A small or rarely-queried table** where the per-row cost is negligible — this is a genuine
  judgment call the guard cannot make statically (it has no row-count or query-frequency signal),
  so a reviewed, intentional case suppresses with
  `-- security: allow-rls-auth-uid-unwrapped`. The pragma is FILE-level, not statement-level,
  unlike the sibling RLS bypass guards' more careful statement-scoped pragmas — an accepted
  trade-off for a hygiene/perf guard where a suppression accidentally silencing an unrelated
  policy in the same migration file is a much lower-stakes mistake than for an access-control
  bypass guard.

## Tests

| Test | What it checks |
|---|---|
| `test_rls_auth_uid_unwrapped_na_without_supabase` / `test_rls_auth_uid_unwrapped_applies_with_supabase` | `applies()` gates on the `supabase` feature |
| `test_flags_unwrapped_auth_uid_in_using` | planted violation: a bare `auth.uid()` in `USING` fires |
| `test_flags_unwrapped_auth_uid_in_with_check` | a bare call in `WITH CHECK` fires independently of a wrapped `USING` in the same policy |
| `test_flags_unwrapped_auth_jwt` | `auth.jwt()` fires with its own rule id |
| `test_flags_both_clauses_unwrapped_as_two_findings` | `USING` and `WITH CHECK` each unwrapped -> two independent findings |
| `test_fp_bait_wrapped_auth_uid_stays_silent` / `test_fp_bait_wrapped_auth_jwt_stays_silent` | FP-bait: the documented safe form never fires, for both functions |
| `test_fp_bait_wrapped_form_is_case_and_whitespace_insensitive` | FP-bait: `( SELECT   AUTH.UID(  )  )` (mixed case, extra whitespace) still counts as wrapped |
| `test_pragma_opt_out` | the SQL pragma silences the finding |
| `test_na_without_sql_dir` | no `sql/` directory at all doesn't crash |
| `test_line_number_points_at_the_unwrapped_call` | the reported line matches the call's own line, not the statement head |
| `test_fp_bait_pg_dump_deparsed_wrapped_call_stays_silent` | #855: the `( SELECT auth.uid() AS uid)` deparse (single- and multi-line) and its quote-all twin stay silent |
| `test_fp_bait_deparsed_operator_and_cast_targets_stay_silent` | #855: deparsed jwt-operator targets (no alias, cast key) and cast targets (`AS uuid`, `AS uid`), plain and quoted |
| `test_fp_bait_hand_written_wrapped_forms_stay_silent` | #855: the Clerk example's jwt-in-subquery shapes, `::text`, `as me`, `(select(auth.uid()))`, a schema-qualified helper |
| `test_fp_bait_flagship_pg_dump_policies_stay_silent` | #855: the 98-policy flagship dump fixture (35 wrapped quoted calls) yields zero findings |
| `test_flags_quoted_unwrapped_call_from_a_dump` | #855 sibling FN: a quoted `"auth"."uid"()` / `"auth"."jwt"()` outside any sub-SELECT fires, with the right rule id |
| `test_flags_call_in_a_correlated_sub_select` | traded-against direction: a sub-SELECT that reads the outer row (`= t.id`, `COALESCE(…, t.id)`, a helper taking `t.org_id`) still fires |
| `test_flags_call_inside_exists_from_sub_select` / `test_fp_bait_wrapped_call_inside_exists_stays_silent` | the nearest sub-SELECT decides: a call in an `EXISTS (SELECT … FROM …)` body fires even under an outer wrapper; a wrapped call inside it is silent |
| `test_wrapped_and_bare_in_one_policy_fires_once_at_the_bare_call` / `test_deparsed_multi_line_policy_reports_the_bare_calls_line` | one finding per unwrapped call, at the call's own line |
| `test_fp_bait_call_spelling_inside_a_name_or_literal_stays_silent` / `test_bare_call_beside_a_literal_or_policy_name_spelling_still_fires_once` | the spelling in a quoted name, a literal or `myauth.uid()` is not a call; the real call beside them still fires exactly once |
| `test_flags_unwrapped_call_in_a_do_block_policy` / `test_flags_unwrapped_call_in_dynamic_execute_sql` | views are built per statement: a policy inside a `DO $$` body or an `EXECUTE` literal is still read as code |
| `test_unreadable_sub_select_body_is_a_known_residual_that_fires` | the safe-direction residuals below are pinned |
| `test_dump_copy_of_unwrapped_policy_gates` | end to end through `audit()`: the dump's copy of an unwrapped policy is reported and NOT superseded, so it gates |
| `test_sub_select_scan_cost_is_linear` | perf: nested sub-SELECTs, many calls sharing one sub-SELECT, deep parens and many calls all grow linearly (`assert_growth`) |
| `test_hostile_many_heads_no_terminator_bounded_time` | adversarial: 30,000 `create policy` heads with no `;` anywhere stays bounded (`iter_statement_spans` bails after the first failed terminator search) |
| `test_many_findings_bounded_time` | perf: 20,000 separate, well-terminated policies each with one unwrapped call all report, in linear time (the bisect-based line index, not a per-finding rescan) |

## Known bypasses

- **A sub-SELECT body the residue test cannot positively read keeps firing** (false positives, in
  the safe direction, pinned by `test_unreadable_sub_select_body_is_a_known_residual_that_fires`):
  a `FROM`, even an uncorrelated `FROM (select 1) s`; a multi-word cast type
  (`::timestamp with time zone`); an alias without `AS` (pg_dump always writes `AS`); SQL keywords
  in the body (`CASE … END`, `IS NOT NULL`, `= ANY (ARRAY[…])`); a hand-written
  `CAST(x AS type)` (its deparse, `(x)::type`, is silent); and a sub-SELECT that also contains
  another sub-SELECT. A CTE or other planner-cached form that is not a `( select` group is not
  recognized either.
- **`auth.role()` is out of scope.** Supabase's own `auth_rls_initplan` lint covers it too; this
  guard matches `uid`/`jwt` only.
- **A statement-level pragma cannot silence one specific unwrapped call while leaving a genuinely
  intentional one in the same file uncommented** — the pragma is file-level (see "When NOT to
  flag"), so a reviewed exception in one migration file silences the whole file, not just the one
  policy.
- **A `;` inside a quoted literal that spans MORE THAN ONE LINE terminates the statement span
  early** — `iter_statement_spans` finds the terminator with `find_statement_end`, which reads a
  `;` inside a single-line `'…'`/`"…"` as content (issue #559) but treats a quote whose close lies
  past a newline as stray and falls back to the first raw `;`. That bound is what keeps a stray
  quote, or an `EXECUTE '… CREATE POLICY …'` literal, from swallowing the next real policy; a
  multi-line literal containing `;` is the residual, shared with every guard on this helper.
- **Comments (closed in #442 phase 2b).** The guard reads the shared `strip_sql_comments(sql, blank=True)`, the length- and newline-preserving lexer the other SQL guards use. A `--` inside a literal (e.g.
  `note = 'a--b'`) used to blank an unwrapped call later on the same line, a false negative of the
  private `--[^\n]*` blank; it now fires
  (`test_string_literal_double_dash_does_not_hide_an_unwrapped_call`). A policy commented out inside a
  `DO` body, and a `COPY` data row, stay silent.
- **A doubled quote inside a dynamic-SQL policy body reads as residue.** In
  `EXECUTE 'CREATE POLICY … USING ((select auth.jwt() ->> ''role'') = …)'` the per-statement view
  starts inside the outer literal, so `''role''` reads as two empty literals around a bare word,
  and the wrapped call fires. It fired before #855 too.

## Superseded migrations

Append-only migration histories recreate the same policy many times (64 `uid-unwrapped` findings on the
flagship were policies a later migration had already re-`CREATE`d wrapped). This guard scans every
`.sql` file independently, so each historical copy fires on its own — by design: the guard stays a
precise pre-deploy lens, and cross-file `DROP POLICY` / re-`CREATE` replay is the static migration
interpreter the project deliberately does not build (it re-implements the database's own state
resolution at lower fidelity than the live DB or a dump). The reconciliation happens one layer up,
in `agentsec/sql_state.py`: when the repo ships an authoritative dump (a dump-like name such as
`schema-snapshot.sql`, `schema.sql` or `*.dump.sql`, **and** pg_dump's session preamble or banner
in its head), the audit stamps a SCHEMA-STATE finding in every *other* `.sql` file of the dump's
own directory subtree `superseded`. A name alone is not evidence: a hand-written `schema.sql` used
to un-gate every migration in the repo (#1037). Scoped to schema state on purpose: the check declares `schema_state` when a
dump can speak for it, so a homoglyph, an invisible-unicode payload or a committed secret that
merely sits in a migration file is never demoted — a dump carries none of those (#829).
Since #800 that stamp is a verdict, not a rank hint. A superseded finding stays in the
report (tagged with the dump that governs it, `history: schema dump <path> is authoritative here`)
and in the Summary-by-check table, but it leaves
the headline tally and the `--format summary` verdict, sinks below every live finding, is
deprioritized at every severity, and is **non-gating** — `--fail-on` ignores it and the CI line
discloses `N superseded (non-gating)`. The dump's own copy of the policy is scanned at full priority,
so anything still live is still caught — in the dump. A Splinter-confirmed finding (`agentsec live`) is
never treated as historical, whichever file declares it. No dump, no demotion: a repo with only
numbered migrations keeps the per-file behaviour (commit a dump, or run Splinter).

## What this guard does NOT prove

It proves a specific `auth.uid()`/`auth.jwt()` call (bare or quoted) is not inside a sub-SELECT it
can read as self-contained; it does not measure the actual query-plan cost, the table's row count, or whether the
unwrapped call is on a hot path at all — a policy on a table with ten rows and this guard's finding
carries the same MEDIUM severity as one on a hundred-million-row table, because the guard has no
signal to tell them apart. It also never touches access control: a silent result here says nothing
about whether the policy itself is correctly scoped — that is `rls-permissive-policy`'s and
`rls-no-user-metadata-claim`'s territory entirely.

# Examples

```sql
-- Fires: re-evaluated per row (hand-written, and the quote-all `supabase db dump` of the same)
USING (auth.uid() = user_id)
USING (("auth"."uid"() = "id"))

-- Fires: the sub-SELECT reads the outer row, so it is a per-row subplan, not an initplan
USING (( SELECT (auth.uid() = t.id)))
USING ((EXISTS ( SELECT 1 FROM public.members m WHERE (m.user_id = auth.uid()))))

-- Silent: wrapped, in every spelling the deparser produces
USING ((select auth.uid()) = user_id)
USING ((( SELECT auth.uid() AS uid) = user_id))
USING ((( SELECT "auth"."uid"() AS "uid") = "user_id"))
USING ((( SELECT (auth.jwt() ->> 'org'::text)) = org_id))
USING ((EXISTS ( SELECT 1 FROM public.members m WHERE (m.user_id = ( SELECT auth.uid() AS uid)))))
```

# Citations

[1] agentsec checklist item `7-rls-auth-uid-unwrapped` (§7)
[2] OWASP:A04 (Insecure Design)
[3] Supabase docs — [Row Level Security: Call functions with SELECT](https://supabase.com/docs/guides/database/postgres/row-level-security#call-functions-with-select)
[4] agentsec checklist items `8-async-route-no-blocking-io` and `3a-upload-size-cap` — the
    severity precedent for a real, non-bypass, DoS-adjacent performance finding
[5] Postgres `ruleutils.c::get_target_list` and `parse_target.c::FigureColnameInternal`: why a
    deparsed function-call target gets `AS uid`, a cast target `AS uuid`, and an operator target no
    alias (#855's measured deparse oracle, Postgres 17)
