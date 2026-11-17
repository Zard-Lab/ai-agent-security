---
type: Guard
title: "rls-update-privileged-column"
description: "Self-update RLS policy lets the owner write privileged columns."
timestamp: "2026-10-24T00:00:00Z"
guard_id: "rls-update-privileged-column"
checklist_section: ["7"]
standards: ["OWASP:A01"]
---

# Self-update RLS policy lets the owner write privileged columns

Flags a self-scoped `UPDATE` RLS policy on a table that has privilege columns when those columns aren't
write-protected. Closes checklist item `7-rls-update-privileged-column`. OWASP:A01. Related:
the exposed-schema RLS blind spot — the newest member of the RLS static-mirror family.

## The threat

A common AI-generated pattern scopes an `UPDATE` policy to the row owner and *tries* to protect
authorization columns with a **denylist** `WITH CHECK` that pins only one or two of them:

```sql
CREATE POLICY "Users can update their own profile" ON user_profiles
  FOR UPDATE
  USING  (auth.uid() = id)
  WITH CHECK (auth.uid() = id AND is_admin IS NOT DISTINCT FROM FALSE);
```

RLS is enabled, the policy is scoped (not `USING (true)`), and it doesn't gate on `user_metadata`, so
`rls-permissive-policy`, `policy-exists-rls-disabled`, and `rls-no-user-metadata-claim` all stay silent.
But a `WITH CHECK` is evaluated against the **NEW** row only and cannot reference `OLD`, so it cannot pin
a column to its prior value. Every *other* privilege column the policy doesn't name is therefore writable
by any authenticated user via a direct `UPDATE` on their own row — no UI required. This is column-level
mass-assignment at the RLS layer: CWE-639 (authorization bypass through a user-controlled key) / CWE-915
(mass assignment). WHO: any authenticated end-user. WHAT effect: self-grant `is_admin`/`is_pro`/`roles`,
inject `*_access_token`, self-credit a `tokens`/`balance` column, remap `external_id`, etc.

This guard exists because a live audit of the flagship (`9_Agent_SaaS` — vector `tokens`) and a production
fork (`../hwh/ai-agent-mastery` — vectors `is_pro`/`roles`/`external_id`/`subscription_*`, surfaced by
react-doctor) had this exact hole, and the existing five RLS guards all missed it.

## Exploitability rationale

The checklist item is **CRITICAL** (direct privilege/value escalation). The **finding** is **HIGH**:
"privilege-named column on a self-update policy with no write-hardening" is a strong, specific signal, but
the lexicon is a heuristic (a `tokens` column that isn't a balance, a `plan` that isn't authz) so HIGH +
a pragma rather than CRITICAL-no-escape.

## Why this guard fits the stack

Supabase exposes tables to the client over the Data API on the anon/authenticated key; RLS is the only
thing between a signed-in user and a direct `supabase.from('user_profiles').update({...})`. Codegen tools
reliably produce the scoped-row/denylist-`WITH CHECK` shape — it *looks* careful — and each new privilege
column added in a later migration is exposed by default.

## Detection design

1. **applies()** — `"sql" in profile.features`.
2. **Files** — the detected SQL dir (`root / profile.sql_dir if profile.sql_dir else root`) via
   `iter_files(..., (".sql",))`. (Standard sibling pattern; relies on the #111 `detect.py` fix that picks
   the live top-level `sql/` over an archived `old/**/sql`, so the real schema is scanned.)
3. **Pass A — privilege columns per table** (`priv: dict[table, set[col]]`), from `CREATE TABLE` bodies
   (balanced-paren split on top-level commas) and `ALTER TABLE … ADD COLUMN`, over comment-stripped text,
   aggregated across ALL files. A column is "privileged" if it full-matches `_PRIV_COL`
   (`is_admin`, `is_pro`, `roles?`, `[a-z_]*permissions?`, `[a-z_]*access_token`, `subscription_*`,
   `tokens?`, `credits?`, `balance`, `quota`, `external_id`, …) and is not a scoping column
   (`id`/`user_id`/`owner_id`/`owner`/`auth_id`/`uid`).
4. **Pass B — write-hardened tables** (`protected`), aggregated across ALL files:
   - a `BEFORE UPDATE` trigger on the table (statement-spanning regex — the real `sql/171` puts
     `BEFORE UPDATE` and `ON <t>` on separate lines). This is the sound, future-proof fix.
   - a **role-gated** `REVOKE (UPDATE|ALL) … ON <t> FROM (authenticated|public)`.
5. **Pass C — emit.** For each `CREATE POLICY … ON <t> … ;` (comment-blanked, `re.S`) where the
   table is in `priv` and not in `protected`, and the policy is: UPDATE-capable (`FOR UPDATE`/`FOR ALL`,
   or no `FOR` clause), self-scoped (`auth.uid()`/`auth.jwt()`), client-role (`TO authenticated|public|anon`
   or no `TO`), and **not admin-gated** (`is_admin()`/`is_admin = true`) — fire if its `WITH CHECK`
   (balanced extraction) leaves ≥1 privilege column unconstrained (or there is no `WITH CHECK`).
   The quoted policy name is masked (`policy_stmt_without_name`) before **every** one of these reads,
   not only the table lookup. A name is free text, so before #957 a `to`, `as`, `for select`,
   `with check (` or `is_admin = true` inside `"Allow users to update own row"` and the like was read
   as a clause, which silenced real policies and fired on read-only ones.
   The `TO` role list is read by `_to_clause_roles`, a linear scan that returns exactly what the
   original lazy `_TO_CLAUSE` regex captured. That regex was O(n²) on a hostile statement: it retried
   from every `to` and re-walked the role run from every `\s+` split (#429).
   Comments are blanked with `strip_sql_comments(blank=True)` (#442), which is string-aware: the
   `--`-only regex it replaced blanked from a `--` inside `'a--b'` to end of line, taking any policy
   after it on that line with it, and never blanked a `/* … */` block, so a block-commented policy
   fired. Lines are numbered the `str.splitlines()` way, the same numbering the pragma check uses.
   In every pass a comment opened inside a dollar-quoted body ends inside it, so the `/*` of
   `$$See docs/*.md$$` cannot blank a table (Passes A and B) or a policy (Pass C) below the body.
   Until the lexer bounded it (#442 phase 2), that glob plus any later `*/` hid either one; a
   comment wholly inside a `DO $$ … $$` body still blanks.
6. **Pragma** — `-- security: allow-self-update-privileged-column` on the policy's first line or the
   line above it (#442; the line above was ignored before). It counts only as a real comment, read
   from the SQL comment view's line (#1040), so a string literal quoting it does not suppress. That
   view reads a `$$…$$` body as code, so the opt-out of an idempotent `DO $$ … CREATE POLICY … $$`
   migration, written inside the body, still counts. The cost is that a previous statement's
   trailing pragma comment on the line directly above suppresses too.
7. **Emitted** — `severity="high"`, `rule="rls-update-privileged-column/unpinned-column"`,
   `standards=["OWASP:A01"]`; the message names the table and the unconstrained columns.

## When NOT to flag (and the pragma)

- Tables with no privilege columns → silent.
- A `BEFORE UPDATE` trigger or a `REVOKE … FROM authenticated|public` on the table → protected, silent
  (the `NEW := OLD` allowlist trigger of `sql/171` is the model fix).
- **Admin policies** gated on `is_admin()` / `is_admin = true` — even when they reference `auth.uid()` in
  an `EXISTS (… WHERE id = auth.uid() AND is_admin = true)` membership check — the legit admin path.
- **service_role** policies (`TO service_role`) → the backend path.
- A reviewed, intentional case → `-- security: allow-self-update-privileged-column`.
- An incidental `REVOKE ALL … FROM anon` (RLS already blocks anon DML) is **not** treated as protection —
  it doesn't touch the `authenticated` self-update path, so the finding still fires.

## Tests

| Test | What it checks |
|---|---|
| `test_rls_update_privileged_column_flags_unpinned` | is_admin pinned, `tokens` left open → 1 HIGH finding, names `tokens` |
| `test_rls_update_privileged_column_flags_no_with_check` | self-update policy with no `WITH CHECK` → fires |
| `test_rls_update_privileged_column_flags_policy_with_no_to_clause` | no `TO` clause (PUBLIC) → fires |
| `test_rls_update_privileged_column_passes_when_no_privileged_columns` | only `full_name`/`avatar_url` → silent |
| `test_rls_update_privileged_column_passes_with_before_update_trigger` | multi-line trigger in a separate file (mirrors `sql/171`) → silent |
| `test_rls_update_privileged_column_passes_when_column_grants` | `REVOKE UPDATE … FROM authenticated` → silent |
| `test_rls_update_privileged_column_fires_despite_revoke_from_anon` | `REVOKE ALL … FROM anon` → still fires |
| `test_rls_update_privileged_column_passes_service_role_only` | `TO service_role` → silent |
| `test_rls_update_privileged_column_passes_admin_policy` | `EXISTS(… is_admin = true)` admin policy → silent |
| `test_rls_update_privileged_column_pragma_opt_out` | pragma on the policy line → silent |
| `test_rls_update_privileged_column_na_without_sql` | `applies()` false without `sql` feature |
| `test_rls_update_privileged_hostile_headless_sql_is_linear` | `;`-less trigger/revoke/policy soup at 1.9k→15k heads grows linearly, with a registered backstop budget at the top size (#419; a growth ratio since #1155) |
| `test_to_clause_roles_matches_the_retired_regex_on_edge_cases` | the `TO` scan equals the frozen retired regex on pinned edge cases: backtrack branch, failed-start retry, `$`/`as`/`with check` terminators (#429) |
| `test_to_clause_roles_matches_the_retired_regex_on_a_seeded_random_corpus` | the same oracle over 20k seeded random statements (#429) |
| `test_rls_update_privileged_column_skips_service_role_after_an_earlier_failed_to` | a `to backend (` comment ahead of `TO service_role` → still silent |
| `test_rls_update_privileged_column_fires_on_authenticated_after_an_earlier_failed_to` | the same comment ahead of `TO authenticated` → still fires |
| `test_rls_update_privileged_hostile_to_clause_cost_is_linear` | many-`to` and one-`to` whitespace-split tails on a gate-clearing policy: linear growth, still fires (#429, slow) |
| `test_rls_update_block_commented_policy_is_silent` | a policy inside a single- or multi-line `/* */` → silent (#442) |
| `test_rls_update_live_policy_below_a_block_comment_fires_on_its_raw_line` | the live policy below a block comment fires on its raw line |
| `test_rls_update_double_dash_inside_a_literal_does_not_swallow_the_next_policy` | `'a--b'` in an earlier policy on the same line no longer hides the violating one (#442) |
| `test_rls_update_pragma_on_the_line_above_suppresses` / `test_rls_update_pragma_two_lines_above_does_not_suppress` | the pragma reaches exactly one line above (#442) |
| `test_rls_update_pragma_inside_a_do_block_still_suppresses` | an opt-out inside a `DO $$ … $$` block keeps working; without it the policy fires |
| `test_rls_update_form_feed_inside_a_comment_keeps_finding_and_pragma_aligned` | a form feed inside a comment shifts neither the finding's line nor the pragma's |
| `test_rls_update_policy_after_a_dollar_quoted_glob_still_fires` / `test_rls_update_table_after_a_dollar_quoted_glob_is_still_read` | a policy, or the privileged table, between `$$See docs/*.md$$` and a later block comment is still read (#442 phase 2) |
| `test_rls_update_policy_commented_out_inside_a_do_body_is_silent` | FP-bait for the above: a policy commented out inside a `DO $$ … $$` body stays silent, while a live one there fires |
| `test_rls_update_keyword_in_policy_name_does_not_silence_the_finding` | a `to` / `as` / `for select` / `is_admin = true` in the policy name (one-line, multi-line, escaped-quote and pg_dump forms) no longer silences a real violation (#957) |
| `test_rls_update_masked_policy_name_keeps_the_real_skips` | with the same names, a real `TO service_role`, `FOR SELECT` or admin gate still skips (#957) |
| `test_rls_update_keyword_in_policy_name_does_not_raise_a_finding` | a `to public` / `for all` / `for update` / `with check (` in the name no longer fires on a service_role, FOR SELECT or fully-pinned policy; the same name on a vulnerable policy still fires (#957) |

## Known bypasses (honest limits)

- **Privilege column named outside the lexicon** (a bespoke authz column) is missed.
- **Presence-only suppression**: any `BEFORE UPDATE` trigger on the table suppresses, even one that
  doesn't actually freeze the privilege columns (e.g. a trivial `updated_at` stamper) — an accepted
  false-negative. The guard does not parse the trigger body.
- **Statement-span / parse limits**: a policy whose `ON <table>` can't be matched, or constructed via
  dynamic SQL / `EXECUTE format(...)`, is missed.
- **Multi-table indirection**: a column made writable via a view or a function is not traced.

## What this guard does NOT prove

It proves a self-update policy leaves a privilege-named column write-open with no trigger/column-grant in
the SQL. It covers only the **WRITE** escalation — column-level **READ** exposure (e.g. a client-readable
secret column, the hwh `sql/172` concern) is a separate class, out of v1 scope. It does not cover
`tenant_id`/`org_id` cross-tenant writes (those double as scoping columns → FP risk; future extension),
does not resolve the effective policy+grant+trigger set, and does not verify a present trigger is correct.
Absence of a finding ≠ the table's column writes are safe.

# Citations

[1] agentsec checklist item `7-rls-update-privileged-column` (§7)
[2] OWASP:A01
