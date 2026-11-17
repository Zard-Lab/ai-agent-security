---
type: Guard
title: "policy-no-role-scope"
description: "CREATE POLICY with no TO clause (or TO public) is graded by its predicate: HIGH when anon can reach rows, LOW hygiene when the predicate already scopes them."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "policy-no-role-scope"
checklist_section: ["7"]
standards: ["OWASP:A01"]
---

# CREATE POLICY has no role scope — applies to anon, not just authenticated

_Author — 2026-08-23; rewritten 2026-09-13 for #801 (severity follows the predicate)_

---

## The threat

A `CREATE POLICY ... ON <table> ...` statement with **no `TO <role>` clause** is scoped
to PUBLIC by Postgres default — every role, including Supabase's `anon` key, not just
`authenticated`. The same is true of a policy explicitly written `TO public`: PUBLIC is a
pseudo-role that matches everyone, so it widens the policy regardless of any other named
role listed alongside it (`TO public, authenticated` is still fully public).

WHO reaches this: any unauthenticated caller holding only the Supabase `anon` key — the
credential every browser client ships. WHAT privilege: none; `anon` is the lowest-privilege
role in the system. WHAT effect depends entirely on the policy's **predicate**, and that is
the honest statement of this threat:

- The `TO` clause and the `USING` / `WITH CHECK` expression are two independent gates.
  Postgres shows a row only when the expression returns **TRUE**; FALSE and **NULL** both
  hide it. For `anon`, `auth.uid()` IS NULL, so `auth.uid() = id` is NULL and admits zero
  rows. A missing `TO` clause on that policy is **not exploitable today** — it is hygiene
  and defence-in-depth: the next edit to the predicate (an `OR is_public` branch, a
  `COALESCE(auth.uid(), …)`) widens it to `anon` silently, because nothing scopes the role.
- The scope gap is **exposure** only when the predicate is anon-reachable: `USING (true)`,
  no expression at all (Postgres defaults it to `true`), an identity-free predicate
  (`status = 'published'`), or a predicate whose identity reference has an escape
  (`auth.uid() = id OR is_public`, `auth.uid() IS NULL`, `WITH CHECK (true)` beside a
  scoped `USING`). Those rows are readable/writable (per the `FOR` clause) by anyone.

Before #801 every unscoped policy was HIGH regardless of the predicate; on the flagship's
`pg_dump` schema that was 37 HIGHs of which 36 were noise (8 `USING (false)` deny rules and
28 self-scoped predicates) burying the one genuine `USING (true)`, and every one tripped
the default `--fail-on high` gate. Findings carry `OWASP:A01` (Broken Access Control).

## Why it's often introduced

Supabase's own quickstart docs and most AI-generated migrations write the condition first
and treat `TO <role>` as optional boilerplate:

```sql
-- self-scoped: NULL for anon, zero rows — LOW (hygiene: add TO authenticated)
CREATE POLICY "Users can view their own profile"
  ON public.profiles
  USING (auth.uid() = id);

-- anon-reachable: TRUE for everyone — HIGH
CREATE POLICY "Anyone can read maintenance_message"
  ON public.maintenance_message FOR SELECT USING (true);
```

A generated `pg_dump` / `supabase db dump` writes the same policies with every identifier
quoted and the identity call wrapped in an initplan —
`USING ((( SELECT "auth"."uid"() AS "uid") = "user_id"))` — which is the spelling the grader
has to read, because that is what a real schema snapshot contains (the #827 postmortem's
lesson 3: the guard, tests and wiki agreed for four rounds while 0 of 28 real policies were
downgraded).

## Detection design

1. **`applies()` gate** — `"supabase" in profile.features or "postgres" in profile.features`
   (same gate as `pg_rls_no_policy.py`, its closest sibling on SQL-migration scanning).
2. **Files scanned** — every `.sql` file under `profile.sql_dir` (falling back to `root`),
   filtered through `is_reference_sql_path` (keeps `migrations/`/`alembic/` in scope — the
   deployed schema for SQL guards — while dropping `examples/`/`fixtures/`/`tests/` noise).
3. **Statement parsing** — `CREATE POLICY ... ;` statements are carved out with
   `iter_statement_spans` over `strip_sql_comments(text, blank=True)` (quote-aware, length-
   and newline-preserving, so an offset maps back to the raw file's line): a linear
   head-to-`;` walk, not a naive `[^;]*?` lazy regex (issue #419). Within each span a
   `TO <roles>` clause is searched for, anchored on what must immediately follow the role
   list — `USING`/`WITH CHECK`/the statement's own `;` — the identical anchoring
   `rls_permissive_policy.py`'s `_TO_CLAUSE` uses, so a `to` inside a *quoted policy name*
   is never mistaken for the role clause. A `TO` clause naming only non-public roles → silent.
   The quoted policy name is additionally space-filled by `blank_policy_names` before the
   `AS RESTRICTIVE` skip runs, so a name like `"mark as restrictive"` cannot smuggle an
   `AS RESTRICTIVE` clause past the check and silently void a real `no-to-clause` HIGH
   (#824 class; PR #893 re-review).
4. **Bodies and views** — every `USING (…)` / `WITH CHECK (…)` body is located on two
   **same-length views** of the statement (no rewriting, no normalisation — the #827
   postmortem's lesson 2): the *literal view*, `blank_sql_literals` (content of `'…'`,
   `E'…'`, `$tag$…$tag$` spaced out, delimiters kept, `"…"` untouched), on which leaves are
   read; and the *structural view*, the same with `"…"` identifier content spaced out too,
   on which **all** structure (parens, `AND`/`OR`/`NOT`, `EXISTS`, `SELECT`, `WHERE`,
   set-ops, `IS`) is found. A column named `"or"` therefore cannot split a conjunction, and
   `"auth"."uid"()` is still visible to the identity regex. One O(n) paren map over the
   structural view serves every depth-0 scan; an unbalanced statement, a `USING`/`WITH
   CHECK` with no `(…)` body, or zero bodies (implicit `true`) is **reachable**. The search
   resumes past each body's close, so a `JOIN … USING (col)` inside a body is never a second
   clause.
5. **Evaluator** — `_eval(lo, hi, depth)` over index spans, returning the **set** of truth
   values the span can take for a caller with no identity (a bitmask over {T, F, N}),
   combined with Kleene's three-valued tables:
   - E0 `depth > 64` → ANY; E1 strip redundant outer parens (one loop over the paren map);
     E2 split at depth-0 `OR`; E3 split at depth-0 `AND`; E4 leading `NOT`; E5 leaf.
   - `NOT` swaps T and F and keeps N. Because an unrecognised leaf is the **full set**, `NOT`
     over it stays the full set — a single "worst case = TRUE" value would turn
     `NOT is_public` into FALSE, and it is TRUE for every private row.
6. **Leaf whitelist** — applied to the literal-view slice after E1; first match wins and
   **L10 is the default**. This is the only source of F or N:

   | rule | shape | value |
   |---|---|---|
   | L3 | `IDENT IS NOT NULL` / `IDENT NOTNULL` | {F} |
   | L4 | `IDENT IS NULL` / `IDENT ISNULL` | {T} |
   | L0 | any other depth-0 `IS` / `ISNULL` / `NOTNULL` (a postfix IS test never propagates NULL: `auth.uid() = id IS UNKNOWN` is TRUE for anon) | ANY |
   | L1 | `true`, `1 = 1` | {T} |
   | L2 | `false`, `1 = 0` | {F} |
   | L5 | `IDENT CMP x` — CMP ∈ `= <> != <= >= < > IN LIKE ILIKE`, whole-token, and `x` not `ALL (…)` (`NULL op ALL (empty)` is TRUE) | {N} |
   | L6 | `x CMP IDENT` — same CMP set without `IN` (`id IN (SELECT auth.uid())` stays a retained HIGH) | {N} |
   | L7 | argument-less `is_admin()` / `is_superuser()`, optional `public.` prefix — exactly the set `rls_update_privileged_column.py` trusts by name | {F, N} |
   | L8 | `EXISTS (SUBQ)` | {F} if SUBQ is provably empty, else ANY |
   | L9 | `x IN (SUBQ)`, `x = ANY (SUBQ)` — `x NOT IN (…)` is ANY (`NOT IN (empty)` is TRUE) | same |
   | L10 | anything else | ANY |

   `IDENT` is `auth.uid()` / `auth.email()`, bare or in `pg_dump`'s initplan
   `( SELECT "auth"."uid"() AS "uid")` under any (bounded) number of wrapping parens, with
   optional `::casts`; a lookbehind stops a quoted identifier literally named `"auth.uid()"`
   from matching. `auth.jwt()`, `auth.role()` and `current_setting('request.jwt…')` are
   **deliberately outside** the identity set: the anon key *is* a JWT (`role: anon`), so
   NULL-ness depends on the claim. **SUBQ is provably empty** only when it is a plain
   `SELECT <list> FROM … WHERE w` with no depth-0 set operation, no `(` in the select list
   (an aggregate or window call yields one row over empty input), no `HAVING` and no call
   in the tail after the WHERE (`ORDER BY count(*)`), and `w` — truncated at the first
   depth-0 `GROUP BY`/`HAVING`/`ORDER BY`/`LIMIT`/`OFFSET`/`WINDOW` — can never be TRUE.
   Postgres whitespace is spelled out (`[ \t\n\r\f\v]`, the lexer's own set) instead of
   `\s`, so a non-ASCII blank such as NBSP is neither whitespace nor a word character and can
   only leave a leaf unrecognised.
7. **Verdict per statement** — every body's E1-stripped text matches L2 → **deny** → no
   finding. Any body's value set contains T → **reachable** → HIGH (title/message/remediation
   unchanged from before #801). Otherwise → **scoped** → LOW, same rule id, its own
   title/message/remediation naming `TO authenticated`. `USING (false) WITH CHECK
   (auth.uid() = id)` is scoped, not deny.
8. **Totality** — the grader is wrapped `try … except Exception → reachable`. A
   `RecursionError` escaping a guard is swallowed by `audit.py`'s per-guard `except`, which
   drops **every** finding of the guard and exits 0 (#827 round-1 H1); degrading a grader
   bug to the pre-#801 HIGH for that one statement is loud and safe.
9. **Inline opt-out pragma** — `-- security: allow-policy-no-role-scope`, counted only as a real
   comment (the SQL comment view, so a phrase quoted in a literal does not count, #1040), on the
   lines of the statement's OWN span only (not the whole file, and not a line before it),
   **before** the grade — so it silences a LOW too, and a pragma next to one
   intentionally-public policy cannot silence an unrelated policy elsewhere in the file.
10. **Severity/rule/standards** — rules `policy-no-role-scope/no-to-clause` (no `TO`) and
    `policy-no-role-scope/to-public` (`TO public`, identical exploitability, same grade);
    `high` for reachable, `low` for scoped, `standards=["OWASP:A01"]`.

## Retained HIGH by design

These predicates are scoped in reality, but the v1 whitelist does not recognise them and
the worst-case default keeps them exactly where they were before #801. None of them appear
among the flagship's 28. Each widening is its own follow-up with a fires/stays-silent pair,
never a patch inside a review round (the review charter in the #801 plan):

- `auth.jwt() ->> 'sub' = x`, `auth.role() = 'authenticated'`, `auth.jwt() ->> 'role' = …`,
  the `current_setting('request.jwt…')` GUC forms — needs a per-claim model of the anon key.
- `lower(auth.email()) = email`, `trim(auth.email()) = email` — any function wrapping the
  identity; needs a STRICT built-in list.
- `(auth.uid() = id) IS TRUE` / `IS FALSE` / `IS NOT UNKNOWN` / `IS NOT NULL` — postfix IS
  tests a NULL operand *fails*; needs L0 split by which test is applied.
- `id IN (SELECT auth.uid())`, `x = ANY (SELECT auth.uid())` — a subquery with no WHERE
  yields NULL, not TRUE.
- `id BETWEEN auth.uid() AND h` — BETWEEN propagates NULL; needs a BETWEEN leaf.
- `auth.uid() <> ALL (…)` — kept HIGH because `NULL <> ALL (empty)` is TRUE whenever the
  subquery can be empty; this one is a genuine escape, not a widening candidate.
- `EXISTS (… WHERE … = auth.uid() GROUP BY 1 HAVING true)` — with a `GROUP BY` an empty
  input yields no group, but telling that from `HAVING` without `GROUP BY` (one row, TRUE)
  is modelling; v1 treats every `HAVING` as unrecognised.
- `x IN (SELECT … WHERE … = auth.uid() FOR UPDATE)` — a locking clause after the WHERE.
- Any helper **given an argument** (`is_admin(auth.uid())`, `has_access(auth.uid())`) and
  any helper outside the `is_admin()`/`is_superuser()` name set — resolving in-tree
  `CREATE FUNCTION` bodies is a follow-up.

## When NOT to flag

- **`TO authenticated`** (or any other single named role, or a list of named roles that does
  not include `public`) is exactly the intended shape and stays silent.
- **`TO service_role`** stays silent for the same reason `rls-permissive-policy` exempts it:
  `service_role` bypasses RLS entirely, so scoping a policy to it is never an anon-widening
  concern — there is no RLS check left to widen.
- **Deny rules** — `USING (false)`, `WITH CHECK (false)`, `1 = 0`, in any paren wrapping:
  the policy grants nothing to anyone, so a `TO` clause would change nothing. No finding.
  (A deny `USING` beside a scoped `WITH CHECK` is *scoped*, LOW, not deny.)
- **A self-scoped predicate is LOW, not silent** — the hygiene grade is the point: nothing
  scopes the role, and the next predicate edit can widen it without any diff to the `TO`
  clause. Suppress a genuinely public table with the pragma; add `TO authenticated` to the
  rest.
- **A quoted policy name containing the word "to"** (`"Grant read access to profiles"`) does
  not satisfy the role-clause pattern (the anchor requires `USING`/`WITH CHECK`/`;`
  immediately after the captured role list) — the policy is correctly evaluated as having no
  real `TO` clause and still fires, for the right reason.
- **Reference/example/test SQL** (`examples/`, `fixtures/`, `tests/`) is out of scope via
  `is_reference_sql_path`, same as every other SQL-migration guard in this codebase.

## Tests

| Test | What it checks |
|---|---|
| `test_policy_no_role_scope_fires_on_no_to_clause` | The checklist anchor: an identity-free predicate (`status = 'published'`) with no `TO` clause fires `no-to-clause`, HIGH, `OWASP:A01` |
| `test_policy_no_role_scope_self_scoped_no_to_clause_grades_low` | Its self-scoped twin (`user_id = auth.uid()`) is LOW, same rule, remediation names `TO authenticated` |
| `test_policy_no_role_scope_fires_on_to_public` | `TO public` fires `to-public` |
| `test_policy_no_role_scope_to_public_follows_the_same_grade_as_no_to_clause` | `TO public USING (true)` is HIGH and `TO public` self-scoped is LOW — identical exploitability to no `TO` |
| `test_policy_no_role_scope_fires_on_to_public_alongside_named_role` | `TO public, authenticated` still fires — PUBLIC widens regardless of other roles listed |
| `test_policy_no_role_scope_silent_when_scoped_to_authenticated` | FP-bait: `TO authenticated` is silent |
| `test_policy_no_role_scope_silent_when_scoped_to_service_role` | FP-bait: `TO service_role` is silent (RLS-bypass carve-out) |
| `test_policy_no_role_scope_silent_when_scoped_to_multiple_named_roles` | FP-bait: `TO authenticated, service_role` (no `public`) is silent |
| `test_policy_no_role_scope_pragma_suppresses_only_its_own_statement` | the pragma silences only its own statement; an adjacent unscoped policy in the same file still fires |
| `test_policy_no_role_scope_pragma_governs_the_low_tier_too` | the pragma is checked before the grade, so it silences a LOW too (rule 4) |
| `test_policy_no_role_scope_applies_gate` | `applies()` gates on supabase/postgres, not on plain python |
| `test_policy_no_role_scope_no_sql_files` | no `.sql` files → empty list, no crash |
| `test_policy_no_role_scope_skips_examples_dir` | `is_reference_sql_path` drops `examples/` |
| `test_policy_no_role_scope_quoted_policy_name_containing_to_is_not_mistaken_for_role_clause` | adversarial: a quoted policy name containing "to" does not create a false `TO` clause match |
| `test_policy_no_role_scope_identity_text_in_policy_name_does_not_downgrade` | `auth.uid()` or `using (…)` spelled inside the quoted policy NAME never reads as a scope or a clause |
| `test_policy_no_role_scope_hostile_headless_sql_is_linear` | `create policy ` × 30,000 with no `on`/`;` completes in well under 8s (issue #419 regression class) |
| `test_policy_no_role_scope_pragma_survives_a_preceding_block_comment` | a multi-line block comment before the statement does not desync the pragma window (rule 4) |
| `test_policy_no_role_scope_line_number_correct_after_a_preceding_block_comment` | same fixture, no pragma: the finding reports the statement's own line |
| `test_policy_no_role_scope_string_literal_double_dash_no_longer_merges_spans` | FN-guard: a `--` inside a string literal no longer merges its span with the next `CREATE POLICY`; still HIGH |
| `test_policy_no_role_scope_plain_string_literal_still_fires` | control: same shape without a `--` in the literal |
| `test_policy_no_role_scope_semicolon_in_policy_name_does_not_hide_the_to_clause` | #559 FP arm: a `;` inside a quoted name does not carve the `TO` clause away |
| `test_policy_no_role_scope_semicolon_in_policy_name_still_fires_when_unscoped` | #559 FN arm: same name shape, no `TO`, still HIGH on the right table |
| `test_policy_no_role_scope_flagship_pg_dump_oracle` | **the oracle**: all 98 flagship `pg_dump` policies (`tests/fixtures/policy_no_role_scope/`), exact counts — 61 `TO`-scoped silent, 8 deny silent, 28 LOW, 1 HIGH at `maintenance_message`, line sets derived from the fixture |
| `test_policy_no_role_scope_scoped_predicate_grades_low` | parametrised `_SCOPED_LOW` corpus (bare and `pg_dump` spellings, EXISTS/IN/= ANY subqueries, NOT over identity, quoted `"or"` columns, `E'…'`/`$$`-in-literal neighbours) → LOW |
| `test_policy_no_role_scope_reachable_predicate_stays_high` | parametrised `_REACHABLE_HIGH` corpus (Rule 1 pairing): identity-free, `OR` escapes, `IS NULL`, `IS DISTINCT FROM`, postfix `IS NOT TRUE`, `NOT IN`, `ALL`, `COALESCE`, helpers with arguments, `NOT` over unrecognised leaves, aggregate/HAVING subqueries, NBSP, dollar quotes, unbalanced bodies → HIGH |
| `test_policy_no_role_scope_retained_high_by_design_stays_high` | parametrised `_RETAINED_HIGH_BY_DESIGN` corpus — each entry is listed above with the widening it would need |
| `test_policy_no_role_scope_deny_rule_does_not_fire` | `USING (false)` / `WITH CHECK (false)` / `1 = 0` / `((false))` → no finding |
| `test_policy_no_role_scope_deny_rule_does_not_hide_the_next_statement` | the deny skip is per statement; the open policy after it still fires on its own line |
| `test_policy_no_role_scope_multiline_dump_shape_grades_low` | a multi-line `supabase db dump` policy is LOW and reported on its first line |
| `test_policy_no_role_scope_unbalanced_expression_is_never_downgraded` | a body that does not balance is HIGH, never graded down on a guess |
| `test_policy_no_role_scope_grader_exception_degrades_to_high` | a grader exception (monkeypatched) degrades that statement to HIGH and loses no other finding (#827 round-1 H1) |
| `test_policy_no_role_scope_deep_nesting_grades_high_and_keeps_other_findings` | 5,000 right-nested ORs → HIGH via E0, no crash, the other file's finding present; 5,000 redundant paren layers → LOW (E1 is a loop, not depth) |
| `test_policy_no_role_scope_postgres_whitespace_matches_the_regex_class` | the regex whitespace class and the trim set are the same Postgres set; NBSP is in neither (#827 round 6) |
| `test_policy_no_role_scope_pg_dump_conjuncts_cost_is_linear` | `slow`: n ANDed `pg_dump` conjuncts (with the `AS "uid"` alias) read `linear` by `assert_growth`, still LOW, under the registered backstop budget |
| `test_policy_no_role_scope_nested_or_cost_is_linear_in_depth` | `slow`: n right-nested gated ORs read `linear` (E0 caps the descent) |
| `test_policy_no_role_scope_redundant_paren_layers_cost_is_linear` | `slow`: n redundant paren layers read `linear` (E1 is one loop over the paren map) |

The shared literal blanker has its own contract tests in `tests/guards/test_base.py`
(`test_blank_sql_literals_*`): same length, `''` doubling, `E'…'` parity both ways, `$tag$`,
`$$` inside an ordinary literal, `"…"` untouched by default, unclosed literal.

## Known bypasses

- **Helper functions receiving arguments are untrusted (HIGH)** — `is_admin(auth.uid())`,
  `has_access(auth.uid())` and any helper outside the argument-less `is_admin()` /
  `is_superuser()` name set grade HIGH, whatever their body does. Conversely the trusted two
  are trusted **by name**: a repo whose `public.is_admin()` returns `true` for everyone is
  graded LOW on a lie. Resolving in-tree `CREATE FUNCTION` bodies is a follow-up.
- **`auth.jwt()`, `auth.role()` and the GUC identity forms are HIGH** even when the claim
  compared is absent from the anon key — retained by design (above).
- **`ALTER POLICY … TO authenticated` after the fact is not tracked** — if the original
  `CREATE POLICY` had no `TO` clause and a later `ALTER POLICY` in the same migration set
  narrows it, this guard still fires on the original statement it can see.
- **Dynamic policy creation outside `.sql` files** — a `CREATE POLICY` issued from application
  code or an ORM migration DSL is not seen; this guard only scans `.sql` text. *Within* a `.sql`
  file the scan is a plain statement-head search with no PL/pgSQL or string-literal awareness, so a
  statement inside a `DO $$ … $$` block IS scanned like any top-level statement — including one
  built as a string, `EXECUTE format('CREATE POLICY %I ON t FOR SELECT USING (true)', 'p')`, which
  fires `no-to-clause` (both verified by running the guard during #800/#829; this bullet previously
  claimed `DO` blocks were skipped). A `DROP POLICY IF EXISTS` + `CREATE POLICY … TO authenticated`
  recreation in a `DO` block is therefore scanned and stays silent on its own merits.
- **Role-membership tricks** — a role granted membership in `public`/`authenticated` via
  `GRANT authenticated TO some_role` is invisible here; only the literal `TO <role>` clause
  on the `CREATE POLICY` statement itself is evaluated.
- **The table name in the finding message can mislabel** when a quoted policy name itself
  contains the standalone word "on" (`CREATE POLICY "Read on profiles" ON real_table ...`) —
  the same pre-existing, shared limitation `pg_rls_no_policy.py`'s identical `ON` search has.
  It affects only the displayed table name, never whether or how the finding fires.
- **Encoding tricks can only keep a HIGH.** NBSP, `$$` inside a literal, `E'…'` escape
  parity, unicode whitespace and quoted-identifier tricks all land in "unrecognised → HIGH"
  (each has a parametrised test); no such trick can produce a LOW, because LOW requires a
  positive whitelist match on every path.

## Superseded migrations

Append-only migration histories recreate the same policy many times (the flagship's `user_profiles`
policies are re-`CREATE`d by migrations 46/136/144/160/162/169/173/244/245). This guard scans every
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

- **LOW is a *syntactic* grade of the committed SQL.** It says the predicate, as written,
  is NULL or FALSE for a caller whose `auth.uid()` is NULL. It does not prove the deployed
  policy, it trusts `is_admin()`/`is_superuser()` by name, and it does not know whether
  `auth.uid()` is really NULL in this deployment (a custom JWT hook that stamps `sub` on the
  anon key would defeat the premise). Read LOW as "add `TO authenticated`", never as "safe".
- **A HIGH finding does not mean the table is exploitable today** — RLS must also be enabled
  on the table (`pg_rls_no_policy` / `policy_exists_rls_disabled` cover that), and the rows
  the reachable predicate admits must be worth reading. This guard proves the *scope* is
  wrong and the predicate does not close the gap on its own.
- **Silence does not certify the deployed database matches the scanned SQL.** Like every
  SQL-migration guard in this codebase, this is a repo-static check on committed migrations —
  a policy altered directly against the live database (via the Supabase dashboard, `psql`, or
  a script outside the scanned tree) is invisible here. The live-database equivalent is
  `agentsec live`'s Supabase Splinter integration.

# Citations

[1] agentsec checklist item `7-policy-no-role-scope` (§7)
[2] OWASP:A01
[3] PostgreSQL — CREATE POLICY: "Rows for which the expression returns false or null will not be visible", no `TO` → PUBLIC, no `USING` → `true` — https://www.postgresql.org/docs/current/sql-createpolicy.html
[4] PostgreSQL — Comparison Functions and Operators (which operators propagate NULL; `IS [NOT] DISTINCT FROM`, `IS [NOT] TRUE/FALSE/UNKNOWN`, `ISNULL`/`NOTNULL` do not) — https://www.postgresql.org/docs/current/functions-comparison.html
[5] PostgreSQL — Subquery Expressions (`EXISTS`/`IN`/`= ANY` over an empty set are FALSE; `NOT IN`/`<> ALL` over an empty set are TRUE) — https://www.postgresql.org/docs/current/functions-subquery.html
[6] Supabase — `auth.uid()` in RLS returns NULL for the anon key; the anon key is itself a JWT — https://supabase.com/docs/guides/database/postgres/row-level-security#authuid
[7] Sibling design: `wiki/guards/pg-rls-no-policy.md` (statement-bounded SQL scanning), `wiki/guards/rls-permissive-policy.md` (the `TO`-clause role-list parser this guard's `_TO_CLAUSE` mirrors), `wiki/guards/rls-update-privileged-column.md` (the trusted `is_admin()` name set)
[8] The maintainers' #801 restart plan — the #827 postmortem, the design specification and the review charter
