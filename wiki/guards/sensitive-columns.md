---
type: Guard
title: "sensitive-columns"
description: "Sensitive-named column (password/ssn/api_key/credit_card/…) declared in a public-schema table, exposed via the Supabase Data API by definition."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "sensitive-columns"
checklist_section: ["7"]
standards: ["OWASP:A01", "CWE-200"]
---

# Sensitive-named column in a public-schema table — exposed via the Data API by definition

_Author — 2026-08-23_

---

## The threat

In a Supabase/PostgREST setup, **every column in a public-schema table is exposed via the
auto-generated Data API by definition** — there is no column-level access control without an
explicit view or RLS policy carve-out. `CREATE POLICY` restricts which *rows* a role can see; it
has no mechanism to hide one *column* of a row the role is otherwise allowed to read. A default
`SELECT * FROM public.accounts` (what PostgREST issues unless the client explicitly asks for a
narrower column list, and clients routinely don't) returns every column a role has table-level
SELECT on, filtered only by RLS's row predicate. WHO reaches this: any client whose RLS-scoped
SELECT includes the row at all — the same reach an ordinary, correctly-configured `authenticated`
or `anon` role already has. WHAT privilege: none beyond whatever row-level access RLS already
grants. WHAT effect: full read of a column the schema's author almost certainly did not intend to
put behind the public API — a `password`, `ssn`, `api_key`, `stripe_secret_key`, `credit_card`
column sitting next to ordinary profile fields in the same table. Findings carry `OWASP:A01`
(Broken Access Control — the exposure is a schema-shape gap RLS cannot close) and `CWE-200`
(Exposure of Sensitive Information to an Unauthorized Actor).

This is a **distinct** threat from `terraform_hardcoded_secret_literal.py`: that guard flags a
literal secret **value** committed in `.tf`. This guard flags a column **name** in SQL DDL that
declares a schema shape exposing a *category* of secret to the Data API, regardless of what values
end up stored in it — the column is the leak, not any one row's contents.

## Why it's often introduced

The path of least resistance when adding auth or billing fields to an app's own `users`/`accounts`
table is to add the column right next to the ordinary profile fields the frontend already reads
through the Data API:

```sql
-- looks like an ordinary profile field; is not
CREATE TABLE public.accounts (
    id uuid PRIMARY KEY REFERENCES auth.users(id),
    display_name text,
    stripe_secret_key text,      -- meant for a webhook handler, not the Data API
    password_hash text           -- a hand-rolled auth table, not Supabase Auth's own
);
```

Nothing about this is malicious — the author is thinking about the *column's purpose* (store the
Stripe key, store the password hash), not about the fact that the table it lives in is, by
default, a public HTTP endpoint. RLS policies on `public.accounts` (correctly scoped to `id =
auth.uid()`) make the *row* access look safe, which is exactly what hides the column-level gap
from a manual review: the reviewer checks "can another user see this row?" and stops there.

## Detection design

1. **`applies()` gate** — `"supabase" in profile.features`. The Data-API-exposure mechanism this
   guard is about (PostgREST auto-generating a REST endpoint per public-schema table) is
   Supabase-specific; a hand-rolled Postgres app with no PostgREST layer has no equivalent exposure
   from the same schema shape.
2. **Files scanned** — every `.sql` file under `profile.sql_dir` (or `root`), filtered through
   `is_reference_sql_path` (keeps `migrations/`/`alembic/` in scope, drops `examples/`/`fixtures/`/
   `tests/`).
3. **Patterns**, both comment-stripped via `strip_sql_comments`:
   - `CREATE TABLE [IF NOT EXISTS] [schema.]name (...)` — the column list's closing paren is found
     via the shared quote/nesting-aware `split_call_args` (so `numeric(10,2)` and a `text default
     '(x)'` don't mis-split the list), then each top-level item is checked: a leading
     `CONSTRAINT`/`PRIMARY`/`FOREIGN`/`UNIQUE`/`CHECK`/`EXCLUDE`/`LIKE` keyword means it's a table
     constraint, not a column, and is skipped. Each table's balanced-paren scan is bounded at the
     START of the NEXT `CREATE TABLE` occurrence (or EOF for the last one) rather than left
     unbounded — SQL has no syntax for one `CREATE TABLE` to nest inside another's column list, so
     this never truncates a genuine result, but it does cap how far a MALFORMED table's failed scan
     is allowed to run. This is load-bearing, not defensive-programming: measured before this bound
     existed, 3,000 unclosed `CREATE TABLE t (` occurrences in a 144KB file took 52 seconds
     (`split_call_args` scanning to true EOF on every one of them, O(n²)); bounded, the same input
     runs in under 0.1s.
   - `ALTER TABLE [schema.]table ADD COLUMN [IF NOT EXISTS] name` — matched per statement (bounded
     at the statement's own `;`) so multiple comma-separated `ADD COLUMN` clauses in one `ALTER
     TABLE` are each evaluated independently.
   - Only a `public` schema (or unqualified, which defaults to `public`) table is in scope — a
     column in a non-public schema is not Data-API-reachable the same way and is silent.
4. **The blocklist** — `password` (also matches `password_hash` — see "When NOT to flag"), `ssn`,
   `social_security_number`, `api_key`, `secret_key`, `stripe_key`, `stripe_secret`,
   `private_key`, `credit_card`, `card_number`, `cvv`. Matched via the shared `boundaried_stems`
   helper (the same word-boundary discipline this codebase already uses to keep `auth` from
   bleeding into `author` in `Depends()`-name matching): a term may not be preceded or followed by
   a lowercase letter, so it matches a `_`-delimited compound but not an unrelated longer word.
5. **Inline opt-out pragma** — `-- security: allow-sensitive-column`, anywhere in the `.sql` file
   (file-level, matching `pg_rls_no_policy.py`'s SQL pragma scoping).
6. **Severity/rule/standards** — MEDIUM (a heuristic name match, not proof of an actual live RLS
   gap — the same confidence tier as `hardcoded_password_default_arg.py`'s name-based blocklist).
   Rule id `sensitive-columns/public-schema-sensitive-name`. Standards `["OWASP:A01", "CWE-200"]`.

## When NOT to flag

- **A column name that only contains a blocklist term as a substring of an unrelated word** —
  `passwordless_login_enabled` does NOT fire (the character after `password` is a lowercase `l`,
  which fails the boundary check; the term must be `_`-delimited or end-of-identifier, not
  substring-only). This is a deliberate lean toward fewer false positives, per the guard's own
  design brief.
- **`password_hash` DOES fire** — it is not a separate blocklist entry; `password` alone matches
  it because the boundary after `password` is `_`, not a lowercase letter. There is no need (and
  no separate rule) for compound forms already covered by their root term.
- **A non-public schema table** (`private.accounts`, `auth.password_resets`) is silent — it keys
  on the SCHEMA, not the column name alone, matching the same schema-gating discipline
  `policy_exists_rls_disabled.py`'s Supabase-platform-schema exemption uses.
- **A table constraint clause** (`CONSTRAINT accounts_pkey PRIMARY KEY (id)`, `CHECK (...)`)
  sitting in the same top-level comma list as real column definitions is recognized by its leading
  keyword and never misread as a column.
- **A `*_id`-suffixed reference column** — `api_key_secret_id uuid REFERENCES vault.secrets(id)`
  holds a *pointer* to key material in Supabase Vault (the very remediation this guard recommends),
  not the material itself, so it does NOT fire even though `api_key` is a bounded substring of the
  name. The `_id` suffix is Postgres's universal reference convention, and no blocklist stem has a
  plausible `*_id` form that holds material rather than a reference. Material columns (`api_key
  text`, `secret_key varchar`) don't end in `_id` and still fire. Read what the identifier holds,
  not what it is called (issue #805).
- **A reviewed, intentional case** (e.g. a column already carved out by a column-omitting view, or
  a documented exception) → suppress with `-- security: allow-sensitive-column`.

## Tests

| Test | What it checks |
|---|---|
| `test_sensitive_columns_na_without_supabase` / `test_sensitive_columns_applies_with_supabase` | `applies()` gates on the `supabase` feature |
| `test_flags_password_column_in_create_table` | planted violation: a `password` column in a public `CREATE TABLE` fires |
| `test_flags_password_hash_substring_hit` | `password` matches `password_hash` (bounded by `_`) |
| `test_flags_unqualified_table_defaults_to_public` | an unqualified table name defaults to `public`, per spec |
| `test_flags_multiple_sensitive_columns_in_one_table` | one finding per sensitive column, not one per table |
| `test_flags_add_column` | `ALTER TABLE ... ADD COLUMN` fires |
| `test_flags_multiple_add_column_clauses_in_one_statement` | a comma-separated multi-column `ADD COLUMN` statement evaluates each clause independently |
| `test_fp_bait_non_sensitive_column_name` | FP-bait: ordinary column names stay silent |
| `test_fp_bait_passwordless_login_enabled_is_substring_only` | FP-bait: the spec's own named judgment-call case stays silent |
| `test_fp_bait_non_public_schema_table` / `test_fp_bait_non_public_schema_add_column` | FP-bait: a non-public schema table never fires, `CREATE TABLE` and `ADD COLUMN` alike |
| `test_fp_bait_secret_id_uuid_reference_is_not_material` / `test_fp_bait_secret_id_reference_via_add_column` | FP-bait (#805): a `*_secret_id` uuid vault reference stays silent, `CREATE TABLE` and `ADD COLUMN` alike |
| `test_material_column_still_fires_next_to_a_reference` | the `_id` exclusion silences only the reference, not the `secret_key` material column beside it |
| `test_bare_material_names_still_fire_negative_control` | negative control (#805): bare `api_key`/`secret_key` (not `_id`-suffixed) keep firing |
| `test_fp_bait_table_constraint_clause_not_misread_as_column` | FP-bait: `CONSTRAINT`/`PRIMARY KEY`/`CHECK` clauses are not columns |
| `test_pragma_opt_out` | the SQL pragma silences the finding |
| `test_quoted_column_name` | a double-quoted column identifier is still matched |
| `test_numeric_type_paren_does_not_break_column_split` | `numeric(10,2)`'s internal comma doesn't mis-split the column list |
| `test_hostile_unterminated_create_table_bounded_time` | adversarial: many unclosed `CREATE TABLE t (` occurrences stay bounded (each scan capped at the next head's start) |
| `test_many_alter_table_statements_bounded_time` | perf: thousands of well-terminated `ADD COLUMN` statements stay linear and all report |

## Known bypasses

- **The blocklist is a fixed vocabulary.** A column named `pwd`, `secret`, `token`, or any
  synonym/abbreviation not on the list is invisible to this guard. The list intentionally matches
  the exact terms named in this guard's own design brief rather than trying to be exhaustive —
  widening it is a follow-up, not a correctness fix.
- **A column added via a dynamic `EXECUTE`/`format()`-built DDL string** is invisible — this guard
  reads literal `CREATE TABLE`/`ALTER TABLE` statements, not string-built SQL.
- **Case/quoting tricks do not evade it** — the blocklist match is case-insensitive and a
  double-quoted identifier is unwrapped before matching (see `test_quoted_column_name`), so
  `"Password"` fires exactly as `password` does.
- **Comments (closed in #442 phase 2b).** The guard reads the shared `strip_sql_comments(sql, blank=True)`, the length- and newline-preserving lexer the other SQL guards use. A `--` inside a literal (e.g.
  `DEFAULT 'a--b'`) used to blank to end of line and eat the comma after it, so `split_call_args` merged
  two column definitions and a sensitive name after the comma was missed. It is now reported
  (`test_string_literal_double_dash_does_not_hide_a_later_column`).

## What this guard does NOT prove

It proves a column NAME matches a sensitive-name pattern in a public-schema table; it does not
prove the column actually holds sensitive data (a column named `credit_card` could be a boolean
flag), nor does it prove RLS is otherwise correctly configured — a table with perfect row-level
scoping is still fully in scope for this guard, because RLS cannot narrow columns at all. Absence
of a finding does not mean no sensitive data is exposed: a column named something this blocklist
doesn't cover, or data exposed through a view/RPC this guard doesn't scan, is outside what a
static, name-based check can see.

# Citations

[1] agentsec checklist item `7-sensitive-column-names-public` (§7)
[2] OWASP:A01
[3] CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
[4] Supabase — PostgREST auto-generated Data API: every public-schema table/column is exposed by
    default unless explicitly narrowed by a view or revoked grant
