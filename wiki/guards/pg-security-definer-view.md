---
type: Guard
title: "pg-security-definer-view"
description: "View created without SECURITY INVOKER — bypasses caller RLS."
timestamp: "2026-10-15T18:54:39Z"
guard_id: "pg-security-definer-view"
checklist_section: ["7"]
standards: ["CIS:6.7", "OWASP:A01"]
---

# View created without SECURITY INVOKER — bypasses caller RLS

_Author — 2026-06-21_

---

## Threat

In PostgreSQL, a view created with `CREATE VIEW` runs under **SECURITY DEFINER** semantics by default: it executes with the **owner's** identity, not the querying user's. When the view is served through PostgREST (the Supabase Data API), anon and authenticated callers inherit the view owner's row-level access. RLS policies keyed on `auth.uid()`, `current_user`, or JWT claims evaluate with the owner's identity instead of the caller's — the caller bypasses the policies that are supposed to restrict them.

WHO reaches this: any anon or authenticated caller with access to the PostgREST endpoint.
WHAT privilege: the view owner's — typically `postgres` or a migration role with `SELECT` on every row.
WHAT effect: horizontal data exposure (reads rows they should not see) and, in update views, potential unauthorized writes.

CIS:6.7 (ensure PostgreSQL views use appropriate security context), OWASP:A01 (Broken Access Control). Mirrors Supabase Splinter's `security_definer_view` lint.

## Why it is often introduced

Developers use views as a thin API layer over tables. The convenience `CREATE VIEW public.user_data AS SELECT * FROM users` is a natural migration step. PostgreSQL documents SECURITY DEFINER as the default but this is easy to miss; the view works correctly in ad-hoc queries run as the owner. The bypass only surfaces for end-users hitting PostgREST where the caller context matters.

```sql
-- DANGEROUS default — runs as view owner; bypasses caller RLS
CREATE VIEW public.user_data AS
    SELECT * FROM users;

-- SAFE — runs as caller; their RLS policies apply
CREATE VIEW public.user_data WITH (security_invoker = true) AS
    SELECT * FROM users;

-- SAFE (older Postgres / standard SQL)
CREATE OR REPLACE VIEW public.user_data SECURITY INVOKER AS
    SELECT * FROM users;
```

## Detection design

1. **`applies()` gate** — `"supabase" in profile.features or "postgres" in profile.features`. Both Supabase-specific deployments and any generic Postgres project may have views.

2. **Files scanned** — all `.sql` files under `root` via `iter_files(root, (".sql",))`.

3. **Patterns**

   SQL comments are blanked first (`strip_sql_comments(blank=True)`, same offsets as the raw file),
   so a commented-out view, or comment prose such as `-- Step 2.2: Create view to join …`, is not
   a view (#442; the flagship's `sql/vault-migration*/` files fired HIGH + MEDIUM on both shapes).
   A comment opened inside a dollar-quoted body ends inside it, so the `/*` of
   `$$See docs/*.md$$` cannot blank a view below the body. From #1006 until the lexer bounded it
   (#442 phase 2), that glob plus any later `*/` hid a real view; a comment wholly inside a
   `DO $$ … $$` body still blanks.

   Detect the CREATE VIEW opener on the whole blanked text, so a head split across lines counts:
   ```
   CREATE\s+(?:OR\s+REPLACE\s+)?VIEW\b   (re.IGNORECASE)
   ```

   Then check the view's own statement, from the opener to its terminating `;`
   (`find_statement_end`, quote-aware) or the next `CREATE VIEW` opener, whichever comes first
   (stopping at the next opener keeps a `;`-less file linear, #419), for either safe form:
   ```
   \bSECURITY\s+INVOKER\b               (trailing clause, any Postgres version)
   \bsecurity_invoker\s*=\s*true\b      (WITH option, Postgres 15+)
   ```

   A view that lacks both forms in its statement is flagged, unless a later `ALTER VIEW <name> SET
   (security_invoker = true)` in the same file names it (bare name, matched like
   `pg-function-search-path`'s `ALTER FUNCTION` credit; the option list is read up to 500
   characters, also for #419). An ALTER that precedes a
   `CREATE OR REPLACE VIEW` does not count, because the replace resets the view's options. The
   `security_barrier` check uses the same statement and the same ALTER credit, flag by flag.

   The last later ALTER that touches a flag is that flag's final word (#1006 review), so a
   `SET (security_invoker = false)` (or `off`, `no`, `0`, optionally quoted) or a
   `RESET (security_invoker)` after a hardening ALTER un-hardens the view again, and so does one
   after a view created `WITH (security_invoker = true)`. Keeping only the last turn-ON passed a
   view hardened and then un-hardened in the same file. A value spelled any other way (`on`,
   `yes`, a bare flag) leaves the flag as it was.

   This replaced a fixed 10-line window (#442), which let a neighbouring view's options vouch for
   an unhardened one (a false negative) and missed an option written more than 10 lines into a
   long view, behind a column list (a false positive).

4. **Opt-out pragma** — a `-- security: allow-security-definer-view` comment (matched on the comment-only view, #424; a string literal quoting it does not count). If present anywhere in the file, the entire file is skipped. This is a file-level pragma, not per-statement, so if a file has a known-safe intentional definer view alongside other views, separate the intentional one into its own migration.

5. **Severity and rule**
   - severity: `"high"`
   - rule: `"pg-security-definer-view/view-without-security-invoker"`
   - standards: `["CIS:6.7", "OWASP:A01"]`

## Severity rationale

HIGH (not CRITICAL) because:
- The bypass requires that the underlying table actually has RLS policies (if there are no policies, the view semantics do not change the visible rows).
- Some views are over non-user tables where SECURITY DEFINER is harmless or intentional.
- The pragma allows per-file escape when the pattern is intentional.

Compared to `public-table-rls` (no RLS at all = high) or `definer-function-grants` (secret functions callable by anon = critical), a definer view is serious but often exploitable only in the presence of complementary RLS that the guard cannot confirm exists.

## Known bypasses / false negatives

| Bypass | Why it evades detection |
|---|---|
| View created in a stored procedure / `DO` block | The `CREATE VIEW` inside PL/pgSQL is not scanned as a standalone statement |
| Dynamic SQL building the view (`EXECUTE format('CREATE VIEW ...')`) | String construction is not traced |
| `ALTER VIEW v SET (security_invoker = true)` in a different file from the `CREATE VIEW` | The ALTER credit is per file, like `pg-function-search-path`'s; a cross-file ALTER still leaves the finding (the safe direction). An un-hardening ALTER in a different file is missed the same way, and that one is a false negative |
| An un-hardening ALTER spelled with an abbreviation Postgres accepts (`= f`, `= n`), or with an option list longer than 500 characters | Not read as turning the flag off, so an earlier credit stands (a false negative). Contrived: migrations spell it `false` or `RESET` it |
| An option spelled other than `= true` (`= on`, `= 1`, a bare `security_invoker`, or pg_dump's `='true'`) | `_SECURITY_INVOKER_OPTION` / `_SECURITY_BARRIER_OPTION` match only `= true`. Pre-existing, and it fires rather than misses (a false positive) |

## False positive scenarios

| Scenario | Why it fires (and how to suppress) |
|---|---|
| A view over non-user internal tables (e.g. a config or audit log view) where SECURITY DEFINER is harmless | Still fires; suppress with `-- security: allow-security-definer-view` |
| A materialized view refresh function using SECURITY DEFINER intentionally | Fires on the `CREATE VIEW` or `CREATE MATERIALIZED VIEW` opener; suppress per file |

## Checklist items flipped

| ID | Before | After | Reason |
|---|---|---|---|
| `7-security-definer-view` | `manual` | `covered` | Guard detects the pattern; `verified_by` → `tests/guards/test_pg_security_definer_view.py::test_pg_security_definer_view_flags_missing_invoker` |

## Tests

| Test | Validates |
|---|---|
| `test_pg_security_definer_view_flags_missing_invoker` | True positive: bare `CREATE VIEW` with no security invoker keyword fires exactly one HIGH finding with the correct rule |
| `test_pg_security_definer_view_silent_with_option` | False positive suppression: `WITH (security_invoker = true)` produces no findings |
| `test_pg_security_definer_view_silent_security_invoker_clause` | False positive suppression: trailing `SECURITY INVOKER` clause produces no findings |
| `test_pg_security_definer_view_pragma_silences` | Pragma suppression: file-level pragma skips the file |
| `test_pg_security_definer_view_not_applies_no_postgres` | Feature gate: guard is silent when neither `postgres` nor `supabase` is in features |
| `test_pg_security_definer_view_or_replace_fires` | `CREATE OR REPLACE VIEW` with no security invoker is also flagged |
| `test_pgsdv_commented_out_view_is_silent` | The two flagship prose lines verbatim, a trailing `--`, a single- and a multi-line `/* */` view stay silent (#442) |
| `test_pgsdv_live_view_below_comment_prose_still_fires_on_its_own_line` | The real view under the flagship prose keeps its HIGH + MEDIUM, on its own line |
| `test_pgsdv_neighbouring_hardened_view_does_not_vouch_for_an_unhardened_one` | The 10-line-window false negative: a hardened v2 no longer silences v1 |
| `test_pgsdv_option_more_than_ten_lines_into_the_statement_is_credited` | The 10-line-window false positive: options behind a 12-line column list are seen |
| `test_pgsdv_name_matched_alter_view_hardens_the_view` | A name-matched `ALTER VIEW … SET (…)`, adjacent or 15 lines on, credits the view |
| `test_pgsdv_alter_view_that_does_not_harden_this_view_is_not_credited` | A different view's ALTER, flags set false, a commented-out ALTER, or `OWNER TO` credit nothing |
| `test_pgsdv_alter_before_a_create_or_replace_is_not_credited` | An ALTER before a `CREATE OR REPLACE VIEW` does not harden the replacement |
| `test_pgsdv_alter_view_credits_only_the_flag_it_sets` | A barrier-only ALTER leaves the invoker finding |
| `test_pgsdv_later_alter_turning_the_flags_off_revokes_the_credit` | A hardening ALTER followed by `SET (… = false)`, `= 'off'` / `= 0`, or `RESET (…)` fires both rules again (#1006) |
| `test_pgsdv_later_alter_turning_a_flag_off_overrides_the_views_own_option` | A later un-hardening ALTER overrides the CREATE's own `WITH` options, flag by flag (#1006) |
| `test_pgsdv_alter_that_does_not_leave_a_flag_off_does_not_revoke_it` | FP-bait, each case mutation-proven: off then on, a different view's ALTER, an ALTER before a `CREATE OR REPLACE`, `= on`, and an unrelated option revoke nothing (#1006) |
| `test_pgsdv_head_split_across_lines_is_a_view` / `test_pgsdv_hardened_head_split_across_lines_is_silent` | A `CREATE OR REPLACE` / `VIEW` head split across lines is detected, and its own options still credit it |
| `test_pgsdv_semicolon_inside_a_quoted_column_name_does_not_end_the_statement` | The statement bound is quote-aware |
| `test_pgsdv_hostile_semicolonless_sql_stays_linear` | `;`-less `CREATE VIEW` heads and never-closed `ALTER VIEW … SET (` heads stay linear and still fire (#419 class, slow) |
| `test_pgsdv_view_after_a_dollar_quoted_glob_still_fires` | A view between `$$See docs/*.md$$` and a later block comment still fires both rules on its own line (#442 phase 2) |
| `test_pgsdv_view_commented_out_inside_a_do_body_is_silent` | FP-bait for the above: a view commented out inside a `DO $$ … $$` body stays silent, while a live one there fires |

# Citations

[1] agentsec checklist item `7-security-definer-view` (§7)
[2] CIS:6.7
[3] OWASP:A01
