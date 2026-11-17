---
type: Guard
title: "pg-extension-in-public"
description: "PostgreSQL extension installed in public schema."
timestamp: "2026-10-15T18:54:39Z"
guard_id: "pg-extension-in-public"
checklist_section: ["7"]
standards: ["OWASP:A05"]
---

# PostgreSQL extension installed in public schema

_Author — 2026-06-21_

---

## The threat

**PostgreSQL extensions installed in the `public` schema expose their functions and operators to
every database user**, including unauthenticated `anon` callers in Supabase.  Dangerous extensions:

- **`dblink`** — lets any caller open a connection to an arbitrary PostgreSQL server from within
  the database, bypassing network controls entirely.
- **`file_fdw`** — exposes server-side filesystem reads through the foreign-table machinery.
- **`pg_stat_statements`** — leaks internal query plans and can reveal sensitive parameter values
  logged in query text.

Even "safe" utility extensions (`uuid-ossp`, `pgcrypto`) in `public` bloat the attack surface:
privilege-escalation chains often string together available functions.

The **CIS PostgreSQL Benchmark** (v1, section 2) recommends installing extensions in a dedicated
schema (e.g. `extensions`) so that `search_path` controls limit access.  Supabase itself follows
this guidance — it installs system extensions in `extensions`, not `public`.

- **Who reaches it:** any database user with `CONNECT` privilege, which includes the `anon` role
  used by all unauthenticated Supabase requests.
- **Privilege required:** zero additional privilege — the functions inherit the schema's visibility.
- **Effect:** arbitrary inter-DB connections (dblink), server-side file reads (file_fdw), or
  privilege escalation using extension-provided functions.

Standards carried by findings: **OWASP:A05** (Security Misconfiguration).

---

## Why it's often introduced / Why this guard fits the stack

`CREATE EXTENSION uuid-ossp;` (no `SCHEMA` clause) is copied verbatim from documentation examples.
PostgreSQL installs into the first writable schema in `search_path`, which defaults to `public` in
nearly every setup. Developers do not notice because the extension works correctly regardless of
which schema it lands in. The `SCHEMA extensions` pattern is only mentioned in hardening guides,
not in extension-specific docs.

---

## Detection design

1. **`applies()` gate** — fires on `"supabase" in profile.features or "sql" in profile.features`.

2. **Files scanned** — all `.sql` files returned by `iter_files(root, (".sql",))` directly
   (not via `python_scan_dirs` — SQL files can live anywhere in the repo).

3. **Logic (per-file, per-line):** each line is read with its SQL comments blanked
   (`sql_code_lines()`), so a commented-out `-- CREATE EXTENSION …` is not an install and a
   trailing `-- … SCHEMA public` comment cannot escalate a real install to HIGH (#442; the
   flagship's `sql/vault-migration/01-verify-vault.sql:50` was the first shape). A comment opened
   inside a dollar-quoted body ends inside it, so the `/*` of `$$See docs/*.md$$` cannot blank an
   install below the body. From #1006 until the lexer bounded it (#442 phase 2), that glob plus any
   later `*/` hid a real install; a comment wholly inside a `DO $$ … $$` body still blanks.

   - Match `_CREATE_EXT = re.compile(r"CREATE\s+EXTENSION(?:\s+IF\s+NOT\s+EXISTS)?\s+(\S+)", re.IGNORECASE)`
     on each line to find an extension declaration.
   - On the same line, match `_SCHEMA_CLAUSE = re.compile(r"\bSCHEMA\s+(\w+)", re.IGNORECASE)`.
   - Decision tree:
     - **No `SCHEMA` clause match** → no schema specified → severity **MEDIUM**,
       rule `pg-extension-in-public/no-schema-clause`.
     - **`SCHEMA public`** (case-insensitive) → explicit public schema → severity **HIGH**,
       rule `pg-extension-in-public/explicit-public-schema`.
     - **`SCHEMA <other>`** → non-public dedicated schema → **safe, skip**.

4. **File-level opt-out pragma** — a `-- security: allow-extension-in-public` comment anywhere in the
   `.sql` file (e.g. at the top) silences the check for that file only.

5. **Severity / rule / standards:**
   - HIGH: `pg-extension-in-public/explicit-public-schema`
   - MEDIUM: `pg-extension-in-public/no-schema-clause`
   - Standards: `["OWASP:A05"]`

---

## When NOT to flag

- Reference/example SQL (`examples/`, `.agents/examples/`, `fixtures/`, tests) is skipped via `is_reference_sql_path`. `migrations/` is deliberately NOT skipped — for SQL it is the DEPLOYED schema (Supabase `supabase/migrations/*.sql`), so an RLS/extension gap there still fires (round-2 §C.2, PR #484 review).
- **Non-public schema declared:** `CREATE EXTENSION foo SCHEMA extensions;` — the `SCHEMA` clause
  names something other than `public`; the guard is silent.
- **File-level pragma:** `-- security: allow-extension-in-public` anywhere in the file.
- **No `CREATE EXTENSION` in any `.sql` file:** nothing to check.

The pragma is appropriate when the extension is in `public` but all non-admin roles have been
explicitly restricted with `REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC`.

---

## Tests

| Test | What it checks |
|---|---|
| `test_pg_extension_in_public_no_schema_fires_medium` | True positive: `CREATE EXTENSION uuid-ossp;` (no SCHEMA) emits MEDIUM. |
| `test_pg_extension_in_public_explicit_fires_high` | True positive: `CREATE EXTENSION dblink SCHEMA public;` emits HIGH. |
| `test_pg_extension_in_public_named_schema_silent` | False positive guard: `CREATE EXTENSION pgcrypto SCHEMA extensions;` stays silent. |
| `test_pg_extension_in_public_pragma_silences` | Pragma path: `-- security: allow-extension-in-public` in file silences both checks. |
| `test_pg_extension_in_public_if_not_exists` | Variant: `CREATE EXTENSION IF NOT EXISTS uuid-ossp;` (no SCHEMA) also fires MEDIUM. |
| `test_pg_extension_in_public_applies_gate` | `applies()` returns False for a profile with neither `supabase` nor `sql` in features. |
| `test_pg_extension_in_public_commented_out_install_is_silent` | Whole-line (flagship shape), trailing, single- and multi-line block-commented installs stay silent (#442). |
| `test_pg_extension_in_public_trailing_comment_is_not_a_schema_clause` | `CREATE EXTENSION dblink; -- was SCHEMA public` is MEDIUM no-schema, not HIGH (#442). |
| `test_pg_extension_in_public_live_install_below_a_comment_still_fires_high` | A live `SCHEMA public` install below a block comment, with a trailing comment, still fires HIGH. |
| `test_pg_extension_in_public_install_after_a_dollar_quoted_glob_still_fires` | An install between `$$See docs/*.md$$` and a later block comment still fires on its own line (#442 phase 2). |
| `test_pg_extension_in_public_install_commented_out_inside_a_do_body_is_silent` | FP-bait for the above: an install commented out inside a `DO $$ … $$` body stays silent, while a live one there fires. |

---

## Known bypasses

- **Multi-line `CREATE EXTENSION`:** if the `SCHEMA` clause is on the next line, `_SCHEMA_CLAUSE`
  won't match the same line as `_CREATE_EXT`, so the guard treats it as no-schema and fires MEDIUM
  instead of suppressing. Multi-line extension statements are rare in practice.
- **Extension name as quoted identifier:** `CREATE EXTENSION "pg_trgm";` — the regex captures the
  quoted form including quotes; the extension name in the finding message will include the quotes
  but detection still works correctly.
- **Pragma only in a non-`.sql` file:** the pragma check is file-scoped and only applies to `.sql`
  files, so a pragma in a Python migration script would not suppress the SQL file's finding.

---

## What this guard does NOT prove

- It does not verify what the extension actually does or whether it is inherently dangerous.
- It does not check whether `REVOKE` statements adequately restrict the installed functions.
- It does not detect extension installation via PL/pgSQL `EXECUTE` statements or migration
  frameworks that generate SQL at runtime.
- It does not check whether `search_path` is set to a non-public schema at the session or
  function level, which would also mitigate the risk.

# Citations

[1] agentsec checklist item `7-extension-not-in-public-schema` (§7)
[2] OWASP:A05
