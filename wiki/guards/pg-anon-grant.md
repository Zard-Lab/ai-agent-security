---
type: Guard
title: "pg-anon-grant"
description: "GRANT to anon/public role bypasses RLS for unauthenticated callers."
timestamp: "2026-10-15T18:54:39Z"
guard_id: "pg-anon-grant"
checklist_section: ["7"]
standards: ["CIS:6.3", "OWASP:A01", "SOC2:CC6.3"]
---

# GRANT to anon/public role bypasses RLS for unauthenticated callers

## Threat

In Supabase and vanilla PostgreSQL deployments, the `anon` and `public` roles are inherited by
every unauthenticated connection.  When a developer grants table or schema privileges to these
roles, any visitor who has not authenticated can exercise those privileges directly — bypassing
Row Level Security (RLS) policies entirely.

This is a common misconfiguration in Supabase projects: a developer runs `GRANT SELECT ON TABLE
users TO anon` to make the REST API work and does not realise that RLS (if not yet enabled on
the table) now exposes every row to the public internet.

Standards: OWASP A01 (Broken Access Control), CIS PostgreSQL Benchmark 6.3 (Least Privilege).

## Detection design

**Files scanned:** all `.sql` files under the project root (via `iter_files(root, (".sql",))`).

**Pipeline:**

1. Read the file with `base.read()` (UTF-8, `errors="ignore"`).
2. Check for the file-level suppress pragma (a `-- security: allow-pg-anon-grant` comment).  If present, skip
   the file entirely.
3. Blank SQL block comments (`/* ... */`) and line comments (`-- ...`) to spaces with
   `sql_code_lines()` so commented-out or suppressed GRANTs do not produce spurious findings.
   Blanked, not deleted, and sliced at the raw file's own line offsets, so line `i` is raw line `i`:
   deleting a multi-line `/* … */` header took its newlines with it and reported every GRANT below
   it too high (#442). The definer-name pre-scan is a presence check and still deletes. In both,
   a comment opened inside a dollar-quoted body ends inside it, so the `/*` of
   `$$See docs/*.md$$` cannot blank a GRANT, or hide the `SECURITY DEFINER` function that
   escalates a grant to HIGH, below the body. Until the lexer bounded it (#442 phase 2), that glob
   plus any later `*/` did both; a comment wholly inside a `DO $$ … $$` body still blanks.
4. Scan line-by-line for the pattern:

```
GRANT\s+.+\s+ON\s+.+\s+TO\s+(?:anon|public)\b   (re.IGNORECASE)
```

5. Emit one `Finding` per matching line.

**Why line-by-line after stripping?**  Multi-statement SQL files may contain both safe and unsafe
GRANTs.  A file-level match would miss per-line granularity.  Stripping comments first means the
regex only sees executable SQL.

## Severity rationale (tiered by what is actually exposed)

The finding is severity-calibrated by the granted object, because an anon GRANT's blast radius varies
enormously:

| Grant | Severity | Why |
|---|---|---|
| `GRANT {SELECT\|INSERT\|UPDATE\|DELETE\|ALL} ON [TABLE/SEQUENCE] … TO anon/public` | **HIGH** | Direct table/data access — unauthenticated read = full data leak, write = corruption. The real RLS-bypass. |
| `GRANT EXECUTE ON FUNCTION f … TO anon/public` where `f` is **`SECURITY DEFINER`** | **HIGH** | The definer body runs privileged and **bypasses the caller's RLS** — anon can read/write whatever the function touches. The `exec_sql` class (see `sql/111-revoke-exec-sql-anon-grants.sql` in the flagship — a real past incident). Detected by cross-referencing the granted name against `CREATE … FUNCTION … SECURITY DEFINER` across the SQL set. |
| `GRANT EXECUTE ON FUNCTION f … TO anon/public` where `f` is `SECURITY INVOKER` / unknown | **MEDIUM** | RPC-call grant; the body runs as the caller, so RLS still gates the underlying tables. The standard Supabase pattern, but worth confirming the routine is RLS-aware. |
| `GRANT USAGE ON SCHEMA … TO anon/public` | **LOW** | Namespace access only — the ability to *reference* objects, not read any table. Required for the anon RPC pattern; exposes nothing on its own (tables still need their own RLS). |

`GRANT ALL`/`GRANT CREATE ON SCHEMA` is **not** USAGE and stays HIGH (anon could create objects).

An incorrect HIGH GRANT is directly exploitable — any unauthenticated request to the Supabase REST API (or
a `psql` connection) inherits `anon` and exercises the privilege immediately.

## Known bypasses / false negatives

| Scenario | Why not caught | Mitigation |
|---|---|---|
| Multi-line GRANT statement (`GRANT SELECT\nON TABLE users\nTO anon;`) | Regex matches per line; only the `TO anon` line would lack the leading `GRANT` keyword | Rare in practice; most SQL tooling emits single-line GRANTs |
| GRANT stored inside a PL/pgSQL `EXECUTE` string | Dynamic SQL is not evaluated statically | Out of scope for static guards; flag in code review |
| Role named `anon_backup` or `anon_readonly` | `\b` word boundary prevents these from matching | By design — only exact `anon` or `public` is flagged |
| GRANT in a migration file excluded from `iter_files` by `.gitignore` | Walk respects `.gitignore` | Ensure migration dirs are not gitignored |
| **`SECURITY DEFINER` whose function body literally contains `CREATE `** (e.g. dynamic DDL) placed *after* the body | The definer pre-scan is bounded so it can't cross into the next `CREATE …`; a `CREATE` inside the body stops it early | Rare; the EXECUTE grant still fires MEDIUM with the definer warning, just not escalated to HIGH |
| **Superseded definer.** A function defined `SECURITY DEFINER` in an old migration, later replaced by an invoker one | Per-file static scan does not reconcile cross-file redefinition | The grant **over-escalates** to HIGH (safe direction — flags the potentially-dangerous case for review) |

## False positive scenarios

| Scenario | Why it does NOT fire |
|---|---|
| `GRANT USAGE ON SCHEMA public TO authenticated;` | Role is `authenticated`, not `anon` or `public` |
| `GRANT SELECT ON TABLE logs TO service_role;` | Role is `service_role` |
| `REVOKE ALL ON TABLE secrets FROM anon;` | Line does not match `GRANT ... TO ...` |
| `-- GRANT SELECT ON TABLE users TO anon;` (commented out, or in any `/* */` form) | Comment blanked before scanning |
| File with a `-- security: allow-pg-anon-grant` comment | File skipped at the pragma check step |

## Checklist items flipped

| ID | Before | After | Reason |
|---|---|---|---|
| 7-no-grant-to-anon-public | `manual` | `covered` | Guard detects GRANT to anon/public in .sql files; tests `test_pg_anon_grant_fires` and `test_pg_anon_grant_silent` validate TP/FP |

## Tests

| Test | Validates |
|---|---|
| `test_pg_anon_grant_fires` | True positive: `GRANT SELECT ON TABLE users TO anon;` produces one HIGH finding with rule `pg-anon-grant/grant-to-anon-public` |
| `test_pg_anon_grant_fires_multiple` | Multiple matching lines in one file produce one finding per line |
| `test_pg_anon_grant_silent_safe` | False positive guard: grants to `service_role` and `authenticated` produce no findings |
| `test_pg_anon_grant_pragma_silences` | A `-- security: allow-pg-anon-grant` comment in the file suppresses all findings for that file |
| `test_pg_anon_grant_not_applies` | Guard returns `[]` (short-circuits via `applies()`) when neither `supabase` nor `postgres` is in features |
| `test_pg_anon_grant_case_insensitive` | `grant insert on orders to anon;` (lowercase) fires correctly |
| `test_pg_anon_grant_line_below_block_comment_header_is_the_raw_line` | A GRANT below a 5-line `/* */` header reports raw line 6, not 2 (#442) |
| `test_pg_anon_grant_commented_out_grant_is_silent` | Whole-line, trailing, single- and multi-line block-commented GRANTs stay silent |
| `test_pg_anon_grant_live_grant_with_trailing_comment_still_fires` | A live GRANT with a trailing comment still fires HIGH on its raw line |
| `test_pg_anon_grant_form_feed_inside_a_comment_keeps_raw_line_numbering` | A form feed inside a comment still ends a line for numbering (#442) |
| `test_pg_anon_grant_grant_after_a_dollar_quoted_glob_still_fires` | A GRANT between `$$See docs/*.md$$` and a later block comment still fires HIGH on its own line (#442 phase 2) |
| `test_pg_anon_grant_definer_after_a_dollar_quoted_glob_still_escalates` | A `SECURITY DEFINER` function in the same position still escalates the grant on it to HIGH (#442 phase 2) |
| `test_pg_anon_grant_grant_commented_out_inside_a_do_body_is_silent` | FP-bait for the above: a GRANT commented out inside a `DO $$ … $$` body stays silent, while a live one there fires |

# Citations

[1] agentsec checklist item `7-no-grant-to-anon-public` (§7)
[2] CIS:6.3
[3] OWASP:A01
[4] SOC2:CC6.3
