---
type: Guard
title: "definer-dynamic-sql"
description: "SECURITY DEFINER function executes arbitrary/dynamic SQL."
timestamp: "2026-07-04T17:58:18Z"
guard_id: "definer-dynamic-sql"
checklist_section: ["7"]
standards: ["OWASP-LLM:LLM08", "OWASP:A01"]
---

# SECURITY DEFINER function executes arbitrary/dynamic SQL

_Added 2026-07-04 — closes the DB half of a critical flagship finding (`execute_custom_sql`) that every existing definer guard missed. Companion to the app-side `llm-query-engine-execution/raw-sql-exec-rpc` rule._

---

## The threat

A `SECURITY DEFINER` function executes with its **owner's** privileges (typically `postgres`), so
Row-Level Security is bypassed inside its body. When such a function runs **dynamic SQL built from
an argument** — `EXECUTE query`, `RETURN QUERY EXECUTE q`, `EXECUTE format(...)` — it becomes an
*arbitrary-SQL execution primitive*: any caller that can reach it reads (or writes) any table, RLS
bypassed, with no table restriction.

This was a **critical** flagship finding. `execute_custom_sql(text)` was `SECURITY DEFINER` owned by
`postgres` running `RETURN QUERY EXECUTE query`, exposed through the `execute_sql_query` agent tool
(`supabase.rpc("execute_custom_sql", {"query": sql_query})`) — so a prompt-injected `SELECT email
FROM user_profiles` exfiltrated other users' data. The flagship fix (PR #394) removed the whole
capability. Findings carry **OWASP A01 (Broken Access Control)** and **OWASP-LLM:LLM08**.

## Why the existing definer guards missed it

The two definer guards reason about properties *orthogonal* to the actual danger, and both went
**silent** on the flagship function because it had been hardened on their axes:

- `definer-function-grants` — flags a definer function whose `EXECUTE` is not revoked from
  PUBLIC/anon/authenticated. The flagship revoked it (`sql/111`) and granted only `service_role`.
  Silent. It reasons about *who can call it*, never the body.
- `pg-function-search-path` — flags a definer function that doesn't pin `search_path`. The flagship
  pinned it (`sql/46`). Silent. Orthogonal concern (schema-injection, not arbitrary SQL).
- `pg-security-definer-view` — views only; a `CREATE FUNCTION` never matches.

So a definer function can pass every existing check while remaining a full RLS-bypass primitive.
This guard inspects the **body** for a dynamic `EXECUTE`, which none of the others do.

## Detection design

DB-independent, cross-file, comment-stripped (parsing uses `strip_sql_comments`; the pragma is read from the
comment-only view of the same text, #424). Mirrors `definer-function-grants`'s per-`CREATE FUNCTION`-block scan.

1. **`applies()` gate** — `"sql" in profile.features`.
2. **Structure resolved on a `_mask_quoted` copy.** plpgsql interleaves three quoting contexts — `'…'`
   strings (with `''` escaping), `$tag$…$tag$` dollar bodies (arbitrary text, incl. bare `'` and `$$`),
   and comments (stripped upstream) — and deciding whether a given `'`, `$$`, `create function`, or
   `execute` is real structure or content is **inherently stateful**; a single-pass regex or `re.sub`
   cannot do it (this took four review rounds of #322 to settle). `_mask_quoted` makes one stateful
   pass, returning a **same-length** copy with the *content* of every string and dollar body replaced by
   spaces (delimiters kept). The structural regexes then run safely on the mask:
   - `_CREATE_FN` / `_SEC_DEFINER` match only at top level (never inside a string or a body) — so a
     `create function` or `security definer` substring inside a literal or body is inert;
   - each function's own `$tag$…$tag$` body is delimited correctly regardless of bare apostrophes or
     `$$`/`create function`/`execute` substrings inside strings; a single-quoted body (no `$tag$`) is
     cleanly skipped, never misattributed; a standalone `DO` block / trailing SQL is never adopted.
   The body is located by **anchoring to the `AS` keyword** (`\bas\s*(\$\w*\$)`), not by taking the first
   dollar-quote in the region — so a dollar-quoted *parameter default* (`DEFAULT $tag$…$tag$`, valid
   Postgres) is never mistaken for the body. Because the mask preserves length, the body's offsets index
   straight back into the original text to recover its **real** content, which is then scanned for the
   **dynamic** `EXECUTE` (with the body's own `'…'` strings blanked so `RAISE '…execute…'` doesn't fire,
   while a genuine `EXECUTE '' || v` still matches). `SECURITY DEFINER` may sit before the `AS` (in the
   header) or after the body (in the trailing attrs).
3. **Dynamic EXECUTE** (`_EXECUTE_DYNAMIC`) — the `EXECUTE` keyword followed by a variable/parameter
   (`EXECUTE <identifier>`), `format(...)`, a string concatenation (`EXECUTE 'sql ' || …`), or a
   parenthesized expression (`EXECUTE (query)` / `EXECUTE(query)` — with or without a space before
   the paren, since `(` is self-delimiting in PL/pgSQL). A negative lookahead excludes the
   non-dynamic / non-body forms: `EXECUTE FUNCTION|PROCEDURE` (trigger syntax) and
   `... EXECUTE ON ...` (the `GRANT/REVOKE EXECUTE ON FUNCTION` grammar). A purely static
   `EXECUTE 'literal'` (bare or parenthesized, spaced or not) does not match.
4. **Finding** — `offenders − pragma-allowed`, severity **critical**, rule
   `definer-dynamic-sql/dynamic-execute`, standards `["OWASP:A01", "OWASP-LLM:LLM08"]`.

## When NOT to flag

- A `SECURITY INVOKER` function (the default) — it runs as the caller, so RLS applies; a dynamic
  EXECUTE there is the caller's own privilege, not a bypass.
- A static `EXECUTE 'literal'` (e.g. `REFRESH MATERIALIZED VIEW`) — no argument-derived SQL.
- A top-level `DO $$ … EXECUTE format(...) … $$` block (e.g. the `sql/169`-style revoke loop) — it
  is not a `CREATE FUNCTION` body, so it is never treated as a definer-dynamic-SQL function.
- An audited case where the dynamic SQL is provably constrained — opt out with
  `-- security: allow-definer-dynamic-sql` on (or just above) the `CREATE` line.

## Tests

| Test | What it checks |
|---|---|
| `test_definer_dynamic_flags_execute_of_argument` | definer + `RETURN QUERY EXECUTE query` → CRITICAL |
| `test_definer_dynamic_fires_even_when_grants_and_search_path_hardened` | fires with revoke + `SET search_path` present (independence from the other guards) |
| `test_definer_dynamic_execute_format` | `EXECUTE format('… %I', arg)` → fires |
| `test_definer_static_execute_literal_silent` | static `EXECUTE 'literal'` → silent |
| `test_definer_dynamic_execute_parenthesized_query` | `EXECUTE (query)` (parenthesized form) → fires |
| `test_definer_dynamic_execute_parenthesized_static_literal_silent` | static `EXECUTE ('literal')` (parenthesized) → silent |
| `test_definer_dynamic_execute_parenthesized_query_no_space` | `EXECUTE(query)` (no space before paren) → fires |
| `test_definer_dynamic_execute_parenthesized_static_literal_no_space_silent` | static `EXECUTE('literal')` (no space) → silent |
| `test_definer_dynamic_execute_parenthesized_literal_concat_fires` | `EXECUTE ('literal' || var)` (literal + concat, parenthesized) → fires |
| `test_definer_dynamic_invoker_function_silent` | SECURITY INVOKER + dynamic EXECUTE → silent |
| `test_definer_dynamic_no_execute_silent` | definer, no EXECUTE → silent |
| `test_definer_dynamic_revoke_loop_not_flagged` | top-level DO-block `EXECUTE format` → silent |
| `test_definer_dynamic_pragma_opt_out` | `-- security: allow-definer-dynamic-sql` → silent |
| `test_definer_dynamic_not_applicable_without_sql` | `applies()` False without `sql` |

## Known bypasses

- **Single-quoted function body** — a plpgsql function written `AS 'body'` (single-quoted, not
  dollar-quoted) has no `$tag$` body to isolate, so it is **cleanly skipped** (a false *negative*, not a
  misattribution — the mask guarantees it never adopts a neighbouring function's body). Overwhelmingly
  rare (`$$` is the universal convention); a dollar-quoted body is required for detection.
- **Syntactically-invalid SQL** — the guard assumes deployable (valid) migration SQL. Malformed input
  that Postgres itself rejects — e.g. an *illegal same-tag* nested dollar-quote (`$t$ … $t$ … $t$`, which
  Postgres closes at the second `$t$`) or an unbalanced `'` — can desync `_mask_quoted` and cause a miss.
  Such SQL never deploys, so a missed finding on it has no security impact; it is explicitly out of scope.
- **Dynamic function creation** — a definer function built by string-concatenated DDL or an
  extension doesn't appear as a literal `CREATE FUNCTION` and isn't seen.
- **Indirect dynamic SQL** — SQL assembled into an intermediate variable via non-`format`, non-`||`
  means (e.g. `quote_ident` chains across many lines) before a bare `EXECUTE v` is still caught by
  the `EXECUTE <identifier>` arm, but SQL passed through a helper function first is not traced.
- **Block-window coarseness** — the block runs to the next `CREATE FUNCTION`; a `SECURITY DEFINER`
  on function A and a dynamic `EXECUTE` on function B are correctly separated, but unusual nesting
  could misattribute. In practice migrations define one function per block.

## What this guard does NOT prove

That an actual exploit exists — only that a definer function runs argument-derived SQL, which is the
primitive. A read-only DB role, a hard-coded allowlist inside the body, or a caller that never
passes untrusted text could make a specific instance safe; those are opt-out (pragma) cases. It does
not analyze the live database or how the function is reached from application code (the companion
`llm-query-engine-execution/raw-sql-exec-rpc` rule covers the LLM-tool reach path).

# Citations

[1] agentsec checklist item `7-definer-no-dynamic-sql` (§7)
[2] OWASP-LLM:LLM08
[3] OWASP:A01
