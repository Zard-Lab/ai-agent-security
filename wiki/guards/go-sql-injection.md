---
type: Guard
title: "go-sql-injection"
description: "SQL query built from unparameterized string formatting/concatenation."
timestamp: "2026-08-11T11:20:17+08:00"
guard_id: "go-sql-injection"
checklist_section: ["3b"]
standards: ["ASVS:1.2.4", "OWASP:A03"]
---

# SQL query built from unparameterized string formatting/concatenation

Flags a Go SQL query built from unparameterized string formatting (`fmt.Sprintf`) or string
concatenation, fed directly into a `database/sql`-family `Query`/`QueryRow`/`Exec`/`QueryContext`/
`QueryRowContext`/`ExecContext` call. This is the Go-side counterpart to `sqlalchemy-text-parameterized`
(Python) and `js-sql-injection` (JS/Node) — this is the first Go-specific guard agentsec ships, landing
just after the Go stack-detection + `strip_go_comments`/`go_scan_dirs` scanning infrastructure. CWE-89,
OWASP:A03.

**Licensing note:** this guard's threat class overlaps with what gosec (Apache-2.0) also covers. Per an
explicit project constraint, detection logic and test fixtures here are 100% original — developed from
Go language/stdlib documentation (`database/sql`) and independent security reasoning, without reading,
fetching, or referencing gosec's source, rule descriptions, or test corpus in any way.

_Author — 2026-08-10_

---

## The threat

Go's `database/sql` package treats the query-text argument to `.Query`/`.QueryRow`/`.Exec` (and their
`*Context` siblings, on a `*sql.DB`/`*sql.Tx`/`*sql.Conn`) as opaque SQL, sent to the driver verbatim.
The documented safe idiom binds untrusted values as SEPARATE arguments after a static query string, with
placeholders (`?` for MySQL/SQLite drivers, `$1`/`$2` for `lib/pq`/`pgx`) marking where each one goes:

```go
db.Query("SELECT * FROM users WHERE id = ?", userID)   // safe — driver binds userID separately
```

When the value is instead baked into the query TEXT itself — via `fmt.Sprintf` or string concatenation —
the driver never sees a placeholder to bind against, so it cannot distinguish attacker input from query
structure:

```go
db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID))          // injectable
db.Exec("DELETE FROM sessions WHERE token = '" + token + "'")                // injectable
```

An attacker who controls `userID`/`token` here controls query structure: read/write arbitrary rows,
bypass a `WHERE`-clause authorization check, in the worst case (multi-statement-capable driver config)
chain additional statements. CWE-89 (SQL Injection), OWASP:A03 (Injection).

## Why this guard fits the stack

agentsec's flagship targets are FastAPI + React + Postgres + LLM/RAG apps, but the same collaboration
that motivated Go stack detection means a Go backend service, sidecar, or worker talking directly to
Postgres/MySQL via `database/sql` is now a first-class scan target. Before this guard, agentsec had zero
Go-side SQL-injection coverage — the Python guard only sees `sqlalchemy`/`text()`/`.execute()` call
shapes, and the JS guard only sees `mysql`/`pg`-style Node driver calls. Neither pattern matches Go's
`database/sql` method-call surface (`Query`/`Exec`-family method names on a connection/pool/transaction
object, not a cursor). This closes that specific gap with the same dependency-free, always-available
guard mechanism used everywhere else in agentsec — no external scanner installation required for a
CRITICAL-class control.

Typical introduction path — an AI-assisted or rushed hand-write of a Go HTTP handler:

```go
func getUser(db *sql.DB, w http.ResponseWriter, r *http.Request) {
    userID := r.URL.Query().Get("id")
    rows, err := db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID))
    // ...
}
```

## Detection design

1. **`applies()` gate** — `"go" in profile.features`.
2. **Files scanned** — `.go` files under `go_scan_dirs(root, profile)` via `iter_files`, skipping
   non-product paths (`is_nonproduct_path` — `tests?`/`examples?`/`fixtures?`/`migrations?` directory
   segments, same shared gate every other guard uses; Go's own `_test.go` filename suffix convention is
   NOT specially recognized by that shared helper today, so a Go test file only avoids scanning if it
   sits under one of those directory names).
3. **Two-view line handling.** `raw_lines = read(f).splitlines()` keeps comments intact (so the pragma,
   itself a `//` comment, is visible); `code_lines = strip_go_comments(read(f)).splitlines()` has all
   comments blanked (string/rune/raw-string-aware) before pattern matching, so a vulnerable pattern
   appearing only in a commented-out line never fires. `strip_go_comments` preserves line count and
   every newline boundary, so the two views stay index-aligned.
4. **Sink anchor** — `_SINK_CALL`: `\.(?P<method>Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext)\s*\(`,
   a method call on some receiver. Neither `fmt.Sprintf` nor `+`-concatenation fires on its own anywhere
   in the file — only when it feeds this specific sink call's query-text argument. `*Context` variants
   take `(ctx, query, args...)` — the query text is argument INDEX 1, not 0 — so `_split_args` extracts
   every top-level (depth-0) comma-separated argument of the matched call and `_QUERY_ARG_INDEX` picks
   the right one per method name (0 for `Query`/`QueryRow`/`Exec`, 1 for the three `*Context` siblings).
   A comma nested inside a further call's own parens (e.g. between `fmt.Sprintf`'s format string and its
   value arguments) stays at depth > 0 and does not split the outer call's argument list.
5. **Two sub-rules, evaluated per matched sink call, in this order:**
   - `sprintf-query` — `_SPRINTF_CALL` (`\bfmt\.Sprintf\s*\(`) found inside the query argument. Fires
     both when `fmt.Sprintf(...)` is written directly in the argument (same line) AND when the argument
     is a bare identifier (`_BARE_IDENT`, `^[A-Za-z_]\w*$`) whose value was assigned via
     `<ident> := fmt.Sprintf(...)` / `<ident> = fmt.Sprintf(...)` (`_SPRINTF_ASSIGN`) on one of the
     `_LOOKBACK_LINES` (5) lines immediately before the sink call line. The lookback is purely textual —
     nearest matching assignment within that fixed window, same file — not dataflow.
   - `string-concat-query` — `_CONCAT_ARG` (`["'\`].*?["'\`]\s*\+\s*\w`) found inside the query argument:
     a string/rune/raw-string literal, non-greedy up to its own closing delimiter, followed by `+` and
     an identifier. The non-greedy `.*?` (not a quote-exclusion character class) is deliberate: it lets
     the match span a quote character legitimately embedded inside the literal — e.g. a SQL string
     delimiter nested in a Go double-quoted string, `"... WHERE token = '"` — by backtracking to the
     literal's real closing delimiter rather than stopping at the first embedded quote. Inline only, no
     variable lookback for this shape. A literal-plus-literal concat (`"a" + "b"`) is not matched.
   - `sprintf-query` is checked before `string-concat-query`, so a (rare) argument matching both never
     double-fires.
6. **Inline opt-out pragma** — `security: allow-go-sql-injection` inside a `// ...` comment (matched
   against the comment-only view of the line, #424: `strip_go_comments` would blank the pragma text itself
   out of the pattern-matching view). Checked per finding: on the sink call's own physical line, OR — for the
   `sprintf-query` variable-lookback form specifically — on the `fmt.Sprintf` assignment line, so a
   reviewer can suppress at the point of construction instead of every call site that reuses the
   variable.
7. **Severity / rule / standards** — fires **HIGH** for both sub-rules (mirrors the Python/JS sibling
   guards' severity for the same CWE-89 shape), `rule = "go-sql-injection/sprintf-query"` or
   `"go-sql-injection/string-concat-query"`, `standards = ["CWE-89", "OWASP:A03"]`.

## When NOT to flag

- A parameterized call — a static string with `?`/`$1` placeholders and the value(s) as separate
  arguments (`db.Query("... WHERE id = ?", userID)`) — stays silent: the query argument extracted by
  `_split_args` is just the static string, no `fmt.Sprintf`/concat pattern present.
- A fully static query string (`db.Query("SELECT * FROM users WHERE active = true")`) — no matching
  pattern, stays silent.
- `fmt.Sprintf`/string concatenation that never feeds a `Query`/`Exec`-family call at all — a log
  message, an HTTP response body, an error string — stays silent by construction: the guard only ever
  inspects the query-argument slot of an actual matched sink call, never scans for `fmt.Sprintf`
  in isolation.
- A vulnerable-looking pattern that appears only inside a `//` comment — stays silent (comments are
  blanked before pattern matching).
- A reviewed case — most importantly, `fmt.Sprintf` used to build a TABLE/COLUMN NAME from a small,
  fixed, internal set of constants (a real, common, safe Go idiom, e.g.
  `fmt.Sprintf("SELECT * FROM %s", tableName)` where `tableName` is never attacker-controlled) — suppress
  with `// security: allow-go-sql-injection` on the sink line (or the assignment line, for the variable
  form). See "Known bypasses" for why this guard cannot distinguish that case on its own.

## Tests

| Test | What it checks |
|---|---|
| `test_flags_sprintf_inline_in_query` | `db.Query(fmt.Sprintf("... %s", userID))` fires `sprintf-query` |
| `test_flags_string_concat_in_exec` | `db.Exec("DELETE ... token = '" + token + "'")` fires `string-concat-query` |
| `test_flags_sprintf_via_nearby_variable` | `query := fmt.Sprintf(...)` then `db.Query(query)` a line later fires `sprintf-query`, anchored at the sink line |
| `test_flags_queryrow_and_execcontext_variants` | `QueryRow` (index-0 sink) and `ExecContext` (index-1 sink, `ctx` first) both fire — proves the `*Context` argument-index split |
| `test_silent_on_parameterized_placeholder_query` | `db.Query("... WHERE id = ?", userID)` (FP-bait) stays silent |
| `test_silent_on_fully_static_query` | `db.Query("SELECT * FROM users WHERE active = true")` (FP-bait) stays silent |
| `test_silent_on_sprintf_not_feeding_a_sql_sink` | `fmt.Sprintf` for a log message + `fmt.Fprintf` for an HTTP response (FP-bait) both stay silent — proves the sink-anchoring, not a bare `fmt.Sprintf` scan |
| `test_silent_on_commented_out_vulnerable_pattern` | the vulnerable shape inside a `//` comment stays silent |
| `test_pragma_suppresses_sprintf_inline` | `// security: allow-go-sql-injection` on the sink line suppresses `sprintf-query` |
| `test_pragma_suppresses_string_concat` | same pragma suppresses `string-concat-query` |
| `test_pragma_on_assignment_line_suppresses_variable_form` | the pragma on the `fmt.Sprintf` assignment line (not the sink line) also suppresses the variable form |
| `test_na_without_go` | `applies()` is `False` for a `python`-only profile |
| `test_applies_with_go` | `applies()` is `True` for a `go`-only profile |
| `test_nonproduct_path_skipped` | a finding under `tests/` is skipped via `is_nonproduct_path` |

Adversarial self-check (throwaway script, run manually, not part of the committed suite):
- **Bypass attempt 1** — building the query across two variables (`base := fmt.Sprintf(...)`; `query :=
  base` on the next line; `db.Query(query)` two lines after that) evaded detection: the lookback only
  matches a DIRECT `fmt.Sprintf(` assignment to the exact identifier passed to the sink, so a second
  indirection hop is invisible. Confirms the documented lookback-window limitation.
- **Bypass attempt 2** — a driver-specific call variant not in the task's six method names,
  `db.Prepare(fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID))` followed by `.Query()` on the
  resulting `*sql.Stmt` with placeholders, evaded detection: `Prepare` is not in `_SINK_CALL`'s method
  set. This is a real, if less common, `database/sql` sink this guard does not cover (`Prepare`/
  `PrepareContext` build a query template too) — see "Known bypasses".
- **FP-bait check** — `tableName := "users"; query := fmt.Sprintf("SELECT * FROM %s WHERE active = true",
  tableName); db.Query(query)` (the constant-table-name idiom) FIRED — confirmed expected per "What this
  guard does NOT prove"; not a bug, the documented dataflow limitation.

## Known bypasses (honest limits)

- **`Prepare`/`PrepareContext` not covered.** Only `Query`/`QueryRow`/`Exec` and their `*Context`
  siblings are in `_SINK_CALL`'s method set (the six names given in this guard's build spec). A query
  string built unsafely and passed to `db.Prepare(...)`/`db.PrepareContext(...)` — even though the
  resulting `*sql.Stmt` is then called safely with placeholders — is invisible to this guard.
- **Multi-hop variable indirection.** The `sprintf-query` lookback matches only a DIRECT
  `<ident> := fmt.Sprintf(...)` assignment to the exact identifier passed to the sink, within 5 lines.
  `base := fmt.Sprintf(...)`; `query := base`; `db.Query(query)` — two indirection hops — is not traced.
- **Lookback window / cross-function.** A `fmt.Sprintf`-built query assigned more than 5 lines above the
  sink call, in a different function, as a struct field, or returned from a helper function, is not
  traced. This is a deliberately short, textual, same-physical-region heuristic, not dataflow.
- **Table/column-name idiom (the FP class).** As documented above and in the module docstring: a
  `fmt.Sprintf` building a table/column name from fixed internal constants looks textually identical to
  one building a value from user input. This guard cannot tell them apart without dataflow, and fires on
  both. Confirmed by the adversarial self-check above.
- **Non-Sprintf/non-`+` string building.** `strings.Builder`, `strings.Join`, `bytes.Buffer`, or manual
  byte-slice concatenation building the query text are not covered — only `fmt.Sprintf` and `+` concat.
- **Dynamic/computed method names.** `db.MethodName(query)` where `MethodName` is resolved at runtime
  (a value, not a literal identifier) is invisible to a regex-anchored guard.
- **Multi-line sink call.** `db.Query(\n  fmt.Sprintf(...),\n)` — the sink method and its query argument
  split across physical lines — is not matched; detection is single-line only (same limitation as the
  Python/JS sibling guards).

## What this guard does NOT prove

It proves a single `Query`/`QueryRow`/`Exec`/`QueryContext`/`QueryRowContext`/`ExecContext` call's query
argument is built by `fmt.Sprintf` or string concatenation, either inline or via a same-file variable
assigned within a 5-line lookback; it does not trace real dataflow, confirm the formatted/concatenated
value is actually attacker-reachable, or distinguish a safe fixed-constant table/column-name build from
an unsafe user-input value build — that distinction requires dataflow analysis this guard does not
attempt. It does not cover `Prepare`/`PrepareContext`, non-`fmt.Sprintf`/non-`+` string-building
mechanisms, or ORM/query-builder-level SQL construction (e.g. GORM/sqlx raw-query helpers). Absence of a
finding does not mean the Go code is injection-free — it means this specific, common, literal
`fmt.Sprintf`/concat-into-`database/sql`-sink shape was not found. It is the fast, dep-free, high-
precision static check for the dominant Go SQLi shape, and the Go-side mirror of
`sqlalchemy-text-parameterized` / `js-sql-injection`.

# Citations

[1] agentsec checklist item `3b-sql-parameterized` (§3b)
[2] ASVS:1.2.4
[3] OWASP:A03
