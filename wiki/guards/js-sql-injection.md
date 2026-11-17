---
type: Guard
title: "js-sql-injection"
description: "JS/Node interpolated SQL query string."
timestamp: "2026-10-20T12:00:00Z"
guard_id: "js-sql-injection"
checklist_section: ["3b"]
standards: ["ASVS:1.2.4", "OWASP:A03"]
---

# JS/Node interpolated SQL query string

Flags JS/Node SQL query strings built by template-literal interpolation or string concatenation
inside a `.query()`/`.execute()` call on a `mysql`/`mysql2`/`pg`/`pg-promise` connection or pool.
This is the JS/Node-side counterpart to `sqlalchemy-text-parameterized` (the existing Python-side
SQL-injection guard). Prior to this guard, agentsec had zero JS/Node SQL-injection coverage. CWE-89,
OWASP:A05.

_Author — 2026-07-15_

---

## The threat

Node's `mysql`/`mysql2`/`pg`/`pg-promise` driver `.query()`/`.execute()` methods accept the SQL text
as their first argument. When that text is built by template-literal interpolation
(`` `SELECT ... WHERE id = ${userId}` ``) or string concatenation (`"SELECT ... " + userId`), the
attacker-controlled value is baked into the query string before the driver ever sees it — the driver
has no way to distinguish it from the query structure, so it cannot be bound as a parameter. Any
request-derived value (a route param, a query string, a request body field) reaching one of these
calls is classic SQL injection: read/write any row, bypass auth checks in a `WHERE` clause, in the
worst case (stacked queries, depending on driver config) execute arbitrary statements. CWE-89,
OWASP:A05 (Security Misconfiguration is A05 in the 2021 list is close but the injection category is
really A03 — this guard cites A05 per the task's given standard; see note in "Known limits").

## Why this guard fits the stack

agentsec targets FastAPI + React + Postgres + LLM/RAG apps, but the flagship-adjacent stacks
frequently ship a Node-based API gateway, a background worker, or a BFF layer alongside the Python
backend — any of which may talk to Postgres/MySQL directly via `pg`/`mysql2`. Before this guard,
agentsec's only SQL-injection coverage was Python-side (`sqlalchemy-text-parameterized`, plus the
Semgrep `python-llm` rule pack) — a JS/Node SQL sink in the same repo was invisible to a guards-only
run. This closes that specific gap using the same dep-free, always-available guard mechanism (no
scanner installation required), mirroring the doctrine that a critical control (SQLi) must not depend
solely on an external tool being installed.

Typical introduction path — an AI-assisted or rushed hand-write of a Node route handler:

```js
const { Pool } = require('pg');
const db = new Pool();

app.get('/users/:id', async (req, res) => {
  const result = await db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
  res.json(result.rows);
});
```

## Detection design

1. **`applies()` gate** — `"javascript" in profile.features or "typescript" in profile.features`
   (same convention as the sibling JS-scoped guards, e.g. `js_client_side_open_redirect.py`).
2. **Files scanned** — `.js`/`.jsx`/`.ts`/`.tsx` via `iter_files`, skipping non-product paths
   (`is_nonproduct_path`). **Import-scoped**: a file is only scanned once it `require()`s or
   `import`s one of `mysql`, `mysql2`, `pg`, `pg-promise` (`_DRIVER_IMPORT`). `.query()`/`.execute()`
   are extremely common method names on unrelated objects (an ORM, a search client like
   Elasticsearch, a job queue) — without the import gate this guard would false-positive heavily on
   those. This is the precision-over-recall choice flagged in the guard's build task; see "Known
   bypasses" for the cost.
3. **Patterns**:
   - `_CALL` — `\.(?:query|execute)\s*\(`, a method call on some receiver (`db.query(`,
     `pool.execute(`).
   - `_first_arg()` — a bracket- and quote-aware extractor (ported directly from
     `sqlalchemy_text_parameterized.py`'s `_first_arg`, with backtick added to the quote set) that
     returns only the call's OWN first positional argument, stopping at a depth-0 comma or the
     call's closing `)`. This is what keeps a parameterized call's separate values-array argument
     (`db.query("...", [userId])`) from ever being inspected, and what lets a whole options object
     (`db.query({ sql: ..., values: [...] })`) be captured intact since its internal braces/brackets
     keep bracket depth > 0 across the object's own commas.
   - `_TEMPLATE_INTERP` — `` `[^`]*\$\{ `` : a backtick-delimited string containing a `${`
     interpolation.
   - `_CONCAT_INTERP` — `["'][^"'\n]*["']\s*\+\s*\w` : a quoted string literal followed by `+` and an
     identifier (concatenation with a variable). A literal-plus-literal concat (`"a" + "b"`) is NOT
     matched — same choice as the Python-side guard.
   - A finding fires when EITHER pattern matches inside the extracted first argument of ANY
     `.query()`/`.execute()` call on the line.
   - **String-literal anchor filter (#749)** — a `_CALL` match counts only if its `(` is code in the
     anchor mask (`strip_js_comments(text, strip_strings=True, keep_substitutions=True)`, tested
     with `js_anchor_is_code`). The mask blanks string content and template text but keeps `${...}`
     substitution code, so `"pool.query(...)"` in a docs or error string is dropped while
     `` `${await pool.query(...)}` `` still fires. Only the anchor is tested: both interpolation
     patterns need the quoted SQL and the `${`, so they still read the strings-intact line.
4. **Inline opt-out pragma** — `// security: allow-js-sql-injection`, checked as a whole-file
   substring match (matches `js_client_side_open_redirect.py`'s convention: presence anywhere in the
   file suppresses the whole file, not just the flagged line).
5. **Severity / rule / standards** — fires **HIGH** (mirrors `sqlalchemy-text-parameterized`'s
   severity for the same CWE-89 shape) with `rule = "js-sql-injection/interpolated-query-string"`,
   `standards = ["OWASP:A05", "CWE-89"]` (task-specified; note OWASP:A03 — Injection — is the more
   precise 2021-list category for SQLi specifically, but `OWASP:A05` is what this guard was speced
   against and is what it emits).

## When NOT to flag

- A parameterized call — a static string with `?`/`$1` placeholders and a separate values array
  (`db.query("... WHERE id = ?", [userId])`) — stays silent: the values array is a SIBLING argument,
  outside the first-arg extraction window.
- A fully static query string (`db.query("SELECT * FROM users WHERE active = true")`) — no
  interpolation pattern present, stays silent.
- A `.query()`/`.execute()` call in a file that never imports `mysql`/`mysql2`/`pg`/`pg-promise` —
  the import gate keeps this guard silent on unrelated `.query()`-named methods (ORMs, search
  clients, job queues). If a repo wraps the driver in its own `db.js` module and callers only import
  that wrapper, this guard will not see the underlying driver import in the caller's file and stays
  silent there too — see "Known bypasses".
- A reviewed case where the interpolated fragment is a trusted, server-controlled constant (never
  user input) — suppress the line/file with `// security: allow-js-sql-injection`.

## Tests

| Test | What it checks |
|---|---|
| `test_flags_template_literal_interpolation` | `` db.query(`...${userId}`) `` on a `pg`-imported file fires |
| `test_flags_string_concatenation` | `pool.query("..." + name + "...")` fires |
| `test_flags_mysql2_import` | the `mysql2` import variant also gates the guard on |
| `test_flags_sql_key_in_options_object` | `db.query({ sql: \`...${userId}\`, values: [] })` — the options-object `sql:` shape — fires |
| `test_silent_on_parameterized_query` | `db.query("... WHERE id = ?", [userId])` (FP-bait) stays silent |
| `test_silent_on_fully_static_query` | `db.query("SELECT * FROM users WHERE active = true")` (FP-bait) stays silent |
| `test_silent_without_driver_import` | `.query()` on an unrelated object (`elastic.query(...)`) with no driver import stays silent — proves the import-scoping choice |
| `test_silent_on_comment_mentioning_pattern` | a `//`-commented-out line does not fire |
| `test_pragma_suppresses` | `// security: allow-js-sql-injection` suppresses the whole file |
| `test_not_applies_without_js_or_ts` | `applies()` is `False` for a `python`-only profile |
| `test_applies_with_typescript` | `applies()` is `True` for a `typescript`-only profile |
| `test_nonproduct_path_skipped` | a finding under `examples/` is skipped via `is_nonproduct_path` |
| `test_js_sql_injection_trailing_comment_sink_silent` | an interpolated `.query()` in a trailing same-line comment does not fire (#395 H1) |
| `test_pragma_quoted_in_a_template_literal_does_not_suppress` | a template literal quoting the pragma is content, not an opt-out (#424 E4) |
| `test_silent_on_query_spelled_out_in_a_string_literal` | a template-literal and a concatenated query, each spelled out inside a string (FP-bait, #749), stay silent |
| `test_flags_query_nested_in_a_template_substitution` | a real query inside a `${...}` substitution still fires (the traded direction, #749) |
| `test_query_between_two_desyncing_substitutions_fires` | the former accepted #749 false negative, fixed by #543: a query between a `{`-regex substitution and a later `}`-regex one fires, as do one such construct alone and a query after the pair |
| `test_quoted_query_does_not_hide_a_real_one_on_the_same_line` | a quoted query and a real one on one line leave exactly the real one |

Adversarial self-test (throwaway script, run against a standalone fixture file, not part of the
committed test suite): a file with all four of the task's canonical lines — template-literal
interpolation, string concatenation, a parameterized call, and a fully static call — produced exactly
2 findings (the two injectable lines), 0 on the two safe lines.

## Known bypasses (honest limits)

- **Driver import indirection.** The import-scoping gate looks for a literal `require('pg')`/
  `import ... from 'pg'` (etc.) in the SAME file as the `.query()` call. A repo that centralizes the
  driver behind a wrapper module (`db.js` does `require('pg')` and exports a `query()` helper; every
  route file only imports `./db`) will not have the driver import visible in the route file, so this
  guard stays silent there — a false negative. This is the direct cost of the precision choice (see
  "Detection design" §2); the alternative (no import gate) trades this FN for false-positiving on
  every unrelated `.query()`-named method in the codebase, which was judged worse for signal quality.
- **Pre-built query variable.** `const q = \`SELECT ... ${x}\`; db.query(q);` on a later line is not
  traced — the interpolation and the call must be on the same physical line (same limitation as
  `sqlalchemy-text-parameterized`).
- **Multi-line call.** `db.query(\n  \`SELECT ... ${x}\`\n)` — the sink and the interpolated string
  split across lines — is not matched; detection is single-line only.
- **Non-driver-literal SQL clients.** ORMs/query-builders (Knex, Sequelize, Prisma, TypeORM) that
  wrap raw SQL in their own `.raw()`/`$queryRaw` methods are out of scope — this guard targets only
  the four literal driver packages named in its design brief.
- **Dynamic/computed method names.** `db[method](...)` or any call not spelled literally as
  `.query(`/`.execute(` in source is invisible to a regex-based guard.
- **Options-object `values` cross-talk.** Because the whole first-argument object literal (when the
  call takes an object) is scanned as one blob rather than gating strictly on the `sql:`/`text:` key,
  an (unusual) unrelated interpolated template literal elsewhere in that same options object — not in
  `sql:`/`text:` — could in principle also trigger a match. This is judged a rare shape in practice
  (a `values:` array is normally a plain array of bound values, not template literals) and is not
  covered by a dedicated test.
- **Pattern text inside a string literal: fixed in #749.** Until #749, a string that spelled out an
  interpolated query (``const doc = "pool.query(`SELECT ... ${id}`)";``) fired HIGH in any
  driver-importing file, because the scan saw string content. The call's anchor is now tested
  against the anchor mask (see Detection design), so it stays silent. One false positive remains,
  measured: text between JSX tags is not a string literal to the lexer, so a query spelled out in JSX
  character data still reads as code. Until #543, a `{` in a regex or comment inside one
  substitution and a `}` in a later one shifted the lexer's substitution frame and back, so a real
  query between the two read as template text and was dropped, where the pre-#749 guard fired. The
  lexer now consumes a substitution's regexes and comments whole, and that query fires again, pinned
  by `test_query_between_two_desyncing_substitutions_fires`.

## What this guard does NOT prove

It proves a single line contains a `.query()`/`.execute()` call on a driver-imported file whose first
argument is built by interpolation or concatenation; it does not trace dataflow, confirm the
interpolated value is actually attacker-reachable, or evaluate ORM/query-builder-level SQL
construction. Absence of a finding does not mean the app is injection-free — it means this specific,
common, literal-driver-call shape was not found. It is the fast, dep-free, high-precision static check
for the dominant JS/Node SQLi shape, and the JS-side mirror of `sqlalchemy-text-parameterized`.

# Citations

[1] agentsec checklist item `3b-sql-parameterized` (§3b)
[2] ASVS:1.2.4
[3] OWASP:A03
