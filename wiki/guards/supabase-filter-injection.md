---
type: Guard
title: "supabase-filter-injection"
description: "Unparameterized Supabase/PostgREST filter built from untrusted input."
timestamp: "2026-08-28T00:00:00Z"
guard_id: "supabase-filter-injection"
checklist_section: ["3b"]
standards: ["OWASP:A03", "OWASP-LLM:LLM08"]
---

# Unparameterized Supabase/PostgREST filter built from untrusted input

_Author — 2026-08-28, NotebookLM security-news sweep NS-14_

---

## The threat

**CVE-2026-77071** (n8n's Supabase node, Row Get Many / Delete / Update operations): filter
queries were built by concatenating an expression-bindable value directly into the PostgREST
filter STRING, without escaping. An attacker who controls that value can inject a condition that
widens the filter to match every row — turning an intended single-row operation into full-table
disclosure, deletion, or modification.

This is a DISTINCT injection sink from raw SQL. Every existing SQL-injection guard in this
codebase (`semgrep`'s rules, `js-sql-injection`, `go-sql-injection`) targets literal SQL text or
the Mongo-operator DSL. Supabase-py's own filter-builder methods — a Python/postgrest-py client
wrapping PostgREST's own mini filter-language — are a third, unrelated DSL nothing here already
covered (confirmed by reading every SQL-injection-adjacent guard before building this).

## Why this guard fits the stack

Supabase apps in this project's target stack routinely call `supabase.table(...).select(...)`
chains directly from FastAPI route handlers. `.or_()` is the documented way to express a combined
OR condition, and its API is a single raw filter-string argument — there is no safe multi-argument
form for it at all, unlike every per-column method (`.eq(`/`.gt(`/`.in_(`, etc.), which take the
value as a SEPARATE argument that never enters PostgREST's filter-string parser.

## Detection design

AST-based (`ast.Call`/`ast.JoinedStr`/`ast.BinOp` via `safe_ast_parse`, not text matching),
whole-file — no route-scoping needed, since the sink is unconditionally unsafe wherever it's
built this way, regardless of which function it's called from:

1. **`applies()` gate** — `"python" in profile.features`.
2. A call to `.or_(` or single-argument `.filter(` (the 2-3 argument `.filter(column, operator,
   value)` form is inherently safe — the value is separate — and is excluded by an arg-count
   check) whose sole argument is `_is_untrusted_string_build`:
   - an f-string (`ast.JoinedStr`) with any `ast.FormattedValue` — an interpolated value;
   - a `+`/`%` concatenation/formatting (`ast.BinOp`) where at least one operand isn't a plain
     `ast.Constant`;
   - a `"...".format(...)` call on a string constant.
3. **Finding** — **critical** (the same severity class as `3b-sql-parameterized`: a successful
   injection here reaches the exact same PostgREST-fronted table, with the exact same full-table
   blast radius), rule `supabase-filter-injection/unparameterized-filter`, standards
   `["OWASP:A03", "OWASP-LLM:LLM08"]`.

## When NOT to flag

- **A static string literal** — `.or_("status.eq.active,status.eq.pending")` has no untrusted
  input at all; it cannot be injected into regardless of its content.
- **The parameterized per-column methods** — `.eq(`/`.neq(`/`.gt(`/`.lt(`/`.like(`/`.ilike(`/
  `.is_(`/`.in_(` all take the value as a separate argument and are never flagged, even when
  that argument is built from an f-string (the string interpolation there produces the VALUE,
  not a filter EXPRESSION — PostgREST never re-parses it as filter syntax).
- **The safe 3-argument `.filter(column, operator, value)` form.**
- **Suppress** an audited case with `# security: allow-supabase-filter-concat`.

## Tests

| Test | What it checks |
|---|---|
| `test_supabase_filter_injection_fstring_or_fires` | CVE-2026-77071's shape: `.or_(f'id.eq.{order_id}...')` → CRITICAL |
| `test_supabase_filter_injection_concat_or_fires` | `+`-concatenation into `.or_(` |
| `test_supabase_filter_injection_format_call_fires` | `"...".format(...)` into `.or_(` |
| `test_supabase_filter_injection_percent_format_fires` | `%`-formatting into `.or_(` |
| `test_supabase_filter_injection_single_arg_filter_fires` | the rarer single-argument `.filter(f'...')` form |
| `test_supabase_filter_injection_static_literal_stays_silent` | a static, non-injectable `.or_()` literal → silent |
| `test_supabase_filter_injection_parameterized_eq_stays_silent` | the safe `.eq(column, value)` form → silent |
| `test_supabase_filter_injection_three_arg_filter_stays_silent` | the safe 3-argument `.filter(column, operator, value)` form → silent |
| `test_supabase_filter_injection_any_or_method_fires_disclosed_scope` | pins the disclosed over-approximation: any `.or_(<f-string>)` fires, not only a provable Supabase chain |
| `test_supabase_filter_injection_pragma_opt_out` | `# security: allow-supabase-filter-concat` → silent |
| `test_supabase_filter_injection_not_applicable_without_python` | `applies()` False without `python` |

## Known bypasses

- **No chain-provenance check (deliberate over-approximation).** The guard matches ANY
  `.or_(...)`/single-argument `.filter(...)` call with the unsafe shape — it does not verify the
  receiver is provably a Supabase query builder (e.g. via a `.table(...)` call earlier in the
  chain). Narrowing to a provable chain would also narrow away real Supabase calls built across
  multiple statements or a helper function (`qb = supabase.table(...); qb.or_(...)` on a later
  line) — a false-negative risk judged worse than the false-positive risk of an unrelated
  `.or_()`-named method with the exact same "raw string built from untrusted input" shape. Pinned
  by `test_supabase_filter_injection_any_or_method_fires_disclosed_scope`.
- **Indirect construction** — a filter string assembled across several statements and passed in
  via a variable (`raw = f"id.eq.{x}"`; `... .or_(raw)`) is not traced; only the argument
  expression AT the call site is inspected.
- **Non-f-string interpolation this guard doesn't model** — `str.join(...)`,
  `"".__mod__(...)`, or a template-engine render are not recognized as untrusted-string-building
  shapes.

## What this guard does NOT prove

That the interpolated value is actually attacker-controlled in production (it could be a
hardcoded internal constant assembled via string formatting for readability, not user input) —
the guard flags the STRUCTURAL shape (a raw filter string NOT built from a literal), not a
confirmed taint path from an HTTP request to the filter argument.

# Citations

[1] agentsec checklist item `3b-supabase-filter-parameterized` (§3b)
[2] OWASP:A03
[3] OWASP-LLM:LLM08
[4] CVE-2026-77071 (n8n Supabase node)
