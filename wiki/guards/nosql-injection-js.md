---
type: Guard
title: "nosql-injection-js"
description: "NoSQL query filter built from unvalidated request input (Node/Mongoose)."
timestamp: "2026-10-20T12:00:00Z"
guard_id: "nosql-injection-js"
checklist_section: ["3b"]
standards: ["OWASP:A03", "CWE-943"]
---

# NoSQL query filter built from unvalidated request input (Node/Mongoose)

Flags a MongoDB/Mongoose query filter (`.find()`/`.findOne()`/`.updateOne()`/etc.) whose value is a
direct, unvalidated Express request-input reference (`req.body.x`/`req.query.x`/`req.params.x`) —
the JS/Node counterpart to agentsec's existing (Python-only) `nosql-metadata-injection` guard.
CWE-943, OWASP:A03.

_Author — 2026-08-29_

---

## The threat

Node's JSON body parser (`express.json()`, and DDP/WebSocket-style message parsers alike) accepts
arbitrary nested types for any field — a client can submit `{"username": {"$regex": ".*"}}` just as
easily as `{"username": "alice"}`. If a query filter passes that value straight through —

```js
Users.findOne({ username: req.body.username });
```

— Mongo receives the attacker's object as the filter VALUE and interprets its `$regex` key as a
live query operator. The app's own source never wrote `$regex` anywhere; the vulnerability is the
missing type check, not a literal operator string in code. This is a type-confusion NoSQL injection
(CWE-943), and per the confirmed real-world case below it is an authentication-bypass primitive, not
a lesser info leak: a login lookup that matches on `{ username: <attacker object> }` can be made to
match every row, or a `$where` value in an object can run attacker JavaScript on the database.

**Confirmed real-world instance**: Rocket.Chat CVE-2026-30833 (GHSL advisory, `ddp-streamer`
service), verified against the published advisory and fix — a login-flow query passed unsanitized
username input directly into a MongoDB filter, letting `$regex`/similar operators bypass or widen
the intended match. Fixed in Rocket.Chat 7.10.8/7.11.5/7.12.5/7.13.4/8.0.2/8.1.1/8.2.0.

## Why this guard fits the stack

Before this guard, agentsec's only NoSQL-injection coverage was `nosql-metadata-injection`
(Python-only, pymongo/motor), which targets a DIFFERENT shape: a developer who wrote a literal
`$where`/`$regex`/etc. key with a dynamically-built value. A JS/Node backend or BFF layer using
Mongoose/the native MongoDB driver — a real, detected `javascript`/`typescript` stack in agentsec's
target range — had zero coverage for the type-confusion shape, which per the CVE above is the more
common and more severe real-world manifestation. Extends the existing `3b-nosql-injection` checklist
item (adds `javascript`/`typescript` to `applies_when`) rather than creating a new item, mirroring
how `js-command-injection` extended `3b-command-injection` and `js-sql-injection` extended
`3b-sql-parameterized` — same requirement, a genuinely different code surface.

## Detection design

1. **`applies()` gate** — `"javascript" in profile.features or "typescript" in profile.features`
   (same convention as every other JS-scoped guard).
2. **Files scanned** — `.js`/`.jsx`/`.ts`/`.tsx` via `iter_files`, skipping non-product paths.
   **Import-scoped**: a file is only scanned once it `require()`s or `import`s `mongoose` or
   `mongodb` (`_DRIVER_IMPORT`) — mirrors `js_sql_injection.py`'s identical driver-import gate for
   the identical reason: `.find()`/`.update()` are common method names on unrelated objects (a
   search client, a cache, an ORM query builder), and without the gate this guard would
   false-positive on those.
3. **Patterns**:
   - `_CALL` — a member call to one of `find`/`findOne`/`findOneAndUpdate`/`findOneAndDelete`/
     `updateOne`/`updateMany`/`deleteOne`/`deleteMany`/`countDocuments`.
   - `_first_arg()` — a bracket- and quote-aware extractor (ported from `js_sql_injection.py`'s
     identical helper) that returns only the call's own first positional argument (the filter
     object), so a separate update/options argument never leaks into the check.
   - `_RAW_REQ_INPUT` — `req.body.x`/`req.query.x`/`req.params.x` (dotted or bracket form) anywhere
     inside the extracted filter argument.
   - `_SAFE_CAST` — a type-coercing call (`String(`/`Number(`/`Boolean(`) or a sanitizer
     (`mongoSanitize(`/`sanitize(`/`escape(`) immediately wrapping the matched request-input
     reference. Checked against the text immediately preceding each match, so an unrelated cast on
     a DIFFERENT key in the same filter object does not clear this one — mirrors
     `nosql_metadata_injection.py`'s own per-operator, not per-line, precision.
   - A finding fires when the filter argument contains a raw request-input reference not preceded
     by one of the safe-cast/sanitizer calls.
   - **String-literal anchor filter (#749)** — `_CALL` matches on the comment-stripped text, and a
     match is kept only if its `(` is code in the anchor mask
     (`strip_js_comments(text, strip_strings=True, keep_substitutions=True)`, tested with
     `js_anchor_is_code`). That mask blanks string content and template text but keeps `${...}`
     substitution code, so a lookup spelled out in a docs string or an error message is dropped
     while a real one nested in a substitution still fires. The filter argument is still read from
     the strings-intact line, so the bracket form `req.body['x']` and a `$where` template keep the
     quoted text they need.
4. **Inline opt-out pragma** — `// security: allow-js-nosql-injection`, checked as a whole-file
   substring match.
5. **Severity / rule / standards** — fires **CRITICAL** (matches the real-world impact — the
   confirmed CVE was an authentication-bypass/data-exfiltration primitive, not a lesser info leak)
   with `rule = "nosql-injection-js/unvalidated-filter-value"`, `standards = ["OWASP:A03",
   "CWE-943"]`.

## When NOT to flag

- A filter value cast to a plain type before use — `String(req.body.username)`,
  `Number(req.query.id)` — stays silent: a value that cannot be an object can no longer carry a
  nested `$operator`.
- A filter value passed through a sanitizer (`mongoSanitize(req.body.username)`) stays silent.
- A fully static/literal filter value (`{ role: 'admin' }`) — no request-input reference present,
  stays silent.
- A `.find()`/`.findOne()`/etc. call in a file that never imports `mongoose`/`mongodb` — the import
  gate keeps this guard silent on unrelated same-named methods.
- A reviewed case (a value already validated upstream, or a deliberately permissive admin-only
  query) — suppress the line with `// security: allow-js-nosql-injection`.

## Tests

| Test | What it checks |
|---|---|
| `test_flags_raw_request_body_in_find_one` | `Users.findOne({ username: req.body.username })` on a `mongoose`-imported file fires |
| `test_flags_raw_request_query_in_update_one` | `collection.updateOne({ id: req.query.id }, ...)` on a `mongodb`-imported file fires |
| `test_flags_bracket_form_request_input` | `req.body['username']` (bracket form) fires |
| `test_silent_on_string_cast` | `String(req.body.username)` (FP-bait) stays silent |
| `test_silent_on_sanitizer_call` | `mongoSanitize(req.body.username)` (FP-bait) stays silent |
| `test_silent_on_static_literal_filter` | `{ role: 'admin' }` (FP-bait) stays silent |
| `test_silent_without_driver_import` | `.findOne()` on an unrelated object with no driver import stays silent — proves the import-scoping choice |
| `test_silent_on_comment_mentioning_pattern` | a `//`-commented-out line does not fire |
| `test_pragma_suppresses` | `// security: allow-js-nosql-injection` suppresses the whole file |
| `test_not_applies_without_js_or_ts` | `applies()` is `False` for a `python`-only profile |
| `test_applies_with_typescript` | `applies()` is `True` for a `typescript`-only profile |
| `test_nonproduct_path_skipped` | a finding under `examples/` is skipped via `is_nonproduct_path` |
| `test_silent_on_filter_spelled_out_in_a_string_literal` | a docs string and an error-message template that spell out the vulnerable lookup (FP-bait, #749) stay silent |
| `test_flags_filter_nested_in_a_template_substitution` | a real lookup inside a `${...}` substitution still fires (the traded direction, #749) |
| `test_filter_between_two_desyncing_substitutions_fires` | the former accepted #749 false negative, fixed by #543: a lookup between a `{`-regex substitution and a later `}`-regex one fires, as do one such construct alone and a lookup after the pair |
| `test_flags_where_template_holding_request_input` | request input in a `$where` template still fires: only the anchor is masked, not the argument |
| `test_quoted_filter_does_not_hide_a_real_one_on_the_same_line` | a quoted lookup and a real one on one line leave exactly the real one |

## Known bypasses (honest limits)

- **Receiver-level dataflow.** The import gate scopes to which driver/ODM the FILE imports, not to
  which specific identifier is the actual Mongoose model — a file that imports `mongoose` and
  separately calls an unrelated object's own `.find()`/`.update()` with raw request input can still
  false-positive. This is the same trade-off `js_sql_injection.py` makes for the identical reason.
- **Pre-built filter variable.** `const filter = { username: req.body.username }; Users.findOne(filter);`
  on a later line is not traced — the request-input reference and the call must be on the same
  physical line.
- **Destructured/aliased request field.** The same-physical-line rule above also covers the most
  idiomatic Express shape there is: `const { username } = req.body; Users.findOne({ username });`
  is SILENT, because the `req.body` reference and the call sit on different lines. This is the
  identical vulnerability to this guard's own canary plant, so it is worth naming explicitly rather
  than leaving implied by the general rule — the shorthand-property form carries no `req.` token at
  the call site at all.
- **Multi-line call.** A filter object literal split across multiple lines is not matched; detection
  is single-line only.
- **Indirect validation.** A `typeof req.body.username === 'string'` guard on an earlier line, with
  no cast at the call site itself, is not recognized — only a cast/sanitizer call directly wrapping
  the reference clears the finding.
- **Non-Express request objects.** The `req.body`/`req.query`/`req.params` shape is Express's own
  convention; a different framework's request-input accessor (Koa's `ctx.request.body`, Fastify's
  `request.body`, GraphQL resolver args) is not recognized.
- **Pattern text inside a string literal: fixed in #749.** A quoted example such as
  `const doc = "Users.findOne({ username: req.body.username })";` used to fire CRITICAL, because the
  scan saw string content. The call's anchor is now tested against the anchor mask (see Detection
  design), so it stays silent. Two false positives remain, both measured:
  - **A quoted request-input value inside a REAL filter.** `Users.findOne({ note: "see req.body.x" })`
    still fires, because the argument check deliberately reads string content (the bracket form
    needs it).
  - **JSX character data.** Text between JSX tags (`<code>Users.findOne(...)</code>`) is not a
    string literal to the lexer, so a lookup spelled out there still reads as code.

  Until #543, a `{` in a regex or comment inside one substitution and a `}` in a later one shifted
  the lexer's substitution frame and back, so a real lookup between the two read as template text
  and was dropped, where the pre-#749 guard fired. The lexer now consumes a substitution's regexes
  and comments whole, and that lookup fires again, pinned by
  `test_filter_between_two_desyncing_substitutions_fires`.

## What this guard does NOT prove

It proves a single line contains a Mongo/Mongoose filter-building call on a driver-imported file
whose filter argument contains a raw, unguarded request-input reference; it does not trace dataflow
across variables, confirm the value is actually attacker-reachable end-to-end, or evaluate
GraphQL/non-Express request shapes. Absence of a finding does not mean the app is injection-free —
it means this specific, common, literal-call shape was not found.

# Citations

[1] agentsec checklist item `3b-nosql-injection` (§3b)
[2] GHSL advisory for CVE-2026-30833 (Rocket.Chat `ddp-streamer`)
[3] OWASP:A03
