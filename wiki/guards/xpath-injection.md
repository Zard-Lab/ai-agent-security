---
type: Guard
title: "xpath-injection"
description: "XPath expression built from untrusted input."
timestamp: "2026-07-11T20:22:28+08:00"
guard_id: "xpath-injection"
checklist_section: ["3b"]
standards: ["OWASP:A03"]
---

# XPath expression built from untrusted input

_Marconi (research-cycle: codeql-security-queries) — 2026-07-11_

---

## The threat

An XPath evaluation call — the `xpath`/`xpath.js` npm packages' `.parse()`/`.select()`/
`.select1()`, or the DOM's `document.evaluate()`/`.createExpression()` — whose expression argument
is built from untrusted input lets an attacker alter which nodes the query matches, or inject
boolean/union-based XPath logic to read data outside the intended scope. The XML analogue of SQL
injection. CWE-643. OWASP A03:2021 — Injection.

## Why this guard fits the stack

Mined from CodeQL's `javascript/ql/src/Security/CWE-643/XpathInjection.ql`, verified against the
real `XpathInjectionCustomizations.qll`: two sink families — the `xpath`/`xpath.js` package's
`parse`/`select`/`select1`/`useNamespaces` first argument, and the DOM's `document.evaluate`/
`.createExpression` first argument, with `location.hash`/`location.search` explicitly modeled as a
source for the DOM variant (`DocumentUrlSource`).

**Corpus-prevalence note, said plainly:** same caveat as `ldap-injection`, its paired candidate
from this research pass — XPath/XML processing is a niche pattern for this stack, flagged
low-priority at the human gate and approved anyway because the detection is clean.

## Detection design

1. `applies()` gates on `"frontend" in profile.features` — matches the other JS/TS guards
   (`js-prototype-pollution`, `jsx-href-scheme`).
2. Scans `.js`/`.jsx`/`.ts`/`.tsx` files via `iter_files`.
3. `_XPATH_CALL` matches `xpath.(parse|select|select1|useNamespaces)(` (assuming the common
   `xpath` import alias) or `document.(evaluate|createExpression)(`.
4. `_DYNAMIC_OR_TAINTED_ARG` fires on a template literal WITH an interpolation (`` `...${x}...` ``,
   not a plain static template literal), string concatenation, or a direct `location.hash`/
   `location.search` reference — matching the real DOM source CodeQL models explicitly.
5. Severity MEDIUM (`standards=["OWASP:A03"]`). Suppress with a `// security: allow-xpath-injection`
   comment (a string literal quoting the phrase does not count, #424).

## When NOT to flag

- A static expression (`xpath.select('//item[@id="fixed"]', doc)`) — no interpolation/concat/
  location reference, silent.
- A plain template literal with no `${...}` interpolation — same as a static string.

## Tests

| Test | What it checks |
|---|---|
| `test_flags_template_literal_interpolation` | `` xpath.select(`//item[@id="${userTag}"]`) `` → MEDIUM |
| `test_flags_concatenation` | `xpath.select1('...' + userTag + '...')` → fires |
| `test_flags_dom_evaluate_from_location` | `document.evaluate` with `location.hash` → fires |
| `test_silent_on_static_expression` | Static literal expression → silent |
| `test_pragma_suppresses` | `// security: allow-xpath-injection` → silent |
| `test_prose_mention_does_not_suppress` | The phrase quoted in a string without its `//` → still fires |
| `test_prose_mention_with_the_comment_marker_does_not_suppress` | The documented `// security: …` form quoted in a string → still fires (#424: a pragma counts only as a comment) |
| `test_not_applicable_without_frontend` | `applies()` returns False without `frontend` |

## Known bypasses (honest limits)

- **No interprocedural tracking**, same class of limitation as `js-prototype-pollution` and every
  regex-based guard in this codebase: `const expr = \`//item[@id="${userTag}"]\`;` on one line,
  then `xpath.select(expr, doc)` on the next, is NOT flagged — verified during this guard's own
  adversarial self-test as a deliberate, accepted bypass case, not a silent gap.
- Assumes the `xpath` import is aliased as `xpath` (the overwhelmingly common convention); an
  unusual alias would evade the package-sink check (the DOM sink has no such assumption).
- Other DOM taint sources beyond `location.hash`/`location.search` (e.g. `document.referrer`,
  `postMessage` data) are not recognized for the DOM sink — scoped to what CodeQL's own query
  explicitly models.

## What this guard does NOT prove

It flags a plausible same-line sink reachable from a same-line dynamic-construction or
known-tainted-source pattern; it does not prove the input is actually attacker-reachable, nor that
no XPath injection exists via a longer call chain or an XML/XPath library this guard doesn't
recognize.

# Citations

[1] agentsec checklist item `3b-xpath-injection` (§3b)
[2] OWASP:A03
