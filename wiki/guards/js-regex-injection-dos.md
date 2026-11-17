---
type: Guard
title: "js-regex-injection-dos"
description: "User-controlled input used to construct a regular expression."
timestamp: "2026-10-20T16:00:00Z"
guard_id: "js-regex-injection-dos"
checklist_section: ["3a"]
standards: ["CWE-400", "OWASP:A1"]
---

# User-controlled input used to construct a regular expression

## Threat

`new RegExp(userInput)`, or `someString.search/match/split(userInput)` where
`userInput` is request-controlled, lets an attacker supply the regex *pattern*
itself, not just the string being matched. A crafted catastrophic-backtracking
pattern (e.g. `(a+)+$` against a pathological input, or simply a pattern
expensive enough on its own) can make a single request block the Node.js
event loop for seconds — a Layer-7 Denial-of-Service that starves every other
request on that process (CWE-400, OWASP-Web:A1).

This is a distinct failure mode from agentsec's existing `redos` guard: `redos`
scans **hardcoded** patterns in source for backtracking-prone shapes (the
pattern is fixed, but poorly written); this guard flags patterns that are
**attacker-supplied at runtime** — the vulnerability exists regardless of how
well-written any individual pattern might be, because the attacker chooses it.

## Why this guard fits the stack

Regex-from-user-input is a well-known, static, textual pattern in Express
route handlers — exactly the kind of check agentsec's zero-dependency guard
model is built for. The rule is adapted from njsscan's `regex_injection.yaml`
(`ajinabraham/njsscan`, real Semgrep-syntax rule `regex_injection_dos`),
verified against the actual fetched source rather than taken from a
description of it.

## Detection design

1. `applies()` gates on `"express" in profile.features`.
2. Scans all `.js`, `.jsx`, `.ts`, `.tsx` files (`iter_files`).
3. Skips a file entirely if the pragma comment is present anywhere in it (a string literal quoting it
   does not count, #424); skips
   an individual line if the pragma is on that same line.
4. First pass over the whole file: collect every local variable assigned from
   an expression containing `req.<prop>` (`const`/`let`/`var NAME = ...req.foo...;`)
   — this is the "assign-then-use" half of njsscan's rule, adapted from AST
   dataflow to a same-file regex scan.
5. Second pass, line by line: for each `new RegExp(...)` or
   `.search/.match/.split(...)` sink call, the captured argument fires if
   either:
   - it directly contains `req.<prop>` (the "used inline" half of njsscan's
     rule), or
   - it is a bare identifier that appears in the tainted-variable set from
     step 4 (the "assign-then-use" half).

### Regexes used

```python
_REQ_TAINT = re.compile(r"\breq\.\w")
_NEW_REGEXP = re.compile(r"new\s+RegExp\s*\(([^)]{0,300})\)")
_STRING_METHOD_SINK = re.compile(r"\.(?:search|match|split)\s*\(([^)]{0,300})\)")
_ASSIGN_FROM_REQ = re.compile(r"\b(?:const|let|var)\s+(\w+)\s*=[^;\n]*\breq\.\w[^;\n]*;?")
```

The trailing `;` on `_ASSIGN_FROM_REQ` is **optional** (#422). Requiring it meant that in
semicolon-free (ASI) style — the norm in a great deal of modern JS/TS — the variable was never
marked request-tainted, so every downstream regex sink fed by it went unreported. Nothing is given
up by dropping the requirement: the `[^;\n]*` classes already stop the expression at the line
boundary, so the match cannot run past the statement either way.

Both sink families (RegExp construction and the three string methods) map to
the same rule slug (`user-controlled-regex-sink`), mirroring njsscan's own
single-rule-id design (`regex_injection_dos` covers all these shapes as one
rule, not several).

## Severity rationale

**HIGH.** Unlike a hardcoded vulnerable pattern (which requires the app's own
author to have written something exploitable), here the attacker fully
controls the pattern — the vulnerability is present the moment unvalidated
input reaches any of these sinks, with no additional precondition.

## When NOT to flag

A sink call whose argument is a string/regex literal, or a variable that was
never assigned from `req.*` anywhere in the file, never matches — the guard
only fires on a demonstrable path from request input to a regex-construction
or regex-method-argument position.

## Known bypasses / false negatives

| Bypass | Description |
|--------|-------------|
| Multi-hop assignment | `const a = req.query.x; const b = a; new RegExp(b);` — the guard only tracks one level of `req.*`-direct assignment; a second intermediate variable (`b` assigned from `a`, not from `req.*` directly) breaks the chain. |
| Cross-file taint | Request input extracted in one file (e.g. a middleware), passed as a function argument to a handler in another file that calls the sink — the guard is file-scoped and won't join them. |
| Object/array destructuring | `const { pattern } = req.query; new RegExp(pattern);` — the assign-from-req regex expects a direct `= ...req.*...` expression, not a destructuring pattern binding a new name. |
| Concatenation/template literals | `new RegExp('^' + req.query.x + '$')` — the guard's `_REQ_TAINT` check searches the whole captured argument text for `req.`, so this direct-inline case is actually caught; only the assign-then-use half has the multi-hop/destructuring gaps above. |

## What this guard does NOT prove

A silent guard does not prove the app validates or sanitizes regex input
anywhere else in its dependency graph (e.g. a shared validation middleware
applied globally) — it only proves that, within a single file, no local
`req.*`-derived value (direct or one-hop-assigned) reaches one of these 4
sink shapes.

## False positive scenarios

| Scenario | Why it fires | Mitigation |
|----------|-------------|------------|
| Input is already validated/allowlisted before the sink | The guard has no way to recognize a preceding validation check (e.g. a regex-safe-charset allowlist) as sufficient — it only sees that request input reaches the sink. | Add a `// security: allow-js-regex-injection-dos` comment after confirming the validation genuinely constrains the input to a safe character set. |
| The substring `req.` appears only inside a **comment or string literal** (e.g. `const s = 'req.count: total'`) | No longer fires — the taint match runs on a comment- AND string-blanked copy of the source (PR #407 review). | n/a (fixed). |
| A real `req` local variable unrelated to the Express request object | An actual identifier `req` with a `.` member access still matches (it is real code, not a string) — the file-scoped, no-type-info tradeoff every JS/TS guard here accepts. | Rename the unrelated variable, or add the pragma. |

## Checklist items flipped

| ID | Before | After | Reason |
|----|--------|-------|--------|
| `3a-no-regex-injection` | (new item) | `covered` | Guard statically detects request input reaching a regex-construction or regex-method sink in Express apps; fires HIGH; silenceable per-file/per-line. Distinct from `3a-no-redos` (hardcoded vulnerable pattern, Python-only) — this is attacker-supplied pattern content. |

## Tests

| Test | Validates |
|------|-----------|
| `test_js_regex_injection_dos_flags_direct_new_regexp` | True positive: `new RegExp(req.query.pattern)` fires. |
| `test_js_regex_injection_dos_flags_indirect_via_variable` | True positive: `const term = req.body.term; someString.search(term);` fires via the assign-then-use path. |
| `test_js_regex_injection_dos_flags_direct_match` | True positive: `data.match(req.params.x)` fires. |
| `test_js_regex_injection_dos_silent_with_literal_pattern` | False positive guard: a literal regex and a literal-string `.split(',')` — no finding. |
| `test_js_regex_injection_dos_silent_when_tainted_var_never_reaches_sink` | False positive guard: a variable assigned from `req.*` that's only logged, never passed to a sink — no finding. |
| `test_js_regex_injection_dos_pragma_silences` | Pragma: inline suppress comment silences the finding. |
| `test_js_regex_injection_dos_not_applies_without_feature` | Feature gate: `applies()` is `False` when `"express"` is not in `profile.features`. |
| `test_commented_sink_after_a_brace_in_a_substitution_regex_stays_silent` | #543 FP direction: a commented-out sink after a `{` in a regex inside a `${…}` stays silent. |
| `test_sink_between_two_brace_regex_substitutions_fires` | #543 FN direction: a sink between a `/{/` substitution and a later `/}/` one fires. |

# Citations

[1] agentsec checklist item `3a-no-regex-injection` (§3a)
[2] CWE-400
[3] OWASP:A1
