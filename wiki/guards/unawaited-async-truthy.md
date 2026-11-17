---
type: Guard
title: "unawaited-async-truthy"
description: "No unawaited async function call used as a truthy conditional (if/while)."
timestamp: "2026-10-20T12:00:00Z"
guard_id: "unawaited-async-truthy"
checklist_section: ["8"]
standards: ["OWASP:A04", "CWE-252"]
---

# Unawaited async function call used as a truthy conditional

Flags an `if (...)`/`while (...)` condition that calls a locally-declared `async` function without
`await` — since a Promise object is always truthy, the branch always takes the truthy path
regardless of the call's real result. CWE-252 (Unchecked Return Value), OWASP:A04.

_Author — 2026-08-29_

---

## The threat

An `async function` always returns a Promise, even for a same-tick `return true`/`return false`
body. A Promise object is truthy in JavaScript regardless of what it will eventually resolve to —
so calling an async function directly inside `if (...)`/`while (...)` without `await` makes the
branch ALWAYS take the truthy path:

```js
async function validatePassword(pw) {
  return pw === getStoredHash();
}

if (validatePassword(req.body.password)) {   // always true — this is a Promise, not a boolean
  grantAccess();
}
```

The call's real result — and any rejection it might throw — is silently discarded. When the
condition guards a security-relevant check (an auth check, an authorization check, a rate-limit
check), this is a full bypass: the branch behaves as if the check always passed.

**Confirmed real-world instance**: Rocket.Chat CVE-2026-28514 (GHSL advisory, `ddp-streamer`
service), verified against the published advisory and fix — an `async function validatePassword`
was called as `if (validatePassword(password))` with no `await`, so login succeeded regardless of
whether the submitted password was actually correct. Fixed alongside CVE-2026-30833 in Rocket.Chat
7.8.6/7.9.8/7.10.7/7.11.4/7.12.4/7.13.3/8.0.0.

## Why this guard fits the stack

This is a general JS/TS control-flow bug class, not specific to password checks or any particular
framework — any codebase with `async`/`await` (which is to say, essentially every modern Node/React
codebase) can introduce it. No existing agentsec guard checked unawaited-Promise-as-truthy before
this one; it is a genuinely new sink class with no close sibling to extend. A static analyzer cannot
tell whether a given instance guards something security-relevant or an inconsequential branch —
but the fix is identical either way (add `await`), and the confirmed real-world instance was a full
authentication bypass, so this guard grades every instance CRITICAL rather than trying to guess
severity from context.

## Detection design

1. **`applies()` gate** — `"javascript" in profile.features or "typescript" in profile.features`.
2. **Files scanned** — `.js`/`.jsx`/`.ts`/`.tsx` via `iter_files`, skipping non-product paths.
   The whole scan below reads the anchor mask (#749),
   `strip_js_comments(text, strip_strings=True, keep_substitutions=True)`: comments, string content
   and template text are blank, while `${...}` substitution code is kept. None of this guard's
   patterns needs string content, so text that only spells out a declaration, a condition or a
   call cannot fire, and a real call nested in a substitution still can.
3. **Declaration resolution (`_local_async_names`)** — collects the set of locally-declared async
   function names from the whole file, across the 3 syntactic shapes:
   - `async function name(...)` — a named function declaration.
   - `const/let/var name = async (...) => ...` or `= async function ...` — an arrow/function-expression
     assignment.
   - `async name(...) { ... }` (no `function` keyword, no receiver `.` immediately before `async`)
     — a class/object method shorthand.
4. **Condition extraction (`_balanced_paren_span`)** — a bracket- and quote-aware extractor
   (structurally the same shape as `js_sql_injection.py`'s/`nosql_injection_js.py`'s first-argument
   extractors) that returns the full text between an `if (`/`while (`'s opening paren and its
   matching close, so a nested call inside the condition doesn't end the span early.
5. **Unawaited-call check (`_unawaited_calls_in_condition`)** — within the extracted condition,
   finds every FREE call (`(?<![.\w$])name(` — not preceded by `.`, so a member call like
   `auth.validatePassword(...)` is excluded, see "Known bypasses") to one of the file's known async
   names, and checks whether the text immediately before that call ends with `await`. A finding
   fires when at least one such call is unawaited.
6. **Inline opt-out pragma** — `// security: allow-unawaited-async-truthy`, checked as a whole-file
   marker before the line scan: the pragma anywhere in a file silences the guard for that ENTIRE
   file, not just the annotated line (the same convention as `js_sql_injection.py`,
   `js_command_injection.py` and `nosql_injection_js.py`).
7. **Severity / rule / standards** — fires **CRITICAL** unconditionally (see "Why this guard fits
   the stack" for why there is no lower-severity case to grade down to) with
   `rule = "unawaited-async-truthy/unawaited-call"`, `standards = ["OWASP:A04", "CWE-252"]`.

## When NOT to flag

- `if (await validatePassword(pw))` — the call is properly awaited, stays silent.
- `if (isValid(pw))` where `isValid` is an ordinary (non-`async`) function — only calls to
  LOCALLY-DECLARED async names are tracked; a plain sync function call in a conditional is entirely
  ordinary code.
- `auth.validatePassword(pw)` — a member call on a receiver, even when `validatePassword` was
  declared via method shorthand and is a known async name; see "Known bypasses".
- A commented-out line, or a trailing `//` comment mentioning the pattern, stays silent.
- A reviewed "fire and forget" call genuinely meant to run without awaiting its result — suppress
  with `// security: allow-unawaited-async-truthy`. Note the scope: that pragma silences the guard
  for the WHOLE file, so prefer `await`-ing (or `void`-ing) the call when the rest of the file still
  needs cover.

## Tests

| Test | What it checks |
|---|---|
| `test_flags_unawaited_call_from_function_declaration` | `async function validatePassword` called unawaited in `if (...)` fires |
| `test_flags_unawaited_call_from_arrow_assignment` | the `const name = async (...) => ...` declaration shape fires the same way |
| `test_flags_unawaited_call_in_while` | the identical bug inside `while (...)` fires |
| `test_silent_when_awaited` | `if (await validatePassword(...))` (FP-bait) stays silent |
| `test_silent_on_sync_function_call` | a call to a plain non-async function in `if (...)` (FP-bait) stays silent |
| `test_silent_on_member_call_to_declared_async_name` | `auth.validatePassword(pw)` — a member call, not a free call (FP-bait) — stays silent, proving the free-call-only precision is intentional |
| `test_silent_on_comment_mentioning_pattern` | a `//`-commented-out line does not fire |
| `test_pragma_suppresses` | `// security: allow-unawaited-async-truthy` silences the file |
| `test_pragma_scope_is_the_whole_file_not_the_annotated_line` | two findings, only the first annotated — BOTH go silent, proving the pragma is a whole-file marker (the single-finding test above passes under either scope, so it cannot show this) |
| `test_not_applies_without_js_or_ts` | `applies()` is `False` for a `python`-only profile |
| `test_applies_with_typescript` | `applies()` is `True` for a `typescript`-only profile |
| `test_nonproduct_path_skipped` | a finding under `examples/` is skipped via `is_nonproduct_path` |
| `test_silent_on_pattern_inside_a_string_literal` | a docs string spelling out the unawaited call, next to the real async declaration (FP-bait, #749), stays silent |
| `test_silent_when_async_declaration_exists_only_inside_a_string` | an `async function` spelled out in a string does not make a same-named sync function count as async |
| `test_silent_on_async_name_inside_a_string_argument` | `if (log("isAdmin(u)"))`, where the async name is only quoted text, stays silent |
| `test_flags_unawaited_call_nested_in_a_template_substitution` | ``if (`${isAdmin(u)}`)`` still fires (the traded direction, #749) |
| `test_condition_between_two_desyncing_substitutions_fires` | the former accepted #749 false negative, fixed by #543: a condition between a `{`-regex substitution and a later `}`-regex one fires, as do one such construct alone and a condition after the pair |
| `test_quoted_condition_no_longer_hides_a_real_one_later_on_the_line` | a quoted `if (` before a real unawaited condition on the same line no longer masks it (a fixed false negative) |
| `test_quoted_condition_then_awaited_call_stays_silent` | the same line with `await` stays silent (FP-bait for that widening) |

## Known bypasses (honest limits)

- **Single-file scoping.** The async function must be declared and called in the SAME file — an
  async function imported from another module and called unawaited is a real but rarer shape; a
  cross-file resolver would need the same import-binding-resolution machinery
  `js_command_injection.py` built for `child_process` bindings, and the in-file case already covers
  the confirmed CVE's shape.
- **Free calls only.** A class/object-method-shorthand declaration is collected as a known async
  name, but a call to it on its OWN receiver (`obj.name(...)`) is a member call and is not tracked
  — resolving which receiver's method it is would need the same binding-resolution machinery as
  the single-file limitation above, not a name-only lookup.
- **`if`/`while` conditions only.** A ternary (`cond ? a : b`) or a bare `&&`/`||` logical operand
  referencing an unawaited async call is a real but much rarer manifestation of the identical bug;
  it is not tracked, since the bracket-aware condition extraction this guard relies on is anchored
  on `if`/`while`'s own parentheses.
- **Multi-line conditions.** A condition whose async call spans multiple physical lines is not
  matched; detection is single-line only (per-line iteration, one balanced-paren extraction per
  matched `if`/`while` on that line).
- **Reassignment/shadowing.** A local variable that shadows an outer async function's name with a
  non-async value is not distinguished — the name-based resolver has no scope awareness.
- **Pattern text inside a string literal: fixed in #749.** Three false positives and one false
  negative shared this cause, because the scan used to see string content:
  - A quoted example such as `const doc = "if (validatePassword(pw)) { grantAccess(); }";` fired
    CRITICAL.
  - An `async function` declared only inside a string minted the name.
  - An async name quoted in a string argument (`if (log("isAdmin(u)"))`) fired.
  - A quoted `if (` before a real condition on the same line was analysed instead of the real one.

  The scan now reads the anchor mask (see Detection design), so all four are fixed. One false
  positive remains, measured: text between JSX tags is not a string literal to the lexer, so a call
  spelled out in JSX character data still reads as code. Until #543, a `{` in a regex or comment
  inside one substitution and a `}` in a later one shifted the lexer's substitution frame and back,
  so a real condition between the two read as template text and was dropped, where the pre-#749
  guard fired. The lexer now consumes a substitution's regexes and comments whole, and that
  condition fires again, pinned by `test_condition_between_two_desyncing_substitutions_fires`.

## What this guard does NOT prove

It proves a single `if (...)`/`while (...)` condition calls a locally-declared async function
(by name, via a free call) without a preceding `await`; it does not trace whether the condition
actually guards something security-relevant, resolve cross-file or member-call sites, or evaluate
ternary/logical-operand usage. Absence of a finding does not mean the app is free of this bug class
— it means this specific, common, single-file/single-line shape was not found.

# Citations

[1] agentsec checklist item `8-unawaited-async-truthy-check` (§8)
[2] GHSL advisory for CVE-2026-28514 (Rocket.Chat `ddp-streamer`)
[3] OWASP:A04
