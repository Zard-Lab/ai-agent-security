---
type: Guard
title: "incorrect-suffix-check"
description: "indexOf/lastIndexOf used as a homemade endsWith without handling -1."
timestamp: "2026-08-08T21:11:17+08:00"
guard_id: "incorrect-suffix-check"
checklist_section: ["3a"]
standards: ["CWE-020"]
---

# indexOf/lastIndexOf used as a homemade endsWith without handling -1

_Author — 2026-08-08_

---

## The threat

**Hand-rolled `endsWith` emulation missing the `-1` case, CWE-020.**
`String.prototype.endsWith()` exists and has no edge case; `x.indexOf(y) === x.length -
y.length` is a common reimplementation that breaks silently:

```js
function hasExtension(path, ext) {
  return path.indexOf(ext) === path.length - ext.length;
}
```

`indexOf()` returns `-1` when `ext` is not found at all in `path`. If `path.length -
ext.length` also happens to equal `-1` — which happens whenever `ext` is exactly one
character longer than `path` — the comparison is `-1 === -1`, TRUE, even though `ext`
is not a suffix of `path` (it is not present in `path` at all). The check passes when
it should fail.

- **Who reaches it:** an attacker who controls the value being suffix-checked (a
  filename extension gate, a domain-suffix check, an allowed-path-ending validator).
- **Privilege required:** none beyond reaching whatever the suffix check gates.
- **Effect:** entirely dependent on what the check protects — a file-extension
  allowlist that can be bypassed lets through an unexpected file type; a domain-suffix
  check bypass is a smaller-scoped sibling of the substring-sanitization bug this same
  batch's `incomplete-url-substring-sanitization` guard covers more generally.

Standards carried by findings: **CWE-020** (Improper Input Validation).

---

## Why it's often introduced / Why this guard fits the stack

The `indexOf()`-and-subtract idiom predates `endsWith()` being universally available
(it shipped in ES2015) and still shows up in code written by habit, or copied from an
older reference. It also LOOKS correct — for genuinely matching inputs, both the
subtraction and `indexOf()`'s real return value agree, so ordinary testing never
surfaces the bug. The failure mode only appears for the specific, easy-to-miss
one-character-longer-than-expected input.

Sourced from GitHub CodeQL's `js/incorrect-suffix-check`
(`javascript/ql/src/Security/CWE-020/IncorrectSuffixCheck.ql`, verified against real
fetched source). CodeQL's own query is considerably more thorough than this guard: it
tracks equivalent `indexOf` calls across a function via real dataflow, several
comparison-operator shapes, and whether a companion `-1`/range check elsewhere in the
function already neutralizes the bug. This guard implements a **narrower,
same-line-only approximation** of the same core anti-pattern — see Known bypasses for
what that gives up.

---

## Detection design

1. **`applies()` gate** — `"javascript" in profile.features or "express" in profile.features`.

2. **Files scanned** — all `.js`/`.jsx`/`.ts`/`.tsx` files under `root`
   (`is_nonproduct_path` excluded), comment-stripped via `strip_js_comments` before
   matching.

3. **Logic (single-line, backreference-matched):** `_SUFFIX_CHECK` matches
   `<recv>.indexOf(<arg>)` (or `.lastIndexOf(`) compared with `===`/`!==`/`==`/`!=`
   against `<recv>.length - <arg>.length`, where the SAME receiver text (`\1`) and the
   SAME argument text (`\2`) — a bare identifier or a quoted string literal — appear on
   both sides. Anything else (a different receiver, a different argument, a differently
   shaped comparison) does not match.

4. **Inline opt-out pragma** — `// security: allow-incorrect-suffix-check` on the line.

5. **Severity / rule / standards:**
   - Severity: `medium` — real but conditionally exploitable (depends on what the
     check gates and whether the specific off-by-one input is reachable).
   - Rule: `incorrect-suffix-check/indexof-endswith-emulation`
   - Standards: `["CWE-020"]`

---

## When NOT to flag

- **`endsWith()` used directly** — the recommended fix, no `indexOf`/`.length`
  arithmetic present at all.
- **Different receiver or argument on each side** — `path.indexOf(ext) === other.length
  - ext.length` is not the homemade-endsWith shape (a different, probably unrelated
  comparison); the backreference requirement excludes it.
- **An ordinary `indexOf() !== -1` "contains" check** — no length arithmetic at all, a
  completely different (and correct) idiom.
- **Pragma suppressed** — `// security: allow-incorrect-suffix-check`.

---

## Tests

| Test | What it checks |
|---|---|
| `test_incorrect_suffix_check_fires_on_indexof_length_comparison` | True positive: `path.indexOf(ext) === path.length - ext.length` fires MEDIUM. |
| `test_incorrect_suffix_check_fires_on_last_index_of` | True positive: `.lastIndexOf(` also fires. |
| `test_incorrect_suffix_check_fires_on_string_literal_arg` | True positive: a quoted-string argument (`'.json'`) on both sides also fires. |
| `test_incorrect_suffix_check_silent_on_endswith` | False-positive bait: `path.endsWith(ext)` — the recommended fix — silent. |
| `test_incorrect_suffix_check_silent_on_different_receiver` | False-positive bait: `path.indexOf(ext) === other.length - ext.length` — different receiver on each side — silent. |
| `test_incorrect_suffix_check_silent_on_plain_indexof_check` | False-positive bait: `haystack.indexOf(needle) !== -1` — no length arithmetic, a different idiom — silent. |
| `test_incorrect_suffix_check_pragma_silences` | Pragma: `// security: allow-incorrect-suffix-check` silences the line. |
| `test_incorrect_suffix_check_does_not_apply_without_js` | Feature gate: `applies()` returns `False`, `run()` returns `[]`, for a profile without `javascript`/`express`. |

---

## Known bypasses

**This guard is deliberately narrower than CodeQL's own query, in ways that trade
recall for simplicity — documented explicitly, not discovered by accident:**

- **A companion `-1`/range check elsewhere already neutralizes the bug** — CodeQL's
  full query checks whether the SAME `indexOf` call (or an equivalent one) is ALSO
  compared against `-1` or bounded by a relational comparison anywhere in the
  containing function, and stays silent if so (the bug is provably unreachable). This
  guard does not perform that check — a same-line match always fires, even if a nearby
  `if (path.indexOf(ext) === -1) return false;` guard already makes the pattern safe in
  practice. Accepted as a precision-for-simplicity tradeoff: a single-character-line
  regex cannot see "elsewhere in the function" without real parsing.
- **Multi-line comparison** — the check and the length-arithmetic must be on ONE
  physical line; a comparison split across lines (a common formatter output for long
  expressions) is not matched.
- **A single-character argument** (`x.indexOf("a") === x.length - "a".length`) — CodeQL
  excludes this case explicitly (it can only be bypassed if `x` is the empty string,
  "unlikely to be a security issue... obviously not a domain name check"). This guard
  does not carry that exclusion, so it is slightly MORE willing to fire than CodeQL on
  single-character suffixes — a rare real-world shape, but a documented over-match.
- **Equivalent `indexOf` calls tracked via a chain** (`x.indexOf(y) === x.length -
  y.length` where the `indexOf` call and the comparison reference DIFFERENT, but
  provably-equal, expressions) — CodeQL's `getAnEquivalentIndexOfCall()` tracks these;
  this guard's plain backreference match does not.

---

## What this guard does NOT prove

- It does not verify the off-by-one input is actually reachable by an attacker — that
  depends entirely on what calls the checked function.
- It does not check whether the specific one-character-longer-than-expected value is
  meaningful in context (a real bypass needs `ext` to be exactly `path.length + 1`
  characters, a narrow but attacker-controllable condition when both values come from
  request input).
- A silent guard does not mean every suffix-check idiom in the file is correct — a
  multi-line comparison, a companion `-1` check nearby, or an equivalent-but-not-
  textually-identical `indexOf` call chain are all real, undetected residuals.

# Citations

[1] agentsec checklist item `3a-incorrect-suffix-check` (§3a)
[2] CWE-020
