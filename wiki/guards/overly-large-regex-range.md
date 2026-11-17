---
type: Guard
title: "overly-large-regex-range"
description: "Overly permissive regular-expression character range."
timestamp: "2026-08-08T21:04:54+08:00"
guard_id: "overly-large-regex-range"
checklist_section: ["3a"]
standards: ["CWE-020"]
---

# Overly permissive regular-expression character range

_Author — 2026-08-08_

---

## The threat

**Overly permissive character-class range, CWE-020.** `[A-z]` is a common typo for
`[A-Za-z]`. It looks like "any letter," but the ASCII range from `Z` (0x5A) to `a`
(0x61) also includes six punctuation/control characters: `[`, `\`, `]`, `^`, `_`, and
`` ` ``. A regex meant to validate "letters only" — a username filter, a sanitizer
allowlist, an input character check — silently admits these six characters too.

- **Who reaches it:** an attacker whose input passes through a filter/sanitizer built on
  the mistaken range.
- **Privilege required:** none beyond reaching whatever accepts the filtered input.
- **Effect:** depends entirely on what the filter is protecting — a filter meant to
  block `[`/`]`/`` ` `` (template-literal-adjacent characters, for instance) that
  actually admits them because the range was meant to be letters-only is a real, if
  narrow, injection surface. The guard flags the pattern shape itself; the exploit
  depends on the specific filter's purpose.

Standards carried by findings: **CWE-020** (Improper Input Validation).

---

## Why it's often introduced / Why this guard fits the stack

```js
// validate.js — a typical "letters only" filter, written wrong
function isAlpha(value) {
  return /^[A-z]+$/.test(value);
}
```

`A` through `Z` is uppercase, `a` through `z` is lowercase — writing `A-z` as a single
range reads as "the full alphabet" to someone glancing at it, and in casual testing with
ordinary letter input it behaves exactly as expected. The six extra characters it
silently admits are easy to never notice, because nobody tests a "letters only" filter
with `[`, `\`, `]`, `^`, `_`, or `` ` `` unless they already know to look for this exact
mistake.

Sourced from GitHub CodeQL's `js/overly-large-range`
(`javascript/ql/src/Security/CWE-020/OverlyLargeRange.ql`, verified against real fetched
source): "Overly permissive regular expression ranges match a wider range of characters
than intended. This may allow an attacker to bypass a filter or sanitizer."

---

## Detection design

1. **`applies()` gate** — `"javascript" in profile.features or "express" in profile.features`.

2. **Files scanned** — all `.js`/`.jsx`/`.ts`/`.tsx` files under `root`
   (`is_nonproduct_path` excluded), comment-stripped via `strip_js_comments` before
   matching.

3. **Regex-literal extraction** — the same `_REGEX_LITERAL` shape as the sibling
   `hostname-regex-unsafe` guard (a JS regex literal `/pattern/flags`).

4. **Bad-range detection** — `_BAD_RANGE` finds an `X-Y` sequence where `X` is
   `[A-Z0-9]` and `Y` is `[A-Za-z]`, then checks whether `(X, Y)` is one of three
   well-known bad-range pairs: `("A", "z")`, `("0", "Z")`, `("0", "z")`. This is
   deliberately a small, precise allowlist of KNOWN mistakes rather than a general
   "does this range span an unexpected gap" analysis (which the CodeQL query performs
   via real character-category reasoning) — a narrower but zero-ambiguity check.

   **No security-context gate is required** — unlike the other new guards in this
   batch, this pattern is a mistake wherever it appears; a regex used purely for
   display formatting still benefits from being written correctly, and CodeQL's own
   query has the same unscoped severity framing (MEDIUM, not gated on a security-check
   heuristic).

5. **Inline opt-out pragma** — `// security: allow-overly-large-regex-range` on the
   line containing the regex literal.

6. **Severity / rule / standards:**
   - Severity: `medium` — the impact is real but conditional on what the filter
     protects; unlike `incomplete-url-substring-sanitization`'s unambiguous SSRF/
     redirect shape, this guard cannot tell from the pattern alone how sensitive the
     filtered context is.
   - Rule: `overly-large-regex-range/unintended-character-span`
   - Standards: `["CWE-020"]`

---

## When NOT to flag

- **A correctly joined range**: `[A-Za-z]`, `[0-9A-Za-z]` — neither contains one of the
  three bad-range pairs (see the FP-bait tests: `A-Z` alone, or `0-9` alone, are legal
  and NOT in the bad-pairs set).
- **Pragma suppressed** — `// security: allow-overly-large-regex-range` for a
  deliberately wide range.

---

## Tests

| Test | What it checks |
|---|---|
| `test_overly_large_regex_range_fires_on_a_to_z` | True positive: `[A-z]` fires MEDIUM. |
| `test_overly_large_regex_range_fires_on_zero_to_z` | True positive: `[0-z]` also fires. |
| `test_overly_large_regex_range_fires_on_zero_to_upper_z` | True positive: `[0-Z]` also fires. |
| `test_overly_large_regex_range_silent_on_correct_range` | False-positive bait: `[A-Za-z]` (the correct fix) — silent. |
| `test_overly_large_regex_range_silent_on_alphanumeric_range` | False-positive bait: `[0-9A-Za-z]` — the individual sub-ranges (`0-9`, `A-Z`) are not themselves bad pairs — silent. |
| `test_overly_large_regex_range_pragma_silences` | Pragma: `// security: allow-overly-large-regex-range` silences the line. |
| `test_overly_large_regex_range_does_not_apply_without_js` | Feature gate: `applies()` returns `False`, `run()` returns `[]`, for a profile without `javascript`/`express`. |

---

## Known bypasses

- **A bad range not in the fixed 3-pair allowlist** — e.g. a reversed or otherwise
  unusual range CodeQL's general character-category analysis would catch but this
  guard's specific-pairs approach does not. Accepted tradeoff: the three pairs covered
  are overwhelmingly the common real-world typo, and a broader heuristic risks flagging
  legitimate narrow ranges (`[a-f]` for hex digits, `[X-Z]` for a deliberately small
  set) that a full semantic analysis would correctly clear but a looser regex-only
  check might not.
- **`new RegExp("...")` built from a string** — only regex literals are matched.
- **The bad range spans a character class other than a top-level one** (nested groups,
  Unicode property escapes) — the detection is purely textual on the extracted pattern
  string, not a real regex parser.

---

## What this guard does NOT prove

- It does not determine whether the filter is actually used as a security boundary —
  a `[A-z]`-shaped range used only for display formatting or a non-security allowlist
  carries no real exploit path, but this guard flags the shape regardless (worth fixing
  either way, since the pattern's own stated intent — "letters only" — is violated).
- It does not verify the six unintended characters are actually meaningful in whatever
  context consumes the filtered value — that depends entirely on the caller, which this
  single-file, no-dataflow guard does not trace.
- A silent guard does not mean every character-class range in the file is correct — a
  bad range outside the three known pairs, or one built from a string rather than a
  literal, is a real, undetected residual.

# Citations

[1] agentsec checklist item `3a-overly-large-regex-range` (§3a)
[2] CWE-020
