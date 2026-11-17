---
type: Guard
title: "regex-html-sanitizer"
description: "Hand-rolled HTML tag-stripping via a wildcard regex."
timestamp: "2026-07-12T14:17:03+08:00"
guard_id: "regex-html-sanitizer"
checklist_section: ["6a"]
standards: ["CWE-116", "OWASP:A03"]
---

# Hand-rolled HTML tag-stripping via a wildcard regex

## Threat

**CWE-116 (Improper Encoding or Escaping of Output), CWE-020 family.** HTML is not a regular
language — a generic wildcard regex cannot correctly tokenize it. A vibe-coder reaching for
`re.sub()` to "strip HTML tags" instead of a real HTML parser/sanitizer produces code that looks
correct on simple inputs and fails open on the input that matters:

```python
clean = re.sub(r"<.*?>", "", user_input)      # looks reasonable, is not a sanitizer
clean = re.sub(r"<[^>]+>", "", llm_output)
```

Both compile and pass casual testing, then are bypassed by an attribute value containing `>`
(`<img alt=">"  onerror=alert(1)>`), nested/malformed markup, or an HTML comment wrapping a
`<script>` tag. This is CodeQL's own conclusion for `py/bad-tag-filter`: "matching HTML tags
using regular expressions is hard to do right, and can easily lead to security issues."

Standards: **OWASP:A03** (Injection), **CWE-116**.

## Detection design

1. **`applies()` gate:** `"python" in profile.features`.
2. **Files scanned:** all `.py` files under `python_scan_dirs`, excluding non-product paths
   (`is_nonproduct_path`).
3. **Pattern:** a whole-file scan (not per-line — the call may wrap across lines) for
   `re.sub(` calls, with arguments split on top-level commas via a local balanced-paren helper
   (`_split_top_level_args`, mirroring `dom_xss_sinks.py`'s `_scan_broken_sanitizer` and
   `insecure_cookies.py`'s `_balanced_args`). A call fires when:
   - The first argument (the pattern) contains a `<...>` span built from a wildcard construct —
     `.*`, `.+`, or a negated character class like `[^>]` — via `_WILDCARD_TAG_PATTERN`. This is
     the "generic tag matcher" shape, not a single literal tag name.
   - The second argument (the replacement) is an empty string literal (`""`, `''`, optionally
     with a 1-2 letter prefix like `r""`), via `_EMPTY_STRING_LITERAL`. This scopes the guard to
     the "strip all tags" idiom specifically, not a transformation.
4. **Pragma:** a `# security: allow-regex-html-sanitizer` comment anywhere in the file skips it entirely (a
   docstring or string quoting the phrase does not count, #424).
5. **Severity / rule:** `regex-html-sanitizer/wildcard-tag-strip`, **HIGH**.

**Scoped to `re.sub(...)` direct calls only** — `PATTERN.sub(...)` on a `re.compile()`-produced
object is not tracked (would require correlating two separate lines/variables, dataflow beyond
this guard's single-call-site design).

**Relationship to `dom-xss-sinks/incomplete-sanitization`:** that check (JS/TS side) flags a
`.replace()` call stripping a single *literal* tag string only once — bypassable by nesting. This
guard flags a different, Python-side mistake: using a *generic wildcard* regex as an HTML parser
substitute at all, which is unreliable regardless of whether removal is single-pass or repeated
(Python's `re.sub()` replaces all occurrences by default, so the "only strips once" bug class
does not apply here — the bug is that no wildcard regex can correctly tokenize arbitrary HTML).
The two guards target genuinely distinct mistakes, not the same one from two languages.

## When NOT to flag

- `re.sub(r"<b>", "", text)` — a single literal tag name, not a wildcard construct. Out of scope
  by design: this is a narrower, different risk (see `dom-xss-sinks/incomplete-sanitization`
  bypassable-by-nesting case) that this guard does not attempt to also catch.
- `re.sub(r"\s+", " ", text)` — no `<`/`>` in the pattern at all.
- `re.sub(r"<.*?>", "[REDACTED]", text)` — non-empty replacement; a transformation, not a strip.
  (Still potentially unreliable as a sanitizer, but scoped out to keep false positives low —
  "strip to empty" is the dominant, highest-confidence vibe-coder idiom this guard targets.)

## Tests

| Test | What it checks |
|---|---|
| `test_regex_html_sanitizer_flags_dot_star_pattern` | `re.sub(r"<.*?>", "", user_input)` fires HIGH |
| `test_regex_html_sanitizer_flags_negated_class_pattern` | `re.sub(r"<[^>]+>", "", llm_output)` fires |
| `test_regex_html_sanitizer_silent_literal_tag` | `re.sub(r"<b>", "", ...)` (no wildcard) stays silent |
| `test_regex_html_sanitizer_silent_non_empty_replacement` | Non-empty replacement stays silent |
| `test_regex_html_sanitizer_silent_unrelated_re_sub` | `re.sub(r"\s+", " ", ...)` (no tag shape) stays silent |
| `test_regex_html_sanitizer_pragma_silences` | File-level pragma suppresses all findings |
| `test_regex_html_sanitizer_documented_pragma_form_in_a_string_does_not_suppress` | A string quoting the documented `# security: …` form does not suppress (#424) |
| `test_regex_html_sanitizer_applies_gate` | Guard does not apply when `python` not in features |
| `test_regex_html_sanitizer_applies_with_python` | Guard applies when `python` in features |

## Known bypasses

| Bypass | Why missed |
|---|---|
| `PATTERN = re.compile(r"<.*?>"); PATTERN.sub("", text)` | Only direct `re.sub(...)` calls are tracked, not a compiled pattern's `.sub()` method |
| `re.sub(r"<.*?>", replacement_var, text)` where `replacement_var = ""` | The replacement must be a literal empty string on the call site, not a variable that happens to hold one |
| A wildcard pattern spanning a genuinely different construct not matched by `_WILDCARD_TAG_PATTERN` (e.g. `<\w+.*?>` without a `.` immediately after `<`) | The wildcard-detection regex covers the common `.*`/`.+`/`[^>]`-style idioms, not every possible regex shape that is equally unreliable |
| Multi-step sanitization split across several `re.sub()` calls, each individually narrow | Each call is evaluated independently; no cross-call reasoning |

**Known limitation (review #395):** this exact idiom is also the common benign "strip to
plaintext preview/word-count" pattern, where the result is never re-rendered as HTML — the guard
has no dataflow to tell that apart from a real sanitizer bypass, so severity is demoted to MEDIUM
(from HIGH) rather than narrowed, trading some noise for zero false negatives.

## What this guard does NOT prove

A file with no finding from this guard may still sanitize HTML unsafely via a compiled-pattern
`.sub()` call, a hand-rolled character-by-character parser, or a third-party library used
incorrectly (e.g. `bleach.clean()` called with an overly permissive `tags=` allowlist). This
guard proves the *absence of the specific wildcard-`re.sub()`-strip idiom*, not the presence of
correct HTML sanitization.

# Citations

[1] agentsec checklist item `6a-regex-html-sanitizer-unreliable` (§6a)
[2] CWE-116
[3] OWASP:A03
