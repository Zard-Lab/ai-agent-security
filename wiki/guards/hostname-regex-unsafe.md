---
type: Guard
title: "hostname-regex-unsafe"
description: "Hostname/URL allowlist regex is unsafe (unescaped dot or missing end anchor)."
timestamp: "2026-08-08T20:46:48+08:00"
guard_id: "hostname-regex-unsafe"
checklist_section: ["3a"]
standards: ["CWE-020"]
---

# Hostname/URL allowlist regex is unsafe (unescaped dot or missing end anchor)

_Author — 2026-08-08_

---

## The threat

**SSRF / open-redirect via a broken hostname allowlist regex, CWE-020.** A hand-written
regular expression is a common way to implement "only fetch/redirect to a trusted
domain." Two independent regex mistakes both defeat this defence in a way that reads as
correct at a glance: an unescaped `.` (which matches ANY character, not just a literal
dot) and a missing end anchor (which lets the pattern match a PREFIX of the tested value
instead of requiring an exact or suffix match).

- **Who reaches it:** an attacker who can supply or influence a URL/hostname the app
  later fetches (SSRF) or redirects to (open redirect), when that value passes through
  a broken allowlist check first.
- **Privilege required:** none beyond reaching whatever endpoint accepts the URL.
- **Effect:** the "trusted domain" check passes for an attacker-chosen domain
  (`trusted.com.evil.com` for the missing-anchor case, `trustedXcom` for the
  unescaped-dot case combined with an incomplete pattern), defeating the SSRF/redirect
  defence entirely.

Standards carried by findings: **CWE-020** (Improper Input Validation).

---

## Why it's often introduced / Why this guard fits the stack

```js
// auth.js — a typical hand-written domain allowlist
const TRUSTED_HOST = /^https:\/\/trusted.com/;

function isTrusted(target) {
  return TRUSTED_HOST.test(new URL(target).hostname);
}
```

Both mistakes are easy to make and easy to miss in review: the pattern LOOKS like it
requires `trusted.com`, and in casual testing with a genuinely trusted URL it behaves
correctly. The bypass only shows up when an attacker deliberately crafts
`https://trusted.com.evil.com/steal` (missing end anchor — matches, since the pattern
only requires the string to START with `https://trusted.com`) or `https://trustedXcom`
(unescaped dot — `.` matches `X` just as readily as a literal `.`).

Sourced from GitHub CodeQL's `js/incomplete-hostname-regexp` and
`js/regex/missing-regexp-anchor` (`javascript/ql/src/Security/CWE-020/
IncompleteHostnameRegExp.ql` + `MissingRegExpAnchor.ql`, verified against real fetched
source — both queries share the same underlying `HostnameRegexp` library, so this guard
treats them as one threat surfaced through two independent checks, not two unrelated
findings).

---

## Detection design

1. **`applies()` gate** — `"javascript" in profile.features or "express" in profile.features`.

2. **Files scanned** — all `.js`/`.jsx`/`.ts`/`.tsx` files under `root`
   (`is_nonproduct_path` excluded), comment-stripped via `strip_js_comments` before
   matching.

3. **Regex-literal extraction** — `_REGEX_LITERAL` matches a JS regex literal
   (`/pattern/flags`), where the pattern excludes a bare unescaped `/` or newline
   (`(?:[^/\\\n]|\\.)+` — a `\\.` alternative consumes an escaped character, including
   an escaped `/`). Does not handle a `/` inside a character class (`/[a/b]/`) — a
   known, accepted limitation shared with other JS-literal-scanning guards in this
   codebase.

4. **Context gate (either side satisfies it)** — a regex literal only counts as a
   hostname/URL check if:
   - it's assigned to a `const`/`let`/`var` whose name contains
     `host`/`origin`/`domain`/`trusted`/`allowed` (`_HOSTNAME_VAR_NAME`, checked against
     the 80 characters immediately preceding the literal), OR
   - it's followed within 80 characters by a `.test(...)` call whose argument mentions
     `hostname`/`.host`/`origin`/`url` (`_HOSTNAME_TEST_CALL`).

   This keeps an unrelated regex elsewhere in the file (a form-validation pattern, a
   slug matcher) out of scope — see the FP-bait test with a price-format regex.

5. **Two rules, both fired independently per matched literal:**
   - `unescaped-dot` (HIGH): `_UNESCAPED_DOT_BEFORE_TLD` finds a `.` not preceded by
     `\` immediately before a common TLD-like suffix (`com`/`org`/`net`/`io`/`dev`/
     `app`/`co`/`gov`/`edu`).
   - `missing-end-anchor` (HIGH): the pattern text does not end with `$` (optionally
     followed by nothing else before the closing delimiter — checked via
     `re.search(r"\$/?$", pattern)`).

   A single pattern can fire both rules at once (as the canary plant does) if it has
   both defects.

6. **Inline opt-out pragma** — `// security: allow-hostname-regex-unsafe` on the line
   containing the regex literal.

---

## When NOT to flag

- **A properly anchored, properly escaped pattern**: `/^https:\/\/trusted\.com$/` —
  both rules stay silent (see the "safe pattern" FP-bait test).
- **A regex with no hostname/URL context signal** — neither a hostname-ish variable
  name nor a hostname-ish `.test()` argument nearby. An ordinary form-validation regex
  (e.g. a price format `/^\d+.\d{2}/`, itself carrying an unescaped dot) is not flagged,
  since it is not a security-relevant allowlist check.
- **Pragma suppressed** — `// security: allow-hostname-regex-unsafe` on the line.

---

## Tests

| Test | What it checks |
|---|---|
| `test_hostname_regex_unsafe_fires_on_unescaped_dot` | True positive: an unescaped `.` before `com` in a hostname-ish-named pattern fires `unescaped-dot`. |
| `test_hostname_regex_unsafe_fires_on_missing_end_anchor` | True positive: a properly escaped pattern with no `$` anchor fires `missing-end-anchor`. |
| `test_hostname_regex_unsafe_silent_on_safe_pattern` | False-positive bait: `/^https:\/\/trusted\.com$/` (escaped dot, end-anchored) — silent on both rules. |
| `test_hostname_regex_unsafe_silent_without_hostname_context` | False-positive bait: an unrelated form-validation regex with an unescaped dot and no anchor — silent, since neither context gate matches. |
| `test_hostname_regex_unsafe_fires_via_test_call_context` | True positive via the OTHER context gate: no hostname-ish variable name, but `.test(new URL(u).hostname)` names "hostname" directly. |
| `test_hostname_regex_unsafe_pragma_silences` | Pragma: `// security: allow-hostname-regex-unsafe` silences the line. |
| `test_hostname_regex_unsafe_does_not_apply_without_js` | Feature gate: `applies()` returns `False`, `run()` returns `[]`, for a profile without `javascript`/`express`. |

---

## Known bypasses

- **`new RegExp("...")` built from a string** — only regex LITERALS (`/pattern/`) are
  matched; a dynamically constructed pattern is out of scope (would need string-value
  tracking this guard does not attempt).
- **A `/` inside a character class** (`/[a/b]/`) breaks the literal-extraction regex —
  the same accepted limitation several sibling JS-literal-scanning guards carry.
- **Context signal more than 80 characters away** — a regex literal assigned to a
  generically-named variable, later reassigned to a hostname-ish name, or tested against
  a hostname-ish argument far from the literal itself, is not connected back to it.
- **A different TLD not in the fixed suffix list** — the unescaped-dot check only
  recognizes 9 common TLD-like suffixes; a bypass using an uncommon TLD (`.xyz`,
  `.info`) is not detected by that rule (though `missing-end-anchor` would still catch
  an unanchored pattern regardless of TLD).

---

## What this guard does NOT prove

- It does not verify the regex is actually used as a security decision (vs. logging,
  metrics, or a non-security allowlist) — the context gate is a heuristic, not proof of
  intent.
- It does not check that the resulting `isTrusted()`-style function's return value is
  actually respected by the caller before an SSRF-capable fetch or redirect — that is a
  separate dataflow question outside this guard's single-file, regex-literal scope.
- A silent guard does not mean the hostname check is safe — a pattern using URL
  parsing (`new URL(value).hostname === "trusted.com"`) rather than a regex is the
  actually-recommended fix and is never scanned by this guard at all (it has no regex
  literal to find).

# Citations

[1] agentsec checklist item `3a-hostname-regex-unsafe` (§3a)
[2] CWE-020
