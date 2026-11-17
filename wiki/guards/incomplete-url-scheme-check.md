---
type: Guard
title: "incomplete-url-scheme-check"
description: "URL scheme blocklist check covers javascript: but not vbscript:/data:."
timestamp: "2026-08-08T20:53:41+08:00"
guard_id: "incomplete-url-scheme-check"
checklist_section: ["3a"]
standards: ["CWE-020", "CWE-184"]
---

# URL scheme blocklist check covers javascript: but not vbscript:/data:

_Author — 2026-08-08_

---

## The threat

**Incomplete scheme blocklist, CWE-020/CWE-184.** A URL that carries a `javascript:`,
`vbscript:`, or `data:` scheme can execute arbitrary script when a browser navigates to
it or renders it as a link/iframe target — `data:text/html,<script>alert(1)</script>` is
just as capable as `javascript:alert(1)`. A hand-written check that blocks only
`javascript:` (the well-known case) leaves the other two as a live bypass.

- **Who reaches it:** an attacker who controls a URL value the app later uses as a link
  target, redirect destination, or iframe `src` — the exact reachability profile of any
  open-redirect or link-injection surface.
- **Privilege required:** none beyond reaching whatever accepts the URL.
- **Effect:** script execution in the victim's browser session (XSS-equivalent impact)
  via a scheme the blocklist never checked for.

Standards carried by findings: **CWE-020** (Improper Input Validation), **CWE-184**
(Incomplete Blocklist).

---

## Why it's often introduced / Why this guard fits the stack

```js
// sanitize.js — a typical hand-written scheme check
function isSafeUrl(url) {
  return !url.startsWith('javascript:');
}
```

`javascript:` is the scheme every developer remembers to block, because it is the one
most XSS writeups mention. `vbscript:` (a legacy Internet Explorer scheme, still
recognized by some embedded/WebView contexts) and `data:` (which can carry an inline
HTML document with its own `<script>` tag) reach the identical outcome and are far less
commonly top-of-mind — so a review that focuses on "does this block `javascript:`?"
passes a check that is still bypassable.

Sourced from GitHub CodeQL's `js/incomplete-url-scheme-check`
(`javascript/ql/src/Security/CWE-020/IncompleteUrlSchemeCheck.ql`, verified against real
fetched source): the query's own `DangerousScheme` enumeration is exactly `data:`,
`javascript:`, `vbscript:` — this guard mirrors that set.

---

## Detection design

1. **`applies()` gate** — `"javascript" in profile.features or "express" in profile.features`.

2. **Files scanned** — all `.js`/`.jsx`/`.ts`/`.tsx` files under `root`
   (`is_nonproduct_path` excluded), comment-stripped via `strip_js_comments` before
   matching, file-wide pragma checked against the comment-only view of the text first (#424).

3. **Logic (file-wide, presence/absence):**

   - Find the first line where the literal string `"javascript:"` appears AND a
     check-shaped verb (`.startsWith(`, `.includes(`, `===`, `==`) also appears on that
     same line (`_JAVASCRIPT_LITERAL` + `_CHECK_VERB`). A bare mention of the string
     with no check verb (a log line, a comment) does not count — see the FP-bait test.
   - If found, check whether `"vbscript:"` and `"data:"` each appear ANYWHERE in the
     same file as a literal string (`_VBSCRIPT_LITERAL`/`_DATA_LITERAL`) — no check-verb
     requirement on these two, since the goal is just "does the file's defence cover
     this scheme at all," not re-verifying each one is itself check-shaped.
   - If either is missing, emit ONE finding naming whichever scheme(s) are absent.

   This mirrors the same file-wide presence/absence shape this codebase already uses
   for `session-no-csrf`'s CSRF-marker check — appropriate here because the three
   scheme checks are conventionally written together (a `DangerousScheme` array, a
   sequence of `if` statements) rather than deeply separated, so a same-file scan is a
   reasonable proxy for "does this file's defence actually cover all three."

4. **Inline opt-out pragma** — `// security: allow-incomplete-url-scheme-check`
   anywhere in the file (checked before stripping, so it also matches inside what would
   otherwise be treated as a comment — deliberately, since the pragma line itself is
   often a comment).

5. **Severity / rule / standards:**
   - Severity: `medium` — the underlying impact (script execution) is serious, but
     reaching it requires BOTH an attacker-controlled URL value AND that value flowing
     to a rendering/navigation sink after the incomplete check passes it — a real but
     conditional chain, consistent with this guard's file-scoped, no-dataflow design.
   - Rule: `incomplete-url-scheme-check/missing-dangerous-scheme`
   - Standards: `["CWE-020", "CWE-184"]`

---

## When NOT to flag

- **All three schemes checked** — `javascript:`, `vbscript:`, and `data:` all appear as
  literal strings somewhere in the file.
- **No scheme check at all** — the file never checks for `javascript:` in a
  check-shaped context; nothing to compare against.
- **A bare mention with no check verb** — `console.log('Blocked scheme: javascript:')`
  is not a security check, so it does not trigger the file-wide scan in the first place.
- **Pragma suppressed** — `// security: allow-incomplete-url-scheme-check`.

---

## Tests

| Test | What it checks |
|---|---|
| `test_incomplete_url_scheme_check_fires_when_only_javascript_checked` | True positive: `url.startsWith('javascript:')` present, `vbscript:`/`data:` absent — fires MEDIUM, message names both missing schemes. |
| `test_incomplete_url_scheme_check_silent_when_all_three_checked` | False-positive bait: all three schemes present in a `DangerousScheme`-style array — silent. |
| `test_incomplete_url_scheme_check_silent_no_scheme_check_at_all` | False-positive bait: a file with no scheme checking whatsoever — silent. |
| `test_incomplete_url_scheme_check_silent_on_bare_literal_no_check_verb` | False-positive bait: `"javascript:"` mentioned in a log line, no check verb on that line — silent. |
| `test_incomplete_url_scheme_check_pragma_silences` | Pragma: `// security: allow-incomplete-url-scheme-check` silences the whole file. |
| `test_incomplete_url_scheme_check_does_not_apply_without_js` | Feature gate: `applies()` returns `False`, `run()` returns `[]`, for a profile without `javascript`/`express`. |

---

## Known bypasses

- **Only `javascript:` is scanned as the trigger** — a file that checks `vbscript:` or
  `data:` first (and is missing `javascript:` itself) is not flagged; the guard's entry
  point is specifically the `javascript:` check, mirroring the CodeQL query's own
  `select schemeCheckOn(root, path, "javascript:"), ...` framing.
- **Case variation**: `"JAVASCRIPT:"` or `"JavaScript:"` — the literal match is
  case-sensitive; a check written in a different case is not recognized (real code
  overwhelmingly writes scheme literals lowercase, so this is a narrow gap).
- **Indirection**: a scheme literal built from concatenation or a constant imported from
  another file — only a same-line, same-file literal string is matched.
- **A check that handles the scheme differently** (e.g. `url.toLowerCase().includes('data:')`
  nested inside a helper that this guard's `_DATA_LITERAL` check still finds, since it
  only requires the bare literal to appear anywhere) — this direction is intentionally
  permissive, since the absence check's whole purpose is "does the defence exist at
  all," not "is it written identically to the `javascript:` check."

---

## What this guard does NOT prove

- It does not verify the three scheme checks are actually applied to the SAME value, or
  that the check's result is respected by the caller before the value reaches a
  navigation/rendering sink — a separate dataflow question outside this guard's
  file-wide, no-dataflow scope.
- It does not recognize an allowlist-style defence (`url.startsWith('https://')`) as
  equivalent protection — an allowlist is the recommended fix and would legitimately
  make the `javascript:` blocklist check unnecessary, but this guard only understands
  the blocklist shape it was built to audit.
- A silent guard does not mean the file is safe — a file that checks all three schemes
  by a spelling this guard doesn't recognize (case variation, indirection) is a real,
  undetected residual.

# Citations

[1] agentsec checklist item `3a-incomplete-url-scheme-check` (§3a)
[2] CWE-020
[3] CWE-184
