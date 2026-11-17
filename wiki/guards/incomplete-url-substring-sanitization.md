---
type: Guard
title: "incomplete-url-substring-sanitization"
description: "Raw URL substring checked against a trusted domain — bypassable."
timestamp: "2026-10-21T00:00:00Z"
guard_id: "incomplete-url-substring-sanitization"
checklist_section: ["3a"]
standards: ["CWE-020"]
---

# Raw URL substring checked against a trusted domain — bypassable

_Author — 2026-08-08_

---

## The threat

**SSRF / open-redirect via a raw-URL substring check, CWE-020.** Testing whether a
trusted domain string appears anywhere inside an unparsed URL (`.includes(`,
`.indexOf(`, `.startsWith(`) is a classic bypass surface: the check has no concept of
"this is the hostname component," so an attacker who controls the rest of the URL can
place the trusted string anywhere that satisfies the check while the URL still resolves
to an attacker-controlled host.

```js
if (url.includes("trusted.com")) { fetch(url); }
```

bypassed by any of:
- `https://evil.com/trusted.com` (trusted.com in the PATH)
- `https://trusted.com.evil.com` (trusted.com as a SUBDOMAIN PREFIX of the real host)
- `https://trusted.com@evil.com` (trusted.com in the USERINFO component)

- **Who reaches it:** an attacker who controls (or can influence) a URL value the app
  later fetches (SSRF) or redirects to (open redirect).
- **Privilege required:** none beyond reaching whatever endpoint accepts the URL.
- **Effect:** the "trusted domain" check passes for an attacker-chosen host, defeating
  the SSRF/redirect defence.

Standards carried by findings: **CWE-020** (Improper Input Validation).

---

## Why it's often introduced / Why this guard fits the stack

A substring check reads as simpler and "obviously correct" than parsing the URL first —
`url.includes("trusted.com")` looks like it does what it says. The bypass only becomes
visible when you consider that `.includes()` has no notion of URL structure at all; it
is answering "does this string appear ANYWHERE in the value," which is a much weaker
question than "is this the value's hostname."

Sourced from GitHub CodeQL's `js/incomplete-url-substring-sanitization`
(`javascript/ql/src/Security/CWE-020/IncompleteUrlSubstringSanitization.ql`, verified
against real fetched source) — the query's own description states the exact same
principle: "Security checks on the substrings of an unparsed URL are often vulnerable
to bypassing."

---

## Detection design

1. **`applies()` gate** — `"javascript" in profile.features or "express" in profile.features`.

2. **Files scanned** — all `.js`/`.jsx`/`.ts`/`.tsx` files under `root`
   (`is_nonproduct_path` excluded), comment-stripped via `strip_js_comments` before
   matching.

3. **Logic (same-line, three-part gate):**

   - `_URL_ISH_RECEIVER` matches `.includes(`/`.indexOf(`/`.startsWith(` called on a
     variable whose name contains `url`/`uri`/`href`/`target`/`redirect`/`link`
     (case-insensitive) — the "this looks like a raw URL value" signal.
   - `_ALREADY_PARSED` excludes the call if `new URL(` or `.hostname` appears earlier on
     the line — evidence the value was already parsed into a real hostname before
     comparison, which is the CORRECT pattern this guard exists to recommend, not flag.
   - `_DOMAIN_LITERAL_ARG` requires the call's argument text to look like a bare domain
     (contains a `.` followed by 2+ letters) — excludes checks against an unrelated
     substring (a query-param name, a path segment) that happens to share the receiver
     name.

   All three must hold on the SAME line for a finding to fire. The check call (its `(`) and
   the parse evidence (its first character) must also be live code, tested with
   `js_code_matches` on the anchor mask (#1055), so a call or a `new URL(` spelled out in a
   string does not count and one nested in a `${...}` substitution does. Every check call on
   the line is tried, and the line reports at most one finding.

4. **Inline opt-out pragma** — `// security: allow-incomplete-url-substring-sanitization`
   on the line (trailing comment form — the comment is stripped from the matching pass
   but the pragma check reads the comment-only view of that line, #424).

5. **Severity / rule / standards:**
   - Severity: `high` — the substring-check shape is unambiguously a security
     anti-pattern once the context gate matches; unlike some of this batch's other
     guards, there is no legitimate reason to write this exact shape intentionally.
   - Rule: `incomplete-url-substring-sanitization/raw-substring-check`
   - Standards: `["CWE-020"]`

---

## When NOT to flag

- **The value is already parsed** — `new URL(redirectUrl).hostname === "trusted.com"`
  is the recommended fix and is correctly excluded by `_ALREADY_PARSED`.
- **The receiver name has no URL-ish signal** — `query.includes("example.com")` on an
  ordinary search-query variable is not flagged; the domain-shaped literal alone is not
  enough to imply a security check.
- **The argument isn't domain-shaped** — `redirectUrl.includes("?next=")` (checking for
  a query parameter, not a trusted domain) is not flagged.
- **Pragma suppressed** — `// security: allow-incomplete-url-substring-sanitization`.

---

## Tests

| Test | What it checks |
|---|---|
| `test_incomplete_url_substring_sanitization_fires_on_includes` | True positive: `redirectUrl.includes('trusted.com')` fires HIGH. |
| `test_incomplete_url_substring_sanitization_fires_on_starts_with` | True positive: `targetUrl.startsWith('trusted.com')` also fires. |
| `test_incomplete_url_substring_sanitization_silent_when_hostname_parsed` | False-positive bait: `new URL(redirectUrl).hostname === 'trusted.com'` — the recommended fix — silent. |
| `test_incomplete_url_substring_sanitization_silent_non_url_receiver` | False-positive bait: `query.includes('example.com')` on a non-URL-ish variable — silent. |
| `test_incomplete_url_substring_sanitization_silent_non_domain_arg` | False-positive bait: `redirectUrl.includes('?next=')` — argument isn't domain-shaped — silent. |
| `test_incomplete_url_substring_sanitization_pragma_silences` | Pragma: `// security: allow-incomplete-url-substring-sanitization` silences the line. |
| `test_incomplete_url_substring_sanitization_does_not_apply_without_js` | Feature gate: `applies()` returns `False`, `run()` returns `[]`, for a profile without `javascript`/`express`. |

---

## Known bypasses

- **JS/TS anchoring (#1055).** The check call and the parse evidence count only when they are live code, tested with `js_code_matches` on the anchor mask: the call on its `(`, the evidence on its first character. A `new URL(` or `.hostname` named in a log or error string no longer clears a real finding, and a check spelled out in a docs string no longer fires; a real one nested in a `${...}` substitution still counts. Every check call on the line is tried, which also fixes a first-match shadowing FN that predates #1055: `.search` took only the first call, so a quoted copy, or a real call with no domain argument (`url.includes(q) || url.includes('trusted.com')`), hid the real check after it. Accepted residual: the domain argument is still read from the default view on purpose (it IS a string), so a domain-shaped quote nested inside a longer string argument (`url.includes("see 'trusted.com'")`) still counts, as before. Residual: the anchor mask inherits the #543 sub-lexer residual: a `{` inside a regex or comment in one `${...}` substitution, then a `}` in a later one, rebalances the frame, so the code between the two reads as template text and an anchor there is not code (the accepted trade pinned by `test_strip_js_comments_anchor_mask_balanced_desync_masks_code_accepted_trade`). A check there is missed (errs toward silence), and parse evidence there no longer clears (errs toward firing).

- **Indirection**: `const h = redirectUrl; if (h.includes('trusted.com'))` — the
  receiver name gate is defeated by reassigning to a generically-named variable first.
- **A domain literal built from concatenation or a constant** — only a same-line string
  literal argument is matched; `redirectUrl.includes(TRUSTED_DOMAIN)` where
  `TRUSTED_DOMAIN` is defined elsewhere is not tracked.
- **A receiver name with no URL-ish substring** despite genuinely holding a URL value
  (e.g. `dest`, `location` used as a local var name) — the name-based heuristic misses
  it.
- **A full-URL literal argument** (`.includes("https://trusted.com")`) — `_DOMAIN_LITERAL_ARG`
  matches on the bare-domain shape; a scheme-prefixed literal still matches since the
  regex only requires a dot-plus-letters substring somewhere in the quoted text, so this
  case is actually still caught (documented here as a design note, not a gap).

---

## What this guard does NOT prove

- It does not verify the checked value actually reaches an SSRF-capable fetch or a
  redirect sink — a substring check on a URL used only for logging or display carries
  no real exploit path, but this guard flags the check shape regardless (the pattern
  itself is always worth fixing, even if today's caller happens to be benign).
- It does not check whether a DIFFERENT, correct validation already happens elsewhere
  in the call chain — same-line, no-dataflow scope, consistent with the rest of this
  guard family.
- A silent guard does not mean the URL handling is safe — a reassigned/indirected
  receiver name or a non-literal domain argument is a real, undetected residual.

# Citations

[1] agentsec checklist item `3a-incomplete-url-substring-sanitization` (§3a)
[2] CWE-020
