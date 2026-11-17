---
type: Guard
title: "frontend-xss"
description: "Frontend XSS / SRI risk."
timestamp: "2026-06-12T10:08:45Z"
guard_id: "frontend-xss"
checklist_section: ["6a"]
standards: ["ASVS:3.6.1", "OWASP-LLM:LLM05", "OWASP:A03", "OWASP:A08"]
---

# Frontend XSS / SRI risk

_Backfilled 2026-06-12 — documents Dean's guard to the shared guard-design convention._

---

## The threat

Three distinct ways a React frontend ends up rendering attacker-controlled markup or loading
tampered third-party assets — all leading to **XSS / asset compromise** (OWASP A03,
OWASP-LLM:LLM05, the "insecure output handling" angle for LLM-generated text):

1. **`dangerouslySetInnerHTML`** — renders a raw HTML string into the DOM. If that string is
   user content or **LLM output** (a chat answer, a rendered markdown blob), it is a stored/
   reflected XSS vector.
2. **`rehype-raw` without (or before) `rehype-sanitize`** — a markdown pipeline that enables
   raw HTML passthrough. If the sanitizer is missing, raw HTML reaches the DOM unsanitized;
   if `rehypeSanitize` runs *before* `rehypeRaw`, the sanitizer processes the tree before the
   raw HTML exists, so it is silently bypassed. This is a real footgun shipped in many AI-chat
   starters.
3. **Third-party `<script>`/`<link>` without Subresource Integrity (SRI)** — an external asset
   with no `integrity=` hash can be swapped by a compromised CDN and execute in your origin.

## Why it's often introduced

`dangerouslySetInnerHTML` is the path of least resistance for "render this markdown/HTML."
The rehype plugin-order bug is subtle — both plugins are present, so it *looks* safe — and
SRI is simply omitted because the asset "works" without it.

## Detection design

1. **`applies()` gate** — `"frontend" in profile.features`.
2. **Scan root** — `profile.frontend_dir` (or root). Code checks run over
   `.ts/.tsx/.js/.jsx`; the SRI check runs over `.html`.
3. **dangerous-html** (`_dangerous_html`) — flags any line matching `dangerouslySetInnerHTML`
   unless the line *or the line above it* carries `# security: allow-dangerous-html`.
   Severity **high**, rule `frontend-xss/dangerously-set-inner-html`.
4. **rehype** (`_rehype_raw`) — only for files mentioning rehype-raw. If `rehypeSanitize`/
   `rehype-sanitize` is absent → **high**, rule `frontend-xss/rehype-raw-unsanitized`. If
   present, it parses the `rehypePlugins=[...]` array and flags when `rehypeRaw` appears
   *after* `rehypeSanitize` → **high**, rule `frontend-xss/rehype-order`.
5. **SRI** (`_sri`) — HTML comments are blanked first; then third-party `<script src>` and
   asset `<link href>` (stylesheet / `.css` / `.js`) without `integrity=` are flagged
   **medium**, rules `frontend-xss/script-no-sri` / `frontend-xss/link-no-sri`. "Third-party"
   is decided against an optional `first_party` host allowlist (constructor arg).
6. All findings share standards `["OWASP:A03", "OWASP-LLM:LLM05"]`.

## When NOT to flag

`dangerouslySetInnerHTML` on content that is provably sanitized (e.g. via DOMPurify) — annotate
with `# security: allow-dangerous-html`. A correct rehype order `[rehypeRaw, rehypeSanitize]`
passes. A first-party asset, or one with an `integrity=` attribute, is not an SRI finding;
hosts in the `first_party` allowlist are treated as same-origin.

## Tests

| Test | What it checks |
|---|---|
| `test_frontend_dangerous_html` | `dangerouslySetInnerHTML` use → HIGH |
| `test_frontend_dangerous_html_pragma_ok` | same with allow pragma (on line or line above) → silent |
| `test_frontend_rehype_order` | `rehypeSanitize` before `rehypeRaw` → HIGH (bypassed sanitizer) |
| `test_frontend_sri` | third-party `<script>` without integrity → MEDIUM |

## Known bypasses

- **Indirect prop spread** — `<div {...{dangerouslySetInnerHTML: html}} />` or a wrapper
  component hides the keyword from the line scan.
- **Dynamic plugin arrays** — building `rehypePlugins` from a variable, spread, or helper
  (not an inline `[...]` literal) escapes the order check.
- **Templated script tags** — scripts injected at runtime (e.g. via a `<Helmet>` or
  `document.createElement`) aren't in the static `.html` SRI scan.
- **Non-HTML asset loaders** — bundler-injected or dynamically-imported remote modules.

## What this guard does NOT prove

That the app is XSS-free. It catches three specific, common shapes; it does not trace data
flow into `dangerouslySetInnerHTML` (so it can't tell sanitized from unsanitized usage on its
own — hence the pragma), and it does not cover DOM-sink XSS, `href="javascript:"`, or
templating outside these patterns.

# Citations

[1] agentsec checklist item `6a-dangerously-set-inner-html` (§6a)
[2] agentsec checklist item `6a-sri-on-cdn-assets` (§6a)
[3] ASVS:3.6.1
[4] OWASP-LLM:LLM05
[5] OWASP:A03
[6] OWASP:A08
