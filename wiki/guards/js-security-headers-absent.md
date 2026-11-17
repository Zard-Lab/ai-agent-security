---
type: Guard
title: "js-security-headers-absent"
description: "Express app sets no security response headers."
timestamp: "2026-10-21T00:00:00Z"
guard_id: "js-security-headers-absent"
checklist_section: ["6a"]
standards: ["ASVS:3.1.1", "ASVS:3.4.1", "OWASP:A05"]
---

# Express app sets no security response headers

_Added 2026-08-09 — the Express/JS sibling of `security-headers` (the FastAPI absence
guard). Extends checklist item `6a-security-headers`'s `applies_when` with `"express"` rather than
adding a new item: same underlying requirement, same section, different framework and detection
mechanism. Also the second **absence-detection** guard — tuned for false-positive safety over
completeness, same as its sibling._

---

## The threat

§6a of the checklist: *"Security headers on all responses (HSTS, CSP, X-Frame-Options,
X-Content-Type-Options, Referrer-Policy, ...)."* When an Express app sends responses without
these, a network-positioned or web attacker reaches the app's users to several effects:

- **Clickjacking** — no `X-Frame-Options` / CSP `frame-ancestors`: the app can be framed by a
  malicious page and the victim's authenticated clicks hijacked.
- **MIME-sniffing** — no `X-Content-Type-Options: nosniff`: a browser may execute a user-uploaded
  or reflected payload as a different content type (script).
- **Protocol downgrade / cookie theft** — no `Strict-Transport-Security`: a MITM can strip TLS on
  a first or stale-cache request and read session cookies.
- **Referrer leakage** — no `Referrer-Policy`: full URLs (tokens in query strings, internal paths)
  leak to third parties.

Findings carry `["OWASP:A05"]` (Security Misconfiguration) — the same standard as the FastAPI
sibling, since it's the same control.

Sourced from CodeQL's `javascript/ql/src/Security/CWE-451/MissingXFrameOptions.ql`, which CodeQL
itself rates `precision: low`. The reason is exactly why this guard is deliberately conservative: a
reverse proxy / CDN / load balancer can set headers entirely outside the repo, so absence-in-repo
is not proof of absence-in-production — hence LOW severity, not HIGH, and a generous evidence pass.

## Why it's often introduced / why this guard fits the stack

Express ships **no** security headers by default — the app author must add `helmet` or set headers
manually. Teams routinely assume the reverse proxy (nginx/Traefik) or the cloud LB sets headers —
sometimes true, often not, and never visible to a repo scan. The bad pattern is simply the
**absence** of any of:

```js
// none of these anywhere -> the app ships bare responses
app.use(helmet());
// or manual header-setting:
res.setHeader('X-Frame-Options', 'DENY');
res.set('Strict-Transport-Security', 'max-age=63072000');
```

## Detection design

1. **`applies()` gate** — `"express" in profile.features`.
2. **Scan** — every `.js`/`.jsx`/`.ts`/`.tsx` under `root` via `iter_files`, read once into
   `(path, text)` pairs.
3. **Global checks (not per-line)** — header coverage is an app-wide property, so the logic is
   repo-global and emits **at most one** finding:
   - **Evidence pass**, checked against **comment-stripped** code (`strip_js_comments`) so a
     comment or JSDoc merely mentioning "helmet" or a header name can't silence the guard — if
     **any** scanned file matches, silent:
     - `_HELMET_CALL` — any `helmet(...)` call, any form. Helmet is already an established
       header-setting signal (see the `js-helmet-header-disabled` guard).
     - `_MANUAL_HEADER_EVIDENCE` — a `.set(`/`.header(`/`.setHeader(` call whose first argument is
       one of the five standard header-name string literals (case-insensitive):
       `x-frame-options`, `content-security-policy`, `strict-transport-security`,
       `x-content-type-options`, `referrer-policy`.

     A match counts only when it is live code (#1055): its first character must survive the anchor
     mask (`strip_js_comments(text, strip_strings=True, keep_substitutions=True)`, through
     `js_code_matches`). The mask blanks string and template text across the whole file, so prose
     that merely spells out a call (`"install require('helmet')() for headers"`, a multi-line
     template of setup notes) is not evidence, while the patterns' own quoted arguments
     (`require('helmet')`, `.set('X-Frame-Options', …)`) still match because the anchor is never
     inside them. Substitution code is code, so a call nested in `${...}` counts. This replaced a
     private quote-parity heuristic (`_is_top_level_code`) that ignored backticks, could not see a
     string opened on an earlier line, and miscounted a quote inside a regex literal (`/'/`), which
     made a real `helmet()` after it read as prose and fire.
   - **Anchor pass** — only if no evidence: locate the app definition, first match wins — an
     `express()` instantiation, else a `require('express')` / `import express from 'express'`
     line (covers app modules that import Express but build the app via a factory elsewhere). No
     anchor at all → silent (nothing actionable to point at).
4. **Opt-out** — the repo-level pragma `// security: allow-missing-security-headers` in **any**
   scanned file silences the guard. Checked against the comment-only view of each file, since the
   pragma lives inside a real comment (a string literal quoting the phrase does not count, #424).
   Reuses the exact same pragma text as the FastAPI sibling — same underlying claim ("headers are
   set at the proxy"), just on the JS side too.
5. **Severity / rule** — **low**, `js-security-headers-absent/no-security-headers-middleware`,
   `["OWASP:A05"]`.

**Product-file anchoring.** Evidence and pragma are checked across **every** scanned file
(per the "a suppression must not void a user's own opt-out" rule — the pragma/evidence pass must
see everything the guard reads); the finding is only **anchored** in a product file
(`is_nonproduct_path` filters `product_files` before the anchor search). A library/example repo
that only shows `express()` inside `tests/`/`docs_src/` is not flagged.

**Severity rationale.** Same as the FastAPI sibling: **low** (below the default `--fail-on high`
CI gate) because it is an inherently lower-confidence absence advisory. Intentionally
**decoupled** from the `checklist.json` item severity (control importance vs. detection
confidence are different axes).

## When NOT to flag

Any app that calls `helmet()` in any form, or sets a recognized header manually via
`.set(`/`.header(`/`.setHeader(`, is clean (evidence pass). An app whose headers are terminated
upstream (reverse proxy / CDN / LB) is a legitimate negative the scan cannot see — the pragma is
for exactly that reviewed case. A repo with the `express` feature but no `express()`/`require`
import in scanned product source is not flagged (no anchor).

## Tests

| Test | What it checks |
|---|---|
| `test_js_security_headers_absent_flags_missing_evidence` | bare `express()` app, no headers anywhere → one LOW finding, anchored at the `express()` call |
| `test_js_security_headers_absent_silent_with_helmet` | `app.use(helmet())` anywhere → silent |
| `test_js_security_headers_absent_silent_with_manual_header` | a manual `res.setHeader('X-Frame-Options', ...)` call → silent |
| `test_js_security_headers_absent_pragma_opt_out` | `// security: allow-missing-security-headers` → silent |
| `test_js_security_headers_absent_pragma_quoted_in_a_string_does_not_opt_out` | a string literal quoting the pragma → still fires (#424) |
| `test_js_security_headers_absent_not_applicable_without_express` | `applies()` False without `express` |
| `test_js_security_headers_absent_anchors_on_import_when_no_instantiation` | no visible `express()` call → anchors on the `require('express')` line instead |
| `test_js_security_headers_absent_silent_when_express_only_in_tests` | `express()` only in a `tests/` fixture → not flagged (non-product anchor) |
| `test_js_security_headers_absent_not_silenced_by_comment_mentioning_helmet` | a comment mentioning "helmet" with no real call still fires — confirms evidence matching is comment-stripped |
| `test_js_security_headers_absent_known_bypass_indirect_header_name` | pins the documented known-bypass behavior below (see Known bypasses) |
| `test_js_security_headers_absent_quoted_evidence_does_not_silence` | #1055: a helmet or `.setHeader(` call spelled out in a string, one-line template or multi-line template still fires |
| `test_js_security_headers_absent_real_evidence_still_silences` | #1055: real evidence still silences, including after `/'/` on the line, after a quoted copy, and nested in `${...}` |

## Known bypasses

- **Indirect / aliased header name (confirmed via adversarial self-test).** A header name held in
  a variable and passed indirectly —
  ```js
  const headerName = 'X-Frame-Options';
  res.set(headerName, 'DENY');
  ```
  — is **not** recognized as evidence. `_MANUAL_HEADER_EVIDENCE` requires the header-name string
  literal directly as the call's argument; it has no dataflow analysis to trace a variable back to
  its assignment. In this exact case the guard still **fires** even though the header genuinely is
  being set — a false positive, not a false negative, so it fails toward "over-report" rather than
  "silently miss," which is the direction this guard is tuned to accept. Not fixed: a regex-only
  guard cannot safely do dataflow tracing without a real risk of matching an unrelated variable
  named similarly to a header (`hstsConfig`, `xfoValue`, ...) and creating the opposite, more
  dangerous failure (a guard that goes silent on genuinely bare responses). Pinned by
  `test_js_security_headers_absent_known_bypass_indirect_header_name`.
- **Template literals used to count as evidence (#548 round-4 gate; closed by #1055).** The private
  `_is_top_level_code` parity test tracked `'` and `"` only, so a template literal containing the
  text (`` console.log(`remember to require('helmet')() before prod`) ``, and the same text in a
  multi-line `` ` `` block) silenced the guard repo-wide. The whole-file anchor mask closes both
  shapes; they are pinned by `test_js_security_headers_absent_quoted_evidence_does_not_silence`.
- **The anchor mask inherits the #543 sub-lexer residual.** A `{` inside a regex or comment in one
  `${...}` substitution, then a `}` in a later one, rebalances the frame, so the code between the
  two reads as template text and a real `helmet()` there is not evidence (the accepted trade pinned
  by `test_strip_js_comments_anchor_mask_balanced_desync_masks_code_accepted_trade`). It errs toward
  firing, the direction this advisory accepts.
- **Headers set in a file the scan skips** — a vendored/excluded dir, or a non-JS config (e.g.
  middleware wired from a `.yaml`/`.json` reverse-proxy config) — would not count as evidence; the
  guard could false-positive. Mitigated by low severity + the pragma.
- **Non-standard custom header name** — a middleware that sets a bespoke header the regex doesn't
  list silences nothing and the app still flags. A header name passed to a real `.set(` call
  anywhere silences the guard (accepted: evidence is deliberately generous), but one spelled out in
  a comment, a string or template text does not.
- **Header set per-route, not globally** — one route sets HSTS, the rest don't → the single
  evidence hit silences the whole guard. Accepted trade-off for an advisory, same as the FastAPI
  sibling.

## What this guard does NOT prove

That responses are *correctly* secured — only that **some** header-setting exists (or is
deliberately deferred to the proxy). It does **not** verify the header **values** (a weak CSP, a
short `max-age`, `X-Frame-Options: ALLOWALL`), nor that **every** route/response is covered, nor
that the upstream proxy actually sets them. It is a presence/absence advisory, not a configuration
audit; the deeper value checks stay manual.

# Citations

[1] agentsec checklist item `6a-security-headers` (§6a)
[2] ASVS:3.1.1
[3] ASVS:3.4.1
[4] OWASP:A05
