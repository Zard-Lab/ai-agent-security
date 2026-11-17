---
type: Guard
title: "js-host-header-email-link"
description: "Host header used to build a link in an outgoing email."
timestamp: "2026-08-07T07:10:37+08:00"
guard_id: "js-host-header-email-link"
checklist_section: ["6a"]
standards: ["OWASP:A01"]
---

# Host header used to build a link in an outgoing email

_Author — 2026-08-07_

---

## The threat

An attacker sends a request to any endpoint that (eventually) triggers an outgoing email —
password reset, invite, email verification — with a forged `Host` header
(`Host: evil.example.com`). Unlike most other request headers, nothing between the attacker
and the application is guaranteed to normalize `Host`; it is trivially attacker-controlled on
the attacker's own request. If the handler builds the link embedded in that email from
`req.headers.host` (or `req.get('host')` / `req.hostname`), the link a *different, real* victim
receives points at the attacker's domain instead of the real app. The victim clicks it,
believing it's their own password-reset email, and the reset/invite/verification token lands
in the attacker's server logs. This is full account takeover via a single crafted request, no
XSS or CSRF required. CWE-640, OWASP:A01 (Broken Access Control / trust boundary violation).
codeql `@security-severity 9.8`.

## Why this guard fits the stack

Express apps commonly build absolute links for transactional email like this:

```js
async function sendPasswordReset(user, token) {
  const link = `https://${req.headers.host}/reset-password?token=${token}`;
  await transporter.sendMail({ to: user.email, html: `Click here: ${link}` });
}
```

This reads naturally — `req.headers.host` looks like "the app's own domain" to a developer who
hasn't internalized that the client fully controls it. agentsec's existing
`6a-trusted-host-middleware` item only covers FastAPI's `TrustedHostMiddleware` (a Python-only
allowlist mechanism); there is no Express/Node equivalent in the checklist, and no existing
guard ties a Host-header read specifically to an email-generation sink (the general "Host header
used to build a URL" family of bugs is broader than what this guard scopes to — see Known
bypasses).

## Detection design

1. **`applies()` gate** — `"express" in profile.features`.
2. **Files scanned** — `iter_files(root, (".js", ".jsx", ".ts", ".tsx"))`, skipping
   `is_nonproduct_path` (archive/vendor/test-fixture segments).
3. **Pattern, file-scoped in two parts** (the host-header read and the `sendMail` call are
   typically separate statements, not one expression, so this can't be a single-line-only
   regex the way a config-literal check can be):
   - File-level gate: `_MAIL_SEND_INDICATOR` — a `.sendMail(` call, or a `nodemailer`
     `require`/`import`. If absent, skip the file entirely (no mail-sending context at all).
   - Line-level check (only run on files that passed the gate): `_HOST_HEADER_READ`
     (`req.headers.host` / `req.headers['host']` / `req.get('host')` / `req.hostname`) AND
     `_URL_SCHEME_MARK` (a literal `://`) present on the **same line** — i.e. the host-header
     read is being spliced into an absolute URL on that line, not just logged or compared.
4. **Pragma** — `// security: allow-js-host-header-email-link` on the URL-building line.
5. **Severity/rule** — HIGH, `js-host-header-email-link/host-header-in-email-url`, standards
   `["OWASP:A01", "CWE-640"]`.

## When NOT to flag

- The Host header is read but never spliced into a URL on the same line (e.g. logged, or
  compared against an allowlist) — stays silent even in a file that sends email.
- The file builds an absolute URL from a trusted, configured base (`process.env.APP_BASE_URL`,
  a hardcoded domain constant) rather than the request's own Host header — stays silent even if
  the file also sends email.
- A file reads the Host header and builds a URL from it, but the file has no mail-sending
  indicator at all (e.g. it's building a redirect target or a canonical-link `<meta>` tag) —
  this guard stays silent; that's a different sink than the one it's scoped to (see Known
  bypasses).

## Tests

| Test | What it checks |
|---|---|
| `test_js_host_header_email_link_flags_template_literal` | `${req.headers.host}` spliced into a template-literal URL inside a `sendMail` file fires |
| `test_js_host_header_email_link_flags_concatenation` | `'https://' + req.headers.host + ...` (string concatenation, not just template literals) fires |
| `test_js_host_header_email_link_silent_without_mail_context` | Host header built into a URL, but the file never sends email — silent (FP-bait) |
| `test_js_host_header_email_link_silent_host_logged_no_scheme` | Host header present in a mail-sending file, but only logged (no `://` on the line) — silent (FP-bait) |
| `test_js_host_header_email_link_silent_trusted_base_url` | Mail-sending file builds its link from a trusted config var, not the Host header — silent (FP-bait) |
| `test_js_host_header_email_link_pragma` | Inline pragma suppresses |
| `test_js_host_header_email_link_not_applies_without_express` | `applies()` is `False` without the `express` feature |

## Known bypasses

- **Assign-then-use across lines without a scheme marker on the assembly line itself**: e.g.
  `const h = req.headers.host; const link = \`https://${h}/reset\`;` — the host-header read and
  the `://` marker land on different lines, so the same-line co-occurrence check misses it. A
  real dataflow engine (which is what CodeQL's own query is) would catch this; this guard
  trades that recall for zero dependencies and no false-flagging of ordinary Host-header reads
  that never become a URL.
- **Indirect mail send**: any mail-sending call other than `.sendMail(` / a `nodemailer`
  import (e.g. a queued-job email system, a third-party transactional-email SDK like SendGrid's
  `.send(`) is invisible to `_MAIL_SEND_INDICATOR` and the whole file is skipped.
- **A general-purpose URL-building helper function**: if the Host-header read and URL
  assembly happen inside a shared utility function in a *different* file from the one that
  calls `.sendMail(`, this guard's file-scoping never connects the two.

## What this guard does NOT prove

A silent result does not mean the app is safe from Host-header poisoning generally — this
guard is scoped specifically to the **email-generation sink** (mirroring CodeQL's own query
scope, `HostHeaderPoisoningInEmailGenerationQuery`). A Host header spliced into a redirect
target, a canonical `<link>` tag, a CSP `Access-Control-Allow-Origin` value, or any other sink
is not covered here and would need its own guard (or dataflow analysis) to catch.

# Citations

[1] agentsec checklist item `6a-js-host-header-email-link` (§6a)
[2] OWASP:A01
