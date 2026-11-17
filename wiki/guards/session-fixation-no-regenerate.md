---
type: Guard
title: "session-fixation-no-regenerate"
description: "Login route writes session without regenerating it first — session fixation."
timestamp: "2026-08-08T16:26:37+08:00"
guard_id: "session-fixation-no-regenerate"
checklist_section: ["2a"]
standards: ["CWE-384", "OWASP:A07"]
---

# Login route writes session without regenerating it first — session fixation

_Author — 2026-08-08_

---

## The threat

**Session fixation (CWE-384).** An attacker who can plant or predict a session identifier
before a victim authenticates — a shared login link carrying a session id, a session cookie
set by a sibling subdomain, or a session id issued to the attacker's own pre-login browsing —
can walk in behind the victim once the victim logs in, if the application keeps using the same
session identifier across the authentication boundary.

- **Who reaches it:** an unauthenticated attacker who can get a victim to use an
  attacker-known session identifier before logging in (a crafted link, a shared device, or a
  session id fixed via an unrelated XSS/subdomain issue).
- **Privilege required:** none — the attack targets the moment a victim authenticates.
- **Effect:** full account takeover of whatever the victim's post-login session grants.

Standards carried by findings: **OWASP:A07** (Identification and Authentication Failures),
**CWE-384** (Session Fixation).

---

## Why it's often introduced / Why this guard fits the stack

`express-session` (and `cookie-session`) issue a session identifier the first time a request
touches `req.session`, including on the login page itself before the user has authenticated.
A typical login handler writes the newly-authenticated user's id straight into that
already-existing session:

```js
// auth.js — a typical Express login handler
app.post('/login', (req, res) => {
  const user = authenticate(req.body.username, req.body.password);
  req.session.userId = user.id;   // reuses the PRE-login session id
  res.json({ ok: true });
});
```

The fix is one call — `req.session.regenerate(...)` — issued at the moment of authentication,
before any authenticated-user data is written. It is easy to skip because the app still works
correctly without it; nothing breaks functionally, the exposure is purely to an attacker who
fixed the identifier in advance.

Sourced from GitHub CodeQL's `js/session-fixation` query
(`javascript/ql/src/Security/CWE-384/SessionFixation.ql`, verified against real fetched
source): a route whose path matches `%login%`, whose handler writes `req.session.*`, flagged
unless the handler also calls `req.session.regenerate(...)`. CodeQL's own source notes
Passport used to be recognized as an exemption but "they have since added built-in protection
against session fixation" — no library-based exemption carried here either, matching that
decision.

---

## Detection design

1. **`applies()` gate** — `"express" in profile.features`. Session fixation via
   `req.session` is an Express-specific idiom; no Python-side equivalent is claimed (the
   Python stack's session handling goes through Starlette's `SessionMiddleware`, a different
   API surface with no equivalent regenerate-on-login convention checked here).

2. **Files scanned** — all `.js`/`.jsx`/`.ts`/`.tsx` files under `root`
   (`is_nonproduct_path` excluded), comment-stripped via `strip_js_comments` before matching.

3. **Logic (single-file, windowed):**

   - Find a route registration whose path string contains "login" (case-insensitive):
     `\.(?:get|post|put)\s*\(\s*["'][^"']*login[^"']*["']` — any receiver name
     (`app`/`router`/etc.), matching CodeQL's own `%login%` substring test.
   - Within the next 30 lines, look for `req.session.<prop> =` (a write).
   - If a write is found and `req.session.regenerate(` does NOT appear anywhere in that same
     30-line window, emit one MEDIUM finding at the route registration line.

   This is intentionally windowed rather than a real brace-matched handler-body walk — the
   codebase's established tradeoff for JS/TS guards that need "does X happen inside this
   block" without a JS parser (mirrors `zip-slip`'s 5-line window and several sibling guards).

4. **Inline opt-out pragma** — `// security: allow-session-fixation` on the route
   registration line (checked against the unstripped source at that line, not repo-wide —
   a file may register several login routes and only one may need suppression).

5. **Severity / rule / standards:**
   - Severity: `medium` (real exploitability requires an attacker-controllable pre-login
     session identifier — a real but narrower precondition than an unconditional CRITICAL
     sink, consistent with `insecure-cookies`'s SameSite=None rule at the same severity for a
     comparable session-integrity class).
   - Rule: `session-fixation-no-regenerate/login-writes-session-without-regenerate`
   - Standards: `["OWASP:A07", "CWE-384"]`

---

## When NOT to flag

- **`req.session.regenerate(...)` present** anywhere in the same 30-line window as the
  session write — the guard is silent regardless of call order relative to the write (a
  regenerate call anywhere in the handler is evidence the developer knows to rotate the
  session; requiring strict ordering would need a parse, not a window scan).
- **No session write at all** — a login route that issues a stateless JWT with no
  `req.session` involvement has nothing to fixate.
- **Not a login route** — a path string without "login" (a shopping cart, a settings update)
  writing to `req.session` is ordinary session use, not an authentication boundary.
- **Pragma suppressed** — `// security: allow-session-fixation` on the route line.

---

## Tests

| Test | What it checks |
|---|---|
| `test_session_fixation_fires_without_regenerate` | True positive: `/login` route writes `req.session.userId`, no `regenerate()` anywhere nearby — fires MEDIUM. |
| `test_session_fixation_silent_when_regenerate_called` | False-positive bait: `req.session.regenerate(...)` present in the same window — silent even though the write is nested inside its callback. |
| `test_session_fixation_silent_on_router_receiver` | True positive: `router.post(...)` (not just `app.post`) is matched the same way. |
| `test_session_fixation_silent_no_session_write` | False-positive bait: a `/login` route that never touches `req.session` (stateless JWT) — silent. |
| `test_session_fixation_silent_on_non_login_route` | False-positive bait: `/cart/add` writing `req.session.cart` — not a login path, silent. |
| `test_session_fixation_pragma_silences` | Pragma: `// security: allow-session-fixation` on the route line silences that route. |
| `test_session_fixation_does_not_apply_without_express` | Feature gate: `applies()` returns `False`, `run()` returns `[]`, for a profile without `express`. |

---

## Known bypasses

- **Handler body exceeds the 30-line window**: a login route whose session write or
  `regenerate()` call sits more than 30 lines past the route registration is not tracked in
  either direction — a real leak past the window is a false negative, a real fix past the
  window is a false positive.
- **Handler defined elsewhere and referenced by name**: `app.post('/login', handleLogin)`
  where `handleLogin` is a separately-defined function — the route line alone has no session
  write or regenerate call to find; a multi-file/cross-function pattern is out of scope.
- **Dynamic path construction**: `app.post(loginPath, ...)` where `loginPath` is a variable
  set elsewhere to `"/login"` — the path-string regex only sees a literal containing "login".
- **A regenerate call for an unrelated route within the same 30-line window**: two route
  registrations close together, one of which calls `regenerate()`, could in principle silence
  a genuinely vulnerable neighbour — not observed in practice given typical route-per-block
  formatting, but a real limitation of the window approach.

---

## What this guard does NOT prove

- It does not verify `regenerate()` is called BEFORE the session write completes — only that
  both appear somewhere in the same window. A `regenerate()` call after the sensitive data is
  already written provides no protection, and this guard would incorrectly stay silent.
- It does not check that the regenerated session correctly re-establishes any data the
  pre-login session legitimately needs (a shopping cart, a CSRF token) — that is an
  application-correctness concern, not this guard's scope.
- A silent guard does not mean session fixation is fully mitigated — a custom rotation scheme
  that does not call a function literally named `regenerate` (a manual `req.sessionID =
  crypto.randomUUID()` reassignment, for example) is not recognized as a fix.

# Citations

[1] agentsec checklist item `2a-session-regenerated-on-login` (§2a)
[2] CWE-384
[3] OWASP:A07
