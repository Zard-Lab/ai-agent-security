---
type: Guard
title: "session-no-csrf"
description: "SessionMiddleware used without CSRF protection."
timestamp: "2026-06-21T18:50:26+08:00"
guard_id: "session-no-csrf"
checklist_section: ["6a"]
standards: ["CWE-352", "OWASP:A01"]
---

# SessionMiddleware used without CSRF protection

_Author — 2026-06-21_

---

## The threat

**Cross-Site Request Forgery (CSRF) via session cookie.** Any attacker-controlled web page can
cause a logged-in user's browser to submit authenticated HTTP requests to the target FastAPI app.
The browser attaches the session cookie automatically; the server cannot distinguish a legitimate
user action from an attacker-initiated cross-origin form submission.

- **Who reaches it:** any unauthenticated attacker on the internet who can trick a logged-in user
  into visiting a malicious page (phishing link, injected iframe, ad, community forum post).
- **Privilege required:** the victim must have an active browser session — zero attacker privilege.
- **Effect:** the attacker can trigger any state-changing operation the victim can perform:
  password or email change, privilege escalation, fund transfer, API key rotation, data deletion.

Standards carried by findings: **OWASP:A01** (Broken Access Control), **CWE:352** (CSRF).

---

## Why it's often introduced / Why this guard fits the stack

FastAPI's `SessionMiddleware` (from Starlette) is the standard way to add server-side sessions:

```python
# main.py — a typical FastAPI setup
from starlette.middleware.sessions import SessionMiddleware

app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
```

Developers add `SessionMiddleware` to enable OAuth flows, "remember me" logins, or multi-step
wizards. CSRF protection is a separate, explicit step that is easy to skip — the framework does
not add it automatically and no linter warns about its absence. The result is a deployed app with
cookie-based sessions and no CSRF defence.

---

## Detection design

1. **`applies()` gate** — fires on `"fastapi" in profile.features or "python" in profile.features`.
   Cast wide: any Python app that uses sessions is at risk.

2. **Files scanned** — all `.py` files returned by `iter_files(d, (".py",))` over each dir in
   `python_scan_dirs(root, profile)`, deduplicated with a `seen: set[Path]` guard.

3. **Logic (cross-file, repo-wide):**

   - **Step 1:** collect every file that contains the literal string `SessionMiddleware`.
   - **Step 2:** scan all files for any CSRF protection marker:
     `CSRFMiddleware`, `starlette_csrf`, `fastapi_csrf`, `CsrfProtect`, `csrf_token`,
     `double_submit`.
   - **Step 3:** if Step 1 is non-empty AND Step 2 found nothing, emit one `Finding` per
     Step-1 file, pointing at the first line that contains `SessionMiddleware`.

   This is intentionally cross-file: the session and the CSRF defence are almost always in
   different modules (e.g. `main.py` vs `dependencies.py`), so a per-file check would generate
   false positives on every `SessionMiddleware` file even when CSRF is present elsewhere.

4. **Inline opt-out pragma** — `# security: allow-no-csrf` (anywhere in any scanned file, repo-wide).
   Presence of the pragma in any file silences the entire check.

5. **Severity / rule / standards:**
   - Severity: `high`
   - Rule: `session-no-csrf/session-middleware-without-csrf`
   - Standards: `["OWASP:A01", "CWE:352"]`

---

## When NOT to flag

- **CSRF protection present:** any of the six markers (`CSRFMiddleware`, `starlette_csrf`,
  `fastapi_csrf`, `CsrfProtect`, `csrf_token`, `double_submit`) appear anywhere in the codebase.
  The guard is silent even if only one file carries the marker.
- **Pragma suppressed:** `# security: allow-no-csrf` in any scanned Python file.
- **No sessions at all:** `SessionMiddleware` is not present in any scanned file — nothing to check.

The pragma is appropriate when the app uses stateless JWT bearer auth exclusively (no session
cookie reaches state-changing endpoints), or when `SameSite=Strict` is enforced server-side for
all session cookies and the risk is accepted by the team.

---

## Express/Node extension (codeql `js/missing-token-validation`)

Same repo-wide presence/absence shape, run as an independent scan over JS/TS files:

1. **`applies()` gate** — extended to also fire on `"express" in profile.features`.
2. **Files scanned** — all files under `root` with `.js`/`.jsx`/`.ts`/`.tsx` suffixes.
3. **Session markers:** `express-session`, `cookie-session` (require/import string match).
4. **CSRF markers:** `csurf`, `lusca`, `tiny-csrf`, `csrf-csync`, `doubleCsrf`, `csrfProtection`.
5. **Pragma:** `// security: allow-no-csrf` anywhere in a scanned JS/TS file silences the JS half only.

Deliberately kept as a fully separate scan from the Python path rather than pooling both
languages' files into one marker search — a Python `starlette_csrf` import says nothing about
whether an Express app in the same monorepo has CSRF protection, and pooling them would let one
stack's protection silently vouch for the other's absence.

---

## Tests

| Test | What it checks |
|---|---|
| `test_session_no_csrf_fires` | True positive: `SessionMiddleware` present, no CSRF markers anywhere; guard emits a finding with the correct rule. |
| `test_session_no_csrf_silent_csrf_present` | False positive guard: `SessionMiddleware` + `CSRFMiddleware` in a second file; guard stays silent. |
| `test_session_no_csrf_pragma_silences` | Pragma path: `# security: allow-no-csrf` on any line silences the check even with no CSRF markers. |
| `test_session_no_csrf_applies_gate` | `applies()` returns False for a profile with neither `fastapi` nor `python` in features; `run()` returns `[]`. |
| `test_session_no_csrf_no_session_silent` | Baseline: no `SessionMiddleware` anywhere; guard stays silent. |
| `test_session_no_csrf_finding_location` | Location in the emitted finding points to the file:line containing `SessionMiddleware`. |
| `test_session_no_csrf_applies_on_express` | `applies()` returns `True` for a profile with `express` in features. |
| `test_session_no_csrf_js_fires` | True positive: `express-session` required, no JS CSRF markers anywhere; guard fires. |
| `test_session_no_csrf_js_silent_csrf_present` | False positive guard: `express-session` + `csurf` in a second file; guard stays silent. |
| `test_session_no_csrf_js_pragma_silences` | Pragma path: `// security: allow-no-csrf` silences the JS half. |
| `test_session_no_csrf_js_no_session_silent` | Baseline: no session middleware required anywhere in JS/TS files; guard stays silent. |

---

## Known bypasses

- **Import aliasing:** `from starlette.middleware.sessions import SessionMiddleware as SM` — the
  import line still contains `SessionMiddleware` so the guard still detects it. But
  `app.add_middleware(SM, ...)` without the original name on the same line is still caught at
  the import level.
- **Dynamic middleware registration:** `middleware_list = [SessionMiddleware]` assembled at runtime
  and passed to the app factory — the string is present; detection holds.
- **CSRF library not imported at the string level:** an entirely custom CSRF implementation that
  does not use any of the six marker strings (e.g. a bespoke `verify_request_token()` function
  with no reference to "csrf") will not be detected. The guard would fire even though CSRF
  protection exists.
- **SessionMiddleware in a string literal or comment:** the guard would count it as a session
  file. Unlikely to cause a real false positive in practice, but technically possible.
- **CSRF markers only in test files:** if the only `CSRFMiddleware` reference is in a test fixture,
  the guard goes silent even though production code is unprotected. `iter_files` / `walk_files`
  respects `.gitignore` but does not exclude `tests/` by default.

---

## What this guard does NOT prove

- It does not verify that the CSRF middleware is mounted in the correct order (it must be added
  before or after `SessionMiddleware` depending on the library's requirements).
- It does not check whether the CSRF token is actually validated on all state-changing routes —
  a developer could import `CsrfProtect` but forget to inject it as a dependency.
- It does not verify `SameSite` cookie attributes, which can provide partial CSRF mitigation.
- It does not detect CSRF risk in non-FastAPI Python frameworks (Django, Flask) unless they also
  appear in `profile.features` — the gate is `"python"` which is broad but the markers are
  FastAPI/Starlette-ecosystem-specific.
- A silent guard does not mean CSRF is fully mitigated — it means one of the six marker strings
  exists in the codebase. A custom CSRF implementation is possible; a mis-configured one is too.

# Citations

[1] agentsec checklist item `6a-csrf-protection` (§6a)
[2] CWE-352
[3] OWASP:A01
