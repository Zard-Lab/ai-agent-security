---
type: Guard
title: "trusted-host-absent"
description: "FastAPI app running without TrustedHostMiddleware."
timestamp: "2026-06-21T19:50:18+08:00"
guard_id: "trusted-host-absent"
checklist_section: ["6a"]
standards: ["OWASP:A05", "SOC2:CC6.6"]
---

# FastAPI app running without TrustedHostMiddleware

_Author — 2026-06-21_

---

## The threat

**Host-header injection in FastAPI apps without TrustedHostMiddleware.**  FastAPI (via Starlette)
uses the incoming `Host` header verbatim to construct `request.base_url` and `request.url_for(...)`.
An attacker who controls the `Host` header can:

- **Poison HTTP caches** — cached responses carry URLs built from the injected hostname; when served
  to other users, those links point to the attacker's domain.
- **Hijack password-reset and email-verification links** — the reset URL is built from
  `request.base_url`; if the attacker controls `Host`, the link lands on their server, handing over
  the token.
- **Internal-vhost SSRF** — some reverse-proxy setups route requests by `Host` value; an attacker
  who can forge the header may reach internal services not intended for public exposure.

- **Who reaches it:** any HTTP client that can set a `Host` header (default for all HTTP clients).
- **Privilege required:** none — the `Host` header is sent before authentication.
- **Effect:** credential/token theft via forged links; cache poisoning; SSRF to internal hosts.

Standards carried by findings: **OWASP:A05** (Security Misconfiguration), **OWASP:ASVS** (V14).

---

## Why it's often introduced / Why this guard fits the stack

Developers write `app = FastAPI()` and add routes without thinking about `Host` header trust.
`TrustedHostMiddleware` is not enabled by default in Starlette/FastAPI — it must be explicitly
added with an allow-list:

```python
from starlette.middleware.trustedhost import TrustedHostMiddleware

app.add_middleware(TrustedHostMiddleware, allowed_hosts=["api.example.com"])
```

This step is not part of the FastAPI "Getting Started" tutorial and is not enforced by any linter.
The vulnerability is only apparent when a feature like password-reset email generation is added —
by which point the middleware omission is already in production.

---

## Detection design

1. **`applies()` gate** — fires on `"fastapi" in profile.features and "python" in profile.features`.
   Both conditions required: the guard is FastAPI-specific.

2. **Files scanned** — all `.py` files returned by `iter_files(d, (".py",))` over each dir in
   `python_scan_dirs(root, profile)`, deduplicated with a `seen: set[Path]` guard.

3. **Logic (cross-file, repo-wide absence check):**

   - **Step 1:** scan all files for `r"(?:^|\s)app\s*=\s*FastAPI\s*\("` (regex `_APP_INIT`).
     Record the first file+line that matches. Stop after the first hit.
   - **Step 2:** if a FastAPI app init was found, scan all files for the literal string
     `TrustedHostMiddleware`. If found anywhere, guard is silent.
   - **Step 3:** if app init found AND `TrustedHostMiddleware` absent — emit **one finding**,
     anchored to the first app-init file:line.

   Cross-file because the middleware is typically added in a separate `middleware.py` or
   `main.py` from the app-init file.

4. **Inline opt-out pragma** — `# security: allow-no-trusted-host` (anywhere in any scanned
   Python file, repo-wide). Present in any file silences the entire check.

5. **Severity / rule / standards:**
   - Severity: `medium`
   - Rule: `trusted-host-absent/no-trusted-host-middleware`
   - Standards: `["OWASP:A05", "OWASP:ASVS"]`

---

## When NOT to flag

- **`TrustedHostMiddleware` present:** the string appears in any scanned Python file.
- **Pragma suppressed:** `# security: allow-no-trusted-host` in any scanned Python file.
- **No FastAPI app init:** `app = FastAPI(` not found in any scanned file.
- **Behind a validating proxy:** the proxy (nginx, Caddy, AWS ALB with `Host` header routing
  rules) enforces the allow-list before the request reaches FastAPI; suppress with pragma.

---

## Tests

| Test | What it checks |
|---|---|
| `test_trusted_host_absent_fires` | True positive: `app = FastAPI(` present, no `TrustedHostMiddleware` anywhere; guard emits one finding with correct rule and medium severity. |
| `test_trusted_host_absent_silent_middleware_present` | False positive guard: `TrustedHostMiddleware` in a second file; guard stays silent. |
| `test_trusted_host_absent_pragma_silences` | Pragma path: `# security: allow-no-trusted-host` in any file silences the check. |
| `test_trusted_host_absent_applies_gate` | `applies()` returns False for a profile without both `fastapi` and `python` in features. |
| `test_trusted_host_absent_no_fastapi_silent` | Baseline: no `app = FastAPI(` anywhere; guard stays silent. |
| `test_trusted_host_absent_finding_location` | Location points to the file:line containing `app = FastAPI(`. |

---

## Known bypasses

- **Assignment aliasing:** `my_app = FastAPI()` — the regex `app\s*=\s*FastAPI\s*\(` requires the
  variable to be named `app`; a differently-named app object is missed. This is the predominant
  convention in FastAPI projects.
- **App factory pattern:** `def create_app() -> FastAPI: return FastAPI()` — the `return FastAPI()`
  line does not match `app\s*=` and is not detected.
- **`TrustedHostMiddleware` in a comment or string:** the string check is a plain `in` test;
  a middleware name in a comment would suppress the finding even if the middleware is not actually
  mounted.

---

## What this guard does NOT prove

- It does not verify that `allowed_hosts` in `TrustedHostMiddleware` is properly restricted
  (e.g. `["*"]` disables all checking and is equivalent to no middleware).
- It does not check whether the proxy upstream of FastAPI actually forwards or strips the `Host`
  header correctly.
- It does not detect `Host` injection risk in non-FastAPI Python frameworks.

# Citations

[1] agentsec checklist item `6a-trusted-host-middleware` (§6a)
[2] OWASP:A05
[3] SOC2:CC6.6
