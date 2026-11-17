---
type: Guard
title: "insecure-cookies"
description: "Cookies set with HttpOnly + Secure (+ SameSite)."
timestamp: "2026-06-17T13:36:34+08:00"
guard_id: "insecure-cookies"
checklist_section: ["6a"]
standards: ["ASVS:3.3.1", "ASVS:3.3.4", "OWASP:A05"]
---

# Cookies set with HttpOnly + Secure (+ SameSite)

Flags a `set_cookie(...)` call missing `httponly=True` or `secure=True`, and (independently) a
sensitive cookie that explicitly sets `samesite="none"`. Closes checklist item `6a-secure-cookies`.
Applies on `python`; the call is read across lines.

## The threat
A session/auth cookie without `HttpOnly` is readable by JavaScript, so any XSS exfiltrates it; without
`Secure` it is sent over plain HTTP, so a network attacker reads it; without `SameSite` it rides
cross-site requests (CSRF). Missing these on a session cookie is account takeover. OWASP A05.

**`samesite="none"` (added 2026-07-10, CodeQL `py/samesite-none-cookie` cross-check):** a
different failure mode from "SameSite absent" above — this is SameSite *explicitly disabled*.
Leaving SameSite unset defaults to Lax in every modern browser (CSRF-safe by default); setting it
to `"None"` deliberately re-enables cross-site delivery. On a session/auth/token-named cookie that
is the exact exposure SameSite exists to prevent. CWE-1275.

## Exploitability rationale
MEDIUM. Real and common, but it needs a second condition to exploit (an XSS, a MITM position, or a
CSRF-able endpoint), so it is a force-multiplier rather than a standalone critical.

## When NOT to flag (and the pragma)
- All flags present — `set_cookie(..., httponly=True, secure=True, samesite="Lax")` → silent.
- The two critical flags (HttpOnly + Secure) present but SameSite absent → not flagged (SameSite-only
  is lower-signal / higher-FP); the remediation still recommends adding it.
- A deliberately readable, non-session cookie → `# security: allow-insecure-cookie` on the line.
- `samesite="none"` on a cookie whose name doesn't look sensitive (session/auth/token/csrf/
  credential/secret/jwt/sid/api_key) → silent. A widget/embed preference cookie legitimately needs
  `SameSite=None` to survive a third-party iframe context; flagging every such cookie would be
  mostly noise. This mirrors CodeQL's own `cookie.isSensitive()` gate on the same query.
- Bare `samesite=None` (the Python `None` object, unquoted) → silent. In Flask and several other
  frameworks this means "don't set the SameSite attribute at all" (framework default applies), a
  different and safe behavior from the literal cookie attribute value `SameSite=None` — only the
  quoted string form (`"none"`/`'None'`) is matched.

## Known bypasses (honest limits)
- Flags set indirectly (a config object, a framework default like Django's `SESSION_COOKIE_SECURE`, or
  a wrapper helper) are not seen — only flags in the `set_cookie(...)` call itself.
- A cookie set by writing the `Set-Cookie` header manually (`response.headers['Set-Cookie'] = ...`) is
  not matched.
- `samesite=` value passed as a variable (`samesite=SAMESITE_VALUE`) rather than a literal quoted
  string is not seen by the samesite-none check.
- The sensitive-name check is a simple keyword match on the cookie's literal name string; a
  sensitive cookie given a deliberately generic name (`set_cookie("data", session_token)`) is missed.

## What this guard does NOT prove
It checks flags on literal `set_cookie` calls; it does not prove every cookie path is covered, nor that
framework-level cookie defaults are secure. Absence of a finding ≠ all cookies are hardened.

**Known limitation (fixed, review #395 M finding):** the cookie-name extraction used to
recognize only the positional first argument, so `set_cookie(key="session_id", value=sess,
samesite="none")` extracted no name at all and a real CSRF-exposed session cookie went
completely unflagged. It now also matches a `key="..."` keyword argument, and — the safer
default — treats a name it still can't statically extract (e.g. passed as a variable) as
sensitive rather than silently passing it.

# Citations

[1] agentsec checklist item `6a-secure-cookies` (§6a)
[2] ASVS:3.3.1
[3] ASVS:3.3.4
[4] OWASP:A05
