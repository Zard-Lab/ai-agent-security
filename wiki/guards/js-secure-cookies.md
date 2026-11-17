---
type: Guard
title: "js-secure-cookies"
description: "Express cookies set with HttpOnly + Secure (+ SameSite)."
timestamp: "2026-08-09T11:25:41+08:00"
guard_id: "js-secure-cookies"
checklist_section: ["6a"]
standards: ["ASVS:3.3.1", "ASVS:3.3.4", "OWASP:A05"]
---

# Express cookies set with HttpOnly + Secure (+ SameSite)

_Author — 2026-08-09_

Flags an Express `res.cookie(name, value, options)` call whose `options` object is missing
`httpOnly: true` or `secure: true` (or has no options object at all), and independently a
sensitive cookie that sets `sameSite: 'none'` (or `"None"`) without a sibling `secure: true`.
Extends checklist item `6a-secure-cookies` (adds `"express"` to `applies_when` alongside the
existing `"python"` gate) — same language, same misconfiguration, same fix, as
`insecure-cookies` does for Flask/FastAPI/Starlette/Django's `set_cookie(...)`.

---

## The threat

A session/auth cookie set without `HttpOnly` is readable by JavaScript, so any XSS on the page
exfiltrates it; without `Secure` it is sent over plain HTTP, so a network attacker (or a
downgrade) reads it; without `SameSite` it rides along on cross-site requests (CSRF). Missing
these on a session cookie is account takeover. OWASP A05, ASVS 3.3.1 / 3.3.4.

`sameSite: 'none'` on a sensitive cookie is a distinct, sharper failure mode: Express's default
(no `sameSite` key at all) already leaves the browser's own default (Lax in every modern browser,
CSRF-safe) in place. Setting it explicitly to `'none'` re-enables cross-site delivery on purpose —
the exact exposure SameSite exists to prevent — and per the Set-Cookie spec, `SameSite=None`
without `Secure` is supposed to be rejected outright by a compliant browser, so the pairing failure
is itself a signal the author didn't mean to ship this. CWE-1275, sourced from CodeQL's
`javascript/ql/src/Security/CWE-614/ClearTextCookie.ql` — verified as a simple structural check
(`cookie.isSensitive() and not cookie.isSecure()`), not a dataflow query, which is why this guard
is a same-file regex/bracket scan rather than any kind of taint analysis.

## Why this guard fits the stack

Express's cookie-setting API is `res.cookie(name, value, options)`, where `options` is an object
literal that may carry `httpOnly`, `secure`, `sameSite`. The common vulnerable shapes:

```js
res.cookie('session', token);                                   // no options at all
res.cookie('auth_token', token, { httpOnly: false });            // explicit false
res.cookie('session', token, { httpOnly: true, sameSite: 'none' }); // secure missing
```

## Detection design

1. **`applies()`** — `"express" in profile.features`.
2. **Files scanned** — `iter_files(root, (".js", ".jsx", ".ts", ".tsx"))` (the shared walk
   helper: skips vendored/build dirs, nested worktrees, `.gitignore`-matched paths).
3. **Patterns / parse.** `strip_js_comments()` runs first, so a commented-out or documented
   `res.cookie(` never matches. `_RES_COOKIE` (`\bres\.cookie\s*\(`) finds each call on the
   COMMENT-STRIPPED text; `_call_args()` then splits its arguments on top-level commas via a
   bracket-counting scan that tracks `(){}[]` nesting together and skips over string/template
   literals — the same technique `js_cors_wildcard.py::_cors_config_object` uses for its config
   object, generalized here to the call's own argument list. This is necessary (not just
   convenient) because `{ httpOnly: true, secure: true }`'s internal comma sits at the exact same
   `()`-depth a real second/third argument would, so a paren-only counter (like
   `insecure_cookies.py`'s `_balanced_args`) cannot tell an options object's own commas from
   argument-separating ones. Because the scan runs on the whole file text rather than per line, a
   Prettier-formatted multi-line options object is found correctly.
   - **2 arguments (no options object)** → treated as "no security flags at all".
   - **3rd argument not starting with `{`** (a variable, spread, or expression) → skipped, can't
     be statically analyzed.
   - **3rd argument is `{...}`** → checked with `_HTTPONLY_TRUE` (`\bhttpOnly\s*:\s*true\b`),
     `_SECURE_TRUE` (`\bsecure\s*:\s*true\b`), `_SAMESITE_NONE`
     (`\bsameSite\s*:\s*['"]none['"]`) — all case-insensitive, all searched against the whole
     object-literal text so a multi-line object is matched regardless of which line a key sits on.
   - **Cookie name** — the first argument, resolved only if it's a literal quoted string
     (`_cookie_name` / `_STRING_LITERAL`). An unresolvable name (a variable) is treated as
     sensitive — the safer default, same policy as `insecure_cookies.py::_cookie_name`.
   - **Sensitive-name gate** — imports `_SENSITIVE_NAME` directly from `insecure_cookies.py`
     rather than duplicating the pattern, so the two guards can never drift on what counts as
     "sensitive" (session/auth/token/csrf/credential/secret/jwt/sid/api_key).
4. **Pragma** — `// security: allow-js-secure-cookies`, checked against the
   COMMENT-ONLY view of the line where `res.cookie(` itself starts (#424; mirrors
   `js_cors_wildcard.py`'s pragma handling, not `insecure_cookies.py`'s `#`-anchored regex, since
   JS line comments use `//`).
5. **Severity / rules** — all MEDIUM:
   - `js-secure-cookies/no-options` — `res.cookie(name, value)`, sensitive name, no options object.
   - `js-secure-cookies/missing-flags` — options object present but missing `httpOnly: true` and/or
     `secure: true`, sensitive name.
   - `js-secure-cookies/samesite-none` — `sameSite: 'none'` without a sibling `secure: true`,
     sensitive name. Independent of the flags check above — both can fire on the same call (e.g.
     `{ httpOnly: true, sameSite: 'none' }` is missing `Secure` under rule 2 AND fails the
     SameSite=None pairing under rule 3).
   - Standards: `["OWASP:A05"]` on the first two, `["OWASP:A05", "CWE-1275"]` on the third.

### Scope decision — all three rules gate on the sensitive-name heuristic

`insecure_cookies.py` (the Python sibling) splits its two rules differently: the missing-flags
rule applies to **every** `set_cookie(...)` call regardless of name, while only the SameSite=None
rule gates on a sensitive-looking name. This guard does **not** carry that split over — all three
of its rules (including the "no options at all" and "missing flags" ones) gate on the
sensitive-name heuristic. Reason: `res.cookie()` is used pervasively in real Express apps for pure
client-UX state that carries no security weight at all — theme preference, locale, an A/B test
flag, a "dismissed this banner" marker — and it is completely idiomatic to call it with no options
object whatsoever for exactly those cases (`res.cookie('theme_preference', 'dark')`). An
ALL-cookies missing-flags rule, unlike in the Python framework's `set_cookie` (typically called
for more deliberately stateful/security-relevant purposes), would flood a typical Express codebase
with a finding on every one of those calls. Gating on the name keeps the guard's signal on cookies
that actually carry session/auth/token weight, at the acknowledged cost of the same bypass the
Python guard already accepts (see Known bypasses).

## When NOT to flag

- All flags present — `res.cookie('session', t, { httpOnly: true, secure: true, sameSite: 'strict' })`
  → silent.
- A non-sensitive-named cookie, with or without an options object
  (`res.cookie('theme_preference', 'dark')`) → silent. Client-UX cookies are the common case and
  are not security-relevant.
- `sameSite: 'none'` paired with `secure: true` → silent (the correctly configured combination;
  modern browsers require this pairing for `SameSite=None` to be honored at all).
- Options passed as a variable/spread (`res.cookie(name, value, cookieOpts)`) → silent, since the
  guard cannot statically resolve what the variable contains.
- A deliberately non-`httpOnly` cookie (e.g. one a client script legitimately needs to read) →
  suppress the specific line with a `// security: allow-js-secure-cookies` comment.

## Tests

| Test | What it checks |
|---|---|
| `test_js_secure_cookies_flags_sensitive_no_options` | `res.cookie('session', token)` with no options at all fires `no-options`. |
| `test_js_secure_cookies_flags_httponly_false` | `{ httpOnly: false }` (secure absent too) fires `missing-flags` naming both. |
| `test_js_secure_cookies_flags_samesite_none_without_secure` | `sameSite: 'none'` without `secure: true` fires `samesite-none`. |
| `test_js_secure_cookies_silent_all_flags_present` | All three flags correctly set → silent. |
| `test_js_secure_cookies_silent_nonsensitive_no_options` | Non-sensitive name, no options → silent (the sensitive-name scoping). |
| `test_js_secure_cookies_pragma_silences` | a `// security: allow-js-secure-cookies` comment on the `res.cookie(` line silences it. |
| `test_js_secure_cookies_not_applies_without_feature` | `applies()` is False without `"express"` in the profile. |
| `test_js_secure_cookies_flags_multiline_missing_secure` | A Prettier-formatted multi-line options object missing `secure` still fires — proves the bracket-counting scan, not a same-line regex. |
| `test_js_secure_cookies_silent_multiline_all_flags_present` | Same multi-line shape, both flags present → silent — proves the scan works in both directions. |
| `test_js_secure_cookies_silent_on_commented_call` | A `// res.cookie(...)` comment does not fire — confirms `strip_js_comments` runs before matching, not just imported. |

## Known bypasses

- Flags set indirectly (a shared options object built elsewhere and passed by variable, a
  middleware wrapper, a framework-level default) are not seen — only a literal object-literal
  third argument is analyzed.
- A cookie set by writing the `Set-Cookie` header manually (`res.setHeader('Set-Cookie', ...)`) or
  via `res.append('Set-Cookie', ...)` is not matched — only `res.cookie(...)` calls.
- The sensitive-name check is a simple keyword match on the cookie's literal name string; a
  sensitive cookie given a deliberately generic name (`res.cookie('data', sessionToken)`) is
  missed by all three rules here (the same acknowledged trade-off as the Python sibling's
  SameSite=None rule, now extended to all three rules per the scope decision above).
- `httpOnly`/`secure` set to a variable that evaluates to `true` at runtime
  (`{ httpOnly: isProd }`) is not recognized as "true" — only the literal `true` token is matched,
  so this guard would flag it even though it may be correctly configured behind an env check (a
  false positive in production, a false negative in a misconfigured dev/staging build where
  `isProd` is `false`). Accepted: resolving arbitrary expressions is out of scope for a same-file
  regex/bracket guard.
- `sameSite` values are only checked against the literal `'none'`/`"none"` string; a value built
  from a variable or template literal is not seen.

## What this guard does NOT prove

It checks flags on literal `res.cookie(...)` calls with a literal options object; it does not
prove every cookie-setting path in the app is covered, nor that any cookie-parsing middleware or
proxy in front of the app preserves these flags. Absence of a finding does not mean all cookies
are hardened — it means no `res.cookie(...)` call this guard could statically resolve was missing
them.

# Citations

[1] agentsec checklist item `6a-secure-cookies` (§6a)
[2] ASVS:3.3.1
[3] ASVS:3.3.4
[4] OWASP:A05
