---
type: Guard
title: "rate-limit-no-user-key"
description: "Rate limiter keyed only on IP address — bypassed by botnet/proxy rotation."
timestamp: "2026-06-21T19:50:18+08:00"
guard_id: "rate-limit-no-user-key"
checklist_section: ["2c"]
standards: ["OWASP-LLM:LLM10", "OWASP:A04"]
---

# Rate limiter keyed only on IP address — bypassed by botnet/proxy rotation

_Author — 2026-06-21_

---

## The threat

**IP-only rate limiting bypassed by botnet/proxy rotation.**  slowapi's default `key_func` is
`get_remote_address` (the client IP).  An attacker with access to a pool of exit nodes (botnet,
VPN, Tor) can rotate IPs to bypass IP-keyed rate limits on login, password-reset, OTP, and other
high-value endpoints.  Additionally, shared NATs mean many legitimate users share one IP —
IP-based limits cause false positives for enterprise or campus users.  For authenticated endpoints,
the correct key is a stable user identity (user ID, JWT subject, API key).

- **Who reaches it:** any attacker with multiple egress IPs.
- **Privilege required:** none for login/OTP endpoints.
- **Effect:** brute-force bypass on rate-limited authentication endpoints.

Standards: **OWASP:A04** (Insecure Design).

---

## Detection design

1. **`applies()`** — `"python" in profile.features`.
2. **Files scanned** — all `.py` files in `python_scan_dirs`.
3. **Cross-file logic:**
   - Pass 1: if no file imports `slowapi` or `limits` → return `[]` (library not in use).
   - Pass 2: scan all files for `Limiter(` calls; capture `key_func=` value with `_KEY_FUNC_VAL`.
   - Pass 3: if ANY `key_func` value contains a user-identity signal (`user_id`, `current_user`,
     `get_current`, `authenticated`, `.sub`, `identity`) → return `[]` (benefit of the doubt).
   - If ALL captured `key_func` values are `get_remote_address` with no user signal anywhere →
     emit one MEDIUM finding at the first `Limiter(` line,
     rule `rate-limit-no-user-key/ip-only-key-func`.
4. **Severity:** `medium`; **Standards:** `["OWASP:A04"]`.

---

## Tests

| Test | What it checks |
|---|---|
| `test_rate_limit_no_user_key_fires` | `Limiter(key_func=get_remote_address)` with no user-identity signal → MEDIUM finding. |
| `test_rate_limit_no_user_key_user_key_silences` | `key_func=get_user_id` present → silent. |
| `test_rate_limit_no_user_key_no_slowapi_silent` | No `import slowapi` → silent. |
| `test_rate_limit_no_user_key_pragma_silences` | `# security: allow-ip-rate-limit-only` → silent. |

# Citations

[1] agentsec checklist item `2c-per-user-rate-limiting` (§2c)
[2] OWASP-LLM:LLM10
[3] OWASP:A04
