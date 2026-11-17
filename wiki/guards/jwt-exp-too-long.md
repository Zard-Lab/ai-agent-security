---
type: Guard
title: "jwt-exp-too-long"
description: "JWT access-token lifetime exceeds 24 hours."
timestamp: "2026-06-21T18:50:26+08:00"
guard_id: "jwt-exp-too-long"
checklist_section: ["2a"]
standards: ["OWASP:A07"]
---

# JWT access-token lifetime exceeds 24 hours

_Author — 2026-06-21_

---

## The threat

§2a of the checklist: *"Access tokens must be short-lived."* A long-lived access token dramatically
expands the attacker's window after a token is stolen. Unlike a session cookie that expires server-side
on logout, a JWT access token is stateless — once issued, it remains valid until its `exp` claim
passes, regardless of what happens server-side (password change, account suspension, explicit logout).

Concrete attack shape: an access token leaks via XSS, a log aggregator (Datadog, Logfire, Langfuse),
an SSRF response, or a mis-scoped observability event. With a 7-day or 30-day token, the attacker has
persistent, unrevokable access until the token expires. With a 15-minute token, the same leak provides
only a narrow gap.

Findings carry `["OWASP:A07", "CWE:613"]` (Identification and Authentication Failures; Insufficient
Session Expiration).

## Why it is often introduced / Why this guard fits the stack

FastAPI + JWT tutorials frequently use `timedelta(days=7)` or `ACCESS_TOKEN_EXPIRE_MINUTES = 10080`
as examples for convenience — they avoid the need to implement token refresh during development, and
the "it worked" result gets copied into production. LLM/RAG apps compound the risk: access tokens
appear in `Authorization: Bearer` headers that are logged by observability tools alongside prompt
text, making exfiltration via log inspection a real path.

Bad pattern (fires):

```python
ACCESS_TOKEN_EXPIRE_MINUTES = 10080  # 7 days — too long

access_token_expires = timedelta(days=30)   # 30 days — too long
expires_delta = timedelta(hours=48)          # 48 hours — too long
```

Good pattern (silent):

```python
ACCESS_TOKEN_EXPIRE_MINUTES = 60    # 1 hour — fine

access_token_expires = timedelta(minutes=15)  # 15 min — fine
REFRESH_TOKEN_EXPIRE_DAYS = 30               # refresh token — allowed
```

## Detection design

1. **`applies()` gate** — `"python" in profile.features`.

2. **Scan** — every `.py` under `python_scan_dirs`; line-by-line pass.

3. **Two patterns, checked per line:**

   - **Pattern 1 — named constant:** regex
     `r"(?:ACCESS_TOKEN_EXPIRE_MINUTES|access_token_expire_minutes|TOKEN_EXPIRE_MINUTES)\s*=\s*(\d+)"`
     captures the integer value; fires when `value > 1440`.

   - **Pattern 2 — timedelta in expiry context:** the variable on the left-hand side of the
     assignment is extracted and tested for expiry keywords (`expire`, `expir`, `token_lifetime`,
     `\bexp\b`). If the variable name also contains `refresh`, the line is skipped (refresh tokens
     may be long-lived). The timedelta argument is then matched for `days=`, `hours=`, or `minutes=`:
     - `days >= 1` → flag
     - `hours > 24` → flag
     - `minutes > 1440` → flag

4. **Opt-out pragma** — `# security: allow-long-lived-token` on the flagged line suppresses detection
   for that line.

5. **Severity and rule:** `high`, `jwt-exp-too-long/access-token-lifetime-too-long`,
   standards `["OWASP:A07", "CWE:613"]`.

## When NOT to flag

- Access-token lifetimes at or below 24 hours (1440 minutes).
- Any variable whose name contains `refresh` — refresh tokens are deliberately long-lived and have
  a different threat model (they are single-use or stored server-side with revocation).
- `timedelta(minutes=15)`, `timedelta(hours=1)`, `ACCESS_TOKEN_EXPIRE_MINUTES = 60` — all silent.
- Lines carrying the opt-out pragma.

## Tests

| Test | What it checks |
|---|---|
| `test_jwt_exp_too_long_fires_on_minutes_const` | `ACCESS_TOKEN_EXPIRE_MINUTES = 10080` fires HIGH |
| `test_jwt_exp_too_long_fires_on_timedelta_days` | `timedelta(days=30)` in expiry var fires HIGH |
| `test_jwt_exp_too_long_fires_on_timedelta_hours` | `timedelta(hours=48)` in expiry var fires HIGH |
| `test_jwt_exp_too_long_silent_on_refresh_token` | `REFRESH_TOKEN_EXPIRE_DAYS = 30` stays silent |
| `test_jwt_exp_too_long_silent_on_short_lifetime` | `timedelta(minutes=15)`, 60 min const silent |
| `test_jwt_exp_too_long_pragma_opt_out` | pragma on line suppresses finding |
| `test_jwt_exp_too_long_not_applicable_without_python` | `applies()` false without python feature |

## Known bypasses

- **Indirect assignment** — `EXPIRE = 10080; ACCESS_TOKEN_EXPIRE_MINUTES = EXPIRE` is not caught;
  Pattern 1 only matches literal integer right-hand sides.
- **Config indirection** — `ACCESS_TOKEN_EXPIRE_MINUTES = settings.token_ttl` is not matched (not
  a literal integer).
- **Dynamic timedelta** — `timedelta(minutes=LIFETIME)` where `LIFETIME` is a variable is not caught;
  only literal integers are extracted.
- **Aliased names** — `EXPIRY_DURATION = timedelta(days=7)` fires only if `expiry` matches the expiry
  keyword regex; unusual naming escapes detection.
- **Multi-line timedelta** — `timedelta(\n  days=30\n)` spanning multiple lines is not caught (each
  line is checked independently).

## What this guard does NOT prove

That token lifetime is managed securely end-to-end: it does not check that refresh tokens are
single-use, that revocation is implemented, that the `exp` claim is validated on decode, or that
tokens are stored securely on the client. A 1-hour access token stored in `localStorage` is caught
by `token-in-localstorage`, not this guard.

# Citations

[1] agentsec checklist item `2a-short-lived-access-tokens` (§2a)
[2] OWASP:A07
