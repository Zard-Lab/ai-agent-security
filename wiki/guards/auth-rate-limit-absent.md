---
type: Guard
title: "auth-rate-limit-absent"
description: "Auth-sensitive route has no rate-limiting protection."
timestamp: "2026-10-03T12:28:45+02:00"
guard_id: "auth-rate-limit-absent"
checklist_section: ["2c"]
standards: ["OWASP-LLM:LLM10", "OWASP:A04", "OWASP:A07", "OWASP:API4"]
---

# Auth-sensitive route has no rate-limiting protection

## What it detects

A FastAPI/APIRouter route decorator whose path string (or the handler function name declared
on one of the following lines) looks auth-sensitive — login, sign-in, sign-up, register,
reset/forgot/change-password, authenticate, or a `/token` path — in a Python file with NO
recognized rate-limiting signal, on a route that rate limiting wired elsewhere in the app does not
cover either (a rate-limited router mount, slowapi global limits, or an app-level dependency; see
**Cross-file coverage** below).

## Why it matters

Auth-sensitive endpoints are a direct brute-force and credential-stuffing target. A single
unauthenticated caller can hammer `/login` with sequential password guesses, or flood
`/register` to exhaust invite quotas or spam downstream email/SMS verification providers.
`llm-rate-limit-absent` already closes this gap for routes that make a direct LLM API call, but
it does not fire for an auth route with no LLM involvement — this guard covers that remaining
slice of `2c-stricter-limits-sensitive-endpoints`, same shape, different trigger condition.

## Detection scope

- Language: Python
- Applies when: `"python" in profile.features`
- Scanned files: all `.py` files under `python_scan_dirs`, excluding non-product paths
- Fires when a route decorator's path string OR the handler function name (checked up to 3
  lines below the decorator) matches an auth-sensitive keyword AND the file has no
  rate-limiting signal anywhere in it AND no cross-file control covers the route (below)
- Auth-sensitive keywords: `login`/`log-in`/`log_in`, `signin`/`sign-in`/`sign_in`,
  `signup`/`sign-up`/`sign_up`, `register`/`registration`, `reset-password`/`reset_password`,
  `forgot-password`/`forgot_password`, `change-password`/`change_password`,
  `password-reset`/`password_reset`, `authenticate`, or a `/token` path segment (word-boundary
  anchored, so `/tokens` as a resource listing does not match)
- Rate-limiting signals: `slowapi`, `fastapi-limiter`, `starlette-limiter`, `@limiter.limit`,
  `RateLimiter`, `rate_limit`, `Depends(rate`, `Throttle` (same list as `llm-rate-limit-absent`)

## Cross-file coverage

A FastAPI app normally wires rate limiting once, in `main.py`, so the route file carries no trace
of it. Since #472 the guard resolves that wiring (`base.py::rate_limit_wiring`, shared with
`llm-rate-limit-absent`) and a route is covered when any of these holds:

1. **A rate-limited router mount.** `app.include_router(auth.router,
   dependencies=[Depends(RateLimiter(times=5, seconds=60))])`, the dependency list inline or held
   in a variable, or a router constructed in the route's own file with such a list. A rate-limit
   dependency is `base.py::RATE_LIMIT_CALL`: a `Depends(...)` whose callable is
   fastapi-limiter's `RateLimiter(...)` or is named for a rate limit (`rate_limit`,
   `check_rate_limit`, `rate_limiter(10, 60)`). The credit is per router, matched to each route by
   its decorator receiver, and reuses #473's router resolvers, so their fail-closed rules apply:
   a **dual mount** (the same router also mounted bare), a **conditional mount** (under an `if`)
   and a **stem collision** (two product files named `auth.py`) all leave the route uncovered.
2. **slowapi global limits.** The route's scope holds BOTH an unconditional
   `add_middleware(SlowAPIMiddleware)` (or `SlowAPIASGIMiddleware`, or
   `Middleware(SlowAPIMiddleware)` in `FastAPI(middleware=[...])`) AND an unconditional
   `Limiter(...)` with a non-empty `default_limits=` or `application_limits=`. Either half alone
   limits nothing: `SlowAPIMiddleware.dispatch` checks only the configured limits, and limits
   without the middleware reach only `@limiter.limit`-decorated routes (slowapi 0.1.10
   `middleware.py:116-140`). A `Limiter` passing `enabled=` or `auto_check=` anything but a truthy
   constant is not credited: `enabled=False` makes the middleware a pass-through, and
   `auto_check=False` skips the global check. A file with an `@<limiter>.exempt` route gets no
   slowapi credit for any route in it, since the middleware never limits an exempt route.
3. **An app-level dependency.** An unconditional `FastAPI(dependencies=[...])` in the route's
   scope carrying a rate-limit dependency, which every route of that app inherits.

**Scope** is the top-level directory the control is registered in (`base.py::middleware_scope`,
the #954 rule): a root-level `main.py` covers the whole tree, and in a monorepo `svc_a/`'s limits
do not cover `svc_b/`'s routes. Only **product code** counts: a test or example app's wiring never
runs in front of the product's routes. A **mention** counts for nothing: a commented-out
registration, a bare import or a class definition credits no coverage, because the resolver reads
a comment-blanked view and the AST rather than raw text. A pragma'd `main.py` still contributes its
wiring (CLAUDE.md rule 4: the pragma gates where a finding is anchored, not what is read). The
cross-file pass runs only when the per-file pass has a candidate route, so a repo with nothing to
report never pays for it.

## Rules

| Rule ID | Severity | Trigger |
|---|---|---|
| `auth-rate-limit-absent/no-rate-limit` | MEDIUM | Auth-sensitive route + no rate-limit signal in file |

MEDIUM severity because rate limiting is often enforced at the infrastructure layer (nginx, API
gateway) rather than per-route. The finding prompts a targeted code review.

## Opt-out

`# security: allow-unrated-auth-endpoint` anywhere in a file silences the finding for that file.
Use when rate limiting is enforced by the proxy/gateway (Cloudflare, nginx `limit_req`, AWS API
Gateway usage plan).

## Known bypasses / false negatives

| Bypass | Why missed |
|---|---|
| Route registered via `router.add_api_route("/login", handler, methods=["POST"])` | Only the decorator syntax (`@router.post(...)`) is matched |
| A route decorated `@limiter.exempt` (or any receiver named `*limiter`) in a file under slowapi global limits | The same-file signal `@\w*limiter\b` matches the exempt decorator itself, so the file is skipped before the cross-file pass sees it. Pre-existing leniency of the same-file signal, kept as is by #472 |
| A route file mentioning `slowapi` or `RateLimiter` only in an import or a comment | The same-file signal is a raw-text match, so a bare import or a comment silences the whole file. Pre-existing; the cross-file pass does not share this leniency |
| Two FastAPI apps in one top-level directory | Coverage is per directory, not per app object, so one app's global limits or app-level dependency covers the other's routes (inherited from #954's `middleware_scope`) |
| `default_limits=` / `dependencies=` pointing at a name that is empty at runtime | A non-literal limits expression cannot be resolved statically and is credited as configured |
| Non-standard path/function naming (e.g. `/auth/v2/enter`, `def do_signin_flow`) | Keyword list is a fixed set; an unusual name that doesn't contain any of them is not recognized |
| Sensitive keyword more than 3 lines below the decorator (e.g. decorators stacked with other middleware) | Lookahead is capped at 3 lines to bound false-positive risk from scanning too far |

## False positive scenarios

| Scenario | Why it fires | How to handle |
|---|---|---|
| `/register-device` for push-notification device registration (not account registration) | `register` matches | Add `# security: allow-unrated-auth-endpoint`, or confirm rate limiting is applied elsewhere |
| A route literally named `/authenticate` for a non-account-security webhook signature check | `authenticate` matches | Same as above |
| The `Limiter` lives in a different top-level directory from the `SlowAPIMiddleware` registration (root `main.py` importing `core/limiter.py`) | The two slowapi halves must share a scope; which `Limiter` reaches `app.state.limiter` is not resolved | Move the `Limiter` under the app's directory, or suppress with the pragma |
| slowapi limits configured only through app config (`RATELIMIT_DEFAULT` / `RATELIMIT_APPLICATION`), or the `Limiter` toggled by `enabled=settings.X` | A static resolver cannot read runtime config, and a setting-driven switch is treated like an `if` (fail closed) | Pass `default_limits=` in code, or suppress with the pragma |
| The middleware or `Limiter` is registered in both branches of an `if`/`else` (say, a Redis-backed and an in-memory `Limiter`) | Any registration under an `if` is not credited, even when every branch registers one | Hoist the registration out of the conditional, or suppress with the pragma |
| A rate-limit dependency behind an alias (`dependencies=[RateLimitDep]`) or a non-rate-limit name (`Depends(throttle)`) | `RATE_LIMIT_CALL` reads only the callable named directly in `Depends(...)` | Name the callable for what it does, or suppress with the pragma |

## Checklist mapping

`2c-stricter-limits-sensitive-endpoints` (PARTIAL — adds auth-route coverage; the item was
already PARTIAL via `llm-rate-limit-absent`'s LLM-route coverage before this guard)

## Standards

- OWASP:API4 (Lack of Resources and Rate Limiting)
- OWASP:A07 (Identification and Authentication Failures)

## Related guards

- `llm-rate-limit-absent`: same shape of check, scoped to routes making a direct LLM API call
  instead of auth-sensitive routes — the two are mutually exclusive triggers, not duplicates.
- `rate-limit-no-user-key`: rate limiting using IP-only key (no per-user enforcement) — a
  different axis (limiter *quality* vs limiter *presence*).

# Citations

[1] agentsec checklist item `2c-stricter-limits-sensitive-endpoints` (§2c)
[2] OWASP-LLM:LLM10
[3] OWASP:A04
[4] OWASP:A07
[5] OWASP:API4
