---
type: Guard
title: "llm-rate-limit-absent"
description: "LLM-backed route has no rate-limiting protection."
timestamp: "2026-10-03T16:59:47+02:00"
guard_id: "llm-rate-limit-absent"
checklist_section: ["2c"]
standards: ["OWASP-LLM:LLM10", "OWASP:A04", "OWASP:A07", "OWASP:API4"]
---

# LLM-backed route has no rate-limiting protection

## What it detects

Python files that contain BOTH a FastAPI route decorator (any HTTP verb) AND a direct LLM API
call (`client.chat.completions.create`, etc.) but NO recognized rate-limiting signal, and whose
routes rate limiting wired elsewhere in the app does not cover either (see **Cross-file
coverage** below).

## Why it matters

An LLM-backed endpoint without rate limiting is a cost and availability target. A single
unauthenticated caller can hammer the route with sequential requests, draining API credits and
saturating downstream quotas. This differs from generic rate limiting (§2a) — the concern here
is specifically the per-request LLM cost multiplier.

## Detection scope

- Language: Python
- Applies when: `"llm" in profile.features`
- Scanned files: all `.py` files under `python_scan_dirs`, excluding test/fixture paths
- Fires when a file has BOTH route decorator AND direct LLM call AND no rate-limit signal AND
  no cross-file control covers its routes (below)
- Rate-limiting signals: `slowapi`, `fastapi-limiter`, `starlette-limiter`, `@limiter.limit`,
  `RateLimiter`, `rate_limit`, `Depends(rate`, `Throttle`

## Cross-file coverage

A FastAPI app normally wires rate limiting once, in `main.py`. Since #472 the guard resolves that
wiring through `base.py::rate_limit_wiring`, the resolver it shares with `auth-rate-limit-absent`
(whose design doc has the full rules). In short, the file is covered by:

- **slowapi global limits** in its scope: an unconditional `SlowAPIMiddleware` registration AND an
  unconditional `Limiter(...)` with non-empty `default_limits=` / `application_limits=`, not
  switched off by `enabled=` or `auto_check=`, and no `@<limiter>.exempt` route in the file;
- an **app-level dependency** in its scope: an unconditional `FastAPI(dependencies=[...])`
  carrying a rate-limit dependency (`base.py::RATE_LIMIT_CALL`, e.g.
  `Depends(RateLimiter(times=10, seconds=60))`); or
- a **rate-limited router mount** of EVERY router the file's routes sit on
  (`include_router(chat.router, dependencies=[Depends(RateLimiter(...))])`). The finding is per
  file and does not resolve which route reaches the LLM call, so one route on an uncovered router
  keeps the file firing. The guard reads every route registration from the file's syntax tree, on
  a receiver of any name: a route decorator (`@chat_router.post(...)`, `@ws.websocket_route(...)`,
  not only `@router` / `@app`, however it is spaced or split across lines), the same decorator
  applied by hand (`chat_router.post("/chat")(chat)`), or an `add_api_route` / `add_route` call.
  Only a receiver that is a plain name can be covered: a dotted one (`common.router`, another
  module's router), a subscript (`routers["chat"]`) or a call (`get_router()`) never is. A route
  the guard cannot attribute to a receiver withdraws the router-level credit from the whole file:
  a route object (`Route(...)`, `APIRoute(...)`), a `routes=` keyword on any call (a router or app
  constructor, a project's own `attach_routes(router, routes=TABLE)`, or a copy such as
  `APIRouter(routes=router.routes)`), a write to a router's `.routes`, or a file that does not
  parse. Reading `.routes` registers nothing and changes nothing: FastAPI's operation-id recipe, and
  `get_openapi(routes=app.routes)`, the one call exempt from the `routes=` rule, since it only
  builds the schema. #473's router rules apply: a dual
  mount, a conditional mount and a stem collision all leave the router uncovered.

Scope is the top-level directory the control is registered in; a root-level `main.py` covers the
whole tree. Only unconditional product code counts, so a test app, a commented-out registration,
a bare import and a registration under an `if` credit nothing. A pragma'd `main.py` still
contributes its wiring (CLAUDE.md rule 4).

## Rules

| Rule ID | Severity | Trigger |
|---|---|---|
| `llm-rate-limit-absent/no-rate-limit` | MEDIUM | Route + LLM call + no rate-limit in file |

MEDIUM severity because rate limiting is often enforced at the infrastructure layer (nginx, API
gateway) rather than per-route. The finding prompts a targeted code review.

## Opt-out

`# security: allow-unrated-llm-endpoint` anywhere in a file silences the finding for that file.
Use when rate limiting is enforced by the proxy/gateway (Cloudflare, nginx `limit_req`,
AWS API Gateway usage plan).

## False-negative scope

- Split-file patterns: route in one file, LLM call dispatched to a service in another.
- A route file that mentions `slowapi`, `RateLimiter` or `@<x>limiter` anywhere (a bare import, a
  comment, an `@limiter.exempt` decorator) is skipped by the raw-text same-file signal. This
  leniency predates #472 and the cross-file pass does not share it.
- Two FastAPI apps in one top-level directory share coverage: one app's global limits or
  app-level dependency covers the other's routes (the #954 `middleware_scope` granularity).
- A `default_limits=` / `dependencies=` value held in a name is credited as configured, since it
  cannot be resolved statically.
- A route method reached through another name (`post = chat_router.post` and then
  `@post("/chat")`, a decorator bound first, `deco = chat_router.post("/chat")` and then `@deco`, or
  `getattr(chat_router, "post")`) is not read as a registration, so covering the file's other
  routers can withdraw its finding. Reading every such alias as a receiver would
  also read ordinary code (`get = os.environ.get`), so the shape is left as a known bypass.

## False positive scenarios

- Rate limiting implemented through a custom decorator not matching the signal patterns.
- A `Limiter` in a different top-level directory from its `SlowAPIMiddleware` registration, limits
  set only through app config (`RATELIMIT_DEFAULT`), an `enabled=settings.X` switch, or a
  registration under an `if`/`else` (even with one in every branch): all fail closed.
- A rate-limit dependency behind an alias (`dependencies=[RateLimitDep]`).
- A route file that builds a route object, passes a `routes=` keyword to any call but
  `get_openapi`, writes to a router's `.routes` (the Starlette style), or registers a route on a subscript or call receiver gets no router-level
  credit even when every router it names is mounted rate-limited: the guard cannot attribute the
  route, so it fails closed. App-level controls (slowapi global limits, an app-level dependency)
  still cover it.

Each is handled by the opt-out pragma, or by wiring the control in the plain shape above.

## Checklist mapping

`2c-stricter-limits-sensitive-endpoints` (MANUAL → partial via this guard)

## Standards

- OWASP-LLM:LLM04 (Model Denial of Service)
- OWASP:API4 (Lack of Resources and Rate Limiting)

## Related guards

- `llm-input-size-cap`: per-request token ceiling (different axis — cost per request vs
  request frequency)
- `rate-limit-no-user-key`: rate limiting using IP-only key (no per-user enforcement)

# Citations

[1] agentsec checklist item `2c-stricter-limits-sensitive-endpoints` (§2c)
[2] OWASP-LLM:LLM10
[3] OWASP:A04
[4] OWASP:A07
[5] OWASP:API4
