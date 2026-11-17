---
type: Guard
title: "request-body-size-unbounded"
description: "FastAPI route with a Pydantic-model request body and no size cap."
timestamp: "2026-08-24T00:00:00Z"
guard_id: "request-body-size-unbounded"
checklist_section: ["3a"]
standards: ["OWASP:A04", "ASVS:5.1.1"]
---

# FastAPI route with a Pydantic-model request body and no size cap

_Author — 2026-08-24_

---

## The threat

`upload-no-size-limit` covers `UploadFile` routes specifically. A plain JSON/Pydantic
request body has the exact same memory-exhaustion shape and is NOT that guard's target
(its own docstring scopes it to `UploadFile` only): FastAPI buffers the entire request body
in memory and parses it into JSON *before* Pydantic validation ever runs, so an attacker can
POST an arbitrarily large body to any `POST`/`PUT`/`PATCH` route that takes a Pydantic
model — no authentication required if the endpoint is public — and exhaust the server's
heap. An unauthenticated memory-exhaustion DoS on a route that looks entirely ordinary.

## Detection design

1. **applies() gate:** `"fastapi" in profile.features`.

2. **Files scanned:** All `.py` files via `iter_files`/`python_scan_dirs`, minus
   `is_nonproduct_path`.

3. **Pattern (`no-size-check`, MEDIUM, same tier as `upload-no-size-limit`):** a route
   handler decorated with `@app.post/put/patch(...)` or `@router.post/put/patch(...)` whose
   signature contains a parameter annotated with a capitalized type that is neither a
   recognized non-body FastAPI/Starlette type (`UploadFile`, `Request`, `Response`,
   `BackgroundTasks`, `WebSocket`, ...) nor a parameter-marker default
   (`Depends`/`Query`/`Path`/`Header`/`Cookie`/`Form`/`File`/`Security`) — i.e. a Pydantic
   request-body model — and whose function body (and the rest of the file, for middleware)
   contains none of `content_length`, `Content-Length`, `max_size`, `max_body`,
   `body_size`, `max_length`, or a `MAX_*SIZE*`-style constant, and no ASGI middleware whose
   class name mentions `size`/`limit` registered via `app.add_middleware(...)`.

4. **Deliberately out of scope:** a route whose only body-shaped parameter is `UploadFile`
   — that is `upload-no-size-limit`'s target, a distinct, non-overlapping sink (`UploadFile`
   streams rather than buffering the whole body as one parsed JSON object). This guard's
   capitalized-type heuristic excludes `UploadFile` by name specifically so the two guards
   never double-report the same route.

5. **Inline opt-out pragma:** `# security: allow-unbounded-request-body` anywhere in a file
   silences this check for that file — use only when the body size is capped at the
   infrastructure layer (reverse proxy, WAF, cloud gateway, ASGI middleware in a different
   file) and that guarantee is documented.

6. **Severity and rule:** `"medium"`, rule `"request-body-size-unbounded/no-size-check"`,
   standards `["OWASP:A04", "ASVS:5.1.1"]`.

## Why MEDIUM, and the accepted heuristic gap

Same reasoning as `upload-no-size-limit`: the impact (DoS via memory exhaustion) is real
but requires an already-reachable endpoint, and the check is conservative — missing signals
in the scanned scope does not prove the absence of a cap enforced elsewhere (a reverse
proxy, an ASGI middleware in another file, a global body-size limit set at the
framework/server layer).

**Known accepted heuristic gap** (mirrors `upload-no-size-limit`'s own accepted gap): the
`MAX_*SIZE*` naming-convention match and the middleware name-substring match are lexical,
not proof of an actual enforced byte cap — a `max_page_size` (pagination) constant or a
`RequestSizeLoggerMiddleware` (logs size, doesn't cap it) would also silence this guard.
Accepted for the same reason `upload-no-size-limit` accepts it: a real project can't be
distinguished from a look-alike lexically, and tightening this would reopen real gaps it
exists to catch.

## When NOT to flag

- The route's only body-shaped parameter is `UploadFile` (that's `upload-no-size-limit`'s
  target).
- A size-enforcement signal (`content_length`/`max_size`/a `MAX_*SIZE*` constant, or a
  size/limit-named middleware registration) is present anywhere in scope.
- The parameter is `Request`/`Response`/`BackgroundTasks`/`WebSocket`, or carries a
  parameter-marker default (`Depends(...)`, `Query(...)`, etc.) rather than being a bare
  Pydantic body model.
- A `GET` route (no request body to exhaust memory with).
- The file contains `# security: allow-unbounded-request-body`.
- A non-product path (tests, fixtures).

## Tests

| Test | What it checks |
|---|---|
| `test_request_body_size_unbounded_fires_on_post` | Fires: POST route with a body model, no size signal |
| `test_request_body_size_unbounded_fires_on_put_and_patch` | Fires: same shape on PUT/PATCH |
| `test_request_body_size_unbounded_silent_on_uploadfile_only` | Silent: `UploadFile`-only route (different guard's target) |
| `test_request_body_size_unbounded_silent_when_size_check_present` | Silent: a size-check signal present |
| `test_request_body_size_unbounded_silent_when_size_middleware_registered` | Silent: size/limit-named middleware registered |
| `test_request_body_size_unbounded_silent_without_body_model_param` | Silent: no Pydantic-model parameter |
| `test_request_body_size_unbounded_silent_on_depends_param` | Silent: parameter is `Depends(...)` |
| `test_request_body_size_unbounded_silent_on_get_route` | Silent: GET route |
| `test_request_body_size_unbounded_pragma_opt_out` | Silent: pragma present |
| `test_request_body_size_unbounded_silent_on_nonproduct_path` | Silent: test/fixture path |
| `test_request_body_size_unbounded_not_applicable_without_fastapi` | `applies()` gate |

## What this guard does NOT prove

- That no size cap exists — a cap enforced at the reverse proxy/WAF/gateway layer, or in an
  ASGI middleware defined in a different file, is invisible to this guard.
- That a matched "size signal" is a real, correctly-enforced byte cap rather than a
  look-alike name (the accepted heuristic gap above).

# Examples

```python
# Fires — no size signal anywhere in the file:
class CreateUser(BaseModel):
    name: str

@router.post("/users")
async def create_user(body: CreateUser):
    return {"name": body.name}

# Silent — an explicit size check present:
MAX_BODY_SIZE = 1_000_000

@router.post("/users")
async def create_user(body: CreateUser, content_length: int = Header(...)):
    if content_length > MAX_BODY_SIZE:
        raise HTTPException(413, "Payload too large")
    return {"name": body.name}
```

# Citations

[1] agentsec checklist item `3a-request-body-size-cap` (§3a)
[2] OWASP:A04 (Insecure Design)
[3] ASVS:5.1.1 (input validation — request size limits)
[4] Sibling guard: `upload-no-size-limit` (`UploadFile`-specific, non-overlapping sink)
