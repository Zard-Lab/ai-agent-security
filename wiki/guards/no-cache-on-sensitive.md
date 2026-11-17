---
type: Guard
title: "no-cache-on-sensitive"
description: "Sensitive route response missing Cache-Control: no-store (ASVS 14.3.2)."
timestamp: "2026-09-26T17:08:41+08:00"
guard_id: "no-cache-on-sensitive"
checklist_section: ["6a"]
standards: ["ASVS:14.3.2", "OWASP:A05"]
---

# Sensitive route response missing Cache-Control: no-store (ASVS 14.3.2)

_Author — 2026-06-21_

---

## The threat

**Sensitive API responses cached in the browser on shared devices.**  FastAPI routes under
`/me`, `/profile`, `/token`, `/auth`, `/payment`, etc. return PII, session tokens, or billing
data. Without `Cache-Control: no-store`, browsers cache the response. On a shared device (library
computer, hotel kiosk), the next user can retrieve the previous user's data from the cache without
credentials — a privacy breach and potential account takeover.

OWASP ASVS 14.3.2 explicitly requires that authenticated/sensitive responses set
`Cache-Control: no-store`.

- **Who reaches it:** the next user on the same physical device or shared browser session.
- **Privilege required:** physical or session access to the device — not remotely exploitable.
- **Effect:** disclosure of PII, JWT tokens, or payment details from the browser cache.

Standards: **OWASP:ASVS**, **OWASP:A05**.

---

## Detection design

1. **`applies()`** — `"fastapi" in profile.features and "python" in profile.features`.
2. **Files scanned** — all `.py` files in `python_scan_dirs`. A non-product path
   (`is_nonproduct_path(rel, profile.archive_segments)`) neither anchors a finding nor
   contributes middleware coverage.
3. **Per-route logic (pass 2):**
   - Skip a file carrying `# security: allow-cacheable-response`, for anchoring only (see
     step 4).
   - Scan lines for `_ROUTE` — FastAPI route decorator whose path starts with a sensitive prefix
     (`/me`, `/profile`, `/user`, `/account`, `/token`, `/auth`, `/payment`, `/billing`,
     `/subscription`, `/invoice`, `/wallet`, `/admin`, `/secret`).
   - For each matched route, check the enclosing function's full body — from the decorator
     through the end of the function (`enclosing_function_span()`; a 30-line
     look-ahead fallback when no enclosing function is found) — for `_CACHE_CTRL`
     (`Cache-Control`, `no-store`, `no-cache`). If absent, the route is a candidate.
     Look-AHEAD only, never backward into unrelated code above the decorator.
4. **Middleware coverage (pass 1, #899).** Run only when pass 2 produced a candidate. A candidate
   is dropped when its file is covered by a registered middleware that writes
   `Cache-Control: no-store` on every response. Pass 1 reads every product file that mentions
   `cache-control`, `middleware` or `call_next`, or defines a `__call__` / `dispatch`,
   **including a pragma'd one** (CLAUDE.md rule 4: the pragma
   gates where a finding is anchored, not what is read). It parses them with `safe_ast_parse`, so
   prose, comments and docstrings never count.
   - **Registered middleware:** an `@<app>.middleware("http")` function (the decorator is the
     registration), or the `dispatch` / `__call__` of a class — or a `dispatch=` function —
     passed to `add_middleware(...)` / `Middleware(...)` (positionally, or by Starlette's
     `middleware_class=` / `cls=` keyword) or `<app>.middleware("http")(fn)`.
     A registration inside an `if`/`else` body is not proof (the #473 rule).
   - **The write:** a constant `Cache-Control` name with a constant value containing `no-store`
     or `no-cache`: `h["Cache-Control"] = ...`, a write method (`h.setdefault(k, v)`,
     `MutableHeaders.append(k, v)`, `h.update({...})`, a raw list's `append` / `extend` /
     `insert` of a `(b"cache-control", b"no-store")` pair), a header list assigned into a
     subscript (`message["headers"] = [..., pair]`), or a `for` loop over a header constant whose
     body writes each iterated pair (`for k, v in SECURITY_HEADERS.items(): h[k] = v`). A loop
     that only iterates the constant (logs it, filters it, writes it elsewhere) is not a write. A
     same-file module- or class-level constant (`SECURITY_HEADERS = {...}`, `NO_STORE =
     "no-store"`) is resolved. An unsafe value (`public, max-age=3600`) is not coverage, and a
     read such as `h.get("cache-control", "no-store")` is not a write.
   - **The right object (#954 C2):** the write must land on a *sink*: the name the middleware
     returns (`return response`), bound only once, or the message parameter of a raw-ASGI send
     wrapper; or a live view of one (`headers = response.headers`,
     `message.setdefault("headers", [])`, `MutableHeaders(scope=message)`). A write onto another
     object (`other = Response()`), or onto `response` after it is rebound, is not coverage.
   - **Nested defs (#954 C1):** a nested def counts only when it is handed to the framework as a
     callback on every path, which is raw ASGI's `send_wrapper` in
     `await self.app(scope, receive, send_wrapper)`. A helper that is only called
     (`add_no_store()`), perhaps under a flag, or never used, earns nothing: pass 1 does not follow
     calls.
   - **Every response:** the write must not sit in a loop body (it may run zero times), a `match`
     case, an `else` / `elif` branch, an `except` handler (that covers only error responses), or
     under an `if` / ternary, unless that condition is a raw-ASGI protocol-type check
     (`scope["type"]`, `message["type"] == "http.response.start"`), a request-method check, or a
     presence check of the response's own Cache-Control (`"cache-control" not in
     response.headers`, `not response.headers.get("cache-control")`: the deny-by-default shape
     that lets a public route override). A test of the header's value
     (`response.headers.get("cache-control") == "private"`), or of a request header, is not a
     presence check. Each operand of an `and`/`or` must be benign on its own, and any condition
     mentioning `path`, `url`, `route` or `endpoint` is path-scoping and never benign. The write
     must also not follow a statement that can leave the block early (`return`, `raise`, or a
     `continue` / `break` of the enclosing loop); the one exception is a benign `if` with no
     `else` and no further condition inside, such as raw ASGI's `if scope["type"] != "http":
     ...; return`.
   - **No override (#954 C3):** any other Cache-Control write in the middleware (a different or
     non-constant value, `del h["Cache-Control"]`, `h.pop("cache-control")`, a header literal or
     constant carrying another value) voids the credit, wherever it sits: it may be the value
     the client sees.
   - **No hand-off (#954 R2-C1):** pass 1 does not follow calls, so passing the response or its
     header container (`response`, `response.headers`, `message["headers"]` with the key literal
     or a same-file constant, or a view of one) to
     any call it cannot see into (`finalize_headers(response)`, `self._finalize(response)`, an
     imported helper) also voids the credit: that code may overwrite the header. Two calls are
     not hand-offs: `MutableHeaders(scope=message)`, which only builds a view, and raw ASGI's
     `await send(message)` forward to a callable the middleware was handed. A scalar read off
     the response (`record_metrics(request, response.status_code)`) and a call that never
     receives it (`logger.info(...)`) do not void anything.
   - **Scope:** coverage is granted to the top-level directory the middleware is registered in; a
     root-level file (`main.py`) covers the whole tree. So in a monorepo, `app_a/`'s middleware
     does not silence `app_b/`. A registered class name resolves to the definition in the
     registering directory when one exists there, otherwise to any definition (a shared `libs/`
     package).
5. **Severity:** `medium`; rule `no-cache-on-sensitive/missing-no-store`; **Standards:**
   `["ASVS:14.3.2", "OWASP:A05"]`.

---

## Tests

All in `tests/guards/test_no_cache_on_sensitive.py`.

| Test | What it checks |
|---|---|
| `test_no_cache_on_sensitive_fires` | `/me` route with no Cache-Control anywhere in its body → MEDIUM finding. |
| `test_no_cache_on_sensitive_cache_control_silences` | `no-store` anywhere in the route's body → silent. |
| `test_no_cache_on_sensitive_public_path_with_kwarg_silent` | `/items` route → silent (not a sensitive prefix). |
| `test_no_cache_on_sensitive_pragma_silences` | Pragma in file → silent. |
| `test_no_cache_sensitive_silent_when_signal_outside_old_fixed_window` | silent when the header sits past the old 30-line window but is still in the enclosing function. |
| `test_no_cache_sensitive_still_fires_when_signal_is_in_a_decorator_stacked_above` | directionality: a signal-looking token in a decorator stacked ABOVE the route still fires (look-ahead only, never backward). |
| `test_no_cache_sensitive_silent_under_same_file_http_middleware` | #899: `@app.middleware("http")` setting no-store, same file → silent. |
| `test_no_cache_sensitive_silent_under_cross_file_http_middleware` | #899, multi-file: middleware in root `main.py`, route in `routes/users.py` → silent. |
| `test_no_cache_sensitive_silent_under_registered_base_http_middleware` | #899, multi-file: `BaseHTTPMiddleware` class defined, registered and covering in three files under `app/` → silent. |
| `test_no_cache_sensitive_silent_under_raw_asgi_middleware` | #899: raw ASGI `send_wrapper` bytes pair under a `message["type"]` check → silent. |
| `test_no_cache_sensitive_silent_under_header_dict_middleware` | #899: `headers.update({... "Cache-Control": "no-store, max-age=0"})` → silent. |
| `test_no_cache_sensitive_silent_under_module_constant_header_dict` | #899: a module-level header dict applied by `update()`, or by an `.items()` loop writing `h[k] = v` or `h.setdefault(k, v)` → silent. |
| `test_no_cache_sensitive_still_fires_when_header_loop_does_not_apply_no_store` | #954 C4 (parametrized): a loop over a no-store header constant whose body logs the pair, `continue`s past Cache-Control, filters it out, or writes onto another object → fires. |
| `test_no_cache_sensitive_silent_under_equivalent_no_store_shapes` | #954, rule 1 for the round-1 tightening (parametrized): a `headers = response.headers` view, another header written alongside, a `.get("cache-control")` presence check, a method early exit, and calls that never receive the response (a logger, a `response.status_code` metric, `response.set_cookie`) all stay silent. |
| `test_no_cache_sensitive_still_fires_when_response_is_handed_to_an_unseen_call` | #954 R2-C1 (parametrized): after the no-store write the response, or its headers, is passed to a sibling helper (unconditionally or under a flag) or, by keyword, to an imported one → fires. |
| `test_no_cache_sensitive_still_fires_when_dispatch_hands_response_to_a_method` | #954 R2-C1: a `BaseHTTPMiddleware.dispatch` that calls `self._finalize(response)` after the write → fires. |
| `test_no_cache_sensitive_still_fires_when_asgi_headers_are_handed_off` | #954 R3-H1 (parametrized): a raw-ASGI send wrapper hands `message["headers"]`, keyed by a literal or by a same-file constant, to a helper after the no-store append → fires. |
| `test_no_cache_sensitive_silent_when_asgi_non_header_field_is_handed_off` | #954 R5-M1 FP-bait (parametrized): a raw-ASGI send wrapper appends no-store to `message["headers"]`, then hands `message["status"]` to a helper, both keys literal or both same-file constants → silent (a key that does not resolve to a header container is not a hand-off). |
| `test_no_cache_sensitive_silent_under_raw_asgi_mutable_headers` | #954: raw ASGI `MutableHeaders(scope=message).append(...)` in the send wrapper → silent. |
| `test_no_cache_sensitive_silent_under_deny_by_default_middleware` | #899: no-store under `if "cache-control" not in response.headers:` → silent. |
| `test_no_cache_sensitive_silent_under_dispatch_function_middleware` | #899: `add_middleware(BaseHTTPMiddleware, dispatch=fn)` → silent. |
| `test_no_cache_sensitive_middleware_in_pragma_file_still_covers` | #899, rule 4: a pragma'd `main.py`'s middleware still covers a route in another file. |
| `test_no_cache_sensitive_still_fires_when_middleware_is_not_proof` | #899, rule 1 (parametrized): an unsafe value, a path-scoped write, a negated path allow-list, a path early exit, a status check, an `except`-only write, and prose-only middleware all keep firing. #954 adds: an uncalled or flag-called nested helper (C1), a write onto another response (C2), a later overwrite, `del` or `pop` (C3), a rebound `response`, a write in a loop body, and a header-value condition. |
| `test_no_cache_sensitive_silent_under_keyword_registered_middleware` | #1016 review (parametrized): a no-store class registered as `add_middleware(middleware_class=...)` or `Middleware(cls=...)` → silent. |
| `test_no_cache_sensitive_still_fires_under_keyword_registered_middleware_that_is_not_proof` | #1016 review, rule 1: the keyword form only finds the class; a class writing `public, max-age=60` → fires. |
| `test_no_cache_sensitive_still_fires_when_middleware_class_is_not_registered` | #899: a no-store class nothing registers → fires. |
| `test_no_cache_sensitive_still_fires_when_registration_is_conditional` | #899: `add_middleware` inside `if settings.X:` → fires. |
| `test_no_cache_sensitive_middleware_covers_only_its_own_top_level_dir` | #899 monorepo: `app_a/` covered, `app_b/` fires. |
| `test_no_cache_sensitive_same_named_middleware_resolves_per_dir` | #899 (parametrized): two apps each define their own same-named class, including a bare raw-ASGI one; only the no-store one covers. |
| `test_no_cache_sensitive_shared_lib_middleware_covers_the_registering_dir` | #899: a `libs/` class covers the app that registers it, not its sibling. |
| `test_no_cache_sensitive_test_only_middleware_does_not_cover` | #899: middleware in `tests/conftest.py` or `app/tests/conftest.py` does not cover `app/`. |

## Known bypasses

- **Route level (pre-existing):** `_CACHE_CTRL` accepts any `Cache-Control` mention in the
  handler window, so an in-handler `'public, max-age=3600'` value, or a `# TODO: add no-store`
  comment, silences the route. The middleware pass does not share this leniency.
- **Two apps in one top-level directory** (`backend/agent_api.py` and `backend/sso_api.py`) share
  coverage: one app's middleware silences the other's routes. Per-app resolution (which
  `FastAPI()` each router is `include_router`-ed into) would close it and is deferred.
- **The protocol-type and method tests are textual, per `and`/`or` operand.** A single operand
  that carries a `type` or `method` token together with a path decision hidden behind a helper
  or alias (`if message["type"] == kind_for(request):`) is read as benign. The Cache-Control
  presence test is structural (#954) and has no such gap.
- **A method check is benign by design**, so a write under `if request.method != "GET":`, or a
  `if request.method == "GET": return response` before it, is read as covering every response
  although it skips the cacheable GETs.
- **Sinks are tracked by name, not by data flow.** A sink mutated through a container
  (`holder = [response]; holder[0].headers[...] = ...`) is missed (the noisy direction), and a
  view taken through a call other than `setdefault` / `get` / `MutableHeaders(...)` is not a
  view. A send-wrapper parameter is trusted to be the forwarded message.
- **A method called on the response itself is trusted** not to reset the header
  (`response.set_cookie(...)` is common; `response.init_headers(...)` after the write would be
  missed), and so is a call that receives the response only through `*args` / `**kwargs`
  unpacking.

## What this guard does NOT prove

- **Middleware it cannot see keeps firing** (the noisy direction): an app wrapped directly
  (`app = NoStore(app)`), a `dispatch` inherited from a base class, a header name or value
  imported from another module, a negated path
  allow-list (`if not path.startswith("/static"):`), a status-conditional write, a write in a
  helper the middleware calls (`add_security_headers(response)`), a write inside a loop, a
  middleware that also sets another Cache-Control value on some path (a `/static` override,
  inline or in a helper the response is handed to), or one that hands the response to any
  helper at all, before or after the write (a `log_response(response)` call voids the credit
  too). Suppress with the pragma or set the header per route.
- **A global unsafe value** (`public` on every response) fires with the generic "missing"
  message, although it is worse than a missing header.
- A silent route proves only that a no-store write exists on its handler or its directory's
  middleware, not that the response actually carries it at runtime.

# Citations

[1] agentsec checklist item `6a-no-store-on-sensitive-responses` (§6a)
[2] ASVS:14.3.2
[3] OWASP:A05
