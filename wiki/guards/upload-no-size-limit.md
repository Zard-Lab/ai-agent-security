---
type: Guard
title: "upload-no-size-limit"
description: "UploadFile route without a file size limit (memory-exhaustion DoS)."
timestamp: "2026-10-03T17:48:10+02:00"
guard_id: "upload-no-size-limit"
checklist_section: ["3a"]
standards: ["ASVS:5.1.1", "OWASP:A04"]
---

# UploadFile route without a file size limit (memory-exhaustion DoS)

_Author — 2026-06-21_

---

## The threat

**Memory-exhaustion DoS via unbounded file upload.**  FastAPI buffers `UploadFile` content in
memory before handing it to the route handler.  Without an explicit size cap, an attacker can POST
a multi-gigabyte file to any upload endpoint and exhaust the server's heap, crashing the process.
This is an unauthenticated DoS if the endpoint is public; authenticated DoS if it requires login.

- **Who reaches it:** any HTTP client that can reach the upload endpoint.
- **Privilege required:** none (if upload endpoint is public) or low (user account).
- **Effect:** process crash / service outage via heap exhaustion.

Standards: **OWASP:A04** (Insecure Design).

---

## Detection design

1. **`applies()`** — `"fastapi" in profile.features and "python" in profile.features`.
2. **Files scanned** — all `.py` files in `python_scan_dirs`, skipping non-product paths
   via `is_nonproduct_path(rel, profile.archive_segments)`.
3. **Pass 2, per file** (runs first):
   - Skip if the file carries the comment `# security: allow-no-upload-size-limit` (whole-file
     reach). The pragma gates only where a finding is anchored: the file still feeds pass 1.
   - Skip if `_UPLOAD_PARAM` (`:\s*UploadFile\b`) not in file.
   - Split the module into functions with `iter_functions(text, include_closures=False)` and, for
     each block whose signature contains `UploadFile`, check **that function's own body** for
     `_SIZE_CHECK` (`content_length`, `max_size`, `MAX_SIZE`, `MAX_FILE`, `size_limit`,
     `file_size`). If absent, the function is a candidate finding.
   - The body is AST-delimited, not a fixed line count. A fixed 30-line window ran past the end of
     the function, so a size check in the *following* function silently suppressed an unguarded
     route above it (#423). `include_closures=False` because this guard alone decides "is this a
     route?" from a parameter ANNOTATION rather than a decorator: a private helper nested in a
     route body receives the route's `UploadFile` and so carries `: UploadFile` itself, without
     being a route and without the enclosing route's size check.
4. **Pass 1, middleware coverage (#472)** — runs only when pass 2 has a candidate, so a repo with
   no unbounded upload never pays for the AST parse. A candidate is dropped when a size-limiting
   middleware is **registered** in its scope (`base.py::registered_middleware_scopes`):
   - The class name matches `ContentSizeLimitMiddleware` or `MaxBytesMiddleware`, registered by
     `app.add_middleware(...)`, as a `Middleware(...)` entry of an app's `middleware=[...]` list,
     passed by keyword instead (`add_middleware(middleware_class=...)`, `Middleware(cls=...)`), as a
     `dispatch=` keyword, through the functional form `<app>.middleware("http")(...)`, or by
     wrapping the app directly (`app = ContentSizeLimitMiddleware(app, ...)`, or `app=app`). A
     direct wrap counts only when the wrapping class's own name ends in `Middleware` and the
     argument in the app's place (the first positional one, else `app=`) is a name, an attribute or
     a call. So `ContentSizeLimitMiddleware()` with no app, a literal or `None` in the app's place,
     and an exception or config class that only contains the name
     (`ContentSizeLimitMiddlewareError(...)`) are not wraps. The argument's type is not resolved,
     so a variable, attribute or call that is not an app still credits (see Known bypasses), and a
     few rare real wraps get no credit (see When NOT to flag). A dotted reference
     (`mw.ContentSizeLimitMiddleware`) counts, and so does a registration inside an app factory
     function.
   - **Scope** is the top-level directory the registration sits in (`base.py::middleware_scope`,
     the #954 rule): a root-level `main.py` covers the whole tree, and in a monorepo `svc_a/`'s
     middleware does not cover `svc_b/`'s routes.
   - Only **product code** counts: a test or example app's middleware never runs in front of the
     product's routes, so `app/tests/conftest.py` covers nothing.
   - A **mention** counts for nothing, in the route's own file or anywhere else. The pass reads the
     AST, so a commented-out or quoted registration, a bare import, an unregistered class
     definition and a registration under an `if` / `else` do not count. Before #472 the guard
     matched the class name in the route file's raw text, so an import or a `# TODO` comment
     silenced every route in the file.
   - A pragma'd `main.py` still contributes its middleware (CLAUDE.md rule 4).
5. **Severity:** `medium`; rule `upload-no-size-limit/no-size-check`; **Standards:**
   `["OWASP:A04"]`.

---

## Tests

| Test | What it checks |
|---|---|
| `test_upload_no_size_limit_fires` | `async def save(file: UploadFile)` with no size check in its body → MEDIUM finding. |
| `test_upload_no_size_limit_size_check_silences` | `max_size` present in the same function → silent. |
| `test_upload_no_size_limit_same_file_size_middleware_mention_still_fires` | An import, a `# TODO` comment or an `if`-guarded registration of the middleware in the route's own file → still fires (the #472 widening). |
| `test_upload_no_size_limit_content_size_middleware_registered_same_file_silent` | The middleware registered in the route's own file → silent (FP-bait pair for the widening). |
| `test_upload_no_size_limit_keyword_and_asgi_wrap_registration_same_file_silent` | The middleware registered in the route's own file by `add_middleware(middleware_class=...)` or by wrapping the app directly → silent (the #1016 review: both forms were silent before #472 and fired after its first version). |
| `test_upload_no_size_limit_silent_when_main_py_registers_size_middleware` | `main.py` registers it by `add_middleware`, a `Middleware(...)` list entry, a dotted reference, inside an app factory, by the `middleware_class=` / `cls=` keyword or by wrapping the app → the route under `routes/` is silent. |
| `test_upload_no_size_limit_still_fires_when_main_py_only_mentions_size_middleware` | `main.py` only imports, comments out, quotes, defines or conditionally registers it, registers an unrelated middleware (CORS, a `RateLimitMiddleware`, `TrustedHostMiddleware`), wraps the app only under an `if`, constructs it with no app or around a literal, wraps the app in another middleware, or raises or constructs an exception or config class that only contains the name → still fires. |
| `test_upload_no_size_limit_registration_covers_its_own_top_level_dir_only` | Monorepo: `svc_a/`'s registration does not cover `svc_b/`'s route. |
| `test_upload_no_size_limit_test_only_registration_does_not_cover` | A registration in `app/tests/conftest.py` covers nothing. |
| `test_upload_no_size_limit_pragma_in_main_still_contributes_its_middleware` | A pragma'd `main.py` still contributes its registration (rule 4). |
| `test_upload_no_size_limit_unparseable_main_py_gives_no_coverage` | A syntax error in `main.py` credits nothing and raises nothing. |
| `test_upload_no_size_limit_skips_pass_1_when_no_route_fires` | Pass 1 never runs when pass 2 has no candidate (#771 cost class). |

The shared resolver has its own table in `tests/guards/test_base.py::test_registered_middleware_scopes`.

## Known bypasses

| Bypass | Why missed |
|---|---|
| Two FastAPI apps in one top-level directory, only one of them registering the middleware | Coverage is per directory, not per app object, so the registering app covers the other's routes (inherited from #954's `middleware_scope`) |
| A class named like a size limit that does not enforce one (a project's own `ContentSizeLimitMiddleware` that only logs) | The registered NAME is the proof; the class body is not read |
| The middleware is registered with no effective limit (`max_content_size=None`) | The arguments are not read, only the name |
| A name that merely contains a recognised one (`NotMaxBytesMiddlewareDisabled`) | The name match is a substring `search`, case-insensitive |
| A registration that never reaches the served app: a `[Middleware(MaxBytesMiddleware)]` list never passed to an app, an `add_middleware` inside a function nobody calls, or `asgi = ContentSizeLimitMiddleware(app)` while the server runs `app` | Credit is per scope, not per served app object, and a registration in any function body counts so app factories are seen (the #954 rule); the pass does not follow calls or the ASGI entry point |
| A registration inside a `try:` whose body can raise before it runs | Only `if` / `else` make a registration conditional; a `try` body is read as unconditional |
| A middleware-named class constructed around an argument that is not an app: a variable, an attribute or a call (`ContentSizeLimitMiddleware(settings)`, `(settings.app)`, `(Settings())`) | A direct wrap's argument is read by shape (a name, attribute or call), not by type, and a call cannot be rejected because `ContentSizeLimitMiddleware(create_app())` is a real wrap. A middleware's first parameter is the app it wraps, so this shape is a bug in the scanned code rather than an idiom; each of the three shapes is pinned as a known accepted gap |
| A `Request.body()` / `request.stream()` read in a route with no `UploadFile` parameter | Out of this guard's scope: it keys on the `UploadFile` annotation |

## When NOT to flag (false positives the guard still produces)

| Case | Why it fires | Mitigation |
|---|---|---|
| A size-limiting middleware under another name (a project's own `LimitUploadSize`) | Only the two class names above are recognised; a custom class's body is not read | Suppress with `# security: allow-no-upload-size-limit` in the route file |
| The middleware is registered in a different top-level directory from the route (root `core/` registering for `api/`) | Coverage is scoped to the registering directory unless that is the repo root | Register it in the app's own `main.py`, or suppress with the pragma |
| The middleware is registered in both branches of an `if` / `else` | Any registration under an `if` is not credited, even when every branch registers one | Hoist the registration out of the conditional, or suppress with the pragma |
| A rare direct-wrap shape: the app passed as an `await`, a subscript (`apps['main']`) or a conditional expression, the app passed only by another keyword (`application=app`), or a class name with a suffix after `Middleware` (`ContentSizeLimitMiddlewareV2(app)`) | A direct wrap is credited only for a class name ending in `Middleware` and an app argument that is a name, attribute or call, so these fail closed (pinned in `test_registered_middleware_scopes_rare_wrap_shapes_fail_closed`) | Register the class with `app.add_middleware(...)`, which credits it under any of these names, or suppress with the pragma |
| The size limit is enforced by a reverse proxy, WAF or gateway | Infrastructure config is not read | Suppress with the pragma and document the guarantee |

# Citations

[1] agentsec checklist item `3a-upload-size-cap` (§3a)
[2] ASVS:5.1.1
[3] OWASP:A04
