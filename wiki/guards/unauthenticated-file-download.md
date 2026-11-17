---
type: Guard
title: "unauthenticated-file-download"
description: "File-download/export route with no authorization signal."
timestamp: "2026-10-07T02:13:02+02:00"
guard_id: "unauthenticated-file-download"
checklist_section: ["2b"]
standards: ["OWASP:A01", "SOC2:CC6.3"]
---

# File-download/export route with no authorization signal

_Author — Marconi, 2026-07-03_

---

## The threat

A `GET`/`POST` route serves a file by an id or filename taken directly from the URL —
`GET /exports/{export_id}` → `FileResponse(...)` — with no authorization check at all.
Unlike a JSON-returning endpoint with a missing *ownership* check (an authenticated user
reading someone else's record), a missing-auth *file-serving* route often doesn't even
require login: a public URL-guesser or an automated crawler can walk `/exports/1`,
`/exports/2`, … and exfiltrate every file in the system with no session, no rate limit
beyond whatever infra provides, and no audit trail tying the download to an identity.
CVE-2024-0551 (AnythingLLM) was exactly this: an unauthenticated DB-export endpoint
serving backup files by predictable name. OWASP:A01 / CWE-862 (Missing Authorization).

## Why this guard fits the stack

FastAPI apps that add an "export my data" or "download report" feature commonly wire
the file-serving route before (or instead of) the auth dependency other routes in the
same router already carry — a route added later, copy-pasted from a `curl`-tested
prototype, or in a file that predates the app's auth middleware:

```python
@router.get("/exports/{export_id}")
def download_export(export_id: str):
    path = get_export_path(export_id)
    return FileResponse(path)          # no Depends(get_current_user) anywhere
```

## Detection design

1. `applies()` gate — `"fastapi" in profile.features`.
2. Scans every `.py` file under `python_scan_dirs(root, profile)`.
3. Splits each file into function blocks (decorators + `def` + indented body) via the
   shared `guards/base.py::iter_functions` helper `bola` and `auth-dependency-not-applied`
   use — bracket-aware, so multi-line route decorators are captured and triple-quoted
   docstrings are blanked before the scan. A block fires when it has ALL of:
   - a route decorator: `@router.get/post(...)` or `@app.get/post(...)`
     (`_ROUTE_DECORATOR`);
   - any URL path parameter: `{export_id}` / `{filename}` / `{slug}` / … (`_PATH_PARAM`;
     issue #307 simplified this from an id/name/key token list that substring-matched
     `{profile}`/`{monkey}`/`{width}` — a route decorator + file sink is already the
     strong signal, so any URL-derived param is in-scope);
   - a FastAPI file-serving sink: `FileResponse(`, `StreamingResponse(` (`_FILE_SINK`;
     the Flask `send_file`/`send_from_directory` were dropped in #307 — unreachable under
     the fastapi-only `applies()` gate);
   - **no** authorization signal anywhere in the block: `current_user`,
     `get_current_user`, an auth-named `Depends(get_current_user)` or DI alias (`_admin =
     AdminReadDep`), `Security(...)`, `403`, `Forbidden` (`_AUTH_SIGNAL`; a bare non-auth
     `Depends(get_db)` does NOT count — #307);
   - **no** bare auth factory in the route's own `dependencies=[...]` (#872). A returns-nothing
     guard attached un-wrapped (`dependencies=[requires_authenticated()]`) is real auth, but
     `_AUTH_SIGNAL` only knows the wrapped shapes. The guard reads the decorator's inline list
     through the shared `base.py::route_deps_carry_auth`, the same reader
     `auth-dependency-not-applied` uses for #859. It blanks line comments first (so a
     commented-out list can't fake protection), finds the list inside the decorator's balanced
     paren span (`_ROUTE_PATH`'s `<open>` group is the `(`), and searches only the list contents
     for a **curated** auth-named call (`PER_ROUTE_AUTH_FACTORY`: `require`/`role`/`scope`/`auth`/
     `authenticat*`/`authoriz*`/`permission*`). A bare `get_db()` or `RateLimiter(...)` in that
     slot still fires.
4. Inline opt-out: `# security: allow-unauthenticated-file-download` as a real comment anywhere
   in the block (the phrase quoted in a string there does not count, #1040).
5. Severity: `high` (data exfiltration, not privilege escalation — one notch below
   `privileged-field-assignment`'s critical). Rule id:
   `unauthenticated-file-download/no-auth-signal`. Standards:
   `["OWASP:A01", "CWE-862"]`.

### Cross-file router-level auth resolution (backlog #3b)

A download route on a router that carries a router-level `dependencies=[Depends(...)]` auth is
NOT flagged — the router-level dependency applies to every route on it without a per-route signal.
This is resolved via the shared `base.py` helpers `cross_file_authed_routers` /
`same_file_authed_routers` (extracted from `auth-dependency-not-applied`, PR #464): the route
decorator's router variable is captured and checked against same-file
`APIRouter(dependencies=...)` / bare-var `include_router(..., dependencies=...)`, and a repo-wide
pass-1 resolves the cross-file case — `main.py` doing
`include_router(exports.router, dependencies=[Depends(get_current_user)])` exempts every route in
`routes/exports.py` PER ROUTER (matched back by module stem, then by the router attribute name, so an
authed sibling router never silences an unauthed one). An include with no `dependencies=`, a second bare mount of the same
router, a mount under an `if`, an include appearing only in a comment or docstring, or a stem
carried by two product files all leave the routes surfacing — protection must be unconditional
and unambiguous (#473 review §2).

## When NOT to flag

- A static route with no id/name path parameter (`/logo.png`) — intentionally public,
  out of scope by the path-parameter gate.
- A JSON-returning route with an id parameter and no file sink — that's `bola`'s
  territory (ownership scoping on a DB fetch), not this guard's.
- Any route where an auth dependency, `current_user` reference, or an explicit
  `403`/`Forbidden` path is present anywhere in the function — deliberately biased
  toward silence (a bare `Depends(get_current_user)` parameter suppresses even without
  visible per-owner scoping logic, matching `bola`'s and
  `privileged-field-assignment`'s posture).
- A route whose **own** `dependencies=[...]` carries a bare auth-factory call whose name hits the
  curated stem set (`dependencies=[requires_authenticated()]`, #872). A bare non-auth call in that
  same slot (`[get_db()]`, `[RateLimiter(...)]`) is not exempt and still fires, and so does the
  factory merely *called* in the handler body.
- An audited handler, suppressed with `# security: allow-unauthenticated-file-download`.

## Tests

| Test | What it checks |
|---|---|
| `test_unauthenticated_file_download_fires_on_fileresponse` | Positive: `FileResponse` in a GET handler with an `{export_id}` param and no auth signal fires HIGH (**verified_by**). |
| `test_unauthenticated_file_download_fires_on_send_file_filename` | Positive: the `send_file()` sink with a `{filename}` param also fires. |
| `test_unauthenticated_file_download_silent_with_auth_dependency` | FP-bait: `Depends(get_current_user)` present → silent. |
| `test_unauthenticated_file_download_silent_no_id_in_path` | FP-bait: a static route with no id/name path param → silent. |
| `test_unauthenticated_file_download_silent_no_file_sink` | Scope-partition: a JSON-returning route with an id param (bola's shape) → silent. |
| `test_unauthenticated_file_download_pragma_silences` | Suppress pragma → silent. |
| `test_unauthenticated_file_download_not_applies_without_fastapi` | `applies()` gate false without `fastapi`. |
| `test_unauthenticated_file_download_silent_with_403_check` | FP-bait: no `Depends()` but an explicit `403` path is present → silent. |
| `test_cross_file_include_with_auth_dep_suppresses_download_route` | FP-bait (#3b): cross-file `include_router(exports.router, dependencies=[Depends(get_current_user)])` → silent. |
| `test_cross_file_include_with_variable_auth_dep_suppresses` | FP-bait (#3b): cross-file include with a variable-bound auth dep list → silent. |
| `test_cross_file_include_without_deps_still_fires` | FN-guard (#3b): cross-file include with no `dependencies=` still fires. |
| `test_cross_file_protection_is_stem_specific` | FN-guard (#3b): protecting one module's router does not silence an unrelated sibling file's route. |
| `test_cross_file_protection_is_per_router_not_whole_file` | FN-guard (#473): an authed sibling router in the same module does not silence the unauthed one. |
| `test_cross_file_protection_applies_to_the_named_router` | FP-bait: the route sits on the router that IS mounted with auth — still silent. |
| `test_router_level_non_auth_db_dependency_still_fires` | FN-guard (#307/#3b): a router-level `Depends(get_db)` is NOT auth → still fires. |
| `test_cross_file_include_with_non_auth_db_dependency_still_fires` | FN-guard (#307/#3b): cross-file include with `Depends(get_db)` still fires. |
| `test_fp_bait_per_route_bare_auth_factory_dependency` | FP-bait (#872): `dependencies=[requires_authenticated()]`, plain and module-qualified → silent. |
| `test_fp_bait_per_route_bare_auth_factory_alongside_a_non_auth_dependency` | FP-bait (#872): multi-line decorator with a comment, `[get_db(), requires_authenticated()]` → silent. |
| `test_fires_when_per_route_dependency_is_a_bare_non_auth_call` | FN-guard (#872): `[get_db()]` and `[RateLimiter(...)]` both still fire. |
| `test_commented_out_per_route_deps_does_not_exempt` | FN-guard (#872 / #532): a commented-out factory above a live `[get_db()]` still fires. |
| `test_per_route_bare_auth_factory_recognition_is_scoped_to_the_deps_list` | FN-guard (#872): the factory called in the handler body is not an applied dependency → still fires. |
| `test_unauthenticated_file_download_silent_when_the_scheme_only_mentions_auto_error` | FP-bait (#764): an enforcing inline scheme whose only `auto_error=False` is a comment → silent. |
| `test_unauthenticated_file_download_fires_with_disabled_scheme_behind_a_comment` | FN-guard (#764 Rule 1): a comment line ahead of a real `auto_error=False` does not make it auth → fires. |

## Known bypasses

- **Router-level `dependencies=[...]`** IS resolved (backlog #3b, see the Detection
  design section) — same-file `APIRouter(dependencies=...)` and cross-file
  `include_router(module.router, dependencies=...)`. Two residuals: (1) only an
  **auth-named** router-level dependency suppresses (`AUTH_CALL_NAMED`); a bare
  `Depends(get_db)` at the router level does NOT (issue #307 parity with the
  function-level check). (2) The cross-file match keys on the **file stem**, so if two
  route files in different directories share a stem and only one is mounted with auth,
  the other is also treated as protected — a rare residual false negative, the accepted
  trade-off documented in `auth-dependency-not-applied.md`.
- **Security-scheme class instantiation** (`Depends(HTTPBearer())`, `Depends(JWTBearer())`, etc.)
  is recognized at BOTH the router level and the per-route level (fix-round review,
  Medium — the per-route signal used to be built from the narrower `AUTH_DEP_SIGNAL` directly,
  missing the class allowlist the router-level check already had). **Deliberately NOT extended**
  to the module-level-variable alias shape (`bearer_scheme = HTTPBearer()` then
  `Depends(bearer_scheme)`) in this round — that needs the same per-file scoping design
  `websocket-no-auth`/`auth-dependency-not-applied` just got, not a half-applied copy here.
- **Disabling `auto_error`** (`HTTPBearer(auto_error=False)` and friends) does not count as auth
  here either: `blank_disabled_security_schemes` runs on this file's text too, so a disabled scheme
  is gone before any auth-signal search. The flag is read from the constructor's own top-level
  arguments on a comment- and string-blanked view, so a mention inside a comment, a string or a
  nested call no longer disables an enforcing scheme (#764). Its residual gaps apply unchanged:
  in a file the tokenizer rejects, an unresolvable argument span has its constructor token
  blanked, so the scheme stops counting as proven auth and the route surfaces (over-fires when it
  was actually enforcing, the chosen direction), and a quote in a comment inside that call can
  still resync the raw walk to a wrong index, which that does not cover (a triple-quoted string no
  longer can, #613); a non-literal value (`auto_error=settings.OPTIONAL_AUTH`) is not recognized as disabling.
  See `auth-dependency-not-applied.md` for the detail.
- **Per-route bare-factory deps (#872)** are recognized only within limits, each of which
  over-fires (the safe direction) unless stated:
  - A factory named **outside** the curated stems (`verify_jwt()`) still fires; use a `Depends()`
    wrap or the pragma.
  - A per-route `dependencies=<var>` (a list variable, not an inline `[...]`) is out of scope and
    still fires.
  - Only **line comments** are blanked before the list is read. A single-line string inside the
    decorator is left intact.
  - The stems are a residual **false negative** too: a non-guard bare call that happens to carry
    one (`get_role_cache()`, `require_json()`) silences the route. It is bounded by being scoped to
    the decorator's own list.
  - **Router-level** bare factories (`APIRouter(dependencies=[requires_authenticated()])`) are
    not recognized: the shared router resolvers only know the wrapped shapes, so every route on
    such a router over-fires. A follow-up to #872; it spans all four route-auth guards.
- **Cross-function auth**: a decorator-based auth wrapper (`@require_auth`) that isn't
  textually `Depends(`/`Security(`/`current_user`/`403`/`Forbidden` won't be recognized
  — a custom auth decorator pattern slips past. The guard only recognizes FastAPI's
  idiomatic `Depends`/`Security` wiring and bare exception-based checks.
- **Indirect sink**: a file served through a helper function (`return serve(path)`
  where `serve()` internally calls `FileResponse`) is invisible — the sink pattern is
  matched textually within the route handler's own block, not through call resolution.
- **StreamingResponse** and other file-serving mechanisms outside the three matched
  sink calls are not covered — scoped to the three most common FastAPI/Flask-style
  sinks to keep the FP rate low; a broader sink list is a natural follow-up if this
  guard's precision holds up in the field.

## What this guard does NOT prove

A silent guard does not mean the route is safe — it only means no *auth-free*
file-serving route with an id/name path parameter was found by this narrow pattern. It
does not verify a present `Depends(...)` actually enforces per-owner scoping (a
`Depends(get_current_user)` that only confirms *someone* is logged in, not that *this*
export belongs to them, silences the guard even though a same-tenant leak is still
possible — that residual risk is `bola`'s territory, not this guard's). This is a
**surfacing** guard, like `bola`/`auth-dependency-not-applied`, not a proof of absence.

# Citations

[1] agentsec checklist item `2b-authorization-enforced` (§2b)
[2] OWASP:A01
[3] SOC2:CC6.3
