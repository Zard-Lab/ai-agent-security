---
type: Guard
title: "websocket-no-auth"
description: "WebSocket endpoint without authentication dependency."
timestamp: "2026-10-07T02:13:02+02:00"
guard_id: "websocket-no-auth"
checklist_section: ["2b"]
standards: ["OWASP:A01", "OWASP:A07"]
---

# WebSocket endpoint without authentication dependency

## Threat

FastAPI WebSocket endpoints use the same `Depends()` / `Security()` dependency injection
system as HTTP routes. In practice, developers often add WebSocket handlers as a "real-time
add-on" after the HTTP API is already secured, and the auth dependency is simply forgotten.
The result is a persistent, bidirectional channel that any unauthenticated client can open.
Because WebSocket connections are established via an HTTP `101 Upgrade` handshake, many
API gateways and WAFs that enforce auth on the HTTP layer do NOT re-check credentials on
the upgraded connection. The omission therefore bypasses perimeter controls as well as
application-level access control.

This satisfies two OWASP Top 10 categories simultaneously:
- **A01 — Broken Access Control**: the endpoint is reachable without a valid session.
- **A07 — Identification & Authentication Failures**: no identity is established before the
  connection is accepted.

## Detection design

**Rule ID:** `websocket-no-auth/websocket-without-auth-dep`

**Algorithm:**

1. For each `.py` file in `python_scan_dirs`, read with UTF-8 (errors=ignore).
2. If a `# security: allow-websocket-no-auth` comment is present anywhere in the
   file (a string literal quoting the phrase does not count, #424), skip the file entirely.
3. If neither `@app.websocket(` nor `@router.websocket(` appears in the file, skip.
4. Walk lines. When a line matches the decorator regex, inspect the next 1-3 lines (the
   signature window: the `def` / `async def` line and, for a wrapped signature, its first
   continuation lines).
5. If the signature window carries no auth signal (below), read the decorator's own
   `dependencies=[...]` list (see "The decorator's own dependencies"). If neither carries auth,
   emit one HIGH finding pointing at the decorator line.

**Decorator regex:**

```
^[ \t]*@(?P<var>[\w.]+)\.websocket\(
```

(`<var>` captures the router object — any dotted identifier, not just literal `app`/`router` —
so a WebSocket route on a custom-named router is scanned, and its router var can be checked against
the router-level auth resolver below.)

**Auth signal (applied to the signature window):** the shared `AUTH_CALL_NAMED`, extended with
this file's own module-level security-scheme variables (`auth_call_named_with_aliases(text)`, so
`Depends(bearer_scheme)` counts when this file binds `bearer_scheme = HTTPBearer()`),
plus two guard-local branches:

```
<AUTH_CALL_NAMED + this file's scheme aliases>
|current_user
|(?:token|api_key|authorization)\s*(?::\s*\S+)?\s*=.*Query\s*\(
```

`AUTH_CALL_NAMED` needs an auth-NAMED wrapped callable (`Depends(get_current_user)`,
`Security(...)`, `Depends(HTTPBearer())`, a `*Dep` alias): a bare `Depends(` alone, such as
`Depends(RateLimiter(...))`, does not count. The last branch is the Query-param token
pattern WebSockets often use, since many clients cannot send headers on the handshake.

### The decorator's own dependencies (#872)

The signature window starts on the line AFTER the decorator, so the decorator's own
`dependencies=[...]` was never read: a bare auth factory there (`dependencies=[requires_authenticated()]`,
the #859 shape) and even a wrapped `dependencies=[Depends(get_current_user)]` on a one-line decorator
fired HIGH. The guard now reads that inline list through the shared `base.py::route_deps_carry_auth`,
the same reader `auth-dependency-not-applied` uses for #859:

- the file is comment-blanked once (`blank_line_comments`, length-preserving), so a commented-out
  list cannot fake protection;
- the list is found inside the decorator's balanced paren span, and only its contents are searched;
- what counts is the union of this file's auth signal (the wrapped forms above) and the curated
  bare-factory matcher `PER_ROUTE_AUTH_FACTORY` (`require`/`role`/`scope`/`auth`/`authenticat*`/
  `authoriz*`/`permission*`). The other per-route guards need only the bare half, because their
  block-wide signal already sees the wrapped forms. A bare `get_db()`, `RateLimiter(...)`,
  `Depends(RateLimiter(...))` or `Depends(get_db)` there still fires.

Each decorator's text runs only up to the next websocket decorator. `matching_close_paren` walks to
the end of what it is given when a `(` is unbalanced, so handing it the rest of the file made a file
of k unbalanced decorators O(k·n) (measured: 3s at 500, 185s at 4,000). The bounded windows are
disjoint, so the file stays linear (`test_ws_decorator_deps_scan_stays_linear`). Decorator offsets
come from the same `splitlines()` split the guard numbers lines with, so a form feed (`\x0c`) or
another non-`\n` line boundary cannot shift them.

**Scope:** `.py` files only, via `python_scan_dirs` + `iter_files`.

### Cross-file router-level auth resolution (backlog #3b)

FastAPI applies a router-level `dependencies=[Depends(...)]` to WebSocket routes too, so a WS route
on such a router is NOT flagged. The `_WS_DECORATOR` regex captures the router variable (any dotted
identifier — `app`, `router`, a custom `chat_router`), and it is checked against the shared `base.py`
helpers `cross_file_authed_routers` / `same_file_authed_routers` (extracted from
`auth-dependency-not-applied`, PR #464): same-file `APIRouter(dependencies=...)` /
`include_router(..., dependencies=...)`, plus a repo-wide pass-1 that resolves the cross-file case —
`main.py` doing `include_router(chat.router, dependencies=[Depends(get_current_user)])` exempts every
WS route in `routes/chat.py` PER ROUTER (matched back by module stem, then by the router attribute
name, so an authed sibling router never silences an unauthed one). An include with no `dependencies=`, a second bare mount of the same
router, a mount under an `if`, an include appearing only in a comment or docstring, or a stem
carried by two product files all leave the routes surfacing — protection must be unconditional
and unambiguous (#473 review §2).

## Severity rationale

**HIGH.** An unauthenticated WebSocket endpoint:
- Exposes a persistent bidirectional channel with zero credential requirement.
- Bypasses HTTP-layer auth controls enforced by middleware or API gateways.
- Is invisible to many WAFs that inspect HTTP headers rather than WebSocket frames.
- Can be used for data exfiltration, injection of malicious messages, or denial-of-service
  by holding connections open.
- Is exploitable by any network-reachable client with trivial tooling (`websocat`, browser DevTools).

## Known bypasses / false negatives

| Scenario | Why missed | Mitigation |
|---|---|---|
| Auth dependency further down a long multi-line signature | Guard reads only the 3 lines after the decorator | Move the auth parameter up, put it in the decorator's `dependencies=[...]`, or add pragma |
| A bare auth factory in the decorator's `dependencies=[...]` named outside the curated stems (`verify_jwt()`) | `PER_ROUTE_AUTH_FACTORY` is a curated stem list on purpose (#859 / #872) | Over-fires (the safe direction); wrap it in `Depends()` or add pragma |
| A per-route `dependencies=<var>` (a list variable, not an inline `[...]`) | Only the inline-list form is read (#872) | Over-fires (the safe direction); inline the list or add pragma |
| A non-guard bare call in the decorator's `dependencies=[...]` that happens to carry a curated stem (`get_role_cache()`, `require_json()`) | The stems are matched by name, not by what the function does | **False negative**, bounded by being scoped to the decorator's own list (#872) |
| A bare auth factory at the ROUTER level (`APIRouter(dependencies=[requires_authenticated()])`) | The shared router resolvers only know the wrapped shapes | Over-fires on every route of that router; a follow-up to #872, it spans all four route-auth guards |
| Commented-out auth on a multi-line decorator's continuation lines | The signature window reads raw lines, comments included (only the `dependencies=[...]` read is comment-blanked) | **False negative**, pre-existing (the #532 dead-text class, per-route) |
| Auth enforced inside the function body (manual token check, not `Depends`) | Guard looks only at the def signature, not the body | Refactor to use `Depends()` for consistency |
| Custom auth decorator wrapping the websocket handler | Decorator chain analysis not performed | Add pragma if custom decorator is confirmed |
| Cross-file include via an **aliased** import whose alias differs from the file stem (`import routes.chat as c; c.router`) | Cross-file resolution keys on the file stem, so the mount is not matched | Over-fires (the safe direction); add pragma if hit |
| Auth via a dependency with a name other than `current_user` that contains no `Depends(` | Regex requires one of the three signals | Guard relies on standard FastAPI patterns |
| A **custom** security-scheme subclass with a name outside the closed allowlist (`HTTPBearer`, `JWTBearer`, `OAuth2PasswordBearer`, etc. — see `_SECURITY_SCHEME_CLASSES`, base.py) — e.g. `Depends(MyCompanyAuth())` where `MyCompanyAuth` extends `HTTPBearer` under an unrelated name | `AUTH_CALL_NAMED` recognizes the closed class-name list, not arbitrary subclasses — widening it to a stem match reopens issue #345's over-suppression | Rename to a recognized convention, or add pragma |
| A module-level security-scheme variable used ONLY as a router-mount `dependencies=[Depends(name)]` argument, where a DIFFERENT file happens to define its own local, unrelated variable of the exact same name — not fixed by the fix-round review, and NOT safe-by-default: this is the same false-negative direction as the original bug, just a narrower trigger (two files, same rare name collision, specifically at the router-mount call site rather than a per-route signature) | `cross_file_authed_routers` still resolves aliases from the whole run's file set, not scoped per-file the way `_check_file`'s own same-file/per-route checks now are — closing this needs a signature change shared by 4 guards (`unauthenticated-file-download`, `privileged-field-assignment` also call it), not a one-file patch | Avoid reusing a security-scheme variable's name across unrelated files; add pragma if hit |
| A security scheme whose argument span cannot be resolved (genuinely unbalanced parens; or, only in a file the tokenizer rejects, a quote in a comment inside the call, which the raw walk has no `#` state for. A triple-quoted string no longer desyncs it, #613) | `blank_disabled_security_schemes` blanks the constructor TOKEN only, so the scheme stops counting as proven auth while nothing past the token is touched. In a tokenizable file the span is resolved on a comment- and string-blanked view, so a stray quote cannot reach it (#764) | Over-fires when that scheme was actually enforcing (the safe direction; the pragma covers it). The comment quote's OTHER outcome, a wrong non-`None` index, is not covered on the raw path |
| A disabling `auto_error` the scan cannot read as a literal (`auto_error=settings.OPTIONAL_AUTH`, `**{"auto_error": False}`) | The flag is read from the call's own top-level arguments and must be a literal `False`/`None`/`0` | The scheme still counts as auth; add pragma or inline the literal. (Since #764 a mention in a comment, string or nested call no longer disables an ENFORCING scheme) |

## False positive scenarios

| Scenario | Why it fires | How to suppress |
|---|---|---|
| Intentionally public WebSocket (e.g. status stream, read-only ticker) | No auth dependency in signature | Add `# security: allow-websocket-no-auth` to the file |
| Test fixture WebSocket handler without auth | Test code analysed as production code | Add pragma or place test fixtures outside `python_scan_dirs` |
| Auth injected via a parameter named something other than `current_user` and using a non-`Depends` / non-`Security` pattern | Regex does not match | Rename to match standard FastAPI idiom or add pragma |

## Checklist items flipped

| ID | Before | After | Reason |
|---|---|---|---|
| `2b-websocket-auth` | `uncovered` | `covered` | Guard statically detects missing auth dependency on WebSocket decorators |

## Tests

| Test | Validates |
|---|---|
| `test_websocket_no_auth_flags_bare_endpoint` | TP: decorator + plain signature fires |
| `test_websocket_no_auth_flags_router_decorator` | TP: `@router.websocket` variant fires |
| `test_websocket_no_auth_silent_with_depends` | FP guard: `Depends(get_current_user)` in sig suppresses |
| `test_websocket_no_auth_silent_with_security` | FP guard: `Security(verify_token)` in sig suppresses |
| `test_websocket_no_auth_pragma_silences` | Pragma: file-level suppress disables the check |
| `test_websocket_no_auth_not_fastapi` | Gate: no `fastapi` feature → `applies()` returns False |
| `test_cross_file_include_with_auth_dep_suppresses_ws` | FP guard (#3b): cross-file `include_router(chat.router, dependencies=[Depends(get_current_user)])` → silent |
| `test_same_file_router_construct_deps_suppresses_ws` | FP guard (#3b): same-file `APIRouter(dependencies=[Depends(...)])` → silent |
| `test_cross_file_include_without_deps_still_fires_ws` | FN guard (#3b): cross-file include with no `dependencies=` still fires |
| `test_cross_file_protection_is_per_router_not_whole_file_ws` | FN guard (#473): an authed sibling router in the same module does not silence the unauthed one |
| `test_cross_file_protection_applies_to_the_named_router_ws` | FP-bait: the WS route sits on the router that IS mounted with auth — still silent |
| `test_custom_named_router_var_is_matched_ws` | FP guard (#3b): a custom-named authed router (`chat_router`) is recognized (proves the generalized regex captures the var) |
| `test_custom_named_router_var_unprotected_still_fires_ws` | FN guard (#3b): a custom-named UNprotected router still fires (regex broadening does not over-suppress) |
| `test_websocket_no_auth_silent_with_inline_httpbearer` | FN guard: `Depends(HTTPBearer())` recognized despite no `_AUTH_NAME` stem in the class name |
| `test_websocket_no_auth_silent_with_module_level_security_scheme_var` | FN guard: a module-level `bearer_scheme = HTTPBearer()` referenced as `Depends(bearer_scheme)` is resolved |
| `test_websocket_no_auth_fires_when_alias_var_is_not_a_security_scheme` | FP-bait: a variable bound to something OTHER than a security-scheme class is not mistaken for one |
| `test_fp_bait_ws_per_route_bare_auth_factory_dependency` | FP-bait (#872): `@router.websocket('/ws', dependencies=[requires_authenticated()])`, plain and module-qualified → silent |
| `test_fp_bait_ws_wrapped_auth_dependency_on_the_decorator` | FP-bait (#872): one-line decorator with `[Depends(get_current_user)]` / `[Depends(HTTPBearer())]` → silent |
| `test_fp_bait_ws_per_route_bare_auth_factory_alongside_a_non_auth_dependency` | FP-bait (#872): `[get_db(), requires_authenticated()]` → silent |
| `test_ws_fires_when_decorator_dependency_is_not_auth` | FN guard (#872): `[get_db()]`, `[RateLimiter(...)]`, `[Depends(RateLimiter(...))]`, `[Depends(get_db)]` all still fire |
| `test_ws_commented_out_decorator_deps_do_not_exempt` | FN guard (#872 / #532): a commented-out factory above a live `[get_db()]` still fires |
| `test_ws_bare_auth_factory_recognition_is_scoped_to_the_deps_list` | FN guard (#872): the factory called in the handler body is not an applied dependency → still fires |
| `test_ws_multiline_decorator_deps_beyond_the_signature_window` | #872: deps more than 3 lines below the `@` line are read from the decorator span; the `get_db()` twin still fires |
| `test_ws_decorator_offsets_survive_a_form_feed_line` | #872: decorator offsets come from the same `splitlines()` split, so a `\x0c` line does not shift them |
| `test_ws_decorator_deps_scan_stays_linear` | #872 (slow): k decorators with unbalanced `(` stay linear (each read bounded to the next decorator) |
| `test_websocket_no_auth_enforcing_scheme_that_mentions_auto_error_stays_silent` | FP-bait (#764): the flag only in an apostrophe comment, a string or a nested call's kwarg; enforcing schemes stay auth, variable-bound and inline |
| `test_websocket_no_auth_disabled_scheme_behind_a_comment_still_fires` | FN guard (#764 Rule 1): a comment ahead of a real `auto_error=False` does not hide it, variable-bound and inline |

# Citations

[1] agentsec checklist item `2b-websocket-auth` (§2b)
[2] OWASP:A01
[3] OWASP:A07
