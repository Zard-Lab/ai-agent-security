---
type: Guard
title: "auth-dependency-not-applied"
description: "State-changing route has no auth dependency wired."
timestamp: "2026-10-07T02:13:02+02:00"
guard_id: "auth-dependency-not-applied"
checklist_section: ["2b"]
standards: ["OWASP:A01", "OWASP:A07"]
---

# State-changing route has no auth dependency wired

_Author — 2026-07-02_

---

## The threat

The single most common way an endpoint ends up unintentionally public: a developer adds
a new `@router.post(...)` route and simply forgets to attach the `Depends(get_current_user)`
(or equivalent `Security(...)`) parameter that every other route in the file has. Nothing
raises an error — the route works, unauthenticated, for anyone who finds it.
OWASP:A01 (Broken Access Control) / OWASP:A07 (Identification and Authentication
Failures). This is the "the dependency was never wired" class of bug, distinct from
`bola` (which requires an object-id path parameter and a fetch call) — this guard fires
on ANY state-changing route with zero auth signal, regardless of whether it fetches an
object by id.

## Why it's often introduced

A project establishes the auth pattern early (`Depends(get_current_user)` on most
routes), then a later route — often added quickly, or copy-pasted from a public route
like signup — never gets the dependency added:

```python
router = APIRouter()

@router.post("/users/me")
def update_profile(data: ProfileUpdate, current_user: User = Depends(get_current_user)):
    ...

@router.post("/admin/delete-user")   # copy-pasted, dependency never added
def delete_user(user_id: int):
    db.delete(user_id)
    return {"status": "deleted"}
```

## Detection design

1. **applies() gate:** `"fastapi" in profile.features` — only runs for detected FastAPI
   stacks.

2. **Files scanned:** All `.py` files via `iter_files(d, (".py",))` from
   `python_scan_dirs`. Non-product paths (tests, fixtures) skipped via
   `is_nonproduct_path`.

3. **Pattern (`no-auth-dependency`, HIGH):**
   - Reuses the shared `iter_functions()` block-splitting helper in `guards/base.py` (also
     used by `bola.py`) to isolate each function's decorator + signature + body as one text
     block. The helper is bracket-aware, so multi-line decorator calls
     (`@router.post(\n  "/x",\n  status_code=201,\n)`) and multi-line signatures
     (`def f(\n  a,\n) -> dict:`) are captured whole rather than silently dropping the route.
   - `_STATE_CHANGING_ROUTE` matches a decorator on a state-changing HTTP method
     (`post`/`put`/`patch`/`delete`) on any router/app variable, capturing the variable
     name.
   - Router-level auth resolution lives in the **shared `base.py` helpers**
     `same_file_authed_routers(text)` and `cross_file_authed_routers(files)` (backlog #3b extracted
     the pass-1 resolver here from this guard so the sibling route-auth guards —
     `unauthenticated-file-download`, `privileged-field-assignment`, `websocket-no-auth` — resolve
     it identically). `same_file_authed_routers` matches `{var} = APIRouter(... dependencies=<deps>)`
     — a router-level auth dependency applies to every route on that router without a per-route
     `Depends(...)` — and a same-file bare-var `include_router(router, ... dependencies=<deps>)`.
     `<deps>` may be an inline `[...Depends(/Security(...]` list **or** a variable bound to one
     (`_auth = [Depends(...)]`; resolved via `_AUTH_DEP_LIST_VAR` in `_deps_carry_auth`).
   - `cross_file_authed_routers` resolves a `module.router` include **cross-file** in a repo-wide
     pass-1: the module stem maps to the route file (`include_router(admin.router, dependencies=_admin)`
     in `main.py` exempts every route in `routes/admin.py`). This is the common multi-file FastAPI
     layout. A bare-var include (`include_router(router, ...)`) is same-file, handled above.
   - Strictness: this guard passes `AUTH_CALL_NAMED` (a bare `Depends(get_db)`/
     `Depends(RateLimiter(...))` does not count as auth, matching the stricter siblings
     `privileged-field-assignment` and `unauthenticated-file-download`, issue #307 parity).
     `AUTH_CALL_NAMED` also recognizes `Depends(<FastAPI security-scheme class>())` — `HTTPBearer`,
     `JWTBearer`, `OAuth2PasswordBearer`, etc. — and, per-run, a module-level variable bound to one of
     those classes (`bearer_scheme = HTTPBearer()` then `Depends(bearer_scheme)`), via
     `auth_call_named_with_aliases`/`security_scheme_var_names` (neither class name carries
     an `_AUTH_NAME` stem, so both shapes previously read as unauthenticated).
   - A security scheme constructed with a **disabling `auto_error`** (`False`, `None`, `0`) does
     NOT count as auth. `HTTPBearer(auto_error=False)` returns `None` instead of raising 401, so
     the handler runs unauthenticated and the guard must still fire.
     `blank_disabled_security_schemes` (`guards/base.py`) blanks every such constructor call out of
     the file's text (whitespace, offsets preserved) before any auth-signal search runs, so the
     inline `Depends(HTTPBearer(auto_error=False))` and the variable-bound
     `scheme = HTTPBearer(auto_error=False)` shapes are both covered by one pass. It resolves the
     call's real argument span with `matching_close_paren`, not a bounded regex lookahead, which is
     what makes it multi-line and nested-paren tolerant (a fixed-width lookahead cannot
     know where a constructor call ends, so each attempt to widen it traded one bypass for a new
     false positive). The flag is read from the call's **own top-level arguments on a comment- and
     string-blanked view** (`_python_code_chars`, the router views' index-aligned core), so a
     mention in a comment (`# do NOT set auto_error=False here`), a string literal or a nested
     call's kwarg does not disable an enforcing scheme (#764). A comment ahead of a real
     `auto_error=False` still disables it: the comment is blanked before the call is split into
     arguments, which is why splitting the raw text was not the fix.
   - **Both router maps are built from a comment- and string-blanked view, never from raw source**
     (#532 on `main`, #473 re-gate on this branch, which found it independently in the prefix half).
     Only auth wiring that actually *runs* may exempt a route. The shapes that used to populate the
     map and silence every state-changing route on that router: a commented-out
     `include_router(..., dependencies=)`, a commented-out `APIRouter(dependencies=)`, the line
     quoted inside a docstring, and a trailing `#` comment inside an open multi-line call, with or
     without a space before the `#`. Two more shapes were closed by #538: a comment on the
     **closing line** of a multi-line triple-quoted string, and the call quoted inside an ordinary
     **single-line string** (`HINT = "router = APIRouter(dependencies=[...])"`, a `raise` message,
     an LLM prompt constant).

     The views are the shared `base.py` pair, one definition, so the auth resolvers and the prefix
     map cannot drift apart on what counts as a dead line. `router_resolver_view` blanks comments
     and triple-quoted strings, and keeps single-line strings because a `prefix="/auth"` value lives
     in one. `router_code_view` is the same view with every literal's **text** blanked too, and is
     what the auth resolvers read. Quotes are kept so it still parses, and so are an f-string's
     replacement fields, which are code (blanking only the text around a field that spans rows is
     what closes the PEP 701 multi-row shape, #1017 review). The two are
     offset-aligned, so the prefix map matches a router's STRUCTURE on the code view and reads the
     prefix VALUE from the other at the same span. Comments are located by the **tokenizer**: the
     per-line quote-pairing masker this used before paired the leftover delimiter quote on a
     triple-quote closing line with a quote inside the comment and hid the `#`. When there is no
     token stream (a file that does not tokenize), the views fall back to that per-line pass,
     which must be `strip_python_line_comment`, **not** `strip_hash_comments`: that is the
     YAML/shell helper, it treats `#` as a comment only after whitespace, and swapping it in is a
     measured fail-open in both directions (see the prefix note below).
   - `_AUTH_SIGNAL` checks the function block for `Depends(`, `Security(`,
     `current_user`, or `get_current_user`; `_AUTH_DECORATOR` checks for a well-known
     auth decorator (`@login_required`, `@jwt_required`, ...) — route-level auth present.
   - **Per-route bare-factory deps (#859):** a returns-nothing auth guard attached un-wrapped in the
     route's OWN `dependencies=[...]` decorator argument (`dependencies=[requires_authenticated()]`,
     `dependencies=[requires_system_write_role()]`) is real auth, but is neither `Depends()`/
     `Security()`-wrapped nor a `*Dep`/`*Depends` alias, so `_AUTH_SIGNAL` above misses it. The
     reader lives in `guards/base.py` as `route_deps_carry_auth` since #872, which shares it with
     the three per-route siblings (`unauthenticated-file-download`, `privileged-field-assignment`,
     `websocket-no-auth`), each passing its own matcher. The guard
     blanks line-comments in the block first (`blank_line_comments`, length-preserving, so a
     commented-out `dependencies=[...]` can't fake protection — the per-route counterpart of the
     #532 router-level comment-strip), locates *this route's* inline `dependencies=[` inside the
     decorator's balanced paren span (`matching_close_paren`, so a nested-call `)` before the kwarg
     can't hide it) and bracket-balance-scans the list (the shared `_deps_carry_auth`), clipped to
     that same decorator span, for a
     **curated** auth-named callable — `PER_ROUTE_AUTH_FACTORY`, built from `boundaried_stems` over `require`/`role`/`scope`/
     `auth`/`authenticat*`/`authoriz*`/`permission*` only. NOT the full `_AUTH_NAME`: the broad
     members (`user`/`token`/`current`/`login`/`verify`) are excluded so a non-guard dep
     (`track_login_attempt()`) isn't mistaken for auth. Scoped to the list contents, so a bare
     `get_db()`/`RateLimiter(...)` in the same position still fires. The clip to the
     decorator span is #872's one behaviour change here: the bracket scan is not quote-aware, so a
     `[` inside a string literal (`dependencies=[get_db('[')]`) leaves the list unterminated in
     valid Python. Before #872 the scan then ran on into the handler body, where a factory merely
     called there faked protection; now that route fires.
   - **Public-marker decorator (#859):** an explicit `@auth.public` / `@app.allow_anonymous` /
     `@…allow_unauthenticated` / `@…no_auth` / `@…unauthenticated` decorator (`_PUBLIC_MARKER`, whole
     final attribute only) is a deliberate "unauthenticated by design" declaration and is honored
     exactly like the pragma below.
   - Fires for **every** state-changing route (all reported, not just the first per file)
     whose router isn't in the router-level-authed set AND whose block has no auth signal,
     no auth decorator, no per-route deps-list auth, no public marker, and no route-scoped pragma.

4. **Inline opt-out pragma:** `# security: allow-unauthenticated-route` — **route-scoped**
   (checked against the route's own block, not the whole file), so one public route's
   pragma never blinds another route in the same file. Supported placements: **between the
   decorator stack and the `def`**, or **in the handler body**. A pragma *above* the top
   decorator is intentionally not honored — the walker does not capture comments above the
   decorator stack, because prose in such a comment could contain a token (`current_user`,
   `Depends(`) that would be misread as an auth signal and silence a genuinely unauthenticated
   route (a worse, silent false negative).

5. **Severity and rule:** `"high"`, rule
   `"auth-dependency-not-applied/no-auth-dependency"`, standards
   `["OWASP:A01", "OWASP:A07"]`.

## When NOT to flag

- Any `Depends(...)`/`Security(...)` call anywhere in the function — the guard trusts
  it's a real auth dependency, not verifying its target function is actually an auth
  check.
- A router constructed with a **live** `dependencies=[Depends(...)]` — every route on it is
  authenticated at the router level. A *dead* one (commented out, docstring-quoted, or in a
  trailing comment) does not exempt anything (#532).
- A route whose **own** `dependencies=[...]` carries a bare, un-wrapped auth-factory call whose name
  hits the curated stem set (`dependencies=[requires_authenticated()]`) — the idiomatic
  returns-nothing FastAPI guard (#859). A bare non-auth call in that same slot (`[get_db()]`,
  `[RateLimiter(...)]`) is not exempt and still fires.
- A route wearing an explicit **public-marker decorator** (`@auth.public`, `@app.allow_anonymous`)
  — honored like the pragma (#859). `public` is a marker only: a `/public/...` path, a
  `public_upload` handler, or a `@public_router.post(...)` decorator is **not** exempted.
- A GET route — read-only endpoints are frequently, legitimately public; this guard
  only targets state-changing methods.
- A **public-by-design route** — recognized and auto-exempted, no pragma needed (round-2
  §A.1/§E.2), because flagging it is a pure false positive:
  - **auth-flow endpoint** — the **last path segment** or the **whole handler name** (normalized
    `-`→`_`, lowercased) is in the curated `_AUTH_FLOW_NAMES` allowlist (`login`, `logout`,
    `signin`, `signout`, `signup`, `register`, `oauth`, `sso`, `reset_password`, `forgot_password`,
    `password_reset`, `magic_link`, `refresh_token`, and the `sign_in`/`log_out`/… variants). You
    cannot require a session to *create* one. An **ambiguous** auth verb (`exchange`, `callback`,
    `authorize`, `token`, `refresh`, `verify`, `confirm`, `challenge`) counts only when an
    `auth`/`oauth`/`sso`/`authentication` segment is **adjacent** to it *and* that segment sits at
    the path ROOT modulo pure scaffolding — API/version names (`api`, `v1`, …), a further
    `auth`/`oauth`/`sso` namespace segment, and **scaffolding path parameters** (see below). So
    `POST /auth/exchange`, `POST /api/v1/auth/token`, `POST /auth/oauth/token` and
    `POST /sso/auth/token` are exempt while `POST /api/token`, `POST /auth/admin/token` and
    `POST /users/oauth/token` are not.

    **The invariant both branches enforce** (#482 third- and fourth-pass reviews): a route may be
    exempted only when **no caller-supplied path parameter, and no path segment, selects the SUBJECT
    the route acts on**. A public auth-flow route is an ENTRY POINT at or near the path root; a
    resource **before the auth verb** means the route acts ON a resource, so it is not exempt —
    `POST /admin/{user_id}/login` (impersonation), `POST /users/{user_id}/reset-password`
    (arbitrary-user reset), `POST /users/{user_id}/oauth/token` (arbitrary-user token minting) and
    `POST /users/{user_id}/logout` all fire.

    That question is asked of path **parameters** too, by NAME, against the anchored, fail-CLOSED
    `_SCAFFOLD_PARAM` allowlist (`version`/`ver`/`v\d`/`api_version`, `provider`, `idp`, `region`,
    `locale`, `lang`/`language`, `tenant`, `workspace`, `realm`). Those name deployment scaffolding —
    *which* API version / region / identity provider / tenant the caller is talking to — and select no
    subject, so `POST /api/{version}/auth/token`, `POST /v1/{region}/auth/token`,
    `POST /{tenant}/auth/token` and `POST /auth/{provider}/oauth/token` (social login) stay exempt.
    Anything else is a subject: `POST /api/{user_id}/auth/token`, `POST /v1/{account_id}/auth/refresh`,
    `POST /auth/{id}/oauth/token`, `POST /api/{email}/auth/challenge` and
    `POST /auth/{user_id}/token` all fire. The allowlist is **anchored**, so a name that merely
    contains a scaffolding word (`{provider_id}`, `{tenant_user_id}`, `{my_version}`) is not
    scaffolding, and an unrecognized or degenerate name (`{userId}`, `{}`) disqualifies rather than
    exempting. Testing scaffolding on the parameter-free projection of the path instead — which
    answered "parameters do not exist" — took eleven impersonation-shaped routes silently from 1 to 0
    (#482 fourth-pass gate); the allowlist replaced it.

    A parameter **after** the verb is usually an ordinary public shape: the emailed link, where the
    parameter is a credential rather than a subject (`/auth/reset-password/{token}`,
    `/auth/verify/{token}`, `/signup/{invite_code}`). Until #538 it never disqualified, so on a
    verb-first route a SUBJECT trailing the verb was exempt too: `POST /logout/{user_id}`,
    `POST /auth/token/{user_id}`, `POST /reset-password/{user_id}`. Now, for the verbs that **act
    on** the subject a trailing parameter names, the trailing parameters are read by name as well.
    These are `logout`/`signout`/`sign_out`/`log_out`, `reset_password`/`password_reset`,
    `refresh_token`, and in the ambiguous-verb branch `token`/`refresh`/`verify`/`confirm`. The
    route stays exempt only if a trailing parameter is a credential (`_CREDENTIAL_PARAM`), or if
    they are all scaffolding (`_SCAFFOLD_PARAM`). The credential test is **anchored**: the whole
    name must be a credential word (`token`, `code`, `otp`, `nonce`, `signature`/`sig`, `hash`,
    `ticket`, `jwt`, `secret`, `key`), alone or after one or two credential contexts (`reset_token`,
    `resetToken`, `verification_code`, `invite_code`, `api_key`, `password_reset_token`,
    `email_verification_code`, `oauth_access_token`), or `invite`/`invitation`. A qualifier
    (`account_`, `user_`, ...) counts only in front of a context, so `account_recovery_token` is a
    credential while `account_code` and `user_token` stay subjects and fire. An identifier that
    merely ends in a credential word is a subject:
    `/logout/{employee_code}`, `/auth/token/{dealer_code}` and `/logout/{file_hash}` fire. An
    unanchored suffix match exempted all three silently, because a credential anywhere in the run
    forgives the rest (#1017 review). That forgiveness is what keeps the Django-style
    `/password-reset/{uidb64}/{token}` exempt. Like `_SCAFFOLD_PARAM`, the list is fail-CLOSED: a
    credential spelled outside it (`{pin}`) over-fires rather than being exempted. The
    session-creating and request verbs are NOT asked this, a
    disclosed trade (see Known bypasses). Any resource segment still disqualifies, so
    `POST /auth/admin/{user_id}/login` and `POST /users/{user_id}/auth/login` fire.

    The two branches deliberately differ on one shape: the ambiguous-verb branch reads *every*
    parameter before the verb, so `POST /auth/{user_id}/token` fires, while the `_AUTH_FLOW_NAMES`
    branch still exempts `POST /auth/{user_id}/login` (indistinguishable from the social-login
    `POST /auth/{provider}/login` — a disclosed accepted false negative, see Known bypasses).
  - **webhook receiver** — the handler **calls** a signature-verification primitive
    (`construct_event`, `verify_signature`, `verify_header`, `verify_webhook`), checked on
    comment/string-stripped code. The verification CALL is the exemption; a receiver-shaped path is
    not, since the signature is what authenticates the request.

  A router's `prefix=` is **never an exemption in itself** — it only contributes path text, so the
  full path is known when the per-route test runs. Treating "this router has an `/auth` prefix" as
  a blanket exemption silenced every route on it, including `POST /auth/admin/impersonate`,
  `DELETE /auth/users/{id}` and `PUT /auth/users/{id}/role` (20/20 findings down to 8/20 on a
  20-route corpus), and the `/auth` match had no positional bound so `prefix="/auth/admin"` and
  `prefix="/v1/auth/internal"` exempted everything beneath them too. Likewise, a receiver-shaped
  path alone exempted `POST /webhooks/subscribe`, `DELETE /api/v1/webhooks/all` and
  `PUT /webhooks/rotate-secret` — and, worse, a receiver that verified nothing, which is precisely
  the bug worth reporting. (All closed in the PR #482 review.)

  The allowlist is deliberately conservative — **whole-token**, so a compound that merely contains a
  verb (`register_device`, `sso_link_account`, `refresh_dashboard`, `verify_payment`) still fires,
  and `change_password` is excluded (it requires the current session). Every other state-changing
  route still fires.
- A genuinely public endpoint not covered by the above (a health check, a bespoke public
  action) suppressed with the inline `# security: allow-unauthenticated-route` pragma.

## Tests

| Test | What it checks |
|---|---|
| `test_applies_when_fastapi_feature_present` | Guard activates on `fastapi` feature |
| `test_not_applies_without_fastapi_feature` | Guard skips non-FastAPI stacks |
| `test_fires_on_state_changing_route_with_no_auth` | Fires: POST route, no Depends/Security/current_user anywhere |
| `test_fp_bait_route_level_depends` | Silent: `Depends(get_current_user)` on the route |
| `test_fp_bait_router_level_dependencies` | Silent: router constructed with `dependencies=[Depends(...)]` |
| `test_fp_bait_get_route_not_state_changing` | Silent: GET route (read-only, not targeted) |
| `test_fp_bait_security_call_recognized` | Silent: `Security(...)` recognized as an auth signal |
| `test_fp_bait_inline_httpbearer` | Silent: `Depends(HTTPBearer())` recognized despite no `_AUTH_NAME` stem in the class name |
| `test_fp_bait_module_level_security_scheme_var` | Silent: a module-level `bearer_scheme = HTTPBearer()` referenced as `Depends(bearer_scheme)` is resolved |
| `test_fires_when_alias_var_is_not_a_security_scheme` | Fires: a variable bound to something OTHER than a security-scheme class is not mistaken for one |
| `test_fp_bait_pragma` | Silent: route-scoped pragma in the handler body |
| `test_unresolvable_span_with_a_disabled_scheme_still_fires` | Fires (#761 re-review): `auto_error=False` behind an unresolvable span. The FN an earlier revision of the fix left open. Untokenizable file, so the raw path runs (#764), and an apostrophe in the call's own comment is what leaves it unresolvable there (#613) |
| `test_unresolvable_span_with_an_enforcing_scheme_also_fires_accepted_cost` | Fires by design: an unresolvable span cannot be read, so an enforcing scheme surfaces too. The accepted FP, now raw-path only (#764) |
| `test_resolvable_span_with_an_enforcing_scheme_stays_silent` | FP-bait: the ordinary enforcing case stays silent, proving the widening did not leak past unresolvable spans |
| `test_resolvable_span_with_a_disabled_scheme_still_fires` | Fires: the original case, unchanged |
| `test_stray_quote_in_a_tokenizable_file_no_longer_surfaces_an_enforcing_scheme` | Silent (#764): the #613 stray quote sits in a string the code view blanks, so the span resolves and the enforcing scheme counts |
| `test_stray_quote_in_a_tokenizable_file_still_fires_when_disabled` | Fires (#764 Rule 1): the same stray quote with a real `auto_error=False` is still disabled, now by its own argument |
| `test_raw_path_stray_quote_no_longer_surfaces_an_enforcing_scheme` | Silent (#613): in a file the tokenizer rejects, the raw walk reads the triple-quoted description as one span, so the enforcing scheme counts |
| `test_raw_path_stray_quote_still_fires_when_disabled` | Fires (#613 Rule 1): the same raw-path span with a real `auto_error=False` is still disabled, by its own span |
| `test_enforcing_scheme_that_mentions_auto_error_stays_silent` | Silent (#764 FP-bait): the flag only in a comment, an apostrophe comment, a string or a nested call's kwarg; variable-bound and inline |
| `test_disabled_scheme_behind_a_comment_still_fires` | Fires (#764 Rule 1): a comment line, or a comment with a quote, ahead of a real `auto_error=False`; the raw-text `split_call_args` fix would have silenced both |
| `test_unresolvable_scheme_span_does_not_erase_later_routes` | Fires: a later route is not blanked away by an unresolvable span above it (raw path, untokenizable file) |
| `test_unresolvable_scheme_span_does_not_swallow_a_pragma` | Silent for the pragma'd route, fires for its unpragma'd neighbour, so the pragma (not erasure) is what silenced it (raw path) |
| `test_pragma_is_route_scoped_not_file_wide` | Fires: one route's pragma does not blind another unauthed route in the file |
| `test_fires_on_every_unauthed_route_in_file` | Fires: all unauthed routes reported (not just the first) |
| `test_fp_bait_include_router_dependencies` | Silent: `app.include_router(router, dependencies=[Depends(...)])` |
| `test_include_router_without_deps_still_fires` | Fires: `include_router(router)` with no deps |
| `test_fp_bait_cross_file_include_with_variable_dependency` | Silent: `main.py` mounts `admin.router` with a variable dep; resolves cross-file to `routes/admin.py` |
| `test_cross_file_include_without_deps_still_fires` | Fires: cross-file include with no `dependencies=` still surfaces |
| `test_cross_file_protection_is_stem_specific` | Fires: protecting `admin.router` does not silence an unrelated `public.py` router |
| `test_cross_file_protection_is_per_router_not_whole_file` | Fires: an authed sibling router in the same module does not silence the unauthed one (#473) |
| `test_cross_file_protection_applies_to_the_named_router` | Silent: the route sits on the router that IS mounted with auth |
| `test_cross_file_multidot_ref_maps_to_correct_module` | Fires/silent: `app.routes.admin.router` maps to `admin` (segment before `.router`), not the leftmost |
| `test_fp_bait_nested_bracket_before_depends_in_deps_list` | Silent: `[limiter(times=[5]), Depends(...)]` not truncated at the first `]` |
| `test_fp_bait_annotated_auth_dep_variable` | Silent: `_admin: list = [Depends(...)]` (annotated dep-var) resolved |
| `test_fp_bait_router_construct_with_variable_dependency` | Silent: `APIRouter(dependencies=_auth)` where `_auth = [Depends(...)]` |
| `test_fp_bait_per_route_bare_auth_factory_dependency` | Silent (#859 sub-fix A): bare `dependencies=[requires_authenticated()]` / `[requires_system_write_role()]` — the un-wrapped returns-nothing guard |
| `test_fp_bait_per_route_bare_auth_factory_alongside_a_non_auth_dependency` | Silent (#859): `[get_pagination(), requires_authenticated()]` — the bracket-balance scan keeps the second element's auth (a paren-only splitter would truncate at the top-level comma) |
| `test_fires_when_per_route_dependency_is_a_bare_non_auth_call` | Fires (#859 direction traded against): bare `[get_db()]` and `[RateLimiter(...)]` carry no curated auth stem — both routes still fire |
| `test_per_route_bare_auth_factory_recognition_is_scoped_to_the_deps_list` | Fires (#859 scoping guard): a `requires_authenticated()` mention in the route BODY (not the deps list) does not silence it; the deps-list sibling is silent, so recognition is route- and list-scoped |
| `test_fp_bait_public_marker_decorator` | Silent (#859 sub-fix B): `@auth.public` and `@app.allow_anonymous` honored like the pragma |
| `test_public_word_in_path_or_handler_name_still_fires` | Fires (#859 direction traded against): `/public/upload` path, `public_upload` handler, `@public_router.post(...)` — `public` is a marker, not a name/path exemption |
| `test_commented_out_per_route_deps_does_not_exempt` | Fires (#859 review, #532 per-route counterpart): a commented-out `dependencies=[requires_authenticated()]` above the real `dependencies=[get_db()]` does not fake protection (line-comments blanked before the scan) |
| `test_live_per_route_deps_with_a_decorator_comment_still_exempt` | Silent (#859 review FP-bait): a LIVE `dependencies=[requires_authenticated()]` in a multi-line decorator that also carries a comment still suppresses — comment-blanking must not eat live auth |
| `test_unterminated_deps_list_does_not_read_the_handler_body` | Fires (#872 / #1041 R1-M2): `dependencies=[get_db('[')]` leaves the list unterminated, and a factory called in the body no longer fakes protection; the neighbour with the factory applied in the list stays silent |
| `test_fp_bait_auth_decorator` | Silent: `@login_required` (auth-decorator allowlist) |
| `test_near_miss_decorator_does_not_silence` | Fires: `@require_https` (not an auth decorator) |
| `test_fires_on_route_with_comment_between_decorator_and_def` | Fires: comment between decorator and `def` no longer drops the route |
| `test_pragma_between_decorator_and_def_is_honored` | Silent: pragma in that same position is honored |
| `test_exempt_auth_flow_routes_by_path` | Silent (§A.1): `/signup` · `/login` · `/logout` auto-exempt |
| `test_exempt_auth_flow_by_function_name_generic_path` | Silent: generic path but `def refresh_token` handler name |
| `test_exempt_route_on_auth_prefix_router` | Silent: `/auth/exchange` — an ambiguous auth verb under an `auth` path segment |
| `test_auth_prefix_router_exempts_only_the_auth_flow_route` | Fires (#482): `/admin/impersonate`, `DELETE /users/{id}` and `PUT /users/{id}/role` on an `/auth`-prefixed router are NOT exempt — parametrized over `/auth`, `/auth/admin`, `/v1/auth/internal` |
| `test_webhook_path_without_signature_verification_still_fires` | Fires (#482): a receiver-shaped path that verifies NOTHING is the bug, not an exemption |
| `test_webhook_management_routes_are_not_exempt` | Fires (#482): `POST /webhooks/subscribe`, `DELETE /api/v1/webhooks/all`, `PUT /webhooks/rotate-secret` |
| `test_signature_verified_webhook_receiver_is_still_exempt` | Silent (§E.2): the verification CALL is the exemption |
| `test_exempt_route_that_verifies_signature` | Silent (§E.2): handler calls `construct_event` |
| `test_still_fires_on_non_auth_route_beside_auth_flow_routes` | Fires: an admin DELETE beside auth-flow routes still fires (per-route exemption) |
| `test_exemption_does_not_over_match_compound_names` | Fires: `register_device` · `sso_link_account` · `POST /api/token` (whole-token allowlist, no compound over-match) |
| `test_auth_prefix_boundary_does_not_match_authors` | Fires: `prefix="/authors"` is not an `/auth` router |
| `test_sig_verify_in_comment_or_unused_header_does_not_exempt` | Fires: a commented-out `verify_signature()` / an unused `X-*-Signature` header does not exempt |
| `test_webhook_management_collection_still_fires` | Fires: `POST /api/webhooks` management collection (only a `/webhook/<provider>` receiver is exempt) |
| `test_auth_segment_must_be_adjacent_to_the_ambiguous_verb` | Fires (#482): `POST /auth/admin/token`, `POST /oauth/users/{id}/verify` — the auth segment must be adjacent, not anywhere earlier |
| `test_adjacent_auth_segment_still_exempts_the_flow_route` | Silent: `/auth/exchange`, `/auth/callback` |
| `test_resource_scoped_auth_verbs_are_not_public_by_design` | Fires (#482 third pass): `POST /admin/{user_id}/login` (`impersonate_user`), `POST /users/{user_id}/reset-password` (`admin_force_reset_password`), `POST /users/{user_id}/oauth/token` (`mint_token_for_user`) — all 4 routes fire, not just the control |
| `test_privileged_route_spelled_like_an_auth_flow_still_fires` | Fires: 11 resource-scoped shapes (path-segment, handler-name, auth-namespace-with-a-resource, root-anchored ambiguous verb) |
| `test_router_prefix_supplies_the_resource_scope` | Fires: `APIRouter(prefix="/users")` + `POST /{user_id}/login` is impersonation |
| `test_public_auth_flow_routes_stay_exempt` | Silent: 22 genuinely public shapes — `/login`, `/auth/login`, `/api/v1/auth/login`, `/auth/callback`, `/auth/exchange`, `/oauth/token`, `/users/login`, trailing-param link shapes, `/auth/{provider}/login`, `/{tenant}/auth/login`, and `/auth`- / version-prefixed routers |
| `test_signature_verified_webhook_is_unaffected_by_the_path_anchor` | Silent: the webhook exemption is the verification CALL, even on a resource-scoped path |
| `test_commented_out_include_router_dependencies_does_not_exempt` | Fires (#532): a commented-out `include_router(..., dependencies=)` above a live bare mount |
| `test_commented_out_router_constructor_dependencies_does_not_exempt` | Fires (#532): the constructor spelling — commented-out `APIRouter(dependencies=)` |
| `test_dependencies_inside_a_docstring_does_not_exempt` | Fires (#532): a module docstring showing how to wire the router is documentation, not wiring |
| `test_trailing_comment_carrying_dead_dependencies_does_not_exempt` | Fires (#532): a `# was: dependencies=[...]` comment INSIDE an open multi-line mount (the comment must be within the parens to reach the map — after the call closes it never could) |
| `test_dead_dependencies_with_no_space_before_the_hash_does_not_exempt` | Fires (#532): `router,#was dependencies=[...]` — the shape that pins `strip_python_line_comment` over `strip_hash_comments` (the latter needs whitespace before `#`, measured fail-open) |
| `test_live_include_router_dependencies_still_exempts` | Silent (#532 FP bait): real `include_router(..., dependencies=)` still suppresses |
| `test_live_router_constructor_dependencies_still_exempts` | Silent (#532 FP bait): real `APIRouter(dependencies=)` still suppresses |
| `test_live_multiline_include_with_per_argument_comments_still_exempts` | Silent (#532 FP bait): blanking a comment on every argument line must not break the multi-line match |
| `test_hash_inside_a_string_literal_does_not_truncate_the_live_deps` | Silent (#532 FP bait): `tags=["#admin"]` before a live `dependencies=` — a naive `split("#")` would clip the line and invent a finding |
| `test_live_deps_after_a_multiline_description_is_recognized_as_authed` | Silent (#532 **narrowing**): blanking a triple-quoted `description=` removes the paren that used to truncate the DOTALL span, so live router-level auth after it is now seen. Measured 1 finding on `main`, 0 after: a false positive removed (#537 review, Medium 2) |
| `test_a_multiline_description_without_deps_still_fires` | Fires (#532 narrowing guard-rail): the same docstring shape with no `dependencies=` must still report. Goes red if blanking ever lets a match run past the router's own `)` and steal a second router's auth |
| `test_dependencies_in_a_comment_on_a_triple_quote_closing_line_do_not_exempt` | Fires (#538 A): `"""  # TODO restore the "admin" gate: …dependencies=[…]` in `"""`/`'''` and constructor/include spellings — 2 of 2 routes, 0 before |
| `test_include_prefix_in_a_comment_on_a_triple_quote_closing_line_does_not_exempt` | Fires (#538 A, prefix map): the same closing-line comment cannot mint a phantom `/auth` for a bare `POST /token` |
| `test_dependencies_inside_a_one_line_string_do_not_exempt` | Fires (#538 B): one-line dq / sq / f-string / include / implicit-concat / `raise` message / prompt constant, a deps list spelled only inside a LIVE call's `description=`, and (#1017 review) the text around a multi-row f-string field, a string or an f-string inside such a field |
| `test_router_prefix_inside_a_one_line_string_does_not_exempt` | Fires (#538 B, prefix map): a one-line string spelling a constructor or include `prefix='/auth'`, and `prefix=` inside a live call's string argument |
| `test_cross_file_mount_inside_a_one_line_string_does_not_exempt_multi_file` | Fires (#538 B, cross-file): `main.py` quoting `include_router(admin.router, dependencies=…)` it does not perform |
| `test_fp_bait_live_router_auth_beside_dead_text_still_exempts` | Silent (#538 FP bait): live router auth beside a string that spells a deps list (also a **narrowing**: on `main` the lazy scan stopped at the string's `[]` and over-fired), `#`/quotes in strings, a backslash-continued string, a multi-row f-string, one with text, a nested f-string, a format spec and `{{` escapes around the field, and variable deps |
| `test_conditional_mount_still_fires_when_the_file_has_strings` | Fires (#538 guard-rail): the code view must still PARSE, or `_conditional_lines` would silently count a mount under an `if` as protection; the file carries every literal shape the blanker must keep parseable |
| `test_fp_bait_a_live_prefix_still_exempts_through_the_code_view` | Silent (#538 FP bait): live constructor / include `prefix="/auth"` still exempts `POST /token`; plus the **narrowing** where a `)` inside an earlier string no longer hides the live prefix |
| `test_a_paren_in_a_string_does_not_let_a_prefix_bleed_from_the_next_router` | Fires (#538 narrowing guard-rail): with no `prefix=` of its own, a router must not pick up the next router's `/auth` |
| `test_subject_acting_auth_verb_with_a_trailing_subject_param_fires` | Fires (#538 / #510): `/logout/{user_id}`, `/auth/token/{user_id}`, `/auth/verify/{user_id}`, `/reset-password/{user_id}`, `/logout/{session_id}`, a `logout` handler on `/sessions/{user_id}`, and identifiers ending in a credential word (`/logout/{employee_code}`, `/auth/token/{dealer_code}`, `/logout/{file_hash}`, `/logout/{invite_id}`), and a qualifier without a context (`/logout/{account_code}`, `/auth/token/{user_token}`) |
| `test_dead_string_on_the_last_line_does_not_exempt_with_or_without_a_final_newline` | Fires (#1017 re-review, Critical 1): a file with no final newline used to lose its token stream and fall back to the pre-#538 view, so a dead one-line string minted the auth map again (0 vs 1) |
| `test_verb_first_routes_that_stay_public_by_design` | Silent (#538 FP bait): session-creating verbs (`/login/{username}`, `/login/{sns_type}`, `/register/{role}`), request verbs (`/forgot-password/{email}`), trailing credentials alone or after one or two credential contexts (`/reset-password/{resetToken}`, `/auth/verify/{verification_code}`, `/auth/token/{api_key}`, `/reset-password/{password_reset_token}`, `/reset-password/{account_recovery_token}`, `/password-reset/{uidb64}/{token}`), scaffolding, uninspected protocol steps |

## Known bypasses

- A security scheme whose argument span cannot be resolved has its **constructor token**
  (`HTTPBearer(`) blanked, so it stops counting as a proven auth signal and its routes surface for
  review. Nothing past the token is touched, so no later route, auth signal or inline pragma can be
  swallowed. **This over-fires when the unresolvable scheme was in fact enforcing**, and that is the
  chosen direction: a false negative here would silently pass a genuinely unauthenticated route,
  and the pragma covers the false positive. Since #764 this is reached only on the raw path, i.e.
  in a file the tokenizer rejects; in an ordinary file the span is resolved on the code view.
  Two rejected alternatives, both shipped and reverted during #761's review rounds: treating an
  unresolvable span as "runs to end of file" blanked every later route and pragma out of the
  guard's view, silently; and *skipping* the call entirely is not neutral either, because nothing
  downstream re-examines it and neither `_TOP_LEVEL_ASSIGN` nor `security_scheme_var_names` knows
  about `auto_error`, so leaving the text intact positively asserts the scheme enforces and a
  disabled one goes silent.
- On the code view a span is unresolvable only on genuinely unbalanced parens: string contents and
  comments are blanked before `matching_close_paren` runs, so a quote in a comment cannot reach it
  (#764). A file the tokenizer rejects is judged on its raw span instead, walked in the walkers'
  Python mode, which reads a triple-quoted string as one span (#613), so a quote inside a
  docstring-style description no longer desyncs it. **The raw path keeps one residual: a quote in a
  comment.** The walk has no `#` state, so such a quote can leave the span unresolvable (handled
  above) or resync on a later quote and return a confidently *wrong* index instead of `None`, in
  which case the call is treated as ending somewhere it does not and the blanking can reach into
  unrelated code.
- A disabling value the scan cannot read as a literal is not recognized, so that scheme still
  counts as auth: `auto_error=settings.OPTIONAL_AUTH` or `**{"auto_error": False}`. Unchanged by
  #764, which only stopped text that is not one of the call's own arguments from counting.

- Well-known auth **decorators** (`@login_required`, `@jwt_required`, `@requires_auth`,
  `@require_auth`, `@token_required`, `@authenticated`) ARE recognized as applied auth.
  An **exotic/custom** auth decorator outside that allowlist — or manual header parsing
  with no `Depends`/`Security`/`current_user` token — is *not* recognized, so the guard
  **over-fires on a route that is actually protected (a false positive)**. Suppress that
  route with the inline `# security: allow-unauthenticated-route` pragma. (The allowlist
  is deliberately narrow: generic tokens like `require`/`auth`/`protected` are excluded so
  the guard never *under*-fires — a false negative on a genuinely unauthed route is the
  worse failure.)
- A **bare per-route auth factory named outside the curated stem set** (#859) — e.g.
  `dependencies=[verify_jwt()]` or `dependencies=[ensure_session()]`, where the guard name carries
  none of `require`/`role`/`scope`/`auth`/`authenticat*`/`authoriz*`/`permission*` — is not
  recognized and the route **over-fires (a false positive)**. The curated set is deliberately
  narrower than `_AUTH_NAME`: widening it to the broad members (`user`/`token`/`current`/`login`/
  `verify`) would let a NON-guard dependency in a deps list read as auth (`track_login_attempt()`),
  the worse under-fire direction. Suppress the false positive with a `Depends()` wrap or the pragma.
- A **per-route `dependencies=<var>`** bound to a variable rather than an inline `[...]` list is not
  resolved at the route site (#859 is scoped to the inline-list form); the route fires. The
  router-level resolvers DO resolve a `dependencies=<var>` (`_auth_dep_list_vars`), so hoisting the
  guard to the router, or inlining the list, both restore recognition.
- The per-route deps scan blanks LINE-COMMENTS (a commented-out `dependencies=[...]` can't fake
  protection, #859 review) but reads SINGLE-LINE STRINGS as-is. So a route whose decorator carries
  the literal text `dependencies=[requires_auth()]` inside an unrelated single-line string
  (`summary="... dependencies=[requires_auth()] ..."`) BEFORE its real `dependencies=[get_db()]`
  could be silenced. Blast radius is that one route. The router-level resolvers no longer carry the
  equivalent residual: since #538 they read `router_code_view`, where single-line string content is
  blanked. Triple-quoted strings are already blanked upstream by `iter_functions`.
- A comment or unrelated string containing `Depends(` anywhere in the function
  silences the rule without a real dependency being present — the guard doesn't verify
  the auth signal is genuine, only that a recognizable token is present.
- A **custom** security-scheme subclass with a name outside the closed allowlist
  (`HTTPBearer`, `JWTBearer`, `OAuth2PasswordBearer`, etc. — see `_SECURITY_SCHEME_CLASSES`,
  base.py) — e.g. `Depends(MyCompanyAuth())` where `MyCompanyAuth` extends `HTTPBearer` under
  an unrelated name — is not recognized. Widening the allowlist to a
  stem match instead would reopen issue #345's over-suppression, so this stays a closed,
  explicit list rather than a pattern.
- Same-file router-level dependency detection requires the construction/inclusion and the
  `@router.post(...)` decorator to reference the same literal variable name; a reassigned
  same-file router variable is not tracked.
- A module-level security-scheme variable used ONLY as a router-mount `dependencies=[Depends(name)]`
  argument, where a DIFFERENT file happens to define its own local, unrelated variable of the exact
  same name — not fixed by the fix-round review, and NOT safe-by-default: `cross_file_authed_routers`
  still resolves aliases from the whole run's file set rather than being scoped per-file the way the
  same-file/per-route checks now are (closing this needs a signature change shared with
  `websocket-no-auth`, `unauthenticated-file-download`, and `privileged-field-assignment`, not a
  one-file patch). Avoid reusing a security-scheme variable's name across unrelated files; add
  pragma if hit.
- **Multi-file** composition IS now tracked: a repo-wide pass-1 resolves
  `include_router(module.router, dependencies=<auth>)` (inline or variable deps) to the route
  file `module.py` by **stem**, then to the specific ROUTER by the attribute name, so an authed
  sibling router never silences an unauthed one (#473 review). Protection must be unconditional
  and unambiguous: a second bare mount of the same router, a mount under an `if`, an include that
  appears only in a comment or docstring, and a stem carried by two product files all leave the
  routes surfacing. One limit remains: the include must reference `module.<router>` — an
  **aliased** import (`import routes.admin as a; a.router`) whose alias differs from the file stem
  is not matched, so those routes over-fire (a false *positive*, the safe direction); suppress
  with the pragma. Full-path resolution (following the `include`'s import) would close it;
  deferred as not worth the cross-module import-resolution complexity.
- The router **prefix** map, unlike the auth resolution above, is still **same-file only** —
  `prefix="/auth"` applied at a cross-file `include_router(auth.router, prefix="/auth")` is not
  seen from the routes file, so the route's path reads without it. This is a false-*positive*
  direction (an auth route may over-fire), covered by the path/name allowlist for the common auth
  verbs and by the pragma otherwise. It is deliberate that only a **bare** reference records a
  prefix: a dotted `admin.router` names another module's router, and binding its prefix to a local
  name of the same spelling is a mis-attribution that *exempts* a route which should fire (see the
  kwarg-order defect below). Over-firing is the safe direction; mis-attributing is not.
- **The prefix map's two failure directions are not symmetric**, and saying only the safe half of
  that out loud is what let the next bug through (#473 re-gate, HIGH 1). A **missing** prefix is
  fail-CLOSED: the path reads shorter, fewer routes qualify for the exemption, the guard over-fires.
  A **phantom** prefix is fail-OPEN: a prefix the running app never applies makes a route read as
  something `_is_public_by_design` forgives, and the finding vanishes with nothing to notice. The
  prefix map is therefore derived from the same comment/docstring-blanked view as the auth resolvers
  in `base.py`, so a dead line cannot mint a prefix: a stray
  `# app.include_router(router, prefix="/auth")` above a bare `POST /token` used to make it read as
  `/auth/token` and drop the finding entirely (1 -> 0, measured on this branch and on `main`, where it
  arrived with #482). The VALUE is itself a string, so blanking strings outright would delete it.
  Since #538 the map therefore matches a router's structure on `router_code_view`, where a call
  quoted inside a one-line string (`HINT = "router = APIRouter(prefix='/auth')"`) cannot match, and
  reads the prefix from the offset-aligned `router_resolver_view` at the same span. So an ordinary
  `prefix="/auth"` on a live line still exempts.
- The include-prefix map is **parsed**, not pattern-matched, for the same reason the router
  reference is (#473 gate, B6). The regex it replaces took the first token after the paren as the
  router variable, so `include_router(router=admin.router, prefix="/auth")` bound the prefix to the
  keyword NAME `router`; any local `router = APIRouter()` in that file then inherited a prefix it
  did not have, and a `POST /token` on it read as `/auth/token` and was exempted. Measured on
  `main` before the fix: the same file reported 1 finding with the mount spelled positionally and
  **0** with it spelled `router=`. Kwarg order broke it the other way too — `include_router(prefix=…,
  router=x)` matched nothing at all. All three spellings now agree.
- **The router-level dead-line class is closed for both residuals #538 tracked.** An earlier
  version of this page recorded the first as "not reproducible". That was a measurement of the
  wrong shape: the apostrophe probe (`don't_x = 1  # ...`) blanks correctly, but the
  triple-quote-closing-line shape needs a quote of the SAME character as the delimiter inside the
  comment, and with one it reproduced on `main` at 0 findings against a control of 2.
  - **Closed (#538 A):** a comment on the **closing line** of a multi-line triple-quoted string
    (`"""  # TODO restore the "admin" gate: widgets = APIRouter(dependencies=[...])`). The per-line
    masker paired the leftover delimiter quote with the comment's quote and hid the `#`. Comments
    are now located by the tokenizer. The same text minted a phantom `/auth` prefix the same way.
  - **Closed (#538 B):** an ordinary **single-line** string literal
    (`HINT = "router = APIRouter(dependencies=[Depends(require_admin)])"`, a `raise` message, an
    implicit concatenation, an LLM prompt constant, a `description=` argument of a live call, or
    the text around a multi-row PEP 701 f-string field).
    Only triple-quoted strings used to be blanked, which made the gap arbitrary rather than
    principled. The resolvers now read `router_code_view`. This closes the class for every guard
    that shares them (`websocket-no-auth`, `privileged-field-assignment`,
    `unauthenticated-file-download`, `mcp-twin-route-auth-asymmetry`). The same change narrowed one
    false positive: a live `dependencies=[Depends(...)]` after a string spelling
    `dependencies=[]` used to be missed because the lazy scan stopped inside the string.
  - **Still open, per route:** the `_AUTH_SIGNAL` pass reads the **raw** route block, so a
    `Depends(...)` or `current_user` inside a comment or string in a handler still exempts that one
    route (measured: `# TODO: require current_user` in the body, 0 findings against a control of
    1). The blast radius is one route, not every route on the router. Closing it must keep
    `_PRAGMA` seeing the body's comments (CLAUDE.md rule 4), so it is not folded in here.
  - **Fallback:** a file that does not tokenize gets the pre-#538 per-line pass, so both residuals
    reopen for that file. That is no worse than before, and a file that does not tokenize also
    does not import. A file that merely lacks a final newline is NOT such a file: it tokenizes,
    and it is pinned so (the first cut of the token pass sent every such file to the fallback,
    #1017 re-review).
- Conversely, the auth-flow/webhook exemption is a deliberate **false-negative** surface —
  an exemption in an auth guard *is* a suppression, so every shape it covers stops being
  reported. An unusual public-auth route whose path+name are outside `_AUTH_FLOW_NAMES`
  will fire (surface for review, the safe direction). In the other direction these shapes
  are exempted even though they may want auth, and each needs a real `Depends(...)` (a
  pragma cannot help — the route is already silent):
  - a route whose **last path segment or handler name** is a whole `_AUTH_FLOW_NAMES` token
    and that is **not** resource-scoped: `POST /admin/users/login` (nested, but no path
    parameter before the verb — closing it would also fire on `POST /users/login`, the
    ordinary REST login spelling), and `POST /users/{uid}` handled by a function literally
    named `login` (the parameter is the LAST segment, so nothing precedes the anchor). A
    handler named for a SUBJECT-ACTING verb no longer gets this pass: `logout` on
    `POST /sessions/{user_id}` fires (#538).
  - a route inside an explicit **auth namespace** whose only other preceding segment is a
    parameter, in the `_AUTH_FLOW_NAMES` branch: `POST /auth/{user_id}/login` is
    indistinguishable from the social-login `POST /auth/{provider}/login`, so it is exempt.
    Add a resource segment (`/auth/admin/{user_id}/login`) and it fires again. Note the
    ambiguous-verb branch is **stricter** here — `POST /auth/{user_id}/token` fires, because
    that branch reads parameter names against `_SCAFFOLD_PARAM` and `user_id` is a subject.
  - a **VERB-FIRST** route on a **session-creating** or **request** verb, where the auth verb is
    the last NAMED segment and a subject parameter trails it: `POST /login/{user_id}`,
    `/oauth/{user_id}`, `/sso/{user_id}`, `/register/{org_id}`, `/forgot-password/{email}` and
    `/magic-link/{email}` are exempt. This was disclosed by the #482 fourth-pass gate for every
    verb. #538 (carried from #510) closed it for the **subject-acting** verbs:
    `/logout/{user_id}`, `/reset-password/{user_id}`, `/refresh-token/{user_id}`,
    `/auth/token/{user_id}`, `/auth/refresh/{user_id}` and `/auth/verify/{user_id}` now fire. The
    ambiguous-verb half was exempt too, and this page used not to say so.

    The trade for the verbs left exempt is measured, not assumed. In a GitHub code-search sample of
    trailing parameters, `/login/{username}` (19 of 100) and `/login/{sns_type}` (10) are ordinary
    public logins, where the parameter names the account the caller claims and the credential is in
    the body. `/login/{user_id}`, the impersonation case #510 raised, differs from them only in the
    parameter's NAME, so closing it would fire on those public logins. The request verbs send to
    the subject's own mailbox and do not act on the account.

    The earlier argument against fixing this at all was that a credential allowlist's failure mode
    "would be silently exempting real reset links". That has the direction backwards for a
    fail-closed list: an unlisted credential name fires (a false positive the pragma covers). The
    unsafe direction is the other one, a LISTED word carried by a non-credential, which is why the
    list is anchored rather than matched as a suffix (#1017 review). Use the `Depends(...)` — a
    pragma cannot help, the route is already silent.
  - a handler that **calls** a signature-verification primitive (`construct_event`,
    `hmac.compare_digest` + a signature mention, …) but ignores the result, or verifies
    against an attacker-suppliable secret — the call is taken as proof of a
    signature-authenticated receiver; the guard does not check what is done with it.
  The allowlist is kept whole-token, curated, and anchored to path position to keep this
  surface small.
- The mirror-image cost of that position anchor is a small **false-positive** surface on
  genuinely public routes that are resource-scoped without an auth namespace:
  `POST /tenants/{tenant_id}/login` and `POST /{tenant}/login` (tenant-scoped login) fire,
  because they are shape-identical to `POST /users/{user_id}/login` (impersonation). So do
  public auth routes under a non-scaffolding prefix — `POST /backend/auth/token`,
  `POST /integrations/slack/oauth/callback`. `_SCAFFOLD_PARAM` adds the same cost on the
  parameter axis, deliberately: it is **fail-closed**, so a scaffolding parameter spelled
  outside the allowlist over-fires — `{apiVersion}` (camelCase normalizes to `apiversion`, not
  `api_version`), `{stage}`, `{env}`, `{brand}`. `_CREDENTIAL_PARAM` (#538) adds it once more after
  a subject-acting verb: `POST /logout/{session_id}` and `POST /auth/token/{token_id}` fire, because
  an opaque session or token id may or may not be a secret. These are the safe direction for a
  surfacing guard and are suppressed with the inline pragma.


## What this guard does NOT prove

- That an endpoint flagged as missing auth is actually meant to be private — a
  legitimately public route not yet suppressed with the pragma will fire (false
  positive, by design of a surfacing/FN-biased guard family).
- That a present `Depends(...)` call actually enforces authentication correctly (wrong
  dependency function, broken logic inside it) — only that *something* auth-shaped is
  wired in.
- Multi-file or cross-module router composition patterns.

# Citations

[1] agentsec checklist item `2b-auth-dependency-applied` (§2b)
[2] OWASP:A01
[3] OWASP:A07
