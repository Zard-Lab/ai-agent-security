"""Guard: state-changing route with no auth dependency wired (checklist §2b).

The single most common way an endpoint ends up unintentionally public: a developer adds
a new `@router.post(...)` route and simply forgets to attach the `Depends(get_current_user)`
(or equivalent `Security(...)`) parameter that every other route in the file has. Nothing
raises an error — the route just works, unauthenticated, for anyone who finds it.
OWASP:A01 (Broken Access Control) / OWASP:A07 (Identification and Authentication Failures).

This is a **surfacing** guard, like `bola`: it cannot prove an endpoint SHOULD be
authenticated, so it flags the absence for human review rather than asserting a bug. It does,
however, exempt the two route classes that are **public by design** — flagging them is a pure false
positive (round-2 §A.1/§E.2): auth-FLOW endpoints (`/login`, `/signup`, `/logout`, password reset, …,
or a route on an `APIRouter(prefix="/auth")`) — you cannot require a session to *create* one — and
WEBHOOK receivers, authenticated by a provider signature (Stripe `construct_event`), not a session.
The auth-flow match is a **curated, whole-token allowlist** (`_AUTH_FLOW_NAMES`) checked against the
last path segment or the whole handler name, so a compound like `register_device` / `sso_link_account`
/ `verify_payment` — and an ambiguous bare `/token` or `change_password` — still fires. It is also
**anchored to path position**: a public auth-flow route is an entry point at or near the path root
(`/login`, `/auth/login`, `/api/v1/auth/login`). The rule the anchor enforces is that a route may be
exempted only when **no caller-supplied path parameter selects the subject the route acts on** — so a
segment or a parameter naming a resource before the auth verb disqualifies it. `POST /admin/{user_id}/login`
(impersonation), `POST /users/{user_id}/reset-password` (arbitrary-user reset) and
`POST /api/{user_id}/auth/token` (mint a token for a caller-named user) are admin actions spelled like
auth flows, and still fire. Parameters that name pure deployment SCAFFOLDING — which API version,
region, identity provider or tenant the caller is talking to (`_SCAFFOLD_PARAM`) — select no subject and
are forgiven, so `POST /api/{version}/auth/token` and `POST /auth/{provider}/oauth/token` (social login)
stay exempt. The allowlist is anchored and fail-CLOSED: an unrecognized parameter name disqualifies.
Every other state-changing route still fires.

Conservative — fires only when a state-changing route handler (`@router.post/put/patch/
delete(...)` or `@app.post/put/patch/delete(...)`) has ALL of:
  * no `Depends(...)`/`Security(...)` call anywhere in the function's decorator/signature/body;
  * no `current_user`/`get_current_user` reference anywhere in the function;
  * no well-known auth decorator (`@login_required`, `@jwt_required`, `@requires_auth`, ...);
  * the router the route is defined on has NO router-level `dependencies=[...]` auth — neither
    at construction (`APIRouter(dependencies=[Depends(...)])`) nor at inclusion
    (`app.include_router(router, dependencies=[Depends(...)])`), which apply auth to every
    route on that router without a per-route dependency. The `dependencies=` value may be an
    inline list or a variable bound to one (`_admin = [Depends(get_current_admin)]`; ... `dependencies=_admin`).
    Inclusion is resolved **cross-file** and **per router**: `main.py` doing
    `include_router(admin.admin_router, dependencies=_admin)` protects every route on that
    router in `routes/admin.py`, while its bare sibling `router` in the same module keeps
    firing. Both resolvers live in `guards/base.py` and are shared with the other three
    route-auth guards.

Suppress a specific audited public endpoint (signup, health check, Stripe webhook) with an inline
`# security: allow-unauthenticated-route` on that route — the pragma is route-scoped, so it
silences only the route it sits on, not the whole file. Place it **between the decorator stack and
the `def`**, or **in the handler body** — those are the positions scoped to the route. A pragma
placed *above* the top decorator is not honored (it reads as a comment on whatever precedes the
route); the walker deliberately does not pull in comments above the decorator stack, because prose
in such a comment (e.g. "only the current_user may call this") could otherwise be misread as an
auth signal and wrongly silence a genuinely unauthenticated route.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    PER_ROUTE_AUTH_FACTORY,
    CanaryPlant,
    Guard,
    auth_call_named_with_aliases,
    blank_disabled_security_schemes,
    blank_line_comments,
    cross_file_authed_routers,
    include_router_ref,
    is_nonproduct_path,
    iter_files,
    iter_functions,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    route_deps_carry_auth,
    router_code_view,
    router_resolver_view,
    same_file_authed_routers,
    split_call_args,
    strip_python_line_comment,
    strip_python_strings,
)

_PRAGMA = re.compile(r"#\s*security:\s*allow-unauthenticated-route")

_STANDARDS = ["OWASP:A01", "OWASP:A07"]

# A state-changing route decorator: @router.post(...), @app.delete(...), etc.
_STATE_CHANGING_ROUTE = re.compile(
    r"@\s*(?P<var>\w+)\.\s*(?:post|put|patch|delete)\s*\(",
    re.IGNORECASE,
)

# Router-level auth (constructor `dependencies=` and same-file `include_router(..., dependencies=)`)
# is resolved by `same_file_authed_routers` in `guards/base.py`, shared with the other three
# route-auth guards. The two local regexes that used to do it here were removed with #473: they
# were per-file only (no cross-file mount), and their `[^)]*` scan could not cross a nested call's
# `)`, so an ordinary `APIRouter(dependencies=[Depends(get_admin)], prefix="/x")` was matched only
# by luck of argument order.

# was `\bDepends\s*\(` (ANY Depends call, unconditionally) — a route with only
# `Depends(RateLimiter(...))`/`Depends(get_db)` and zero real auth check read as "has an auth
# signal" purely from the wrapper's presence. #473 already fixed this exact class for the two
# STRICT sibling guards (`privileged-field-assignment`, `unauthenticated-file-download` — see
# `AUTH_CALL_NAMED` below) but explicitly left this guard and `websocket-no-auth` on the loose
# default, reasoning their function-level checks were "equally loose" already — a justification
# that stopped holding once `same_file_authed_routers` also went router-level (a single
# `Depends(RateLimiter(...))` here now silences every route in the file, not just this one
# block). `AUTH_CALL_NAMED` requires the wrapped callable's own name to carry a recognizable auth
# stem (auth/token/scope/role/user/require/login/verify/current/oauth/authenticat/authoriz/
# admin/permission/security/credential) — `RateLimiter`/`get_db` don't; `get_current_user`/
# `verify_admin`/`AdminReadDep` do. The bare `current_user`/`get_current_user` alternatives stay:
# FastAPI's parameter-naming convention (`current_user: User = ...`) is a real, distinct signal
# `AUTH_CALL_NAMED`'s Depends()-wrapping pattern doesn't itself cover.
_AUTH_SIGNAL_TAIL = r"|current_user|get_current_user"


def _auth_signal_pattern(auth_call: re.Pattern[str]) -> re.Pattern[str]:
    """`_AUTH_SIGNAL`, built from a caller-supplied `auth_call` — per-run, not a module constant,
    so it can carry this run's own `security_scheme_var_names` aliases
    (`auth_call_named_with_aliases`)."""
    return re.compile(auth_call.pattern + _AUTH_SIGNAL_TAIL, re.IGNORECASE)

# A conservative allowlist of well-known auth DECORATOR names (`@login_required`,
# `@jwt_required`, `@auth.requires_auth`, ...). Route-level auth applied by a decorator
# rather than a Depends(...) parameter. Deliberately narrow + unambiguous — generic tokens
# (`require`, `auth`, `protected`) are excluded so we never silently pass a genuinely
# unauthenticated route (a false negative is worse than the residual false positive an
# exotic custom decorator leaves, which the pragma covers).
_AUTH_DECORATOR = re.compile(
    r"@\s*(?:\w+\.)*(?:login_required|requires_auth|require_auth|jwt_required|"
    r"token_required|authenticated)\b",
    re.IGNORECASE,
)

# #859 sub-fix B: an explicit public-marker DECORATOR (`@auth.public`, `@app.allow_anonymous`) is a
# deliberate "this route is unauthenticated by design" declaration — treat a match exactly like the
# `# security: allow-unauthenticated-route` pragma. Mirrors `_AUTH_DECORATOR`'s conservatism: the
# match is the WHOLE final attribute only, so a `@public_router.post(...)` decorator, a path
# `/public/...` and a handler named `public_upload` all still fire (`public` is a marker, never a
# name/path exemption — the risk called out in the RCA for #859).
_PUBLIC_MARKER = re.compile(
    r"@\s*(?:\w+\.)*(?:public|allow_anonymous|allow_unauthenticated|no_auth|unauthenticated)\b",
    re.IGNORECASE,
)

# #859 sub-fix A: a BARE auth-factory call sitting inside a route's own `dependencies=[...]`
# (`dependencies=[requires_authenticated()]`) is real auth that the `Depends()`-shaped `auth_signal`
# never sees. The scoped reader that recognizes it (`route_deps_carry_auth` + the curated
# `PER_ROUTE_AUTH_FACTORY`) lives in `guards/base.py` since #872, shared with the three per-route
# siblings (`unauthenticated-file-download`, `privileged-field-assignment`, `websocket-no-auth`), so
# the four cannot drift apart. Its rationale (the curated stems, the scoping, the
# dead-comment blanking) is documented there.

# --- public-by-design routes (round-2 §A.1 + §E.2) --------------------------------------------------
# Some state-changing routes are legitimately unauthenticated and flagging them is a false positive:
#   * auth-FLOW endpoints — you cannot require a session to *create* or *establish* one
#     (`/login`, `/signup`, `/logout`, password reset, …). §A.1.
#   * WEBHOOK receivers — authenticated by a provider SIGNATURE (Stripe `construct_event`), not a
#     user session. §E.2.
# Recognized from the route PATH, the handler function NAME, or an `/auth`-prefixed router. The match
# is deliberately CONSERVATIVE (whole-token, curated) so a genuinely-should-be-protected route is never
# silently exempted — a compound like `register_device`/`sso_link_account`/`verify_payment` does NOT
# match `register`/`sso`/`verify`, a `POST /api/token` is not exempted, and every other state-changing
# route still fires. (Widened in PR #482 review after those over-matches were caught.)

# A curated allowlist of auth-flow tokens, matched as the WHOLE last path segment OR the WHOLE handler
# name (after normalizing `-`→`_`, lowercasing), and only on a route that is NOT resource-scoped (see
# `_resource_scoped` — a path PARAMETER before the auth token disqualifies it). Ambiguous bare verbs
# (`token`/`refresh`/`verify`) are intentionally excluded in favor of unambiguous compounds;
# `change_password` is excluded (it requires the current session, so it SHOULD be authed).
_AUTH_FLOW_NAMES = frozenset({
    "login", "logout", "signin", "signout", "signup",
    "sign_in", "sign_out", "sign_up", "log_in", "log_out",
    "register", "oauth", "sso",
    "reset_password", "forgot_password", "password_reset",
    "magic_link", "refresh_token",
})
# A signature-VERIFICATION call (not a bare mention). Checked against comment/string-stripped code, so a
# commented-out mention or a declared-but-unused `X-*-Signature` header alias cannot trigger it.
# UNAMBIGUOUS signature-verification primitives — the call alone is proof.
_SIG_VERIFY = re.compile(
    r"\b(?:construct_event|verify_signature|verify_webhook)\s*\(", re.IGNORECASE
)
# AMBIGUOUS ones that also appear in unrelated code: `csv_reader.verify_header(payload["header"])`
# in a CSV-import handler silently exempted it (#482 second-pass review). These count only when the
# handler also mentions a signature concept. `hmac.compare_digest` is here rather than absent
# because a hand-rolled GitHub-style receiver is the most common real implementation and was
# previously missed entirely (an avoidable false positive).
_SIG_VERIFY_AMBIGUOUS = re.compile(
    r"\b(?:verify_header|compare_digest|hexdigest)\s*\(", re.IGNORECASE
)
_SIG_CONTEXT = re.compile(
    r"signature|x-hub|x-signature|hmac|webhook|sha256=|sha1=", re.IGNORECASE
)
# Ambiguous auth verbs — exempt ONLY when the path also carries an `auth`/`oauth`/`sso` segment.
# `POST /api/token` or `POST /verify` stays a finding; `POST /auth/exchange` is the OAuth code
# exchange and is public by design.
_AUTH_SCOPED_FLOW_NAMES = frozenset({
    "exchange", "callback", "authorize", "token", "refresh", "verify", "confirm", "challenge",
})
_AUTH_PATH_SEGMENT = frozenset({"auth", "oauth", "sso", "authentication"})
# Segments that carry no resource meaning — pure API/version scaffolding. Used to root-anchor the
# ambiguous-verb exemption: `/api/v1/auth/token` is the auth namespace at the path root, while
# `/users/oauth/token` is an auth namespace nested under a resource (#482 third-pass review).
# (`v[\d._]+` as one flat class, not `v\d+(?:[._]\d+)*` — the nested quantifier is a ReDoS shape
# our own `redos` guard rightly flags.)
_NEUTRAL_PREFIX_SEGMENT = re.compile(r"^(?:api|apis|rest|v[\d._]+)$", re.IGNORECASE)
# The same question, asked of a path PARAMETER: does this parameter name deployment SCAFFOLDING
# (which API version / region / identity provider / tenant the caller is talking to), or does it
# name the SUBJECT the route acts on? Only the former may be forgiven.
#
# Testing scaffolding on the parameter-free projection of the path answered "parameters do not
# exist", which is strictly wider than either direction the tests measure: `{version}` and
# `{user_id}` became identical, so `POST /api/{user_id}/auth/token` (mints a token for a
# caller-named user), `/v1/{account_id}/auth/refresh` and `/auth/{id}/oauth/token` all went 1 -> 0 —
# silently unguarded, no error, no skip, no coverage note (#482 fourth-pass gate). The commit that
# shipped that could not distinguish its own must-be-exempt `/auth/{provider}/oauth/token` (social
# login) from `/auth/{id}/oauth/token` (a resource-scoped mint), so it exempted both.
#
# Fail-CLOSED: an unrecognized parameter name disqualifies the exemption (the route fires, the safe
# direction for a surfacing guard). `{apiVersion}` normalizes to `apiversion` and is NOT on this
# list, so it over-fires rather than silently exempting — deliberate.
_SCAFFOLD_PARAM = re.compile(
    r"^(?:api_)?(?:version|ver|v[\d._]*|provider|idp|region|locale|lang|language|"
    r"tenant|workspace|realm)$",
    re.IGNORECASE,
)
# The same question once more, asked AFTER the verb (#538, carried from #510). Both exemption
# branches used to inspect only the parameters before the auth verb, so on a VERB-FIRST route every
# trailing parameter read as the emailed-link credential (`/auth/reset-password/{token}`):
# `POST /logout/{user_id}` (end an arbitrary user's sessions), `POST /auth/token/{user_id}` (mint a
# token for a caller-named user) and `POST /reset-password/{user_id}` (reset an arbitrary account)
# were all exempt, silently.
#
# Inspected only for the verbs that ACT ON the subject a trailing parameter names. Two classes stay
# exempt whatever trails them, deliberately, and are disclosed in the design doc: the
# SESSION-CREATING verbs (`login`, `signup`, `register`, `oauth`, `sso`, ...), whose trailing
# parameter names the account the caller claims while the credential travels in the body
# (`/login/{username}`, `/login/{sns_type}`, `/register/{role}` are among the commonest trailing
# shapes in public code), and the REQUEST verbs (`forgot_password`, `magic_link`), which send
# something to the subject's own mailbox rather than act on the account.
_SUBJECT_ACTING_FLOW_NAMES = frozenset({
    "logout", "signout", "sign_out", "log_out", "reset_password", "password_reset", "refresh_token",
})
# The ambiguous-verb branch's counterpart. `exchange`/`callback`/`authorize`/`challenge` are protocol
# steps whose trailing parameter is a protocol handle (`{provider}`, `{client_id}`, `{flow_id}`) rather
# than a subject, so they are not inspected.
_SUBJECT_ACTING_SCOPED_NAMES = frozenset({"token", "refresh", "verify", "confirm"})
# A trailing parameter that IS the credential: the emailed-link shape, where holding the link is the
# authentication (`{token}`, `{reset_token}`, `{code}`, `{invite_code}`, `{otp}`, `{key}`).
#
# ANCHORED at both ends: the whole name must be a credential word, alone or after one or two
# credential CONTEXT words (`reset_token`, `password_reset_token`, `email_verification_code`; the `_`
# is optional, so the normalized `resetToken` -> `resettoken` still qualifies). An unanchored suffix
# match read every identifier that merely ENDS in a credential word as a credential, and a
# credential anywhere in the trailing run forgives the rest, so `/logout/{employee_code}`,
# `/auth/token/{dealer_code}` and `/logout/{file_hash}` were silently exempt: the unsafe direction
# (#1017 review, High 2). A single context, the first answer to that, fired on every ordinary
# two-context name instead (#1017 re-review, Medium 2), hence the bounded repeat.
#
# A QUALIFIER (`account_`, `user_`, ...) counts only IN FRONT of a context: `account_recovery_token`
# and `userActivationCode` are credentials, while `account_code`, `user_token` and `account_id` stay
# identifiers. Letting a qualifier stand alone would have re-opened High 2 under a new name.
#
# Fail-CLOSED like `_SCAFFOLD_PARAM`, in both of its failure modes: a credential spelled outside the
# lists (`{pin}`, `{employee_otp}`) over-fires, the safe direction, suppressed with the pragma; and
# an identifier that happens to end in a credential word is a subject, so it fires too. No `\w*`
# padding, and the one repeat is bounded, so a long name has nothing to backtrack through.
_CREDENTIAL_WORD = r"(?:token|code|otp|nonce|signature|sig|hash|ticket|jwt|secret|key)"
_CREDENTIAL_CONTEXT = (
    r"(?:reset|invite|invitation|verify|verification|confirm|confirmation|activate|activation|"
    r"access|refresh|auth|oauth|magic|login|email|password|recovery|signup|session|api|client|otp|"
    r"mfa|totp|2fa|two_?factor|one_?time)"
)
_CREDENTIAL_QUALIFIER = r"(?:account|user|member|customer|admin)"
_CREDENTIAL_PARAM = re.compile(
    rf"^(?:(?:{_CREDENTIAL_QUALIFIER}_?)?(?:{_CREDENTIAL_CONTEXT}_?){{1,2}})?{_CREDENTIAL_WORD}$"
    r"|^invit(?:e|ation)$"
)


def _subject_trails(trailing: list[str]) -> bool:
    """True when the path PARAMETERS after the auth verb select a subject: there is at least one,
    none of them is a credential (`_CREDENTIAL_PARAM`), and they are not all deployment scaffolding
    (`_SCAFFOLD_PARAM`). A credential anywhere in the run forgives the rest, because the
    Django-style `/password-reset/{uidb64}/{token}` names the account AND carries the proof for it."""
    params = _param_names(trailing)
    if not params or any(_CREDENTIAL_PARAM.match(p) for p in params):
        return False
    return not all(_SCAFFOLD_PARAM.match(p) for p in params)


# The route's declared path (first string literal of the decorator) and the handler function name.
_ROUTE_PATH = re.compile(
    r"@\s*\w+\.\s*(?:post|put|patch|delete)\s*\(\s*[\"'](?P<path>[^\"']*)[\"']", re.IGNORECASE
)
_DEF_NAME = re.compile(r"\bdef\s+(?P<name>\w+)\s*\(")
# A router's declared `prefix=`, whatever its value. Used to build each route's FULL path, so the
# auth-flow test below sees `/auth/login` rather than just `/login`.
#
# This deliberately does NOT special-case `/auth`. Treating "this router has an /auth prefix" as a
# blanket exemption silenced EVERY route on that router — `POST /admin/impersonate`,
# `DELETE /users/{id}` and `PUT /users/{id}/role` on an `APIRouter(prefix="/auth")` all went dark
# (20/20 findings down to 8/20 on a 20-route corpus). And the `/auth` match had no positional
# bound, so `prefix="/auth/admin"` and `prefix="/v1/auth/internal"` exempted everything under them
# too (#482 review). Now the prefix only contributes path text; the per-route auth-flow test
# decides, so `/auth/login` is exempt while `/auth/admin/impersonate` is not.
_ROUTER_PREFIX = re.compile(
    r"(?P<var>\w+)\s*=\s*APIRouter\s*\([^)]*prefix\s*=\s*[\"'](?P<prefix>[^\"']*)",
    re.IGNORECASE | re.DOTALL,
)
_INCLUDE_CALL = re.compile(r"\.include_router\s*\(")
_PREFIX_KWARG = re.compile(r"^\s*prefix\s*=\s*[\"'](?P<prefix>[^\"']*)", re.IGNORECASE)


def _include_prefixes(code: str, view: str) -> dict[str, str]:
    """`{router var -> prefix}` for every `.include_router(..., prefix="…")` in this file.

    `code` is `router_code_view` and `view` is `router_resolver_view` of the same file: offset-aligned,
    differing only in whether single-line string CONTENT survives. The call and its router reference
    are found in `code`, so a mount quoted inside a one-line string
    (`HINT = "app.include_router(router, prefix='/auth')"`) is not a mount (#538). The arguments are
    then split out of `view` at the same `(`, because the prefix VALUE is itself a string.

    Parsed, not pattern-matched, for the same reason `include_router_ref` is (#473 gate, B6): the
    regex this replaces took `(?P<var>\\w+)` as the first token after the paren, so
    `include_router(router=admin.router, prefix="/auth")` bound the prefix to the KEYWORD NAME
    `router`. Any local `router = APIRouter()` in the same file then inherited a prefix it does not
    have, and `_is_public_by_design` read its `POST /token` as `/auth/token` — an exempted route.
    Measured on `main` before this fix: the same file with the mount spelled positionally reported
    the finding and spelled `router=` reported nothing (1 -> 0). Kwarg ORDER broke it the other way
    too: `include_router(prefix="/auth", router=x)` matched nothing at all.

    Now the router reference comes from the shared order-independent resolver and the prefix from
    the same argument list, so all three spellings agree. Returns the FIRST prefix seen per router,
    matching the caller's `setdefault` precedence (a constructor `prefix=` still wins over this).

    Only a BARE reference is recorded. A dotted `admin.router` names another module's router, whose
    routes are declared in that module and are scanned with THAT file's prefix map, so binding the
    prefix to any local name here can only mis-attribute it — which is the bug above in a second
    spelling. The consequence is that a cross-file mount's prefix does not reach the route file at all.

    **The prefix map fails in BOTH directions, and only one of them is safe.** A MISSING prefix is
    fail-closed: a shorter path exempts less, so the guard over-fires rather than going silent. A
    PHANTOM prefix is fail-OPEN: a prefix the code does not really apply makes the path read as
    something the exemption test forgives, and the finding disappears. Stating only the first half is
    how the comment axis went unexamined until the #473 re-gate — a commented-out or docstring'd
    `include_router(..., prefix="/auth")` invented a prefix and silenced a live route. That is why the
    caller derives this map from the comment/docstring-blanked view, and why "no prefix found" is an
    acceptable outcome here while "a prefix from somewhere unverified" is not.

    Total: never raises."""
    out: dict[str, str] = {}
    for m in _INCLUDE_CALL.finditer(code):
        ref = include_router_ref(code, m.start())
        if not ref or "." in ref:
            continue
        open_idx = code.find("(", m.start())
        args = split_call_args(view, open_idx) if open_idx != -1 else None
        if not args:
            continue
        for arg in args:
            pm = _PREFIX_KWARG.match(arg)
            if pm:
                out.setdefault(ref, pm.group("prefix"))
                break
    return out


def _norm_token(s: str) -> str:
    return s.strip().strip("/").replace("-", "_").lower()


def _param_names(raw: list[str]) -> list[str]:
    """Normalized names of the path PARAMETERS in `raw` (`{user_id:int}` -> `user_id`)."""
    return [_norm_token(s.strip("{}").split(":")[0]) for s in raw if s.startswith("{")]


def _resource_scoped(raw: list[str], anchor: int) -> bool:
    """True if the route acts ON a resource rather than being a public entry point — i.e. a path
    PARAMETER (`{user_id}`) appears before `anchor` (the index of the segment the auth-flow token was
    matched at) outside an auth namespace.

    The auth-flow allowlist was whole-token but had no positional bound, so it matched the last path
    segment / handler name at ANY nesting depth: `POST /admin/{user_id}/login` (`impersonate_user`),
    `POST /users/{user_id}/reset-password` (`admin_force_reset_password`) and
    `POST /users/{user_id}/logout` were all silently exempted — impersonation, arbitrary-user password
    reset and arbitrary-user session kill reported as fine (#482 third-pass review).

    A genuinely public auth-flow route is an ENTRY POINT at or near the path root (`/login`,
    `/auth/login`, `/api/v1/auth/login`, `/users/login`). A path parameter BEFORE the auth verb is
    strong evidence the route acts on a resource instead — that is not a login, it is an admin action
    spelled like one. Two shapes are NOT disqualified, because attacking the first cut of this fix
    showed both are ordinary public routes:
      * a parameter AFTER the verb — the emailed-link shape (`/auth/reset-password/{token}`,
        `/auth/verify/{token}`, `/signup/{invite_code}`);
      * a parameter inside an explicit AUTH NAMESPACE (`/auth/{provider}/login`,
        `/{tenant}/auth/login`, `/api/{version}/auth/login`) — social login and multi-tenant login
        both spell it this way. Any other resource segment still disqualifies, so
        `/auth/admin/{user_id}/login` stays a finding, mirroring `/auth/admin/token` one level up.
    """
    before = raw[:anchor]
    if not any(s.startswith("{") for s in before):
        return False
    named = [_norm_token(s) for s in before if not s.startswith("{")]
    if not any(s in _AUTH_PATH_SEGMENT for s in named):
        return True
    return any(
        s not in _AUTH_PATH_SEGMENT and not _NEUTRAL_PREFIX_SEGMENT.match(s) for s in named
    )


def _verifies_signature(block: str, *, filename: str | Path = "<unknown>") -> bool:
    """True if the handler CALLS a signature-verification primitive. Checked on comment- and
    string-stripped code so a commented-out mention or a string literal (e.g. a declared-but-unused
    `Header(alias="X-Hub-Signature-256")`) can't trigger it (PR #482 review)."""
    code = "\n".join(
        strip_python_line_comment(ln)
        for ln in strip_python_strings(block, filename=filename).splitlines()
    )
    if _SIG_VERIFY.search(code):
        return True
    # An ambiguous primitive needs a signature concept in the same handler. `_SIG_CONTEXT` is
    # checked against the RAW block, since the header name that proves it is usually a string
    # literal (`Header(alias="X-Hub-Signature-256")`) that `strip_python_strings` blanks.
    return bool(_SIG_VERIFY_AMBIGUOUS.search(code)) and bool(_SIG_CONTEXT.search(block))


def _is_public_by_design(
    block: str,
    route_var: str,
    router_prefixes: dict[str, str],
    *,
    filename: str | Path = "<unknown>",
) -> bool:
    """True if this route is an auth-flow endpoint or a signature-verified webhook receiver —
    legitimately unauthenticated, so the missing-auth finding would be a false positive (§A.1/§E.2).

    Decided PER ROUTE, never per router: a router's `prefix=` only contributes path text (so
    `APIRouter(prefix="/auth")` plus a route declared at `"/login"` reads as `/auth/login`), and the route's
    own last path segment or handler name has to be an auth-flow name. A blanket per-router
    exemption silenced every admin/user-management route that happened to live on the auth router
    (#482 review)."""
    path_m = _ROUTE_PATH.search(block)
    path = (router_prefixes.get(route_var, "") + (path_m.group("path") if path_m else "")) or ""
    def_m = _DEF_NAME.search(block)
    name = _norm_token(def_m.group("name")) if def_m else ""
    raw = [s for s in path.split("/") if s]
    # Positions of the real (non-parameter) segments, so the auth token can be located IN the path
    # rather than merely found somewhere in it.
    pos = [i for i, s in enumerate(raw) if not s.startswith("{")]
    segs = [_norm_token(raw[i]) for i in pos]
    last_seg = segs[-1] if segs else ""
    # Everything after the last NAMED segment is a parameter. A subject-acting verb (`logout`,
    # `reset_password`, `token`, ...) followed by a subject parameter (`/logout/{user_id}`) acts on a
    # caller-named account and is not public, whichever spelling (path or handler name) carried the
    # verb (#538). A session-creating verb is never asked this, see `_SUBJECT_ACTING_FLOW_NAMES`.
    subject_trails = _subject_trails(raw[pos[-1] + 1 :] if pos else raw)
    if not _resource_scoped(raw, pos[-1] if pos else 0) and any(
        tok in _AUTH_FLOW_NAMES and not (tok in _SUBJECT_ACTING_FLOW_NAMES and subject_trails)
        for tok in (last_seg, name)
    ):
        return True
    # An ambiguous auth verb counts only under an auth-scoped path, so the auth router's own flow
    # routes (`/auth/exchange`, `/auth/callback`) stay exempt without exempting its siblings.
    # ADJACENT, not anywhere-earlier. Accepting the auth segment anywhere in the path exempted
    # `POST /auth/admin/token` (mints an admin token) and `POST /oauth/users/{id}/verify` (marks an
    # arbitrary user verified) — the same "blast radius wider than intended" bug this PR fixed for
    # the router prefix, one level down (#482 second-pass review). `/auth/exchange` is the auth flow;
    # `/auth/admin/token` is an admin endpoint that merely lives under it.
    # Adjacency alone was still not enough: it never asked WHERE the auth namespace sits, so
    # `POST /users/{user_id}/oauth/token` (mints a token for an arbitrary user) qualified because
    # `oauth` happened to precede `token`. The auth namespace must be at the path ROOT, modulo pure
    # API/version scaffolding (#482 third-pass review).
    if (
        last_seg in _AUTH_SCOPED_FLOW_NAMES
        and len(segs) >= 2
        and segs[-2] in _AUTH_PATH_SEGMENT
        # Scaffolding is tested on the NAMED segments (`segs`), not on `raw`. Reading `raw` counted
        # path PARAMETERS as prefix segments, and a `{version}` never matches the neutral-prefix
        # regex, so it disqualified unconditionally: `/api/{version}/auth/token`,
        # `/v1/{region}/auth/token` and `/auth/{provider}/oauth/token` all went 0 -> 1 (#482 gate).
        # That directly contradicted this PR's own worked example, in which
        # `/api/{version}/auth/login` stays exempt — the sibling `_resource_scoped` above filters
        # params out for exactly this reason, and this branch simply did not.
        #
        # An auth segment is scaffolding here too: `/auth/{provider}/oauth/token` is social login,
        # not a resource-scoped mint. A NON-auth, non-neutral name before the namespace still
        # disqualifies, which is what keeps `/users/{user_id}/oauth/token` a finding.
        and all(
            _NEUTRAL_PREFIX_SEGMENT.match(s) or s in _AUTH_PATH_SEGMENT for s in segs[:-2]
        )
        # …and the same question asked of the PARAMETERS, which the named-segment projection above
        # cannot see at all. Dropping them wholesale answered "parameters do not exist" and re-opened
        # the impersonation class through the parameter slot: `/api/{user_id}/auth/token` read
        # exactly like `/api/{version}/auth/token` (#482 fourth-pass gate). Only a parameter that
        # names deployment scaffolding is forgiven; an identity parameter disqualifies.
        #
        # Scanned over EVERY parameter before the verb (`raw[:pos[-1]]`), not merely those before the
        # namespace: a caller-supplied identity between the namespace and the verb selects the
        # subject just as squarely, so `POST /auth/{user_id}/token` is a mint for an arbitrary user.
        # That also closes it in the ambiguous-verb branch (the `_AUTH_FLOW_NAMES` branch's
        # `/auth/{user_id}/login` stays a disclosed accepted FN — see the design doc).
        and all(_SCAFFOLD_PARAM.match(p) for p in _param_names(raw[: pos[-1]]))
        # …and AFTER the verb (#538): `POST /auth/token/{user_id}` mints for a caller-named user
        # exactly as `/auth/{user_id}/token` does, while `/auth/verify/{token}` (the emailed link)
        # and `/auth/callback/{provider}` stay exempt.
        and not (last_seg in _SUBJECT_ACTING_SCOPED_NAMES and subject_trails)
    ):
        return True
    # A webhook receiver is exempt because a provider SIGNATURE authenticates it — so the
    # verification CALL is the exemption, not the path shape. Accepting a receiver-shaped path on
    # its own exempted `POST /webhooks/subscribe`, `DELETE /api/v1/webhooks/all` and
    # `PUT /webhooks/rotate-secret` (webhook MANAGEMENT routes that must stay protected) and, worse,
    # exempted a receiver that verifies NOTHING — precisely the bug worth reporting (#482 review).
    return _verifies_signature(block, filename=filename)


class AuthDependencyNotAppliedGuard(Guard):
    id = "auth-dependency-not-applied"
    title = "State-changing route has no auth dependency wired"
    area = "Login & access"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted across the canary's five shared plant
    # files (`account_admin.py`, `admin_delete.py`, `llm_route.py`, `stripe_webhook.py`,
    # `webhooks_github.py`), each of which more than one guard trips at once, so those files stay in
    # `canary.py`'s base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    canary_plant = CanaryPlant(expects=frozenset({"auth-dependency-not-applied/no-auth-dependency"}))

    def applies(self, profile: StackProfile) -> bool:
        return "fastapi" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        files: list[tuple[Path, str]] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                # Blank a disabled security-scheme (`auto_error=False`) OUT of the text before
                # anything below sees it — see websocket_no_auth.py's identical
                # comment for why this is applied once, at read time.
                files.append((f, blank_disabled_security_schemes(read(f))))

        # Pass 1 (repo-wide): a route file's routes are authed if the file's module is included
        # with a real auth dependency ANYWHERE (typically `main.py` doing
        # `include_router(admin.router, dependencies=_admin)`). The shared resolver maps
        # `<module>.<router>` back to the route file `<module>.py` by stem, PER ROUTER.
        # Cross-file router-mount resolution genuinely needs a repo-wide view (that's the whole
        # point of this pass), so it keeps the run-wide alias union here — a narrower, disclosed
        # residual of the fix-round review Critical 1 shape (a) than the per-file checks
        # below have (see `wiki/guards/auth-dependency-not-applied.md`'s Known bypasses).
        run_wide_auth_call = auth_call_named_with_aliases(*(text for _, text in files))
        protected_routers = cross_file_authed_routers(files, auth_call=run_wide_auth_call)

        out: list[Finding] = []
        for f, text in files:
            out.extend(self._scan(root, f, text, protected_routers))
        return out

    def _scan(
        self,
        root: Path,
        f: Path,
        text: str,
        protected_routers: dict[str, set[str]],
    ) -> list[Finding]:
        # This file's OWN module-level security-scheme variable bindings only (`bearer_scheme =
        # HTTPBearer()`), so `Depends(bearer_scheme)` reads as authed the same way
        # `Depends(HTTPBearer())` already does via `AUTH_CALL_NAMED` alone — scoped to THIS file,
        # not the whole run, so an unrelated file's own local variable of the same common name
        # (`scheme`, `bearer_scheme`) can never authorize a route here (fix-round review,
        # Critical 1 shape (a)).
        auth_call = auth_call_named_with_aliases(text)

        # A router is authed for every route if it carries router-level dependencies= auth,
        # whether constructed with it (APIRouter(dependencies=...)) or included with it in this
        # same file (app.include_router(router, dependencies=...)). The deps may be an inline list
        # or a variable bound to one. Shared with the other three route-auth guards (#473).
        authed_routers = same_file_authed_routers(text, auth_call=auth_call, filename=f)
        # Cross-file protection merges in PER ROUTER — NOT a whole-file bail. Bailing on the file
        # meant that in the standard public+admin layout (two routers in one module, one mounted
        # with auth and one without), mounting the admin router with `Depends(require_admin)`
        # silenced every route on its sibling (#473 review, HIGH 1).
        authed_routers |= protected_routers.get(f.stem, set())

        # Each router's declared `prefix=`, so a route's FULL path is known when the auth-flow
        # test runs: an `APIRouter(prefix="/auth")` plus a route declared at `"/login"` -> `/auth/login`.
        # Never an exemption in itself — see `_is_public_by_design` (#482 review).
        #
        # Derived from the SAME comment/docstring-blanked view the auth resolvers in base.py use, and
        # for the same reason (#473 re-gate, HIGH 1). A prefix feeds the exemption test, so a prefix
        # read off a DEAD line exempts a live route: a stray
        # `# app.include_router(router, prefix="/auth")` above a bare `POST /token` made it read as
        # `/auth/token` and the finding disappeared (1 -> 0, measured here and on main). The auth map
        # had been given this view when a commented-out include was found to fake protection; the
        # prefix map was left on raw text and fails the same way, one exemption further along.
        #
        # The VALUE is itself a string, which is why two views are needed (#538). Structure is
        # matched on `router_code_view`, where every one-line string's content is blanked, so
        # `HINT = "router = APIRouter(prefix='/auth')"` is not a router (it used to mint `/auth` and
        # exempt a bare `POST /token`, 1 -> 0). The prefix is then read from `router_resolver_view`
        # at the same span: the two are offset-aligned, so `prefix="     "` in one is
        # `prefix="/auth"` in the other.
        #
        # Call the SHARED helpers rather than re-composing them here. This line used to duplicate
        # `strip_hash_comments(strip_python_strings(text))`, which is how it silently diverged from
        # the resolvers it claims parity with — and both copies carried the same defect (#473
        # re-gate). One definition means "the same view the auth resolvers use" is structurally
        # true rather than a comment that has to be re-checked.
        view = router_resolver_view(text, filename=f)
        code = router_code_view(text, filename=f)
        router_prefixes: dict[str, str] = {
            pm.group("var"): view[pm.start("prefix") : pm.end("prefix")]
            for pm in _ROUTER_PREFIX.finditer(code)
        }
        for var, prefix in _include_prefixes(code, view).items():
            router_prefixes.setdefault(var, prefix)
        auth_signal = _auth_signal_pattern(auth_call)

        out: list[Finding] = []
        for lineno, block in iter_functions(text, filename=f):
            m = _STATE_CHANGING_ROUTE.search(block)
            if not m:
                continue
            if m.group("var") in authed_routers:
                continue
            # Per-route auth: a Depends(...)/Security(...)/current_user signal, OR a well-known
            # auth decorator, OR an explicit public-marker decorator (`@auth.public`, #859 sub-fix
            # B), OR an inline pragma on this route — all scoped to THIS route block (not file-wide:
            # one public route's marker/pragma must not blind every other route). The pragma counts
            # only as a real comment in the block, never quoted in a string there (#1040).
            if (
                auth_signal.search(block)
                or _AUTH_DECORATOR.search(block)
                or _PUBLIC_MARKER.search(block)
                or pragma_present(_PRAGMA, block, dialect="python")
            ):
                continue
            # Auth attached through the route's OWN `dependencies=[<factory()>]` list as a bare
            # returns-nothing guard (`dependencies=[requires_authenticated()]`) — not Depends()-
            # wrapped, so `auth_signal` above misses it. Scan just this route's inline deps list for
            # a curated auth-named callable (#859 sub-fix A). `m.end() - 1` is the route decorator's
            # opening `(`.
            if route_deps_carry_auth(blank_line_comments(block), m.end() - 1, PER_ROUTE_AUTH_FACTORY):
                continue
            # Public-by-design routes (auth-flow endpoints, signature-verified webhooks) are
            # legitimately unauthenticated — flagging them is a false positive (§A.1/§E.2). Keep
            # firing on every other state-changing route.
            if _is_public_by_design(block, m.group("var"), router_prefixes, filename=f):
                continue

            out.append(Finding(
                check_id=self.id,
                severity="high",
                title=self.title,
                location=f"{rel(root, f)}:{lineno}",
                message=(
                    "This state-changing route (POST/PUT/PATCH/DELETE) has no auth "
                    "dependency wired — no Depends(...)/Security(...) parameter, no "
                    "current_user reference, no auth decorator, and its router has no "
                    "router-level dependencies=[...] auth. The route works for any caller, "
                    "authenticated or not."
                ),
                remediation=(
                    "Add the auth dependency this project uses elsewhere: "
                    "`current_user: User = Depends(get_current_user)`. If this route is "
                    "legitimately public (signup, webhook, health check), suppress with "
                    "`# security: allow-unauthenticated-route`."
                ),
                rule="auth-dependency-not-applied/no-auth-dependency",
                standards=list(_STANDARDS),
            ))
        return out
