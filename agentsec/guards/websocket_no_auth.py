"""Guard: FastAPI WebSocket endpoint without authentication dependency (§2b — Authorization).

FastAPI WebSocket endpoints use the same dependency injection system as HTTP routes.
A developer who adds an HTTP route almost always remembers to inject an auth dependency
(e.g. `Depends(get_current_user)` or `Security(verify_token)`), but WebSocket handlers
are often written later as a "real-time add-on" and the auth injection is simply
forgotten. The result is a completely unauthenticated persistent connection: any client
can open a socket, stream messages, and receive responses — no credentials required.

One statically detectable pattern:

  **`websocket-without-auth-dep`** (HIGH): A Python function decorated with
  `@app.websocket(...)` or `@router.websocket(...)` whose signature (the 1-3 lines after the
  decorator) carries no auth-named `Depends(...)`, `Security(...)`, `current_user` parameter or
  Query-param token, AND whose decorator's own `dependencies=[...]` list carries no auth-named
  `Depends(...)` or bare auth factory (`dependencies=[requires_authenticated()]`, #872).
  This is the canonical FastAPI pattern for injecting authentication into a WebSocket
  route — its absence means there is no auth gate.

**Why HIGH?** An unauthenticated WebSocket:
  - Bypasses every HTTP-layer auth check (session cookies, Bearer tokens, API keys)
  - Provides a persistent, bidirectional channel for data exfiltration or injection
  - Is invisible to many WAFs and API gateways that inspect HTTP headers, not WS frames
  - Satisfies OWASP A01 (Broken Access Control) and A07 (Identification & Authentication Failures)

**Router-level auth is recognized:** a WebSocket route on a router that carries a router-level
`dependencies=[Depends(...)]` — applied at construction (`APIRouter(dependencies=...)`) or at
inclusion, same-file OR cross-file (`main.py` doing `include_router(chat.router,
dependencies=[Depends(get_current_user)])`) — is NOT flagged, since FastAPI applies router-level
dependencies to WebSocket routes too. Resolved via the shared `base.py` cross-file resolver.

**Scope (it over-fires in these cases, the safe direction):** This guard reads the 1-3 lines
after the `@<router>.websocket` decorator, plus the decorator's own inline `dependencies=[...]`
list. Auth parameters further down a long multi-line signature, auth enforced inside the function
body (not via dependency injection), a per-route `dependencies=<var>`, or custom decorator chains
that wrap auth are NOT recognized — they require dataflow / decorator-chain analysis beyond static
line matching.

**Checklist item:** `2b-websocket-auth` (§2b — Authorization).

**Suppress:** `# security: allow-websocket-no-auth` anywhere in a file silences this
check for that entire file. Use only when the WebSocket endpoint is intentionally public
(e.g. a read-only status stream) and unauthenticated access is an explicit design decision.
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
    is_nonproduct_path,
    iter_files,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    route_deps_carry_auth,
    same_file_authed_routers,
)

_PRAGMA = "security: allow-websocket-no-auth"

_STANDARDS = ["OWASP:A01", "OWASP:A07"]

# Matches an `@<router>.websocket(...)` decorator. `<var>` captures the router object (any dotted
# identifier — `app`, `router`, a custom `chat_router`, or `some.ws`) so a route authed at the
# router level is recognized as authed via its last dotted segment.
_WS_DECORATOR = re.compile(r"^[ \t]*@(?P<var>[\w.]+)\.websocket\(", re.MULTILINE)

# Signals that the function signature contains an auth dependency.
# Extended to catch:
#   - FastAPI DI: Depends(...) / Security(...)
#   - Conventional current_user parameter name
#   - Query-param JWT: token/api_key/authorization param with a Query() default —
#     a valid pattern for WebSocket auth (headers unavailable in the WS handshake
#     on many clients; tokens are often passed as ?token=...)
# the bare `Depends\s*\(|Security\s*\(` branch used to accept ANY wrapped callable —
# `Depends(RateLimiter(...))` on a route with zero real auth check read as authed. `AUTH_CALL_NAMED`
# (same fix #473 already gave the two STRICT route-auth guards) requires the callable's own name to
# carry a recognizable auth stem; `current_user` and the Query-param JWT branch are unrelated,
# already-precise signals and stay as they were.
_AUTH_IN_SIG_TAIL = (
    r"|current_user"
    r"|(?:token|api_key|authorization)\s*(?::\s*\S+)?\s*=.*Query\s*\("
)


def _auth_in_sig_pattern(auth_call: re.Pattern[str]) -> re.Pattern[str]:
    """`_AUTH_IN_SIG`, built from a caller-supplied `auth_call` — per-run, not a module constant,
    so it can carry this run's own `security_scheme_var_names` aliases
    (`auth_call_named_with_aliases`)."""
    return re.compile(auth_call.pattern + _AUTH_IN_SIG_TAIL, re.IGNORECASE)


class WebsocketNoAuthGuard(Guard):
    id = "websocket-no-auth"
    title = "WebSocket endpoint without authentication dependency"
    area = "Login & access"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted across the canary's shared
    # `ws_handler.py` and `ws_origin_handler.py`, each of which several guards trip at once, so those files
    # stay in `canary.py`'s base owned by no guard. The ownership rule this follows is documented on
    # `xxe_safe.py`.
    # ws_handler.py: @router.websocket without Depends/Security -> websocket-without-auth-dep.
    canary_plant = CanaryPlant(expects=frozenset({"websocket-no-auth/websocket-without-auth-dep"}))

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
                # Skip non-product trees BEFORE building the list. This list feeds the
                # cross-file router resolver, so an unfiltered throwaway app in
                # `tests/test_admin.py` that mounts the router WITH auth marked the `admin` module
                # protected and silenced the finding on the production module of the same name.
                # An `old/` archive tree did the same (#473 review, HIGH 4).
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                # Blank a disabled security-scheme (`auto_error=False`) OUT of the text before
                # anything below sees it — every AUTH_CALL_NAMED-based check in this
                # file works on this same `text`, so applying the blank once here, at read time,
                # closes the gap for the router-mount resolvers AND the per-route signature check
                # in one place rather than needing it re-applied at each call site.
                files.append((f, blank_disabled_security_schemes(read(f))))

        # Pass 1 (repo-wide): a route file whose module is included cross-file with a real auth
        # dependency (`main.py` doing `include_router(chat.router, dependencies=[Depends(...)])`)
        # has every WebSocket route on it authed at the router level — matched back by file stem.
        # Cross-file router-mount resolution genuinely needs a repo-wide view (that's the whole
        # point of this pass), so it keeps the run-wide alias union here — a narrower, disclosed
        # residual of the fix-round review Critical 1 shape (a) than the per-file checks
        # below have (see `wiki/guards/websocket-no-auth.md`'s Known bypasses).
        run_wide_auth_call = auth_call_named_with_aliases(*(text for _, text in files))
        protected_routers = cross_file_authed_routers(files, auth_call=run_wide_auth_call)

        out: list[Finding] = []
        for f, text in files:
            if pragma_present(_PRAGMA, text, dialect="python"):
                continue
            if not _WS_DECORATOR.search(text):
                continue
            out.extend(self._check_file(root, f, text, protected_routers))
        return out

    def _check_file(
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

        # Cross-file: every route in this file is authed at the router level if its module was
        # included-with-auth elsewhere (pass 1) — `routes/chat.py` <- `include_router(chat.router, ...)`.
        # Cross-file protection merges into the same-file router set below, PER ROUTER — NOT a
        # whole-file bail. Bailing on the file meant that in the standard public+admin layout (two
        # routers in one module, one mounted with auth and one without), mounting the admin router
        # with `Depends(require_admin)` silenced every route on its sibling (#473 review, HIGH 1).
        # Same-file: routers carrying a router-level `dependencies=` auth gate every route on them.
        authed_routers = same_file_authed_routers(text, auth_call=auth_call, filename=f)
        authed_routers |= protected_routers.get(f.stem, set())
        auth_in_sig = _auth_in_sig_pattern(auth_call)
        # Comment-blanked ONCE per file (length-preserving), not once per decorator.
        view = blank_line_comments(text)

        out: list[Finding] = []
        lines = text.splitlines()
        # Offset of each line in `text`, and so in `view`. Built from the SAME `splitlines()` split as
        # `lines`, so line i's offset stays right when the text carries a line boundary other than
        # `\n` (`\x0c`, `\x1c`, U+2028), which a `split("\n")` count would drift past.
        starts = [0]
        for ln in text.splitlines(keepends=True):
            starts.append(starts[-1] + len(ln))
        decorators = [(i, m) for i, line in enumerate(lines) if (m := _WS_DECORATOR.search(line))]
        for k, (i, m) in enumerate(decorators):
            if m.group("var").split(".")[-1] in authed_routers:
                continue
            # Scan the next 1-3 lines for the function signature.
            # Multi-line signatures and query-param token defaults often span 2+ lines;
            # checking only line N+1 would miss e.g. `token: str = Query(...)` on line N+2.
            sig_window = "\n".join(lines[i + 1 : min(i + 4, len(lines))])
            if auth_in_sig.search(sig_window):
                continue
            # The decorator's OWN `dependencies=[...]` list, which the window above never reads
            # (it starts after the decorator line): a wrapped `Depends(get_current_user)` (this
            # file's `auth_call`) or a bare factory `requires_authenticated()` (the curated
            # `PER_ROUTE_AUTH_FACTORY`) attached there is real auth (#872). Both, unlike the other
            # per-route guards, whose block-wide signal already sees the wrapped forms. Scoped to
            # that list, so a bare `get_db()` or a `Depends(RateLimiter(...))` still fires
            #. The text handed over runs from this decorator's line to the NEXT
            # websocket decorator's, never to the end of file: `matching_close_paren` walks to the
            # end of what it is given when the `(` is unbalanced, so the windows must be disjoint to
            # keep the file linear.
            end = starts[decorators[k + 1][0]] if k + 1 < len(decorators) else len(view)
            window = view[starts[i] : end]
            if route_deps_carry_auth(window, m.end() - 1, auth_call) or route_deps_carry_auth(
                window, m.end() - 1, PER_ROUTE_AUTH_FACTORY
            ):
                continue
            # Neither the signature nor the decorator carries an auth dependency — flag it.
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title="WebSocket endpoint has no authentication dependency",
                    location=f"{rel(root, f)}:{i + 1}",
                    message=(
                        "This `@app.websocket` / `@router.websocket` decorated function "
                        "does not inject `Depends(...)`, `Security(...)`, or `current_user` "
                        "in its signature. FastAPI's dependency injection is the standard "
                        "mechanism for enforcing authentication on WebSocket endpoints — "
                        "omitting it leaves the connection completely unauthenticated. Any "
                        "client can open the socket without credentials."
                    ),
                    remediation=(
                        "Add an auth dependency to the function signature, e.g.: "
                        "`async def ws_endpoint(websocket: WebSocket, "
                        "user: User = Depends(get_current_user)):`. "
                        "For token-in-query-string patterns (common with WebSockets) validate "
                        "the token explicitly inside the handler and call "
                        "`await websocket.close(code=1008)` on failure. "
                        "If the endpoint is intentionally public, suppress with "
                        "`# security: allow-websocket-no-auth`."
                    ),
                    rule="websocket-no-auth/websocket-without-auth-dep",
                    standards=list(_STANDARDS),
                )
            )
        return out
