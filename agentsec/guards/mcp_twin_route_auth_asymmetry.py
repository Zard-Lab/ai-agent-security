"""Guard: two routes sharing the same MCP endpoint family, one authenticated and one not
(checklist §4, new item; agent-audit-kit's `mcp_middleware.py` AAK-MCPWN-001).

CVE-2026-33032 / "MCPwn" (nginx-ui, CVSS 9.8, KEV-listed 2026-04-13, Rapid7 ETR + Picus
writeup) was caused by exactly this shape: `/mcp` was wrapped in an auth middleware, but
its sibling `/mcp_message` was not — the same handler logic, reachable through the
unauthenticated twin, gave full web-server takeover. The bug is not "no auth exists" (that
is `mcp-transport-no-auth`'s scope); it is that auth exists and was applied to the wrong
member of a route pair that should share it.

Fires HIGH when, in one file, two or more MCP-endpoint-shaped routes
(`/mcp`, `/mcp_message`, `/mcp-messages`, `/mcp/invoke`, `/mcp_tool`, `/mcp_msg`, ...) are
declared, at least one carries a recognized auth marker (Depends(auth)/HTTPBearer/
require_auth for FastAPI; authMw/requireAuth/passport.authenticate for Express), and at
least one sibling route does not. Deliberately pragmatic (regex, not full AST) — the shape
is shallow enough that a heavier parse buys little, and the false-positive rate stays low
because the guard only fires when there is a genuine AUTHENTICATED anchor route in the same
file that an unauthenticated sibling contradicts.

Auth that is not written on the route itself still counts, so the protected route is not
flagged as the open one: a router authed as a whole (`APIRouter(dependencies=[Depends(auth)])`,
or mounted from another file with `include_router(mod.router, dependencies=[...])`, resolved
through the shared cross-file resolvers in `guards/base.py`), an app-wide auth middleware
anywhere in the repo (`app.add_middleware(AuthMiddleware)` or an auth-named
`@app.middleware("http")` function; suppresses every Python route finding, disclosed as a
known limitation), and for Express a path-less `app.use(authMw)` registered before the route.

Gin-style route grouping (Go) is out of scope, matching this project's existing
Python/JS-TS source-scanning surface.

Suppress an audited case with a comment anywhere in the file (a string quoting it does not count):

    # security: allow-mcp-twin-route-auth-asymmetry
    // security: allow-mcp-twin-route-auth-asymmetry   (JS/TS)
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    auth_call_named_with_aliases,
    blank_disabled_security_schemes,
    comment_dialect_for,
    cross_file_authed_routers,
    is_nonproduct_path,
    iter_files,
    matching_close_paren,
    pragma_present,
    read,
    rel,
    router_code_view,
    router_resolver_view,
    same_file_authed_routers,
)

_PRAGMA = re.compile(r"(?:#|//)\s*security:\s*allow-mcp-twin-route-auth-asymmetry")

_PY_SUFFIXES = (".py",)
_JS_SUFFIXES = (".ts", ".tsx", ".js", ".mjs")

_MCP_ROUTE_LITERAL = r"/mcp(?:[_\-/](?:messages?|invoke|tool|msg))?"

_AUTH_MARKERS = (
    "Depends(auth)", "Depends(get_current_user)", "Depends(verify_token)",
    "Depends(require_auth)", "Depends(current_user)", "require_auth", "@requires",
    "HTTPBearer", "OAuth2PasswordBearer",
    "authMw", "requireAuth", "ensureAuthenticated", "passport.authenticate",
    "jwtMiddleware", "jwt_middleware", "authenticate(",
)

# Every scan below is LINEAR in the file: the route-start regex only anchors the decorator and
# everything after it is walked by bounded code (`_SPAN` characters, `_MAX_DECORATORS` stacked
# decorators). The earlier single DOTALL regex (`.*?\)\s*\n` then `(?:\s*@.*\n)*`) backtracked
# quadratically to exponentially on a decorator that never reaches a `def`, and
# `_EXPRESS_LINE_RE`'s unbounded `[^;]+?\)` went quadratic on a route line with no closing paren.
_SPAN = 1500
_MAX_DECORATORS = 12

_FASTAPI_ROUTE_START_RE = re.compile(
    r"""@(?P<recv>\w+)\.(?:post|get|put|patch|delete|api_route)\s*(?P<open>\()
        \s*['"](?P<route>""" + _MCP_ROUTE_LITERAL + r""")['"]""",
    re.VERBOSE,
)
_DECORATOR_NAME_RE = re.compile(r"@[\w.]+")
_DEF_OPEN_RE = re.compile(r"(?:async\s+)?def\s+\w+\s*\(")

_EXPRESS_LINE_RE = re.compile(
    r"""(?P<app>\w+)\.(?:post|get|put|patch|delete|use|all)\s*\(
        \s*["'](?P<route>""" + _MCP_ROUTE_LITERAL + r""")["']
        \s*,\s*(?P<mw_and_handler>[^;]{1,400}?)\)""",
    re.VERBOSE,
)
# `app.use(authMw)` / `app.use(passport.authenticate(...))`: a path-less global middleware, which
# in Express covers every route registered AFTER it.
_EXPRESS_GLOBAL_AUTH_RE = re.compile(
    r"^[ \t]*\w+\.use\s*\(\s*(?:" + "|".join(re.escape(mk) for mk in _AUTH_MARKERS) + ")",
    re.MULTILINE,
)

# Plain substring stems (case-insensitive) rather than `boundaried_stems`: a middleware CLASS name is
# UpperCamel (`MyAuthMiddleware`, `JWTAuthMiddleware`), and the boundaried matcher rejects a stem
# whose left neighbour is a lowercase letter. `auth(?!or)` keeps `AuthorMiddleware` out, and
# `session` is deliberately not a stem: Starlette's `SessionMiddleware` is a cookie jar, not a gate.
_AUTH_MW_NAME = r"(?:auth(?!or)|jwt|bearer|token|login|api_?key)"
# App-wide FastAPI/Starlette auth middleware: `app.add_middleware(AuthMiddleware)` or an
# `@app.middleware("http")` function whose name carries an auth stem. Either one runs for every
# request the app serves, so no MCP route on it is "the unauthenticated one".
_FASTAPI_AUTH_MIDDLEWARE_RE = re.compile(
    r"\.add_middleware\s*\(\s*[\w.]*?" + _AUTH_MW_NAME
    + r"|@\w+\.middleware\s*\(\s*['\"]http['\"]\s*\)\s*(?:async\s+)?def\s+\w*?" + _AUTH_MW_NAME,
    re.IGNORECASE,
)


@dataclass(frozen=True)
class _RouteHit:
    route: str
    line: int
    has_auth: bool
    pos: int = 0


def _balanced_end(text: str, open_idx: int) -> int | None:
    """Index of the `)` closing the `(` at `open_idx`, looking at most `_SPAN` characters ahead
    (an unterminated call must not cost the rest of the file, once per candidate)."""
    window = text[open_idx: open_idx + _SPAN]
    end = matching_close_paren(window, 0, python=True)
    return None if end is None else open_idx + end


def _decorated_def_end(text: str, pos: int) -> int | None:
    """End offset of the `def name(...)` signature that follows the decorator stack starting at
    `pos`, or None if no `def` follows within the bounds."""
    for _ in range(_MAX_DECORATORS + 1):
        while pos < len(text) and text[pos].isspace():
            pos += 1
        dm = _DECORATOR_NAME_RE.match(text, pos)
        if dm is not None:
            pos = dm.end()
            if text.startswith("(", pos):
                close = _balanced_end(text, pos)
                if close is None:
                    return None
                pos = close + 1
            continue
        fm = _DEF_OPEN_RE.match(text, pos)
        if fm is None:
            return None
        close = _balanced_end(text, fm.end() - 1)
        return None if close is None else close + 1
    return None


def _extract_fastapi(text: str, authed_routers: frozenset[str] | set[str] = frozenset()) -> list[_RouteHit]:
    """Each MCP-shaped route, with `has_auth` True when its decorator/signature carries an auth
    marker OR it is registered on a router that is authed as a whole (`authed_routers`)."""
    hits: list[_RouteHit] = []
    for m in _FASTAPI_ROUTE_START_RE.finditer(text):
        deco_close = _balanced_end(text, m.start("open"))
        if deco_close is None:
            continue
        end = _decorated_def_end(text, deco_close + 1)
        if end is None:
            continue
        block = text[m.start(): end]
        has_auth = m.group("recv") in authed_routers or any(mk in block for mk in _AUTH_MARKERS)
        lineno = text.count("\n", 0, m.start()) + 1
        hits.append(_RouteHit(m.group("route"), lineno, has_auth, m.start()))
    return hits


def _extract_express(text: str) -> list[_RouteHit]:
    hits: list[_RouteHit] = []
    gm = _EXPRESS_GLOBAL_AUTH_RE.search(text)
    global_at = gm.start() if gm else None
    for m in _EXPRESS_LINE_RE.finditer(text):
        mw_segment = m.group("mw_and_handler")
        has_auth = any(marker in mw_segment for marker in _AUTH_MARKERS)
        if global_at is not None and m.start() > global_at:
            has_auth = True
        lineno = text.count("\n", 0, m.start()) + 1
        hits.append(_RouteHit(m.group("route"), lineno, has_auth, m.start()))
    return hits


def _asymmetry_lines(hits: list[_RouteHit]) -> list[tuple[int, str, str]]:
    """Return (line, unauthed_route, authed_route) for every unauthenticated MCP route
    that has an authenticated sibling in the same file."""
    out: list[tuple[int, str, str]] = []
    auths = sorted({h.route for h in hits if h.has_auth})
    if not auths:
        return out
    for hit in hits:
        if hit.has_auth or hit.route in auths:
            continue
        out.append((hit.line, hit.route, auths[0]))
    return out


def _has_app_wide_auth_middleware(text: str, path: Path) -> bool:
    """True when this file registers an auth-named app-wide middleware (see
    `_FASTAPI_AUTH_MIDDLEWARE_RE`). Runs on the comment/docstring-blanked view, so a commented-out
    `# app.add_middleware(AuthMiddleware)` does not count as protection.

    The regex needs a string VALUE (`@app.middleware("http")`), so it runs on `router_resolver_view`,
    and a match counts only if its first character is CODE in the offset-aligned `router_code_view`.
    Without that check a one-line `DOC = "app.add_middleware(AuthMiddleware)"` read as app-wide auth
    and skipped every Python route this guard checks (#538)."""
    if "add_middleware" not in text and ".middleware" not in text:
        return False
    view = router_resolver_view(text, filename=path)
    code = router_code_view(text, filename=path)
    return any(
        code[m.start()] == view[m.start()] for m in _FASTAPI_AUTH_MIDDLEWARE_RE.finditer(view)
    )


_STANDARDS = ["OWASP:A01", "CWE-862"]


class McpTwinRouteAuthAsymmetryGuard(Guard):
    id = "mcp-twin-route-auth-asymmetry"
    title = "An MCP route has no auth middleware while a sibling MCP route is authenticated"
    area = "AI agent"

    # server.py: /mcp is wrapped in Depends(auth), its sibling /mcp_message is not ->
    # fires mcp-twin-route-auth-asymmetry/unauthed-sibling.
    canary_plant = CanaryPlant(
        files={
            "mcp_twin_routes.py": (
                "from fastapi import FastAPI, Depends\n"
                "app = FastAPI()  # security: allow-api-docs\n\n"
                "@app.post('/mcp')\n"
                "def mcp_handler(user=Depends(auth)):\n"
                "    return handle(user)\n\n"
                "@app.post('/mcp_message')\n"
                "def mcp_message_handler():\n"
                "    return handle(None)\n"
            ),
        },
        expects=frozenset({
            "mcp-twin-route-auth-asymmetry/unauthed-sibling",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "mcp" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        # (path, rel, text) for every file that declares an MCP-shaped route and has not opted out.
        candidates: list[tuple[Path, str, str]] = []
        # Every product .py file, for the repo-wide router-auth resolver and the middleware scan.
        # The pragma and mitigation passes must see files the finding pass skips (a `main.py`
        # with no `/mcp` literal is exactly where the router mount and the middleware live).
        py_files: list[tuple[Path, str]] = []
        for f in iter_files(root, _PY_SUFFIXES + _JS_SUFFIXES):
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            text = read(f)
            if not text:
                continue
            if f.suffix == ".py":
                py_files.append((f, blank_disabled_security_schemes(text)))
            if "/mcp" in text and not pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                candidates.append((f, r, text))
        if not candidates:
            return out

        py_candidates = [c for c in candidates if c[0].suffix == ".py"]
        app_wide_auth = False
        cross_file: dict[str, set[str]] = {}
        if py_candidates:
            app_wide_auth = any(_has_app_wide_auth_middleware(t, f) for f, t in py_files)
            cross_file = cross_file_authed_routers(
                py_files, auth_call=auth_call_named_with_aliases(*(t for _, t in py_files))
            )

        for f, r, text in candidates:
            if f.suffix == ".py":
                if app_wide_auth:
                    continue  # auth runs for every request the app serves: no route is "the open one"
                authed = same_file_authed_routers(
                    text, auth_call=auth_call_named_with_aliases(text), filename=f
                )
                authed |= cross_file.get(f.stem, set())
                hits = _extract_fastapi(text, authed)
            else:
                hits = _extract_express(text)
            if not hits:
                continue

            for line, unauthed_route, authed_route in _asymmetry_lines(hits):
                out.append(self._finding(r, line, unauthed_route, authed_route))
        return out

    def _finding(self, r: str, line: int, unauthed_route: str, authed_route: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{r}:{line}",
            message=(
                f"MCP route {unauthed_route!r} has no auth middleware, while a sibling "
                f"route ({authed_route!r}) in the same file is authenticated — the "
                "CVE-2026-33032 (MCPwn, CVSS 9.8, KEV-listed) shape: the same handler "
                "surface is reachable, unauthenticated, through the sibling route."
            ),
            remediation=(
                f"Apply the same authentication middleware/dependency to {unauthed_route!r} "
                f"that {authed_route!r} already has — every route in an MCP endpoint family "
                "must share the same auth requirement, not just the primary one."
            ),
            rule="mcp-twin-route-auth-asymmetry/unauthed-sibling",
            standards=list(_STANDARDS),
        )
