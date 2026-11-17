"""Guard: FastAPI route with an LLM call but no rate-limiting middleware (checklist §2c).

An AI endpoint without rate limiting is a direct economic and availability attack surface.
A single unauthenticated caller can hammer a POST /chat route with sequential requests and
drain API credits, saturate context windows, or exhaust downstream quotas. This is distinct
from generic rate-limiting (§2a) — the concern here is specifically the LLM call cost.

This guard detects files that contain BOTH:
  - A FastAPI/APIRouter route decorator (any HTTP verb), AND
  - A direct LLM API call (chat.completions.create / responses.create / messages.create)
without any rate-limiting signal in the file:

  **`no-rate-limit`** (MEDIUM): the route file makes a direct LLM call and imports no
  recognized rate-limiting library (slowapi, fastapi-limiter, starlette-limiter).

Rate limiting wired once for the whole app, in another file, also covers the file (#472,
`base.py::rate_limit_wiring`): slowapi global limits (`SlowAPIMiddleware` registered AND a
`Limiter` with `default_limits` / `application_limits`) or an app-level
`FastAPI(dependencies=[...])` rate-limit dependency in the file's top-level directory, or a
rate-limited router mount (`include_router(chat.router, dependencies=[Depends(RateLimiter(...))])`)
of EVERY router the file's routes sit on. Each must be unconditional product code. A dual mount
(one bare include), a test-only app and a mention in a comment still leave the file firing.

A MEDIUM severity is used because rate limiting is often applied at the middleware or
infrastructure layer (nginx, API gateway, Cloudflare) rather than in each route file.
The finding prompts a manual review rather than asserting a definite vulnerability.

Checklist item: `2c-stricter-limits-sensitive-endpoints` (MANUAL → partial).

Suppress: `# security: allow-unrated-llm-endpoint` anywhere in a file silences this guard
for that file. Use when rate limiting is enforced at the proxy/gateway layer.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from agentsec.astutil import safe_ast_parse
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    python_scan_dirs,
    rate_limit_wiring,
    rate_limited_routes,
    read,
    rel,
)

_PRAGMA = "security: allow-unrated-llm-endpoint"

# Direct LLM API calls with explicit receiver — excludes high-level wrappers and
# docstring/comment text that mentions these patterns without an object reference.
_LLM_CALL_DIRECT = re.compile(
    r"\b\w+\.chat\.completions\.create\s*\("
    r"|\b\w+\.responses\.create\s*\("
    r"|\b\w+\.messages\.create\s*\(",
    re.IGNORECASE,
)

# FastAPI route decorators (any verb).
_ROUTE_DECORATOR = re.compile(
    r"@(?:router|app)\.(?:get|post|put|patch|delete)\s*\(",
    re.IGNORECASE,
)

# The router-level credit in `run()` holds only when EVERY route in the file is on a covered router,
# so it is only as sound as the receiver set `_route_receivers` reads: a route it misses lets a
# covered `router` withdraw the whole file's finding (#1007 review, rounds 1 to 3). It reads the
# syntax tree, not the text, so spacing, line breaks, comments and strings neither hide a route nor
# invent one, and it is wider than `_ROUTE_DECORATOR`, the candidate gate, which reads only
# `router` / `app`.
# A route a method registers: `@<receiver>.post(...)` and its siblings, or `<receiver>.add_api_route(...)`.
_ROUTE_DECORATOR_METHODS = frozenset(
    {
        "get", "post", "put", "patch", "delete", "head", "options", "trace",
        "websocket", "websocket_route", "api_route", "route",
    }
)
_ROUTE_CALL_METHODS = frozenset(
    {"add_api_route", "add_route", "add_websocket_route", "add_api_websocket_route"}
)
# A route built as an object and handed over in a table, which no receiver method registers. A
# `routes=` keyword counts on ANY call, not only a router or app constructor: a project's own
# `attach_routes(router, routes=TABLE)` hands the table over just the same (#1007 review round 4).
_ROUTE_OBJECTS = frozenset({"Route", "WebSocketRoute", "APIRoute", "APIWebSocketRoute"})
# A call that only READS its `routes=` keyword: FastAPI's `get_openapi(routes=app.routes)` builds the
# schema from routes already registered (#1007 review round 5). Exempt by callee, not by the value
# passed: `APIRouter(routes=router.routes)` copies `router`'s routes onto a router that may be mounted
# without the limit.
_ROUTES_READERS = frozenset({"get_openapi"})
_LIST_MUTATORS = frozenset({"append", "extend", "insert"})


def _ast_tail(node: ast.expr) -> str | None:
    """The last name of a `Name` / `Attribute` chain (`Route`, `routing.Route`)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _is_routes_list(node: ast.expr) -> bool:
    """`<x>.routes`, or a subscript of it (`router.routes[:]`)."""
    if isinstance(node, ast.Subscript):
        node = node.value
    return isinstance(node, ast.Attribute) and node.attr == "routes"


def _hand_applied_route(call: ast.Call) -> ast.expr | None:
    """The receiver of `router.post("/chat")(chat)`, a route decorator applied by hand. The path
    must be a literal that is empty or starts with `/`, which keeps a dict-dispatch call such as
    `handlers.get("name")(payload)` out."""
    inner = call.func
    if not (isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute)):
        return None
    if inner.func.attr not in _ROUTE_DECORATOR_METHODS:
        return None
    path = inner.args[0] if inner.args else next((k.value for k in inner.keywords if k.arg == "path"), None)
    if (
        isinstance(path, ast.Constant)
        and isinstance(path.value, str)
        and (path.value == "" or path.value.startswith("/"))
    ):
        return inner.func.value
    return None


def _route_receivers(text: str, filename: Path) -> set[str] | None:
    """The receiver of every route `text` registers, as source text (`router`, `common.router`,
    `routers['chat']`, `get_router()`), or None when a route may be registered without one: a
    route object (`Route(...)`, `APIRoute(...)`), a `routes=` keyword on any call but
    `get_openapi`, a write to a router's `.routes`, or a file that does not parse. A read of
    `.routes` (FastAPI's operation-id and `get_openapi` recipes) is no registration. The receiver is kept whole, so only a plain name can
    match a covered router: `common.router` is another module's router, not this file's."""
    tree = safe_ast_parse(text, filename=filename)
    if tree is None:
        return None
    receivers: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            for deco in node.decorator_list:
                func = deco.func if isinstance(deco, ast.Call) else deco
                if isinstance(func, ast.Attribute) and func.attr in _ROUTE_DECORATOR_METHODS:
                    receivers.add(ast.unparse(func.value))
        elif isinstance(node, ast.Call):
            func = node.func
            hand_applied = _hand_applied_route(node)
            if hand_applied is not None:
                receivers.add(ast.unparse(hand_applied))
            elif isinstance(func, ast.Attribute) and func.attr in _ROUTE_CALL_METHODS:
                receivers.add(ast.unparse(func.value))
            elif (
                isinstance(func, ast.Attribute) and func.attr in _LIST_MUTATORS and _is_routes_list(func.value)
            ):
                return None
            callee = _ast_tail(func)
            if callee in _ROUTE_OBJECTS:
                return None
            if callee not in _ROUTES_READERS and any(k.arg == "routes" for k in node.keywords):
                return None
        elif isinstance(node, ast.Assign | ast.AugAssign | ast.AnnAssign):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(_is_routes_list(t) for t in targets):
                return None
    return receivers

# Recognized rate-limiting signals.
_RATE_LIMIT_SIGNAL = re.compile(
    r"slowapi|from\s+fastapi_limiter|from\s+starlette_limiter"
    r"|@\w*limiter\b|RateLimiter\b|rate_limit\b|Depends\s*\(\s*rate"
    r"|Throttle\b|throttle\b",
    re.IGNORECASE,
)

_STANDARDS = ["OWASP-LLM:LLM10", "OWASP:API4"]


class LLMRateLimitAbsentGuard(Guard):
    id = "llm-rate-limit-absent"
    title = "LLM-backed route has no rate-limiting protection"
    area = "AI agent"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `llm_route.py`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # llm_route.py: @router.post + chat.completions.create + no rate-limiting signal -> no-rate-limit (MEDIUM).
    canary_plant = CanaryPlant(expects=frozenset({"llm-rate-limit-absent/no-rate-limit"}))

    def applies(self, profile: StackProfile) -> bool:
        return "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        # CLAUDE.md rule 4: the pragma and per-file skips below gate only where a finding may be
        # ANCHORED. `files` keeps every product file, so a pragma'd `main.py` still contributes
        # the rate limiting it wires. A test or example app is no coverage source, so it is not
        # read at all.
        files: list[tuple[Path, str]] = []
        found: list[tuple[Path, str]] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                r = rel(root, f)
                if is_nonproduct_path(r, profile.archive_segments):
                    continue
                text = read(f)
                files.append((f, text))
                if pragma_present(_PRAGMA, text, dialect="python"):
                    continue
                if not _ROUTE_DECORATOR.search(text):
                    continue
                if not _LLM_CALL_DIRECT.search(text):
                    continue
                if _RATE_LIMIT_SIGNAL.search(text):
                    continue
                found.append((f, text))
        if not found:
            return []
        # Pass 1 runs only once pass 2 has a candidate (#771). Rate limiting wired in another file
        # covers the routes just as a same-file signal does (#472).
        wiring = rate_limit_wiring(root, files)
        out: list[Finding] = []
        for f, text in found:
            covered = rate_limited_routes(root, f, text, wiring)
            if covered.whole_file:
                continue
            # The finding is per FILE and which route reaches the LLM call is not resolved, so a
            # router-level credit holds only when EVERY route in the file is on a covered router.
            # A file whose routes cannot all be attributed (None), or where none can (empty), gets
            # no router-level credit.
            receivers = _route_receivers(text, f)
            if receivers and receivers <= covered.routers:
                continue
            out.extend(self._flag(root, f, text))
        return out

    def _flag(self, root: Path, f: Path, text: str) -> list[Finding]:
        r = rel(root, f)
        for lineno, line in enumerate(text.splitlines(), 1):
            if _LLM_CALL_DIRECT.search(line):
                return [
                    Finding(
                        check_id=self.id,
                        severity="medium",
                        title="LLM route file lacks a rate-limiting import or decorator",
                        location=f"{r}:{lineno}",
                        message=(
                            "This file exposes a FastAPI route that calls an LLM directly "
                            "but contains no recognized rate-limiting signal (slowapi, "
                            "fastapi-limiter, @limiter.limit, RateLimiter). Without rate "
                            "limiting, a single caller can exhaust LLM API quotas or inflate "
                            "costs arbitrarily (OWASP-LLM:LLM10, OWASP:API4)."
                        ),
                        remediation=(
                            "Apply per-user rate limiting to every LLM-backed endpoint. "
                            "With slowapi: add @limiter.limit('10/minute') to the route and "
                            "register SlowAPIMiddleware. With fastapi-limiter: use "
                            "Depends(RateLimiter(times=10, seconds=60)). Set limits based on "
                            "your LLM cost budget, not just traffic. If rate limiting is "
                            "enforced at the proxy/gateway layer, suppress with "
                            "`# security: allow-unrated-llm-endpoint`."
                        ),
                        rule="llm-rate-limit-absent/no-rate-limit",
                        standards=list(_STANDARDS),
                    )
                ]
        return []
