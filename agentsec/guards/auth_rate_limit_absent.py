"""Guard: sensitive auth route has no rate-limiting protection (checklist §2c).

An auth-sensitive endpoint without rate limiting — login, registration, password
reset, or a token-issuing route — is a direct brute-force and credential-stuffing
surface. A single unauthenticated caller can hammer a POST /login route with
sequential password guesses, or flood /register to exhaust invite quotas or spam
downstream email/SMS providers. This is the same shape of gap
`llm-rate-limit-absent` already closes for LLM-calling routes, but that guard is
scoped specifically to routes that make a direct LLM API call — it does not fire
for an auth route with no LLM involvement at all.

This guard detects a FastAPI/APIRouter route decorator whose path string (or the
immediately-following handler function's name) looks auth-sensitive — login,
sign-in, sign-up, register, reset/forgot/change-password, authenticate, or a
`/token` path — in a file that contains no recognized rate-limiting signal
(slowapi, fastapi-limiter, starlette-limiter, `@limiter`, `RateLimiter`,
`rate_limit`, `Throttle`):

  **`no-rate-limit`** (MEDIUM): the route path or handler name is auth-sensitive
  and the file imports no recognized rate-limiting library.

Rate limiting wired once for the whole app, in another file, also covers the route
(#472, `base.py::rate_limit_wiring`): a router mounted with a rate-limit dependency
(`include_router(auth.router, dependencies=[Depends(RateLimiter(...))])`, matched per
route by its router), an app-level `FastAPI(dependencies=[...])` carrying one, or
slowapi global limits (`SlowAPIMiddleware` registered AND a `Limiter` with
`default_limits` / `application_limits`). Each must be unconditional product code in
the route's top-level directory. A dual mount (one bare include), a test-only app and
a mention in a comment still leave the route firing.

A MEDIUM severity is used because rate limiting is often applied at the
middleware or infrastructure layer (nginx, API gateway, Cloudflare) rather than
in each route file. The finding prompts a manual review rather than asserting a
definite vulnerability.

Checklist item: `2c-stricter-limits-sensitive-endpoints` (PARTIAL — this guard
adds auth-route coverage alongside `llm-rate-limit-absent`'s LLM-route coverage;
routes registered via `add_api_route(...)` instead of a decorator, or whose path
and function name both use non-standard naming, are not detected).

Suppress: `# security: allow-unrated-auth-endpoint` anywhere in a file silences
this guard for that file. Use when rate limiting is enforced at the
proxy/gateway layer.
"""
from __future__ import annotations

import re
from pathlib import Path

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
    route_receiver,
)

_PRAGMA = "security: allow-unrated-auth-endpoint"

# FastAPI route decorators (any verb), capturing the path string literal.
_ROUTE_DECORATOR_WITH_PATH = re.compile(
    r"""@(?:router|app)\.(?:get|post|put|patch|delete)\s*\(\s*["']([^"']*)["']""",
    re.IGNORECASE,
)

# The handler function name, looked up on the lines immediately after a decorator.
_DEF_NAME = re.compile(r"\bdef\s+(\w+)\s*\(")

# Auth-sensitive path segments / function names.
_SENSITIVE_KEYWORD = re.compile(
    r"\b(?:log[-_]?in|sign[-_]?in|sign[-_]?up|register(?:ation)?|"
    r"reset[-_]?password|forgot[-_]?password|change[-_]?password|"
    r"password[-_]?reset|authenticate)\b|/token\b",
    re.IGNORECASE,
)

# Recognized rate-limiting signals (mirrors llm_rate_limit_absent.py).
_RATE_LIMIT_SIGNAL = re.compile(
    r"slowapi|from\s+fastapi_limiter|from\s+starlette_limiter"
    r"|@\w*limiter\b|RateLimiter\b|rate_limit\b|Depends\s*\(\s*rate"
    r"|Throttle\b|throttle\b",
    re.IGNORECASE,
)

_STANDARDS = ["OWASP:API4", "OWASP:A07"]

_LOOKAHEAD_LINES = 3


class AuthRateLimitAbsentGuard(Guard):
    id = "auth-rate-limit-absent"
    title = "Auth-sensitive route has no rate-limiting protection"
    area = "Reliability"

    # auth_login_route.py has one auth-rate-limit-absent plant:
    #   @router.post('/login') + no rate-limiting signal -> no-rate-limit (MEDIUM).
    # Must NOT contain: allow-unrated-auth-endpoint pragma, or any rate-limit signal.
    canary_plant = CanaryPlant(
        files={
            "auth_login_route.py": (
                "from fastapi import APIRouter\n"
                "\n"
                "router = APIRouter()\n"
                "\n"
                "\n"
                "@router.post('/login')\n"
                "async def login(username: str, password: str) -> dict:\n"
                "    return {'token': 'issued'}\n"
            ),
        },
        expects=frozenset({"auth-rate-limit-absent/no-rate-limit"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        # CLAUDE.md rule 4: the pragma and same-file-signal skips below gate only where a finding
        # may be ANCHORED. `files` keeps every product file, so a pragma'd `main.py` still
        # contributes the rate limiting it wires. A test or example app is no coverage source (its
        # wiring never runs in front of the product's routes), so it is not read at all.
        files: list[tuple[Path, str]] = []
        found: list[tuple[Path, str, list[tuple[str | None, Finding]]]] = []
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
                if _RATE_LIMIT_SIGNAL.search(text):
                    continue
                hits = self._scan(root, f, r, text)
                if hits:
                    found.append((f, text, hits))
        if not found:
            return []
        # Pass 1 runs only once pass 2 has a candidate, so a repo with nothing to report never pays
        # for it (#771). Rate limiting wired in another file covers a route just as a same-file
        # signal does (#472): a rate-limited router mount, or slowapi global limits or an app-level
        # dependency in the route's scope.
        wiring = rate_limit_wiring(root, files)
        out: list[Finding] = []
        for f, text, hits in found:
            covered = rate_limited_routes(root, f, text, wiring)
            if covered.whole_file:
                continue
            out.extend(finding for receiver, finding in hits if receiver not in covered.routers)
        return out

    def _scan(self, root: Path, f: Path, r: str, text: str) -> list[tuple[str | None, Finding]]:
        """Each auth-sensitive route in `text`, with the router it is registered on."""
        out: list[tuple[str | None, Finding]] = []
        lines = text.splitlines()
        for i, line in enumerate(lines):
            m = _ROUTE_DECORATOR_WITH_PATH.search(line)
            if not m:
                continue
            sensitive = bool(_SENSITIVE_KEYWORD.search(m.group(1)))
            if not sensitive:
                for j in range(i + 1, min(i + 1 + _LOOKAHEAD_LINES, len(lines))):
                    dm = _DEF_NAME.search(lines[j])
                    if dm:
                        sensitive = bool(_SENSITIVE_KEYWORD.search(dm.group(1)))
                        break
            if not sensitive:
                continue
            finding = Finding(
                check_id=self.id,
                severity="medium",
                title=self.title,
                location=f"{r}:{i + 1}",
                message=(
                    "This route looks auth-sensitive (login, registration, password "
                    "reset, or a token-issuing path) but the file contains no recognized "
                    "rate-limiting signal (slowapi, fastapi-limiter, @limiter.limit, "
                    "RateLimiter). Without rate limiting, a single caller can brute-force "
                    "credentials, exhaust invite/token quotas, or flood downstream "
                    "email/SMS providers used for verification."
                ),
                remediation=(
                    "Apply per-IP or per-account rate limiting to every auth-sensitive "
                    "endpoint. With slowapi: add @limiter.limit('5/minute') to the route "
                    "and register SlowAPIMiddleware. With fastapi-limiter: use "
                    "Depends(RateLimiter(times=5, seconds=60)). If rate limiting is "
                    "enforced at the proxy/gateway layer, suppress with "
                    "`# security: allow-unrated-auth-endpoint`."
                ),
                rule="auth-rate-limit-absent/no-rate-limit",
                standards=list(_STANDARDS),
            )
            out.append((route_receiver(line), finding))
        return out
