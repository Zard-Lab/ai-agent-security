"""Guard: WebSocket accept() without origin validation (§2b — Authorization).

Every browser initiating a WebSocket connection sends an `Origin` header that identifies
the page that opened the socket. Unlike cookies and Bearer tokens — which browsers
withhold from cross-origin requests — the WebSocket upgrade request is NOT subject to the
Same-Origin Policy. Any attacker-controlled page can call

    new WebSocket("wss://victim.com/ws")

from any origin, and the browser will include the victim's session cookies in the upgrade
request. Without an explicit origin check on the server, a malicious site can silently
open a WebSocket to the authenticated user's backend, read streaming data, and inject
messages — a variant of Cross-Site WebSocket Hijacking (CSWSH).

One statically detectable pattern:

  **`accept-without-origin-check`** (HIGH): A Python file that calls
  `websocket.accept()` or `await websocket.accept()` without any reference to
  `origin` or `headers.get("origin"` anywhere from the START of the enclosing function
  through the accept call (`enclosing_function_span()`). A call with no
  enclosing function (module-level code) falls back to a 10-line look-back window.

**Why HIGH?** Cross-Site WebSocket Hijacking allows an attacker to:
  - Initiate an authenticated WebSocket from any page the victim visits
  - Read all server-sent data (streaming AI responses, live notifications, PII)
  - Inject arbitrary frames (as the authenticated user) triggering state changes
  - Exfiltrate the full session silently — no XSS required

**False-negative scope:** This guard looks backward from the accept() call to the start of
its enclosing function (or 10 lines, at module level). Origin checks enforced at middleware
level, via a separate decorator, in a DIFFERENT function this one calls, or before the
enclosing function starts are not detected. Runtime-only allow-list lookups that are
syntactically hidden (e.g. stored in a dict with a computed key) may also be missed.

**Checklist item:** `2b-websocket-origin-validated` (§2b — Authorization, OWASP:A01,
CWE-346).

**Suppress:** `# security: allow-websocket-no-origin` anywhere in the file silences
this check for that file. Use only when origin validation is enforced upstream (e.g.
a middleware layer or a load-balancer rule) and you can prove cross-origin connections
are rejected before reaching the handler.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    enclosing_function_span,
    is_nonproduct_path,
    iter_files,
    iter_functions,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
)

_PRAGMA = "security: allow-websocket-no-origin"

_STANDARDS = ["OWASP:A01", "CWE-346"]

# Matches websocket.accept( with optional await and arbitrary whitespace.
_ACCEPT = re.compile(r"\bwebsocket\.accept\s*\(", re.IGNORECASE)

# Signals that an origin check is present — any reference to the origin header.
# `origin(?![a-rt-z])` matches `origin` / `origins` / `validate_origin` / `origin_header` /
# `ALLOWED_ORIGINS` (a `_` or `(` or plural `s` after is fine) but NOT `original`/`originally`
# (a following letter other than `s` continues a different word). \b would wrongly reject the
# snake_case/constant forms (it treats `_` as a word char), the dominant Python convention.
_ORIGIN_CHECK = re.compile(
    r"""origin(?![a-rt-z])|headers\.get\s*\(\s*["']origin["']|headers\s*\[\s*["']origin["']""",
    re.IGNORECASE,
)

_LOOKBACK = 10  # lines to scan before the accept() call


class WebsocketOriginGuard(Guard):
    id = "websocket-origin"
    title = "WebSocket accept() without cross-origin validation (CSWSH risk)"
    area = "Login & access"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted across the canary's shared
    # `ws_handler.py` and `ws_origin_handler.py`, each of which several guards trip at once, so those files
    # stay in `canary.py`'s base owned by no guard. The ownership rule this follows is documented on
    # `xxe_safe.py`.
    # ws_origin_handler.py: websocket.accept() without origin check ->
    # accept-without-origin-check.
    canary_plant = CanaryPlant(expects=frozenset({"websocket-origin/accept-without-origin-check"}))

    def applies(self, profile: StackProfile) -> bool:
        return "fastapi" in profile.features or "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                text = read(f)
                if pragma_present(_PRAGMA, text, dialect="python"):
                    continue
                if not _ACCEPT.search(text):
                    continue
                out.extend(self._check_file(root, f, text))
        return out

    def _check_file(self, root: Path, f: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        lines = text.splitlines()
        # Computed once per file, not per match: enclosing_function_span() re-parses the AST on
        # every call otherwise, which measures ~900x slower over a many-function file (found in the
        # #685 review).
        funcs = iter_functions(text, filename=f)
        for i, line in enumerate(lines):
            if not _ACCEPT.search(line):
                continue
            # look back to the START of the enclosing function first (an origin check
            # can sit further back than any fixed window reaches), falling back to the fixed
            # look-back only for module-level accept() calls with no enclosing def. Look-BACK
            # only, never forward — an origin check performed AFTER accept() has already run is
            # too late: the connection is already open.
            span = enclosing_function_span(text, i + 1, functions=funcs)
            if span is not None:
                scope_start, _scope_end = span
                scope = "\n".join(lines[scope_start - 1 : i])
                if _ORIGIN_CHECK.search(scope):
                    continue
            else:
                start = max(0, i - _LOOKBACK)
                window = lines[start:i]
                if any(_ORIGIN_CHECK.search(prev) for prev in window):
                    continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title="WebSocket accepted without origin validation",
                    location=f"{rel(root, f)}:{i + 1}",
                    message=(
                        "`websocket.accept()` is called with no origin check in the "
                        "preceding code. The WebSocket upgrade is not subject to the "
                        "browser's Same-Origin Policy — any page the victim visits can "
                        "call `new WebSocket('wss://your-server/ws')` and the browser "
                        "will include session cookies, enabling Cross-Site WebSocket "
                        "Hijacking (CSWSH). An attacker can read streamed responses "
                        "(including live AI output) and inject messages as the "
                        "authenticated user with no XSS required."
                    ),
                    remediation=(
                        "Read the `Origin` header before accepting and reject disallowed "
                        "origins: `origin = websocket.headers.get('origin'); "
                        "if origin not in ALLOWED_ORIGINS: "
                        "await websocket.close(code=1008); return`. "
                        "Maintain `ALLOWED_ORIGINS` as an explicit server-side allow-list "
                        "(never derive it from the request). "
                        "If origin enforcement is handled by upstream middleware or a "
                        "load-balancer rule, suppress with "
                        "`# security: allow-websocket-no-origin`."
                    ),
                    rule="websocket-origin/accept-without-origin-check",
                    standards=list(_STANDARDS),
                )
            )
        return out
