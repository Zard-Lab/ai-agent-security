"""Guard: route path segment names it as debug/internal/leftover (checklist §6a).

OWASP Noir (`owasp-noir/noir`) is an attack-surface-mapping tool: its whole concept is
enumerating every route/endpoint a codebase registers — path, method, params — so that
"shadow APIs, deprecated routes, and undocumented handlers come out as part of the same
inventory" (its own README). Noir's FastAPI analyzer
(`src/analyzer/analyzers/python/fastapi.cr`) walks every `@app.<verb>(...)` /
`@router.<verb>(...)` decorator and every `add_api_route(...)` call to build that inventory,
purely from the literal path string — it does not itself judge any one route's auth. That
"cheap, static, look-at-what's-actually-registered" idea is what this guard borrows: turn
the same route inventory into a naming-convention check.

In practice, developers routinely leave a route reachable that was only ever meant to be
temporary: a `/debug/dump-config` route added to inspect state during an incident, a
`/_internal/reset-cache` admin shortcut wired up for a demo, an `/api/v0/legacy-export`
kept "just in case" after the v1 replacement shipped. None of these are marked non-public in
any framework-visible way — FastAPI serves them exactly like any other route — so they sit
in production, often undocumented and unmonitored, until someone finds the path (OWASP:A09
— Security Logging and Monitoring Failures: these are the routes nobody is watching).

This is a **surfacing** guard, like `bola`/`auth-dependency-not-applied`: a path segment
named this way is a strong signal, not proof — a legitimate feature could be named
`/legacy-importer` on purpose. It flags the naming for human triage rather than asserting
the route is definitely unauthenticated or forgotten.

Fires MEDIUM when a route decorator (`@app.get/post/put/patch/delete/websocket/api_route(...)`
or `@router.<same>(...)`) has a literal string path argument containing a path SEGMENT
(the text between two `/`) that names it as one of two keyword classes:

  * **compound-eligible** (`debug`, `backdoor`, `hidden`, `deprecated`, `legacy`, `staging`):
    matches the whole segment, OR any `-`/`_`-joined sub-token of it — `/debug/dump-config`,
    `/legacy-api/v1`, and `/__debug__/toolbar` (edge underscores stripped first) all match.
  * **strict** (`internal`): matches ONLY when it IS the whole segment (after stripping edge
    underscores) — `/internal/health` and `/_internal/reset-cache` match, but
    `/users/{id}/internal_notes` does NOT, because `internal` there is the first half of a
    compound *business* term (an internal-notes feature), not a segment naming the route
    itself as internal-only. `internal` is deliberately NOT compound-eligible: unlike
    `debug`/`backdoor`/`legacy`, "internal" is common vocabulary in ordinary product features
    (internal notes, internal comments, internal review) and a sub-token match on it produced
    exactly that false positive during adversarial testing of this guard.

`/testimonials` does not match (no keyword token at all) and `/apiinternal` does not match
(the whole segment is `apiinternal`, not `internal`) — matching is always a real token, never
a raw substring slice.

**Checklist item:** `6a-api-inventory-no-stale-endpoints` (§6a — HTTP Security, was
`manual`/uncovered — no check_id previously mapped to it).

**Suppress:** `# security: allow-debug-route-exposed` anywhere in a file silences this check
for that entire file. Use when the naming is a deliberate, reviewed, non-debug feature name.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    _SL_STRING,
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    strip_python_line_comment,
    strip_python_strings,
)

_PRAGMA = "security: allow-debug-route-exposed"

_STANDARDS = ["OWASP:A09"]

# A route-registration decorator: @app.get(...), @router.post(...), @app.websocket(...),
# @router.api_route(...), etc. Captures the quoted path literal (first argument, may be
# followed by other args) so the path can be inspected independent of the rest of the call.
_ROUTE_DECORATOR = re.compile(
    r"""@\s*\w+\s*\.\s*(?:get|post|put|patch|delete|websocket|api_route|route)\s*\(\s*
        (?P<q>['"])(?P<path>[^'"]*)(?P=q)""",
    re.VERBOSE,
)

# Cheap pre-check: is this line the start of a route-registration decorator at all — used to
# decide whether a multi-line decorator (path literal on a continuation line, e.g.
# `@app.get(\n    "/debug/dump",\n    tags=["x"],\n)`) is worth joining forward for.
_ROUTE_DECORATOR_START = re.compile(
    r"@\s*\w+\s*\.\s*(?:get|post|put|patch|delete|websocket|api_route|route)\s*\(",
)

# How many extra lines to fold into a decorator that doesn't close on its own line — enough
# for the common `path, tags=[...], response_model=...` shape without scanning unrelated code.
_CONTINUATION_WINDOW = 4

# `internal` is common ordinary product vocabulary (internal notes, internal comments) when
# it's the first half of a `_`/`-`-joined compound — so it only counts when it IS the whole
# segment (after stripping edge underscores), never as a sub-token of a longer segment.
_STRICT_KEYWORDS = frozenset({"internal"})

# These are not ordinary product vocabulary as a compound qualifier, so a sub-token match
# (`legacy-api`, `debug-tools`, `__debug__`) is still a strong, low-noise signal.
_COMPOUND_KEYWORDS = frozenset({"debug", "backdoor", "hidden", "deprecated", "legacy", "staging"})

_SUB_TOKEN_SPLIT = re.compile(r"[-_]+")


def _flagged_segment(path: str) -> str | None:
    """The first path segment that names the route as debug/internal/leftover, or None.

    A segment matches if, after stripping LEADING/TRAILING underscores only (the `_internal`
    / `__debug__` marker convention), it either equals a strict keyword exactly, or contains a
    `-`/`_`-joined sub-token equal to a compound keyword. See the module docstring for why
    `internal` is strict-only.
    """
    for raw_segment in path.split("/"):
        if not raw_segment:
            continue
        core = raw_segment.strip("_")
        if not core:
            continue
        lowered = core.lower()
        if lowered in _STRICT_KEYWORDS:
            return raw_segment
        sub_tokens = _SUB_TOKEN_SPLIT.split(lowered)
        if any(tok in _COMPOUND_KEYWORDS for tok in sub_tokens if tok):
            return raw_segment
    return None


class DebugRouteExposedGuard(Guard):
    id = "debug-route-exposed"
    title = "Route path looks like a debug/internal/deprecated endpoint left reachable"
    area = "Web setup"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `debug_endpoints.py`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    canary_plant = CanaryPlant(expects=frozenset({"debug-route-exposed/debug-or-internal-path-segment"}))

    def applies(self, profile: StackProfile) -> bool:
        return "fastapi" in profile.features

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
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        text = read(f)
        if pragma_present(_PRAGMA, text, dialect="python"):
            return []
        out: list[Finding] = []
        lines = text.splitlines()
        # Parens for the fold are counted on a fully STRING-BLANKED copy: strip_python_strings
        # blanks TRIPLE-quoted strings (line-preserving) and _SL_STRING blanks single-line ones,
        # so an unbalanced `(`/`)` inside ANY string kwarg (single- or triple-quoted
        # `description=`/`summary=`) can't throw off the fold (PR #452 re-review).
        # Comments are stripped as well as strings. The fold counted parens on a
        # string-blanked but NOT comment-stripped copy, so an unbalanced `(` inside a `#`
        # comment in a wrapped decorator — `# internal only (see RFC 7231 sec 4` — threw
        # the depth off and the route path was never matched (#452 review).
        code_lines = [strip_python_line_comment(ln) for ln in lines]
        paren_lines = [
            _SL_STRING.sub("", strip_python_line_comment(ln))
            for ln in strip_python_strings(text, filename=f).splitlines()
        ]
        for lineno, line in enumerate(lines, start=1):
            stripped = line.lstrip()
            if not stripped.startswith("@"):
                continue
            if not _ROUTE_DECORATOR_START.search(line):
                continue
            m = _ROUTE_DECORATOR.search(line)
            if not m:
                # The path literal may be on a continuation line (multi-line decorator
                # call with tags=/response_model=/status_code= before the closing paren).
                # Fold forward only within THIS decorator's own call — stop at the line that
                # balances its parens — so the window can't spill into the NEXT decorator and
                # match its path (#423). Capped at _CONTINUATION_WINDOW lines.
                win: list[str] = []
                depth = 0
                for k in range(lineno - 1, min(lineno - 1 + _CONTINUATION_WINDOW, len(lines))):
                    # Comment-stripped (strings intact — the path is a string literal), so
                    # a `#` comment sitting between the `(` and the path does not break the
                    # joined match either (#452 review).
                    win.append(code_lines[k] if k < len(code_lines) else lines[k])
                    pl = paren_lines[k] if k < len(paren_lines) else lines[k]
                    depth += pl.count("(") - pl.count(")")
                    if depth <= 0 and k > lineno - 1:
                        break
                m = _ROUTE_DECORATOR.search(" ".join(win))
                if not m:
                    continue
            path = m.group("path")
            seg = _flagged_segment(path)
            if not seg:
                continue
            out.append(Finding(
                check_id=self.id,
                severity="medium",
                title=self.title,
                location=f"{rel(root, f)}:{lineno}",
                message=(
                    f"Route path `{path}` contains a `{seg}` path "
                    "segment — a naming pattern strongly associated with a debug/internal/"
                    "leftover endpoint (a diagnostic route added during an incident, an "
                    "admin shortcut wired up for a demo, or a superseded version kept "
                    "'just in case'). FastAPI serves it exactly like any other route: "
                    "nothing about the name makes it non-public, undocumented, or "
                    "unmonitored in practice — it just usually is."
                ),
                remediation=(
                    "Remove the route if it's genuinely dead code, or move it behind the "
                    "same auth + monitoring every other production route gets. If the name "
                    "is a deliberate, reviewed, non-debug feature, suppress with "
                    "`# security: allow-debug-route-exposed`."
                ),
                rule="debug-route-exposed/debug-or-internal-path-segment",
                standards=list(_STANDARDS),
            ))
        return out
