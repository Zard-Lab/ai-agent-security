"""Guard: file-download/export route with no auth signal (§2b).

A `GET`/`POST` route that serves a file by an id or filename taken from the URL —
`GET /exports/{export_id}` → `FileResponse(...)` — and shows no sign of checking who's
asking is a bulk-data leak waiting for someone to iterate the id space. Unlike `bola`
(an *ORM fetch* returned as JSON with no ownership scoping — ids merely need to belong
to the caller) this pattern is often worse in practice: no auth dependency at all means
the route doesn't even require a login, so a public URL-guesser or an automated crawler
can walk `/exports/1`, `/exports/2`, … and exfiltrate every file, no session needed.
CVE-2024-0551 (AnythingLLM) was this exact shape: an unauthenticated DB-export endpoint
serving files by predictable name.

This is a **surfacing** guard, like `bola`/`auth-dependency-not-applied`: it can't prove
the route SHOULD require auth (a public download link, an already-obfuscated one-time
token in the id itself, or an intentionally public asset are all legitimate), so it
flags the absence for human review rather than asserting a bug.

Conservative — fires only when a route handler has ALL of:
  * a route decorator (`@app.get/post(...)` / `@router.get/post(...)`);
  * a URL path parameter (`{export_id}` / `{filename}` / `{slug}` / …) — any param, since a
    file route driven by a URL value is the shape we care about;
  * a FastAPI file-serving sink (`FileResponse(`, `StreamingResponse(`);
  * **no** authorization signal anywhere in the function (no `current_user`, an auth-named
    `Depends(get_current_user)`, `Security(...)`, `403`, `Forbidden`; a bare non-auth
    `Depends(get_db)` does NOT count — issue #307), and no bare auth factory in the route's own
    `dependencies=[...]` list (`dependencies=[requires_authenticated()]`; a bare `get_db()` there
    does NOT count — #872).

Suppress an audited handler with `# security: allow-unauthenticated-file-download`.

**Scope note:** distinct from `bola` (an ORM/DB fetch returned as JSON with no
*ownership* scoping — some auth may still gate the route) and from `path-traversal`
(a dynamically-BUILT path reaching a file sink — this guard fires even on a perfectly
sanitized path, because the gap here is *authorization*, not path containment; the two
can both fire on the same line from different angles).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    AUTH_CALL_NAMED,
    PER_ROUTE_AUTH_FACTORY,
    CanaryPlant,
    Guard,
    blank_disabled_security_schemes,
    blank_line_comments,
    cross_file_authed_routers,
    is_nonproduct_path,
    iter_files,
    iter_functions,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    route_deps_carry_auth,
    same_file_authed_routers,
)

_PRAGMA = re.compile(r"#\s*security:\s*allow-unauthenticated-file-download")

_STANDARDS = ["OWASP:A01", "CWE-862"]

# The route decorator plus its URL string (first string-literal arg), e.g. `@router.get("/f/{id}")`.
# Path params are matched against THIS captured URL, not the whole function block, so an f-string in
# the body (`f"report_{name}.pdf"`) can't satisfy the "has a URL path parameter" precondition when the
# route itself only takes a query param (issue #307). `<var>` captures the router object the decorator
# is called on (last dotted segment) so a route authed at the router level is recognized as authed.
# `<open>` is the decorator's opening `(`, where the per-route `dependencies=[...]` read starts (#872).
_ROUTE_PATH = re.compile(
    r"""@\s*(?P<var>[\w.]+)\.(?:get|post)\s*(?P<open>\()\s*(?P<q>["'])(?P<path>[^"']*)(?P=q)"""
)
# Any URL path parameter (`{export_id}`, `{filename}`, `{slug}`, `{exportId}`). Deliberately broad:
# the guard already requires a route decorator + a file sink + no auth, so any URL-derived value
# feeding a file route is in-scope. (Was an id/name/key token list that substring-matched
# `{profile}`/`{monkey}`/`{width}` etc. — issue #307.)
_PATH_PARAM = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*\}")
# FastAPI file-serving sinks. `send_file`/`send_from_directory` (Flask) were dropped: this guard is
# gated on `fastapi` in features and detect.py never puts Flask there, so they were unreachable
# (issue #307).
_FILE_SINK = re.compile(r"\b(?:FileResponse|StreamingResponse)\s*\(")
# fix-round review, Medium: this guard's router-level checks already pass
# `AUTH_CALL_NAMED` (below), but the per-route signal was still built from the narrower
# `AUTH_DEP_SIGNAL` directly, so `Depends(HTTPBearer())` inline on a route was recognized at the
# router level but NOT at the per-route level — an overclaiming code comment said otherwise.
# `AUTH_CALL_NAMED` already includes `AUTH_DEP_SIGNAL` plus `Security(...)` plus the inline
# security-scheme class allowlist, so this is a pure widening (adds the class allowlist, drops
# nothing). Deliberately NOT extended to the module-level-variable alias shape
# (`auth_call_named_with_aliases`) in this round — that needs the same per-file scoping design
# `websocket_no_auth.py`/`auth_dependency_not_applied.py` just got, disclosed as a residual rather
# than half-applied here.
_AUTH_SIGNAL = re.compile(
    r"current_user|get_current_user|" + AUTH_CALL_NAMED.pattern +
    r"|\b403\b|Forbidden",
    re.IGNORECASE,
)


class UnauthenticatedFileDownloadGuard(Guard):
    id = "unauthenticated-file-download"
    title = "File-download/export route with no authorization signal"
    area = "Files"

    # exports.py: a file-download route serving by id with no auth signal ->
    # unauthenticated-file-download.
    canary_plant = CanaryPlant(
        files={
            "exports.py": (
                "from fastapi import APIRouter\n\n"
                "router = APIRouter()\n\n\n"
                "@router.get(\"/exports/{export_id}\")\n"
                "def download_export(export_id: str):\n"
                "    path = get_export_path(export_id)\n"
                "    return FileResponse(path)\n"
            ),
        },
        expects=frozenset({"unauthenticated-file-download/no-auth-signal"}),
    )

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
                # anything below sees it — see websocket_no_auth.py's identical
                # comment for why this is applied once, at read time.
                files.append((f, blank_disabled_security_schemes(read(f))))

        # Pass 1 (repo-wide): a route file whose module is included cross-file with a real auth
        # dependency (`main.py` doing `include_router(exports.router, dependencies=[Depends(...)])`)
        # has every route authed at the router level — matched back by file stem. AUTH_CALL_NAMED so
        # a bare `Depends(get_db)` at the router level does NOT count (mirrors this guard's stricter
        # function-level auth policy — issue #307).
        protected_routers = cross_file_authed_routers(files, auth_call=AUTH_CALL_NAMED)

        out: list[Finding] = []
        for f, text in files:
            out.extend(self._scan(root, f, text, protected_routers))
        return out

    def _scan(self, root: Path, f: Path, text: str, protected_routers: dict[str, set[str]]) -> list[Finding]:
        # Cross-file: every route in this file is authed at the router level if its module was
        # included-with-auth elsewhere (pass 1) — `routes/exports.py` <- `include_router(exports.router, ...)`.
        # Cross-file protection merges into the same-file router set below, PER ROUTER — NOT a
        # whole-file bail. Bailing on the file meant that in the standard public+admin layout (two
        # routers in one module, one mounted with auth and one without), mounting the admin router
        # with `Depends(require_admin)` silenced every route on its sibling (#473 review, HIGH 1).
        # Same-file: routers carrying a router-level `dependencies=` auth (construction or a bare-var
        # include in this file) auth every route on them without a per-route signal. AUTH_CALL_NAMED
        # — see the pass-1 note.
        authed_routers = same_file_authed_routers(text, auth_call=AUTH_CALL_NAMED, filename=f)
        authed_routers |= protected_routers.get(f.stem, set())

        out: list[Finding] = []
        for lineno, block in iter_functions(text, filename=f):
            # A real comment in the route block only, never the phrase in a string there (#1040).
            if pragma_present(_PRAGMA, block, dialect="python"):
                continue
            route = _ROUTE_PATH.search(block)
            if route is None:
                continue
            if not _PATH_PARAM.search(route.group("path")):
                continue
            if not _FILE_SINK.search(block):
                continue
            if route.group("var").split(".")[-1] in authed_routers:
                continue
            if _AUTH_SIGNAL.search(block):
                continue
            # Auth attached through the route's OWN `dependencies=[<factory()>]` list as a bare
            # returns-nothing guard (`dependencies=[requires_authenticated()]`): not Depends()-
            # wrapped, so `_AUTH_SIGNAL` above misses it. Same scoped reader and curated matcher as
            # `auth-dependency-not-applied` (#859 sub-fix A), so a bare `get_db()` still fires (#872).
            if route_deps_carry_auth(blank_line_comments(block), route.start("open"), PER_ROUTE_AUTH_FACTORY):
                continue
            out.append(Finding(
                check_id=self.id,
                severity="high",
                title=self.title,
                location=f"{rel(root, f)}:{lineno}",
                message=(
                    "This route serves a file by an id/name from the URL but shows no sign "
                    "of checking who's asking — no auth dependency, no `current_user`, no "
                    "403/Forbidden path. Anyone who can reach the route (not even a logged-in "
                    "session may be required) can walk the id space and download every file "
                    "(OWASP:A01, CWE-862; CVE-2024-0551 was this exact shape: an unauthenticated "
                    "DB-export endpoint serving files by predictable name)."
                ),
                remediation=(
                    "Add an auth dependency (`Depends(get_current_user)`) and, if the file "
                    "belongs to a specific owner, scope the lookup to the caller before "
                    "serving it. If this route is intentionally public (a shared/obfuscated "
                    "link, a public asset), suppress with "
                    "`# security: allow-unauthenticated-file-download`."
                ),
                rule="unauthenticated-file-download/no-auth-signal",
                standards=list(_STANDARDS),
            ))
        return out
