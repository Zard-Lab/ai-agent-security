"""Guard: SessionMiddleware used without any CSRF protection (§6a-csrf-protection).

A FastAPI (or Starlette) application that mounts `SessionMiddleware` gains
cookie-based session support. Once sessions are live, every state-changing
request becomes vulnerable to Cross-Site Request Forgery unless a separate
CSRF defence is also in place — the browser will automatically attach the
session cookie to any cross-origin request a malicious page triggers.

Common CSRF defences in the Python/FastAPI ecosystem:

  - `starlette-csrf` (or equivalent): a middleware that issues and validates a
    per-session CSRF token via the synchronizer-token pattern.
  - `fastapi-csrf-protect`: a library that injects a `CsrfProtect` dependency
    into route handlers.
  - Explicit double-submit cookie patterns (`csrf_token` / `double_submit`).
  - `CSRFMiddleware` from any provider.

This guard fires HIGH when it finds `SessionMiddleware` anywhere in the
scanned Python files but finds no CSRF-protection markers anywhere in those
same files.

**Severity:** HIGH — CSRF lets an attacker trick a logged-in user's browser
into making authenticated state-changing API calls (account changes, transfers,
privilege escalation) without the user's knowledge.

**Standards:** OWASP:A01 (Broken Access Control), CWE-352 (Cross-Site Request
Forgery).

**Express/Node (codeql `js/missing-token-validation`,
`javascript/ql/src/Security/CWE-352/MissingCsrfMiddleware.ql`).** The same repo-wide
presence/absence check applies to `express-session` / `cookie-session`: if either is
required/imported anywhere in the scanned JS/TS files but no CSRF-protection marker
(`csurf`, `lusca`, `tiny-csrf`, `csrf-csync`, `doubleCsrf`) appears anywhere in those same
files, the guard fires. Kept as an independent scan from the Python side — a pure-Express
app has no `starlette_csrf` to find, and cross-stack marker matching would be meaningless.

**Suppress:** add `# security: allow-no-csrf` on any line in any scanned
Python file to silence this check repo-wide. JS/TS files use the equivalent
`// security: allow-no-csrf` line comment. Use only when you have confirmed
that all state-changing endpoints are either stateless (JWT bearer, no
session cookie), protected by SameSite=Strict cookies enforced server-side,
or behind an API-only architecture with no browser clients.
"""
from __future__ import annotations

from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    iter_files,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
)

_PRAGMA = "security: allow-no-csrf"

_STANDARDS = ["OWASP:A01", "CWE-352"]

# Markers that indicate CSRF protection is present somewhere in the codebase.
_CSRF_MARKERS = (
    "CSRFMiddleware",
    "starlette_csrf",
    "fastapi_csrf",
    "CsrfProtect",
    "csrf_token",
    "double_submit",
)

_JS_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")
_JS_PRAGMA_TEXT = "security: allow-no-csrf"
# Markers that indicate express-session / cookie-session is mounted.
_JS_SESSION_MARKERS = ("express-session", "cookie-session")
# Markers that indicate CSRF protection is present somewhere in the JS/TS files.
_JS_CSRF_MARKERS = ("csurf", "lusca", "tiny-csrf", "csrf-csync", "doubleCsrf", "csrfProtection")


class SessionNoCsrfGuard(Guard):
    id = "session-no-csrf"
    title = "SessionMiddleware used without CSRF protection"
    area = "Web setup"

    # express_session.js: express-session with no CSRF protection anywhere in the canary
    # repo -> fires session-no-csrf/session-middleware-without-csrf on the JS branch.
    # Must NOT contain: csurf, lusca, tiny-csrf, csrf-csync, doubleCsrf, csrfProtection,
    # or the allow-no-csrf pragma.
    # session_app.py: SessionMiddleware with no CSRF protection anywhere in the canary
    # repo (no CSRFMiddleware, starlette_csrf, fastapi_csrf, CsrfProtect, csrf_token,
    # or double_submit in any file) -> session-middleware-without-csrf.
    canary_plant = CanaryPlant(
        files={
            "express_session.js": (
                "const session = require('express-session');\n"
                "\n"
                "app.use(session({ secret: 'changeme', resave: false, saveUninitialized: false }));\n"
            ),
        },
        expects=frozenset({"session-no-csrf/session-middleware-without-csrf"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return (
            "fastapi" in profile.features
            or "python" in profile.features
            or "express" in profile.features
        )

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        if not self.applies(profile):
            return []

        out: list[Finding] = []
        if "fastapi" in profile.features or "python" in profile.features:
            out.extend(self._run_python(root, profile))
        if "express" in profile.features:
            out.extend(self._run_js(root))
        return out

    def _run_python(self, root: Path, profile: StackProfile) -> list[Finding]:
        # Collect all Python files from scan dirs, deduplicated.
        files: list[tuple[Path, str]] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                files.append((f, read(f)))

        # Repo-wide pragma check: any file with the allow pragma silences the guard.
        for f, text in files:
            if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                return []

        # Step 1: collect files that contain SessionMiddleware.
        session_files: list[tuple[Path, str]] = [
            (f, text) for f, text in files if "SessionMiddleware" in text
        ]

        # Nothing to check if SessionMiddleware is not used at all.
        if not session_files:
            return []

        # Step 2: check whether any CSRF protection marker exists anywhere in the repo.
        csrf_found = any(
            any(marker in text for marker in _CSRF_MARKERS)
            for _f, text in files
        )

        # Step 3: CSRF absent — emit one finding per file that contains SessionMiddleware.
        if csrf_found:
            return []

        out: list[Finding] = []
        for f, text in session_files:
            # Find the line number of the first SessionMiddleware occurrence for the location.
            lineno = 1
            for i, line in enumerate(text.splitlines(), 1):
                if "SessionMiddleware" in line:
                    lineno = i
                    break
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title="SessionMiddleware active without any CSRF protection",
                    location=f"{rel(root, f)}:{lineno}",
                    message=(
                        "`SessionMiddleware` is mounted but no CSRF defence was found "
                        "anywhere in the codebase (no `CSRFMiddleware`, `starlette_csrf`, "
                        "`fastapi_csrf`, `CsrfProtect`, `csrf_token`, or `double_submit`). "
                        "Cookie-based sessions are vulnerable to Cross-Site Request Forgery: "
                        "a malicious page can trigger authenticated state-changing requests "
                        "on behalf of a logged-in user without their knowledge."
                    ),
                    remediation=(
                        "Add CSRF protection before deploying. Options: "
                        "(1) `pip install starlette-csrf` and mount `CSRFMiddleware` above "
                        "`SessionMiddleware`; "
                        "(2) use `fastapi-csrf-protect` and inject `CsrfProtect` into every "
                        "state-changing route; "
                        "(3) implement the double-submit cookie pattern explicitly. "
                        "If all state-changing endpoints use stateless JWT bearer auth (no "
                        "session cookie), suppress with `# security: allow-no-csrf`."
                    ),
                    rule="session-no-csrf/session-middleware-without-csrf",
                    standards=list(_STANDARDS),
                )
            )
        return out

    def _run_js(self, root: Path) -> list[Finding]:
        files: list[tuple[Path, str]] = []
        for f in iter_files(root, _JS_SUFFIXES):
            files.append((f, read(f)))

        # Repo-wide pragma check: any JS/TS file with the allow pragma silences the JS half.
        for f, text in files:
            if pragma_present(_JS_PRAGMA_TEXT, text, dialect=comment_dialect_for(f)):
                return []

        # Step 1: collect files that require/import express-session or cookie-session.
        session_files: list[tuple[Path, str]] = [
            (f, text) for f, text in files if any(m in text for m in _JS_SESSION_MARKERS)
        ]
        if not session_files:
            return []

        # Step 2: check whether any CSRF protection marker exists anywhere in the JS/TS files.
        csrf_found = any(
            any(marker in text for marker in _JS_CSRF_MARKERS)
            for _f, text in files
        )
        if csrf_found:
            return []

        out: list[Finding] = []
        for f, text in session_files:
            lineno = 1
            for i, line in enumerate(text.splitlines(), 1):
                if any(m in line for m in _JS_SESSION_MARKERS):
                    lineno = i
                    break
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title="Session middleware active without any CSRF protection",
                    location=f"{rel(root, f)}:{lineno}",
                    message=(
                        "`express-session` (or `cookie-session`) is used but no CSRF "
                        "defence was found anywhere in the scanned JS/TS files (no "
                        "`csurf`, `lusca`, `tiny-csrf`, `csrf-csync`, or equivalent). "
                        "Cookie-based sessions are vulnerable to Cross-Site Request Forgery: "
                        "a malicious page can trigger authenticated state-changing requests "
                        "on behalf of a logged-in user without their knowledge."
                    ),
                    remediation=(
                        "Add CSRF protection before deploying. Options: "
                        "(1) `npm install csurf` (or `lusca`/`tiny-csrf`) and mount it as "
                        "middleware ahead of state-changing routes; "
                        "(2) implement the double-submit cookie pattern explicitly. "
                        "If all state-changing endpoints use stateless JWT bearer auth (no "
                        "session cookie), suppress with `// security: allow-no-csrf`."
                    ),
                    rule="session-no-csrf/session-middleware-without-csrf",
                    standards=list(_STANDARDS),
                )
            )
        return out
