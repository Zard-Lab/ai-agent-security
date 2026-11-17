"""Guard: FastAPI app sets no security response headers (checklist §6a).

§6a of the checklist: "Security headers on all responses (HSTS, CSP,
X-Frame-Options, X-Content-Type-Options, Referrer-Policy, ...)". Missing these
leaves clients open to clickjacking (no X-Frame-Options/CSP frame-ancestors),
MIME-sniffing (no X-Content-Type-Options), and protocol downgrade (no HSTS).

Unlike the other guards, this one proves an **absence** — there is no
header-setting code anywhere — which is inherently false-positive-prone because
headers are frequently terminated at a reverse proxy / CDN / load balancer,
entirely outside the repo. The design is therefore deliberately conservative:

  * ANY sign of header-setting anywhere in the scanned Python (a known header
    name, a recognized middleware, the `secure` library) silences the guard.
  * A single repo-level pragma opts out (for "headers are set at the proxy"):
        # security: allow-missing-security-headers
  * The finding is LOW severity — below the default `--fail-on high` CI gate —
    because it is an advisory, not a confirmed vulnerability.

It emits at most ONE finding (header coverage is an app-wide property), anchored
at the FastAPI app definition: the `FastAPI()` instantiation if visible, else
the `from fastapi import` line of the app module.

NOTE: finding severity (low) is intentionally decoupled from the checklist
item's severity (medium = the control's importance). Detection confidence and
control importance are different axes; flagged for curation review.
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
    read,
    rel,
)

_FASTAPI_CALL = re.compile(r"\bFastAPI\s*\(")
_FASTAPI_IMPORT = re.compile(r"\bfrom\s+fastapi\s+import\b")
_PRAGMA = "security: allow-missing-security-headers"
_RULE = "security-headers/no-security-headers-middleware"
_STANDARDS = ["OWASP:A05"]

# Generous evidence of header-setting — ANY hit anywhere silences the guard.
# Covers the six standard header names plus recognized header middlewares/libs.
_HEADER_EVIDENCE = re.compile(
    r"strict-transport-security|content-security-policy|x-frame-options|"
    r"x-content-type-options|referrer-policy|permissions-policy|x-xss-protection|"
    r"SecurityHeadersMiddleware|SecWeb|from\s+secure\b|import\s+secure\b|"
    r"starlette[_-]secure|fastapi[_-]security[_-]headers|ContentSecurityPolicy",
    re.IGNORECASE,
)


class SecurityHeadersGuard(Guard):
    id = "security-headers"
    title = "FastAPI app sets no security response headers"
    area = "Web setup"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `app.py`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # app.py is a FastAPI() app with no security-header middleware (its CORS-wildcard
    # line is the cors-wildcard violation); it carries no header evidence, so this fires.
    canary_plant = CanaryPlant(expects=frozenset({"security-headers/no-security-headers-middleware"}))

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
                files.append((f, read(f)))

        # Conservative / FP-safe: any sign of header-setting, or a repo-level
        # opt-out pragma, silences the guard (headers are often set upstream).
        for _f, text in files:
            if _HEADER_EVIDENCE.search(text) or pragma_present(_PRAGMA, text, dialect="python"):
                return []

        # Absence confirmed — anchor the single finding at the app definition,
        # but only in product files. Library and framework repos expose the constructor
        # in docs or tests only — those shouldn't trigger this guard.
        product_files = [(f, t) for f, t in files if not is_nonproduct_path(rel(root, f), profile.archive_segments)]
        anchor = self._anchor(product_files, _FASTAPI_CALL) or self._anchor(product_files, _FASTAPI_IMPORT)
        if anchor is None:
            return []
        f, lineno = anchor
        return [self._finding(f"{rel(root, f)}:{lineno}")]

    @staticmethod
    def _anchor(files: list[tuple[Path, str]], pat: re.Pattern[str]) -> tuple[Path, int] | None:
        for f, text in files:
            m = pat.search(text)
            if m:
                return f, text[: m.start()].count("\n") + 1
        return None

    def _finding(self, loc: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="low",
            title=self.title,
            location=loc,
            message=(
                "No security-response-headers middleware was found anywhere in this "
                "FastAPI app — responses ship without HSTS, Content-Security-Policy, "
                "X-Frame-Options, X-Content-Type-Options or Referrer-Policy, leaving "
                "clients exposed to clickjacking, MIME-sniffing and protocol downgrade."
            ),
            remediation=(
                "Add a middleware that sets the security headers on every response "
                "(a Starlette BaseHTTPMiddleware, a SecurityHeadersMiddleware, or the "
                "`secure` library). If the headers are terminated at a reverse proxy / "
                "CDN instead, suppress with `# security: allow-missing-security-headers`."
            ),
            rule=_RULE,
            standards=list(_STANDARDS),
        )
