"""Guard: FastAPI app without TrustedHostMiddleware (trusted-host-absent).

A FastAPI application that omits ``TrustedHostMiddleware`` blindly trusts
whatever ``Host`` header the client sends.  ``request.base_url`` and
``request.url_for()`` both reflect the incoming ``Host``, so an attacker can:

  - Poison a shared HTTP cache by injecting an arbitrary hostname in the ``Host``
    header (cache-poisoning attacks surfaced in a wave of CVEs in 2018-2020).
  - Forge password-reset and email-verification links: the server builds the link
    from ``request.base_url``, so the reset URL lands on the attacker's domain.
  - Exploit internal-vhost SSRF: some reverse-proxy setups route requests based on
    ``Host``; an attacker who controls the header can reach internal services.

``TrustedHostMiddleware`` (shipped with Starlette/FastAPI) rejects requests whose
``Host`` is not in an explicit allow-list, closing all three vectors before they
reach any route logic.

This guard fires **MEDIUM** when it detects a FastAPI application initialisation
(the ``app = FastAPI`` assignment pattern) anywhere in the scanned Python files but
finds no file that contains the string ``TrustedHostMiddleware`` — a cross-file
absence check, the same pattern as ``session-no-csrf``.  It emits **one finding**,
anchored to the line of the first app-init occurrence.

**Standards:** OWASP:A05 (Security Misconfiguration), OWASP:ASVS (V14 — config).

**Suppress:** add ``# security: allow-no-trusted-host`` on any line in any scanned
Python file to silence this check repo-wide.  Acceptable when the app sits behind a
reverse proxy or load-balancer that enforces ``Host`` validation before the request
reaches FastAPI, or when all clients are internal services with controlled headers.
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

_PRAGMA = "security: allow-no-trusted-host"

_STANDARDS = ["OWASP:A05"]

# Matches `app = FastAPI` assignment at the start of a statement (with optional
# leading whitespace), covering the most common assignment patterns.
_APP_INIT = re.compile(r"(?:^|\s)app\s*=\s*FastAPI\s*\(")


class TrustedHostAbsentGuard(Guard):
    id = "trusted-host-absent"
    title = "FastAPI app running without TrustedHostMiddleware"
    area = "Web setup"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `app.py`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # app.py defines `app = FastAPI()` with no TrustedHostMiddleware anywhere in
    # the canary repo -> fires no-trusted-host-middleware (MEDIUM).
    canary_plant = CanaryPlant(expects=frozenset({"trusted-host-absent/no-trusted-host-middleware"}))

    def applies(self, profile: StackProfile) -> bool:
        return "fastapi" in profile.features and "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        if not self.applies(profile):
            return []

        # Collect all Python files from scan dirs, deduplicated.
        files: list[tuple[Path, str]] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                files.append((f, read(f)))

        # Repo-wide pragma: any file with the allow pragma silences the guard.
        for _f, text in files:
            if pragma_present(_PRAGMA, text, dialect="python"):
                return []

        # Step 1: find the first file+line that initialises a FastAPI app,
        # restricted to product files. Library/framework repos expose the constructor
        # only in docs or tests — those shouldn't trigger this guard.
        app_init_file: Path | None = None
        app_init_line: int = 1
        for f, text in files:
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            for i, line in enumerate(text.splitlines(), 1):
                if _APP_INIT.search(line):
                    app_init_file = f
                    app_init_line = i
                    break
            if app_init_file is not None:
                break

        # No FastAPI app found — nothing to check.
        if app_init_file is None:
            return []

        # Step 2: check whether TrustedHostMiddleware appears anywhere in the repo.
        trusted_host_found = any("TrustedHostMiddleware" in text for _f, text in files)
        if trusted_host_found:
            return []

        # Step 3: emit one finding anchored to the first app-init location.
        return [
            Finding(
                check_id=self.id,
                severity="medium",
                title="FastAPI app running without TrustedHostMiddleware",
                location=f"{rel(root, app_init_file)}:{app_init_line}",
                message=(
                    "A FastAPI application is initialised here but no Python file in the "
                    "codebase contains `TrustedHostMiddleware`. Without it, FastAPI accepts "
                    "arbitrary `Host` headers from clients. `request.base_url` and "
                    "`request.url_for()` both reflect the incoming `Host`, enabling "
                    "cache-poisoning, password-reset link hijacking, and internal-vhost SSRF."
                ),
                remediation=(
                    "Mount `TrustedHostMiddleware` with an explicit allow-list: "
                    "`from starlette.middleware.trustedhost import TrustedHostMiddleware; "
                    "app.add_middleware(TrustedHostMiddleware, allowed_hosts=[\"yourdomain.com\"])`. "
                    "If a reverse proxy (nginx, Caddy, AWS ALB) enforces `Host` validation "
                    "before the request reaches FastAPI, suppress with "
                    "`# security: allow-no-trusted-host`."
                ),
                rule="trusted-host-absent/no-trusted-host-middleware",
                standards=list(_STANDARDS),
            )
        ]
