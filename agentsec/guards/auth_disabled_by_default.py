"""Guard: authentication explicitly disabled by a hardcoded default (CWE-1188).

    AUTH_ENABLED = False
    AUTH_TOKEN = None

A module-level constant that toggles authentication on/off, hardcoded to the DISABLED
value, means the application ships unauthenticated unless an operator remembers to
override it at deploy time — the opposite of fail-safe. This is the exact configuration
shape exploited by CVE-2026-44338 (PraisonAI): the legacy Flask server shipped
`AUTH_ENABLED = False` and `AUTH_TOKEN = None` hard-coded as defaults, leaving `/agents`
and `/chat` endpoints unauthenticated when deployed without an explicit override. Sysdig's
wave-analysis found internet-exposed instances scanned within 3 hours 44 minutes of
disclosure. The pattern generalizes beyond PraisonAI to any agent/API framework that takes
the same shortcut.

Fires HIGH when one of a curated set of auth-toggle constant names — `AUTH_ENABLED`,
`AUTHENTICATION_ENABLED`, `REQUIRE_AUTH`, `ENABLE_AUTH`, `AUTH_REQUIRED`, `AUTH_GATE` — is
assigned a literal disabling value: `False`, `0`, or `None`, as a genuine module-level
constant: the name must be the first thing on its own unindented line. A dynamic default read
from an environment variable (`AUTH_ENABLED = os.getenv("AUTH_ENABLED", "true") == "true"`)
does NOT fire — only a bare literal does, since that is the case where NO deploy-time override
is even possible without editing source. A function-parameter default
(`def create_app(AUTH_ENABLED=False):`) or a call-site keyword argument
(`configure(AUTH_ENABLED=False)`) does NOT fire either — both are a different shape than a
module-level constant (nothing precedes the name on a real module-level line, so the match
starts at column 0; a `def foo(`/`callee(` prefix pushes it later).

Suppress an audited case (e.g. a local-only dev entrypoint, never deployed) with:

    AUTH_ENABLED = False  # security: allow-auth-disabled-by-default
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
    pragma_line_set,
    python_scan_dirs,
    read,
    rel,
    strip_python_line_comment,
    strip_python_strings,
)

# A curated set of auth-toggle constant names. `\b` on both sides means a longer/prefixed
# identifier (`REQUIRE_AUTH_HEADER`, `MY_AUTH_GATE`) does NOT match — underscore counts as a
# word character, so the boundary naturally rejects both prefix and suffix bleed.
_AUTH_TOGGLE_DISABLED = re.compile(
    r"\b(?:AUTH_ENABLED|AUTHENTICATION_ENABLED|REQUIRE_AUTH|ENABLE_AUTH|AUTH_REQUIRED|AUTH_GATE)\b"
    r"\s*=\s*(?:False|0|None)\b",
    re.IGNORECASE,
)

_PRAGMA = re.compile(r"#\s*security:\s*allow-auth-disabled-by-default")

_STANDARDS = ["OWASP:A07", "CWE-1188"]


class AuthDisabledByDefaultGuard(Guard):
    id = "auth-disabled-by-default"
    title = "Authentication explicitly disabled by a hardcoded default"
    area = "Login & access"

    # auth_disabled_default.py: AUTH_ENABLED = False hardcoded default -> fires
    # auth-disabled-by-default/auth-toggle-literal-false (HIGH, CVE-2026-44338 PraisonAI).
    # Must NOT contain: allow-auth-disabled-by-default pragma.
    canary_plant = CanaryPlant(
        files={
            "auth_disabled_default.py": "AUTH_ENABLED = False\n",
        },
        expects=frozenset({
            "auth-disabled-by-default/auth-toggle-literal-false",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True  # a module-level auth-toggle default is generic Python config, not framework-gated

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
        out: list[Finding] = []
        raw = read(f)
        text = strip_python_strings(raw, filename=f)  # blank triple-quoted docstring/template content
        # The pragma counts only as a real comment on the flagged line, never quoted in a string
        # there (#1040), numbered on the text walked below (a form feed in a docstring
        # shifts the raw count, #1132).
        pragmas = pragma_line_set(_PRAGMA, text, dialect="python")
        for i, raw_line in enumerate(text.splitlines(), start=1):
            code = strip_python_line_comment(raw_line)  # drop a trailing/whole-line `#` comment
            m = _AUTH_TOGGLE_DISABLED.search(code)
            if not m:
                continue
            # A genuine module-level constant is the FIRST thing on its (unindented) line — a
            # function-parameter default (`def f(AUTH_ENABLED=False):`) or a call-site kwarg
            # (`configure(AUTH_ENABLED=False)`) always has something before the name on the same
            # line (the `def foo(` / `callee(` prefix), so `m.start() != 0` there. This also
            # excludes an indented class-body attribute, keeping the scope exactly what every
            # design doc describes (found in review, #530).
            if m.start() != 0:
                continue
            if i in pragmas:
                continue
            out.append(self._finding(root, f, i, m.group(0)))
        return out

    def _finding(self, root: Path, f: Path, line: int, matched: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=(
                f"``{matched}`` is a hardcoded default that ships authentication disabled. "
                "Any deployment that does not explicitly override this constant serves "
                "every endpoint unauthenticated — the opposite of fail-safe. This is the "
                "exact configuration shape exploited by CVE-2026-44338 (PraisonAI), where "
                "internet-exposed instances were scanned within 3 hours 44 minutes of "
                "disclosure."
            ),
            remediation=(
                "Default authentication ON, not off — require an explicit opt-out for "
                "local development instead of an explicit opt-in for production. If a "
                "runtime toggle is genuinely needed, read it from an environment variable "
                "with a SAFE default (`AUTH_ENABLED = os.getenv(\"AUTH_ENABLED\", \"true\") "
                "== \"true\"`), never a bare disabling literal."
            ),
            rule="auth-disabled-by-default/auth-toggle-literal-false",
            standards=list(_STANDARDS),
        )
