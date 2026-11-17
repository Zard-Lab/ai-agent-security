"""Guard: FastAPI interactive docs exposed in production (checklist §6a).

FastAPI enables /docs (Swagger UI) and /redoc by default on every app instance.
In production these expose the full API schema and an interactive "try it out"
console to anyone with the URL. The fix is to pass docs_url=None and
redoc_url=None (or set them only when DEBUG/dev mode is active).

Fires MEDIUM when a FastAPI() constructor has no docs_url= setting at all,
and is not inside a conditional env guard. Suppress an intentional docs
exposure with the inline pragma:

    app = FastAPI()  # security: allow-api-docs
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
    strip_python_strings,
)

_FASTAPI_CALL = re.compile(r"\bFastAPI\s*\(")
_DOCS_URL_SET = re.compile(r"\bdocs_url\s*=")
# An env-conditional guarding the constructor. Matches the bare env keyword AND the common
# `is_production` / `is_prod` / `is_dev` predicate idiom — `\bproduction\b` alone misses
# `is_production` (the `_` before `p` is a word char, so there's no boundary).
_ENV_GUARD = re.compile(
    r"\bif\b.+(?:"
    r"\b(?:DEBUG|PROD|PRODUCTION|ENV|ENVIRONMENT|TESTING|STAGING|DEV)\b"
    r"|\bis_(?:prod|production|dev|development|test|testing|staging|local)\b"
    r")",
    re.I,
)
_PRAGMA = re.compile(r"#\s*security:\s*allow-api-docs")

_WINDOW = 15   # lines after FastAPI( to look for docs_url=
_CONTEXT = 5   # lines before FastAPI( to look for env guard


class ApiDocsExposedGuard(Guard):
    id = "api-docs-exposed"
    title = "FastAPI docs exposed in production"
    area = "Web setup"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted across the canary's seven shared plant
    # files (`app.py`, `debug_endpoints.py`, `error_handler.py`, `error_handler_json.py`, `session_app.py`,
    # `static_mount.py`, `webhooks_github.py`), each of which more than one guard trips at once, so those
    # files stay in `canary.py`'s base owned by no guard. The ownership rule this follows is documented on
    # `xxe_safe.py`.
    canary_plant = CanaryPlant(expects=frozenset({"api-docs-exposed/unconditional-docs-route"}))

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
                    continue  # a test/example app isn't a production docs exposure
                # Blank triple-quoted docstring CONTENT so a constructor EXAMPLE in a docstring
                # doesn't self-match (issue #424).
                raw = read(f)
                text = strip_python_strings(raw, filename=f)
                if not _FASTAPI_CALL.search(text):
                    continue
                lines = text.splitlines()
                # The pragma counts only as a real comment on the constructor's line, never quoted
                # in a string there (#1040), numbered on the text walked below (a form feed in a
                # docstring shifts the raw count, #1132).
                pragmas = pragma_line_set(_PRAGMA, text, dialect="python")
                for i, line in enumerate(lines):
                    if not _FASTAPI_CALL.search(line):
                        continue
                    # Skip a `#`-commented-out constructor line and an inline pragma (#424).
                    if line.lstrip().startswith("#") or i + 1 in pragmas:
                        continue
                    # Look at the preceding lines for an env guard.
                    pre = lines[max(0, i - _CONTEXT) : i]
                    if any(_ENV_GUARD.search(pl) for pl in pre):
                        continue
                    # Look at the constructor window for docs_url= setting.
                    window = lines[i : i + _WINDOW]
                    window_text = "\n".join(window)
                    if _DOCS_URL_SET.search(window_text):
                        continue
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="medium",
                            title="FastAPI interactive docs enabled unconditionally",
                            location=f"{rel(root, f)}:{i + 1}",
                            message=(
                                "FastAPI() at this location has no docs_url= setting. "
                                "The default /docs and /redoc routes expose the full API schema "
                                "and a live 'try it out' console to anyone in production."
                            ),
                            remediation=(
                                "Add docs_url=None, redoc_url=None to disable in production. "
                                "Or guard the constructor: "
                                "`FastAPI(docs_url=None if not DEBUG else '/docs')`. "
                                "If exposure is intentional suppress with `# security: allow-api-docs`."
                            ),
                            rule="api-docs-exposed/unconditional-docs-route",
                            standards=["OWASP:A05"],
                        )
                    )
        return out
