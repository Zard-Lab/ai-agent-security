"""Guard: SECRET_KEY assigned a known-weak or placeholder literal value (CWE-1392).

    SECRET_KEY = "changeme"
    SECRET_KEY = "django-insecure-abc123xyz"   # django-admin startproject's own default

Django's `SECRET_KEY` (and the equivalent `SECRET_KEY`/`JWT_SECRET_KEY` used by Flask,
FastAPI-adjacent session middleware, and JWT-signing code) backs session cookies, CSRF
tokens, password-reset tokens, and any other value the framework signs. A weak or
copy-pasted-from-a-tutorial literal means an attacker who reads the source (or guesses
the well-known default) can forge every one of those tokens — full session hijack and
CSRF bypass across the app.

This is a DIFFERENT signal from two existing guards that sound adjacent:
  - `hardcoded-password-default-arg` flags a *function's own* `password: str = "..."`
    default parameter — not a module-level config assignment.
  - `build_secret` flags Docker build-arg/env *secret exposure* (a secret NAME leaking
    into an image layer) — not the *value* of a secret being a known-weak literal.

Neither one looks at a `SECRET_KEY = "<value>"` assignment's literal VALUE, which is
exactly what this guard does — ported from drogonsec's `PY-023` rule.

Fires HIGH when a `SECRET_KEY` / `APP_SECRET_KEY` / `JWT_SECRET_KEY` assignment (any
case) is a double- or single-quoted string literal whose value starts with one of a
small deny-list of known-weak/placeholder prefixes: `secret`, `changeme`, `development`,
`test`, `default`, `django-insecure` (the literal prefix `django-admin startproject`
itself generates, e.g. `django-insecure-...50-random-chars...`). A random-looking value
(`SECRET_KEY = "kJ8x!mQ2..."`) does NOT start with any of those words, so it stays silent
— the deny-list is deliberately an exact-prefix match, not a broad entropy heuristic, to
keep false positives near zero.

A commented-out mention (`# SECRET_KEY should not be "changeme"`) does not fire either —
only a real assignment statement is matched (comments are stripped per line before the
value pattern is applied).

Suppress an audited case (e.g. a local-only dev settings file) with:

    SECRET_KEY = "django-insecure-local-dev-only"  # security: allow-weak-secret-key
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

# Known-weak/placeholder literal prefixes, ported verbatim from drogonsec's PY-023 deny-list.
# `django-insecure` is Django's OWN `django-admin startproject` default prefix — developers
# routinely ship it unchanged past local dev.
_WEAK_PREFIXES = r"secret|changeme|development|test|default|django-insecure"

# `SECRET_KEY` / `APP_SECRET_KEY` / `JWT_SECRET_KEY` (any case) assigned a quoted string
# literal that STARTS WITH a known-weak prefix. The `\b` + optional `APP_`/`JWT_` prefix
# means a longer identifier like `MY_SECRET_KEY` or `SECRET_KEYSTORE` does not match — this
# is a tight deny-list on the variable name, not a bare "KEY" substring match.
_WEAK_SECRET_KEY = re.compile(
    r"\b(?:APP_|JWT_)?SECRET_KEY\s*=\s*(['\"])(?:" + _WEAK_PREFIXES + r")",
    re.IGNORECASE,
)

_PRAGMA = re.compile(r"#\s*security:\s*allow-weak-secret-key")

_STANDARDS = ["OWASP:A02", "CWE-1392"]


class WeakSecretKeyLiteralGuard(Guard):
    id = "weak-secret-key-literal"
    title = "SECRET_KEY set to a known-weak or default literal value"
    area = "Secrets"

    # weak_secret.py: Django-style SECRET_KEY set to a known-weak literal ->
    # fires weak-secret-key-literal. Must NOT contain: allow-weak-secret-key pragma.
    # weak_secret.py: SECRET_KEY = "django-insecure-..." -> fires known-weak-literal.
    canary_plant = CanaryPlant(
        files={
            "weak_secret.py": 'SECRET_KEY = "django-insecure-canary-placeholder-value"\n',
        },
        expects=frozenset({
            "weak-secret-key-literal/known-weak-literal",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True  # a module-level SECRET_KEY assignment is generic Python config, not framework-gated

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                # A secret in a DEPLOYMENT tree (`alembic/`, `migrations/`) is a REAL committed
                # credential — `alembic/env.py` routinely holds the database URL — unlike the
                # deliberately-fake ones in `tests/`/`fixtures/`. `credential_scan` keeps the former
                # in scope while still skipping the latter (#483 review).
                if is_nonproduct_path(rel(root, f), profile.archive_segments, credential_scan=True):
                    continue
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = strip_python_strings(read(f), filename=f)  # blank triple-quoted docstring/template content
        # The pragma counts only as a real comment on the line, never quoted in a string there (#1040),
        # numbered on the text walked below (a form feed in a docstring shifts the raw count, #1132).
        pragmas = pragma_line_set(_PRAGMA, text, dialect="python")
        for i, raw_line in enumerate(text.splitlines(), start=1):
            code = strip_python_line_comment(raw_line)  # drop a trailing/whole-line `#` comment
            if not code.strip() or not _WEAK_SECRET_KEY.search(code):
                continue
            if i in pragmas:
                continue
            out.append(self._finding(root, f, i))
        return out

    def _finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=(
                "SECRET_KEY is assigned a known-weak or placeholder literal value. This key "
                "backs session cookies, CSRF tokens, and any other value the framework signs "
                "or encrypts — a weak or well-known literal lets an attacker who reads the "
                "source (or simply guesses the common default) forge sessions and bypass CSRF "
                "protection across the whole application."
            ),
            remediation=(
                'Generate a strong random secret: python -c "import secrets; '
                'print(secrets.token_hex(50))" — then load it from an environment variable or '
                "secrets manager, never a literal in source."
            ),
            rule="weak-secret-key-literal/known-weak-literal",
            standards=list(_STANDARDS),
        )
