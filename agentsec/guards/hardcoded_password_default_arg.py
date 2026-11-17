"""Guard: hardcoded password as a function's default argument value (checklist §12, new item).

    def connect(host: str, password: str = "admin123") -> Connection:
        ...

A hardcoded default for a `password`/`passwd`/`pwd` parameter means any caller that
omits the argument connects with that literal credential. This is CWE-798 (Use of
Hard-coded Credentials), OWASP:A07 (Identification and Authentication Failures) — and
distinct from the codebase's existing secret-detection guards, which look for secrets
interpolated into env-var reads or LLM prompts, not literal values sitting in a
function's own signature.

Fires HIGH when a `def` line's parameter list contains a `password`/`passwd`/`pwd`
parameter defaulting to a **non-empty** string literal. An empty-string default
(`password: str = ""`) does NOT fire — it forces the caller to supply a value rather
than silently falling back to a real credential.

Suppress an audited case (e.g. a test fixture or local-dev-only default) with:

    def connect(password: str = "test-only"):  # security: allow-hardcoded-password-default
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

_DEF_LINE = re.compile(r"\bdef\s+\w+\s*\(")
_PASSWORD_DEFAULT = re.compile(
    r"\b(?:password|passwd|pwd)\s*(?::\s*[\w.\[\],| ]+)?\s*=\s*['\"]([^'\"]*)['\"]",
    re.IGNORECASE,
)
_PRAGMA = re.compile(r"#\s*security:\s*allow-hardcoded-password-default")

_STANDARDS = ["OWASP:A07", "CWE-798"]


class HardcodedPasswordDefaultArgGuard(Guard):
    id = "hardcoded-password-default-arg"
    title = "Hardcoded password used as a function's default argument value"
    area = "Secrets"

    # db_helper.py: a def with a password default arg -> fires
    # hardcoded-password-default-arg/non-empty-literal (HIGH).
    canary_plant = CanaryPlant(
        files={
            "db_helper.py": (
                "def get_db_connection(host: str, password: str = \"admin123\") -> object:\n"
                "    return connect(host=host, password=password)\n"
            ),
        },
        expects=frozenset({
            "hardcoded-password-default-arg/non-empty-literal",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features

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
        raw = read(f)
        text = strip_python_strings(raw, filename=f)
        # The pragma counts only as a real comment on the line, never quoted in a string
        # there (#1040), numbered on the text walked below (a form feed in a docstring
        # shifts the raw count, #1132).
        pragmas = pragma_line_set(_PRAGMA, text, dialect="python")
        for i, line in enumerate(text.splitlines(), start=1):
            if i in pragmas or not _DEF_LINE.search(line):
                continue
            m = _PASSWORD_DEFAULT.search(line)
            if m and m.group(1):  # non-empty literal default
                out.append(self._finding(root, f, i))
        return out

    def _finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=(
                "A password/passwd/pwd parameter defaults to a hardcoded, non-empty "
                "string literal. Any caller that omits the argument silently "
                "connects with that credential."
            ),
            remediation=(
                "Remove the hardcoded default — require the caller to supply the "
                "password explicitly, or default to an empty string / None and "
                "raise if it's missing."
            ),
            rule="hardcoded-password-default-arg/non-empty-literal",
            standards=list(_STANDARDS),
        )
