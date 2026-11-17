"""Guard: refresh tokens stored without hashing (checklist §7 — Database Security).

A refresh token is a long-lived credential: if an attacker reads the tokens table
(via SQL injection, a leaked backup, or a misconfigured RLS policy) they can
impersonate any user whose token they obtain. Storing the raw random string gives
the attacker an immediately usable credential; storing a hash means the attacker
must invert it first — infeasible for a 32-byte `secrets.token_urlsafe` value.

This is the server-side analogue of password hashing: you hand the raw token to the
client (over TLS), and only ever persist the hash.

The guard detects one class of mistake:

  **`token-stored-unhashed`** (HIGH): A Python token-generation line
  (`secrets.token_urlsafe(`, `secrets.token_hex(`, or `uuid.uuid4()`) is assigned
  to a variable named *refresh*, *token*, or *refresh_token*, and within the next 10
  lines a DB write call (`db.add(`, `session.add(`, `.create(`, `crud.create`, or
  `db.execute(`) appears WITHOUT an intervening hashing call (`hashlib.`, `bcrypt.`,
  `argon2.`, or `.hash(`). The DB write line is flagged, not the generation line.

**Why HIGH?** A stolen plaintext refresh token is an immediately usable long-lived
credential — no cracking required. An attacker who reads the tokens table owns every
active session.

**False-negative scope:** Only detects direct same-scope patterns where generation
and DB write are within 10 lines. Cross-function or cross-module token flows (generate
in one function, persist in another) are not caught — they require interprocedural
dataflow analysis beyond this guard's scope.

**Checklist item:** `7-refresh-tokens-hashed` (OWASP:A02, CWE-257).

**Suppress:** add `# security: allow-refresh-token-plaintext` anywhere in the file.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    iter_files,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    strip_python_strings,
)

_PRAGMA = "security: allow-refresh-token-plaintext"

_STANDARDS = ["OWASP:A02", "CWE-257"]

# Token generation assigned to a refresh/token variable
_TOKEN_GEN = re.compile(
    r"\b(?:refresh_token|refresh|token)\b\s*=\s*"
    r"(?:secrets\.token_urlsafe\s*\(|secrets\.token_hex\s*\(|uuid\.uuid4\s*\()",
    re.IGNORECASE,
)

# DB write calls (the line we flag)
_DB_WRITE = re.compile(
    r"""(?:db\.add\s*\(|session\.add\s*\(|\.create\s*\(|crud\.create\b|db\.execute\s*\()""",
)

# Any hashing call — presence between token gen and DB write means safe
_HASH_CALL = re.compile(
    r"""(?:hashlib\.|bcrypt\.|argon2\.|\.hash\s*\()""",
)

# Lines to skip as scanning windows (10 lines look-ahead)
_WINDOW = 10


class RefreshTokenPlaintextGuard(Guard):
    id = "refresh-token-plaintext"
    title = "Refresh token written to database without hashing"
    area = "Database"

    # token_service.py: refresh_token = secrets.token_urlsafe(...) then db.add(...)
    # without hashing -> fires refresh-token-plaintext.
    canary_plant = CanaryPlant(
        files={
            "token_service.py": (  # nosec B105
                "import secrets\n"
                "from dataclasses import dataclass\n"
                "\n"
                "\n"
                "@dataclass\n"
                "class RefreshToken:\n"
                "    user_id: str\n"
                "    token: str\n"
                "\n"
                "\n"
                "def create_refresh_token(user_id: str) -> str:\n"
                "    refresh_token = secrets.token_urlsafe(32)\n"
                "    db.add(RefreshToken(user_id=user_id, token=refresh_token))\n"
                "    return refresh_token\n"
            ),
        },
        expects=frozenset({"refresh-token-plaintext/token-stored-unhashed"}),
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
                text = read(f)
                if pragma_present(_PRAGMA, text, dialect="python"):
                    continue
                out.extend(self._scan(root, f, text))
        return out

    def _scan(self, root: Path, f: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        # Blank triple-quoted docstring/template CONTENT so a multi-line token-gen + DB-write
        # EXAMPLE in a docstring doesn't fire within the look-ahead window (issue #424). Real
        # generation/write lines are single-line code, unaffected.
        lines = strip_python_strings(text, filename=f).splitlines()
        n = len(lines)
        for i, line in enumerate(lines):
            if not _TOKEN_GEN.search(line):
                continue
            # Scan the next _WINDOW lines for a DB write without an intervening hash
            window_end = min(i + 1 + _WINDOW, n)
            hash_seen = False
            for j in range(i + 1, window_end):
                candidate = lines[j]
                if _HASH_CALL.search(candidate):
                    hash_seen = True
                if _DB_WRITE.search(candidate):
                    if hash_seen:
                        break  # hash appeared before the write — safe
                    out.append(Finding(
                        check_id=self.id,
                        severity="high",
                        title="Refresh token written to database without hashing",
                        location=f"{rel(root, f)}:{j + 1}",
                        message=(
                            "A refresh token generated with `secrets.token_urlsafe`/`token_hex`/"
                            "`uuid4` is persisted to the database as a plaintext string. If the "
                            "tokens table is leaked (SQL injection, backup exposure, misconfigured "
                            "RLS), every token becomes an immediately usable long-lived credential "
                            "with no cracking required."
                        ),
                        remediation=(
                            "Hash the token before storing it: "
                            "`hashed = hashlib.sha256(raw.encode()).hexdigest()` "
                            "(or bcrypt/argon2 if you need constant-time compare). "
                            "Return the raw token to the client over TLS; store and compare "
                            "only the hash. "
                            "Suppress an audited-safe case with "
                            "`# security: allow-refresh-token-plaintext`."
                        ),
                        rule="refresh-token-plaintext/token-stored-unhashed",
                        standards=list(_STANDARDS),
                    ))
                    break  # one finding per token-gen line
        return out
