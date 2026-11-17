"""Guard: secrets written to cleartext sinks — cookies and plaintext files (checklist §8).

CodeQL's `py/clear-text-storage-sensitive-data` flags a sensitive value flowing into
any persistent, unencrypted sink. This guard approximates two common, same-file cases:

  **`cookie-value`** (HIGH): `set_cookie(<name>, <value>)` where `<value>` is a bare
  identifier whose name looks like a raw secret (password/passwd/secret/private_key/
  credential — NOT `token`/`session_id`/`api_key`, which are legitimately designed as
  opaque bearer values stored client-side; `set_cookie("token", raw_token)` is the
  correct pattern for a session token and must stay silent). A password or private key
  written into a cookie value has no business being there at all, regardless of the
  cookie's other flags — this is a different failure than `insecure-cookies` (missing
  HttpOnly/Secure), which is about protecting a value that's legitimately in a cookie.

  **`plaintext-file-write`** (HIGH): `<file>.write(<value>)` or
  `<file>.write_text(<value>)` where `<value>` is the same kind of bare sensitive
  identifier — persisting a password/secret/private key to disk unencrypted.

Both checks require the value argument to be a **bare identifier**, not a nested call —
this is deliberate: `f.write(hash_password(password))` or
`f.write(encrypt(secret_key))` do not match, since the guard cannot tell what a nested
call does, and treating every such case as unsafe would be far too noisy. The trade is
recall for precision, the same trade `weak-crypto`'s `_INSECURE_RANDOM` check makes.

Identifier matching is name-based (contains the marker word as a whole word), and
explicitly excludes names that look already-protected (`hash`, `encrypt`, `digest`,
`cipher`, `bcrypt`, `argon`, `pbkdf`, `redact`, `mask`, `scrypt`) — `hashed_password`,
`password_hash`, and `encrypted_secret` are silent by design, while `raw_password`,
`user_password`, and `client_secret` fire.

Checklist item: `8-secrets-not-stored-cleartext` (new item → covered by this guard).

Suppress: `# security: allow-cleartext-secret-storage` anywhere in a file silences
this guard for that file.
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

_PRAGMA = "security: allow-cleartext-secret-storage"
_STANDARDS = ["OWASP:A02", "CWE-312"]

# Substring match so common naming conventions ("raw_password"/"user_password"/"client_secret")
# all match, not just the bare word — but RIGHT-boundaried (`(?![a-z])`, case-off, optional
# plural `s`) so a stem can't bleed into an unrelated word whose continuation is lowercase:
# `secret`⊄`secretary` (review #395 M). A camelCase/underscore PREFIX before the stem is still
# fine (`clientSecret`, `client_secret`). The _PROTECTED_NAME_HINT / _NONSECRET_SUFFIX checks
# below keep it precise.
_SENSITIVE_NAME = re.compile(
    r"(?:password|passwd|secret|private_key|credential)s?(?-i:(?![a-z]))", re.IGNORECASE
)
# Names that look already-protected — excluded even if they also match _SENSITIVE_NAME.
_PROTECTED_NAME_HINT = re.compile(
    r"hash|encrypt|digest|cipher|bcrypt|argon2?|pbkdf2?|redact|mask|scrypt", re.IGNORECASE
)
# A trailing metadata suffix means the name describes something ABOUT a secret (its id, expiry,
# length, timestamp), not the secret VALUE — excluded even with a sensitive stem (review #395 M:
# `client_secret_expiry_days` is an int, not a secret).
_NONSECRET_SUFFIX = re.compile(
    r"_(?:id|ids|days?|expiry|expires?|exp|ttl|name|names|count|len|length|size|"
    r"at|on|date|time|timestamp|ts|version|type|status|enabled|url|uri|path)$",
    re.IGNORECASE,
)

# set_cookie("name", <value>) — value must be a bare identifier (second positional arg).
_SET_COOKIE_VALUE = re.compile(r"\bset_cookie\s*\(\s*[\"'][^\"']*[\"']\s*,\s*(\w+)\s*[,)]")
# <file>.write(<value>) / <file>.write_text(<value>) — value must be a bare identifier, AND the
# receiver (captured group 1) must be a bare identifier immediately before the dot. This scopes
# the sink to actual file-like objects: `io.StringIO().write(private_key)` has a `)` (from the
# StringIO() constructor call) immediately before `.write`, not an identifier, so it never
# matches this pattern at all (review #395 M finding — the old sink had no receiver requirement
# and fired on any `.write(...)`, including a plainly in-memory stream write with a misleading
# "filesystem/backup" message).
_FILE_WRITE_VALUE = re.compile(r"\b(\w+)\.write(?:_text)?\s*\(\s*(\w+)\s*\)")
# An identifier assigned from an in-memory stream constructor (`buf = io.StringIO()`) earlier in
# the same file — tracked so a LATER `buf.write(secret)` referencing it by name is also excluded,
# not just the directly-chained `StringIO().write(...)` form.
_STREAM_VAR_ASSIGN = re.compile(r"\b(\w+)\s*=\s*(?:io\.)?(?:StringIO|BytesIO)\s*\(")


def _is_cleartext_secret_name(name: str) -> bool:
    return (
        bool(_SENSITIVE_NAME.search(name))
        and not _PROTECTED_NAME_HINT.search(name)
        and not _NONSECRET_SUFFIX.search(name)
    )


class CleartextSecretStorageGuard(Guard):
    id = "cleartext-secret-storage"
    title = "Secret written to a cleartext sink (cookie or plaintext file)"
    area = "Secrets"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `cleartext_secret.py`, which several guards trip at once, so the file stays in `canary.py`'s base owned
    # by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # cleartext_secret.py plants both rules — cookie-value and plaintext-file-write.
    canary_plant = CanaryPlant(expects=frozenset({
        "cleartext-secret-storage/cookie-value",
        "cleartext-secret-storage/plaintext-file-write",
    }))

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
                r = rel(root, f)
                # A secret in a DEPLOYMENT tree (`alembic/`, `migrations/`) is a REAL committed
                # credential — `alembic/env.py` routinely holds the database URL — unlike the
                # deliberately-fake ones in `tests/`/`fixtures/`. `credential_scan` keeps the former
                # in scope while still skipping the latter (#483 review).
                if is_nonproduct_path(r, profile.archive_segments, credential_scan=True):
                    continue
                text = read(f)
                if pragma_present(_PRAGMA, text, dialect="python"):
                    continue
                out.extend(self._scan(root, f, text))
        return out

    def _scan(self, root: Path, f: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        r = rel(root, f)
        stream_vars = {m.group(1) for m in _STREAM_VAR_ASSIGN.finditer(text)}
        for lineno, line in enumerate(text.splitlines(), start=1):
            if line.lstrip().startswith("#"):
                continue
            m = _SET_COOKIE_VALUE.search(line)
            if m and _is_cleartext_secret_name(m.group(1)):
                out.append(self._finding(
                    r, lineno,
                    "cookie-value",
                    f"Secret-named value '{m.group(1)}' written into a cookie",
                    (
                        f"'{m.group(1)}' looks like a raw password/secret/private key, and it is "
                        "being stored as a cookie value. A cookie is a client-side, browser-"
                        "readable store — a password or private key has no business there under "
                        "any flag configuration."
                    ),
                    (
                        "Do not store raw secrets in cookies at all. If a client-side reference is "
                        "needed, issue an opaque session token (generated with `secrets."
                        "token_urlsafe`) and keep the actual secret server-side."
                    ),
                ))
                continue
            m2 = _FILE_WRITE_VALUE.search(line)
            if m2 and m2.group(1) not in stream_vars and _is_cleartext_secret_name(m2.group(2)):
                out.append(self._finding(
                    r, lineno,
                    "plaintext-file-write",
                    f"Secret-named value '{m2.group(2)}' written to a plaintext file",
                    (
                        f"'{m2.group(2)}' looks like a raw password/secret/private key, written "
                        "directly to a file with no encryption. Anyone with filesystem access "
                        "(a backup, a misconfigured volume mount, another process) reads it in "
                        "clear text."
                    ),
                    (
                        "Never persist a raw secret to a plaintext file. Use a secrets manager "
                        "(Vault, AWS Secrets Manager, or the platform's encrypted env-var store), "
                        "or encrypt at rest with a key that isn't stored alongside the ciphertext."
                    ),
                ))
        return out

    def _finding(
        self, r: str, lineno: int, rule_suffix: str, title: str, message: str, remediation: str
    ) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=title,
            location=f"{r}:{lineno}",
            message=message,
            remediation=remediation + f" Suppress an audited case with `# {_PRAGMA}`.",
            rule=f"cleartext-secret-storage/{rule_suffix}",
            standards=list(_STANDARDS),
        )
