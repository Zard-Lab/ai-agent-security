"""Guard: no weak / broken cryptography in application code (checklist §8).

Three high-signal, low-FP crypto failures, all OWASP:A02 (Cryptographic
Failures), each detectable from a single line:

  * **insecure hash for security** — `hashlib.md5(...)` / `hashlib.sha1(...)`
    (or `hashlib.new("md5"|"sha1")`) used without the explicit
    `usedforsecurity=False` opt-out. MD5/SHA-1 are collision-broken; signing,
    token derivation, or integrity checks built on them are forgeable. A
    non-security use (e.g. a cache key) must say so: `usedforsecurity=False`.
  * **ECB mode** — `MODE_ECB` leaks plaintext structure (identical blocks
    encrypt identically); never use it. Prefer AES-GCM / an AEAD mode.
  * **insecure randomness for a secret** — a security-named value
    (`token`, `secret`, `password`, `api_key`, `private_key`, `nonce`, `salt`,
    `otp`, `session_id`, `csrf_token`) assigned from the `random` module, which
    is a predictable PRNG. Use `secrets` / `os.urandom`.
  * **weak RSA/DSA key size** — a generated public key below 2048 bits is
    breakable with realistic compute (CodeQL `py/weak-crypto-key`'s threshold).
    Detected on pycryptodome's `RSA.generate(<bits>)` / `DSA.generate(<bits>)`
    (positional bit count) and the `cryptography` library's
    `generate_private_key(..., key_size=<bits>, ...)` keyword form.

Fires HIGH. A static, audited case is suppressed with a `# security: allow-weak-crypto` comment
on the flagged line (for a multi-line `generate_private_key(` call, on any line the call spans).
The comment must be a real one: the phrase quoted in a string does not count (#1040).
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
    pragma_line_set,
    python_scan_dirs,
    read,
    rel,
    split_call_args,
)

# hashlib.md5( / hashlib.sha1( / hashlib.new("md5"|'sha1')
_HASH_DIRECT = re.compile(r"\bhashlib\.(?:md5|sha1)\s*\(")
_HASH_NEW = re.compile(r"\bhashlib\.new\s*\(\s*['\"](?:md5|sha1)['\"]")
_USEDFORSECURITY_FALSE = re.compile(r"usedforsecurity\s*=\s*False")
_ECB = re.compile(r"\bMODE_ECB\b")
# a security-named lvalue assigned from a random.<weak-call>
_INSECURE_RANDOM = re.compile(
    r"\b(?:token|secret|password|passwd|api_key|apikey|private_key|nonce|salt|"
    r"otp|session_id|csrf_token)\w*\s*=\s*[^=].*"
    r"\brandom\.(?:random|randint|randrange|choice|choices|getrandbits|"
    r"uniform|sample|shuffle)\b",
    re.IGNORECASE,
)
_PRAGMA = re.compile(r"#\s*security:\s*allow-weak-crypto")

_MIN_SECURE_KEY_SIZE = 2048
# pycryptodome: RSA.generate(1024) / DSA.generate(1024) — positional bit count.
_PYCRYPTODOME_GENERATE = re.compile(r"\b(RSA|DSA)\s*\.\s*generate\s*\(\s*(\d+)")
# cryptography: generate_private_key(public_exponent=65537, key_size=1024, ...). Scoped to the
# call name itself (not a bare `key_size=` anywhere) to avoid matching an unrelated kwarg that
# happens to share the name. The call's balanced argument text is extracted via
# `split_call_args` (not a `[^)]*` scan) so a NESTED call earlier in the arg list — e.g.
# `backend=default_backend()` — can't prematurely close the scan at its own `)` and hide a
# `key_size=` that comes after it (review #395 M finding: a kwarg-order-sensitive false negative).
_GENERATE_PRIVATE_KEY_CALL = re.compile(r"\bgenerate_private_key\s*\(")
_KEY_SIZE_KW = re.compile(r"\bkey_size\s*=\s*(\d+)")


class WeakCryptoGuard(Guard):
    id = "weak-crypto"
    title = "No weak / broken cryptography"
    area = "Crypto & TLS"

    # hashlib.md5 for a digest, no usedforsecurity=False -> weak-crypto.
    # RSA.generate(1024) -> weak-crypto/weak-key-size.
    canary_plant = CanaryPlant(
        files={
            "crypto.py": ("import hashlib\n\n\ndef digest(data: bytes) -> str:\n    return hashlib.md5(data).hexdigest()\n"),
            "keygen.py": "from Crypto.PublicKey import RSA\n\nkey = RSA.generate(1024)\n",
        },
        expects=frozenset({
            "weak-crypto/insecure-hash",
            "weak-crypto/weak-key-size",
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
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        # Both scans honour the pragma only as a real comment, never quoted in a string (#1040).
        pragmas = pragma_line_set(_PRAGMA, text, dialect="python")
        for i, line in enumerate(text.splitlines(), start=1):
            if line.lstrip().startswith("#") or i in pragmas:
                continue
            if (_HASH_DIRECT.search(line) or _HASH_NEW.search(line)) and not _USEDFORSECURITY_FALSE.search(line):
                out.append(self._finding(
                    root, f, i, "insecure-hash",
                    "Broken hash (MD5/SHA-1) used without `usedforsecurity=False`",
                    "MD5 and SHA-1 are collision-broken — any security use (signatures, token "
                    "derivation, integrity checks) is forgeable.",
                    # Remediation order matters (#471 review): leading with `usedforsecurity=False`
                    # reads as "the fix is to add this flag", when the flag only DECLARES that the
                    # hash was never security-relevant. Replacing the algorithm is the fix; the flag
                    # is the annotation for the case where there was nothing to fix.
                    "Replace MD5/SHA-1 with SHA-256 or better (`hashlib.sha256`) for any security "
                    "use — signatures, token derivation, integrity checks. ONLY if this hash is "
                    "genuinely not security-relevant (content deduplication, cache key, ETag, "
                    "file-idempotency checksum), say so explicitly with "
                    "`hashlib.md5(data, usedforsecurity=False)`, which also silences this finding.",
                ))
                continue
            if _ECB.search(line):
                out.append(self._finding(
                    root, f, i, "ecb-mode",
                    "ECB cipher mode leaks plaintext structure",
                    "ECB encrypts identical plaintext blocks to identical ciphertext, leaking "
                    "structure (the classic 'ECB penguin').",
                    "Use an authenticated mode — AES-GCM (`MODE_GCM`) or ChaCha20-Poly1305 — "
                    "with a unique nonce per message.",
                ))
                continue
            if _INSECURE_RANDOM.search(line):
                out.append(self._finding(
                    root, f, i, "insecure-random-secret",
                    "Secret value derived from the predictable `random` module",
                    "The `random` module is a deterministic PRNG seeded from the clock — its "
                    "output is predictable, so a token/key/nonce built from it is guessable.",
                    "Use the `secrets` module (`secrets.token_urlsafe`, `secrets.token_hex`) or "
                    "`os.urandom` for anything security-sensitive.",
                ))
                continue
            m = _PYCRYPTODOME_GENERATE.search(line)
            if m and int(m.group(2)) < _MIN_SECURE_KEY_SIZE:
                out.append(self._finding(
                    root, f, i, "weak-key-size",
                    f"{m.group(1)} key generated at {m.group(2)} bits, below the "
                    f"{_MIN_SECURE_KEY_SIZE}-bit minimum",
                    f"A {m.group(1)} key below {_MIN_SECURE_KEY_SIZE} bits is breakable with "
                    "realistic compute — factoring/discrete-log attacks against small keys are "
                    "practical today.",
                    f"Generate at {_MIN_SECURE_KEY_SIZE} bits or larger: "
                    f"{m.group(1)}.generate({_MIN_SECURE_KEY_SIZE}).",
                ))
        out.extend(self._scan_cryptography_generate(root, f, text, pragmas))
        return out

    def _scan_cryptography_generate(
        self, root: Path, f: Path, text: str, pragmas: frozenset[int]
    ) -> list[Finding]:
        out: list[Finding] = []
        lines = text.splitlines()
        for m in _GENERATE_PRIVATE_KEY_CALL.finditer(text):
            lineno = text.count("\n", 0, m.start()) + 1
            line_text = lines[lineno - 1] if lineno - 1 < len(lines) else ""
            if line_text.lstrip().startswith("#"):
                continue
            open_idx = m.end() - 1
            args = split_call_args(text, open_idx, python=True)
            if not args:
                continue
            joined = ",".join(args)
            # The pragma may sit on ANY line the (possibly multi-line) call spans — e.g. on the
            # `key_size=1024,` line, not the `generate_private_key(` line (review #395 M). The span
            # is 1-indexed `lineno..end_line` inclusive, and no further: a pragma on the following
            # unrelated line must not reach it (#395 RC-1).
            end_line = lineno + joined.count("\n")
            if any(n in pragmas for n in range(lineno, end_line + 1)):
                continue
            km = _KEY_SIZE_KW.search(joined)
            if not km:
                continue
            bits = int(km.group(1))
            if bits >= _MIN_SECURE_KEY_SIZE:
                continue
            out.append(self._finding(
                root, f, lineno, "weak-key-size",
                f"Key generated at {bits} bits, below the {_MIN_SECURE_KEY_SIZE}-bit minimum",
                f"A key below {_MIN_SECURE_KEY_SIZE} bits is breakable with realistic "
                "compute — factoring/discrete-log attacks against small keys are practical "
                "today.",
                f"Generate at key_size={_MIN_SECURE_KEY_SIZE} or larger.",
            ))
        return out

    def _finding(
        self, root: Path, f: Path, line: int, rule: str, title: str, message: str, remediation: str
    ) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=title,
            location=f"{rel(root, f)}:{line}",
            message=message,
            remediation=remediation + " If audited-safe, suppress with `# security: allow-weak-crypto`.",
            rule=f"weak-crypto/{rule}",
            standards=["OWASP:A02"],
        )
