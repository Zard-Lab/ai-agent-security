"""Guard: no weak / broken cryptography in JS/TS application code (checklist §8).

The JS/Node + `crypto-js` counterpart to agentsec's existing (Python-only) `weak-crypto` guard —
same requirement (a broken hash/cipher primitive is a forgeable signature or a recoverable
secret), a genuinely different code surface (Node's built-in `crypto` module and the popular
`crypto-js` npm package instead of `hashlib`/`Crypto`), so it extends the same `8-weak-crypto`
checklist item rather than duplicating it.

Mirrors `weak_crypto.py`'s precision philosophy exactly: flag the WEAK ALGORITHM NAME directly,
with NO requirement to prove the hashed/encrypted input is "sensitive" data via dataflow. CodeQL's
actual JS query (`BrokenCryptoAlgorithm.ql`) requires a full dataflow proof that sensitive data
reaches the weak algorithm; this guard deliberately does not attempt that — a simpler, more
conservative, name-based check, the same accepted trade-off `weak_crypto.py` already ships for
Python (see its own module docstring: "no requirement to prove the hashed input is sensitive").

Three distinct rules, one guard (same "several rules under one class" shape as `weak_crypto.py`):

  * **weak hash algorithm** — `crypto.createHash('md5'|'sha1')` (Node built-in) or
    `CryptoJS.MD5(...)` / `CryptoJS.SHA1(...)` (`crypto-js`). MD5/SHA-1 are collision-broken;
    signing, token derivation, or integrity checks built on them are forgeable.
  * **deprecated cipher function** — `crypto.createCipher(...)` / `crypto.createDecipher(...)`.
    Unlike the other two rules this is NOT algorithm-name-specific: the function itself is
    deprecated and insecure by design regardless of its algorithm argument, because it derives
    the key/IV from a password via a weak, non-salted, single-round hash (Node's own docs:
    "use of createCipher() is being deprecated"). ANY use fires, distinct from the modern
    `createCipheriv`/`createDecipheriv` functions below.
  * **weak cipher algorithm** — `crypto.createCipheriv(...)` / `crypto.createDecipheriv(...)`
    (the safe, modern replacement functions) called with a weak algorithm string as the first
    argument — `'des'`, `'des-ede3'`, `'rc4'`, `'rc2'` — or `CryptoJS.DES.encrypt(...)` /
    `CryptoJS.RC4.encrypt(...)`/`.decrypt(...)`.

Fires HIGH (matches `weak_crypto.py`'s severity for the equivalent Python findings). A static,
audited case is suppressed with:

    const digest = crypto.createHash('md5').update(data).digest('hex');  // security: allow-js-weak-crypto

Deliberately OUT of scope, matching `weak_crypto.py`'s own Python-side scope: `crypto.createHmac(...)`
is never flagged, even with a weak digest like `createHmac('sha1', key)`. HMAC-SHA1 is not the same
weak-algorithm class as bare SHA-1 hashing — HMAC's construction remains collision-resistant even
with a broken underlying hash, so it is still considered acceptable for many purposes (e.g. webhook
signature verification) unlike bare SHA-1 for password hashing or `crypto.createHash('sha1')`.
`weak_crypto.py`'s Python side draws the identical line: `hashlib.md5`/`hashlib.sha1` calls are
flagged, `hmac.new(key, msg, hashlib.sha1)` is not.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_view,
    is_nonproduct_path,
    iter_files,
    read,
    rel,
    strip_js_comments,
)

_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")
_PRAGMA = "security: allow-js-weak-crypto"

_WEAK_HASH_ALGOS = frozenset({"md5", "sha1"})
_WEAK_CIPHER_ALGOS = frozenset({"des", "des-ede3", "rc4", "rc2"})

# crypto.createHash('md5' | 'sha1') — Node built-in, optionally destructured (bare `createHash(`).
# The algorithm name is captured and checked case-insensitively against `_WEAK_HASH_ALGOS`.
_CREATE_HASH = re.compile(r"\b(?:crypto\.)?createHash\s*\(\s*['\"]([\w-]+)['\"]")

# crypto.createCipher(...) / createDecipher(...) — deprecated regardless of algorithm. Node
# spells the decrypt variant "createDecipher" (lowercase `c` — "De" + "cipher", not "De" +
# "Cipher"), so the alternation is spelled out explicitly rather than an "(?:De)?" prefix on
# "Cipher". The `\(` right after the matched name (no `iv` in between) is what keeps this from
# matching createCipheriv/createDecipheriv: "Decipher" is a PREFIX of "Decipheriv", so matching
# it there still leaves "iv" before the `(`, and `\s*\(` cannot match "iv(" — no explicit
# negative lookahead needed.
_CREATE_CIPHER_DEPRECATED = re.compile(r"\b(?:crypto\.)?create(?:Cipher|Decipher)\s*\(")

# crypto.createCipheriv(...) / createDecipheriv(...) — the modern, safe replacement functions,
# flagged only when the algorithm string (the first argument) is on the weak list.
_CREATE_CIPHERIV = re.compile(r"\b(?:crypto\.)?create(?:Cipheriv|Decipheriv)\s*\(\s*['\"]([\w-]+)['\"]")

# CryptoJS.MD5(...) / CryptoJS.SHA1(...) — the crypto-js library's own weak hash entry points.
_CRYPTOJS_HASH = re.compile(r"\bCryptoJS\.(MD5|SHA1)\s*\(")

# CryptoJS.DES.encrypt(...)/.decrypt(...), CryptoJS.RC4.encrypt(...)/.decrypt(...) — the crypto-js
# library's own weak cipher entry points.
_CRYPTOJS_CIPHER = re.compile(r"\bCryptoJS\.(DES|RC4)\.(?:encrypt|decrypt)\s*\(")


class JsWeakCryptoGuard(Guard):
    id = "js-weak-crypto"
    title = "No weak / broken cryptography (JS/TS)"
    area = "Crypto & TLS"

    # express_weak_crypto.js: crypto.createHash('md5') ->
    # fires js-weak-crypto/weak-hash-algorithm.
    canary_plant = CanaryPlant(
        files={
            "express_weak_crypto.js": (
                "const crypto = require('crypto');\n"
                "const digest = crypto.createHash('md5').update(data).digest('hex');\n"
            ),
        },
        expects=frozenset({"js-weak-crypto/weak-hash-algorithm"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "javascript" in profile.features or "typescript" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            text = read(f)
            out.extend(self._scan(root, f, text))
        return out

    def _scan(self, root: Path, f: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        # strip_js_comments blanks a TRAILING `// ...` comment too, string/regex-literal aware —
        # a commented-out example of the pattern must not fire (mirrors js_command_injection).
        # The comment-only view keeps the inline pragma visible.
        view_lines = comment_view(text, "js").splitlines()  # same length: comments only (#424)
        code_lines = strip_js_comments(text).splitlines()
        for i, (view_line, line) in enumerate(zip(view_lines, code_lines, strict=True), start=1):
            if _PRAGMA in view_line:
                continue

            hm = _CREATE_HASH.search(line)
            if hm and hm.group(1).lower() in _WEAK_HASH_ALGOS:
                out.append(self._finding(
                    root, f, i, "weak-hash-algorithm",
                    "Broken hash (MD5/SHA-1) used via crypto.createHash",
                    "MD5 and SHA-1 are collision-broken — any security use (signatures, token "
                    "derivation, integrity checks) built on them is forgeable.",
                    "Use SHA-256 or stronger: crypto.createHash('sha256').",
                ))
                continue

            jm = _CRYPTOJS_HASH.search(line)
            if jm:
                out.append(self._finding(
                    root, f, i, "weak-hash-algorithm",
                    f"Broken hash ({jm.group(1)}) used via CryptoJS",
                    "MD5 and SHA-1 are collision-broken — any security use (signatures, token "
                    "derivation, integrity checks) built on them is forgeable.",
                    "Use CryptoJS.SHA256(...) or stronger.",
                ))
                continue

            if _CREATE_CIPHER_DEPRECATED.search(line):
                out.append(self._finding(
                    root, f, i, "deprecated-cipher-function",
                    "crypto.createCipher/createDecipher is deprecated and insecure",
                    "createCipher/createDecipher derive the encryption key and IV from a "
                    "password via a single, non-salted, weak hash — it is insecure regardless "
                    "of the cipher algorithm argument.",
                    "Use createCipheriv/createDecipheriv with an explicit, properly-derived key "
                    "and a random IV (or a modern AEAD like AES-256-GCM).",
                ))
                continue

            cm = _CREATE_CIPHERIV.search(line)
            if cm and cm.group(1).lower() in _WEAK_CIPHER_ALGOS:
                out.append(self._finding(
                    root, f, i, "weak-cipher-algorithm",
                    f"Weak cipher algorithm ({cm.group(1)}) used via crypto.createCipheriv",
                    "DES/3DES/RC4/RC2 are broken or dangerously weak ciphers — small block/key "
                    "sizes and known practical attacks make them unsuitable for confidentiality.",
                    "Use a modern authenticated cipher: AES-256-GCM (aes-256-gcm) or "
                    "ChaCha20-Poly1305.",
                ))
                continue

            jc = _CRYPTOJS_CIPHER.search(line)
            if jc:
                out.append(self._finding(
                    root, f, i, "weak-cipher-algorithm",
                    f"Weak cipher algorithm ({jc.group(1)}) used via CryptoJS",
                    "DES and RC4 are broken or dangerously weak ciphers — small block/key sizes "
                    "and known practical attacks make them unsuitable for confidentiality.",
                    "Use CryptoJS.AES.encrypt(...) (AES) instead.",
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
            remediation=remediation + " If audited-safe, suppress with "
            "`// security: allow-js-weak-crypto`.",
            rule=f"js-weak-crypto/{rule}",
            standards=["OWASP:A02"],
        )
