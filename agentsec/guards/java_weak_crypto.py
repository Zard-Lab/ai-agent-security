"""Guard: no weak / broken cryptographic primitive in Java application code (checklist §8).

The Java counterpart to agentsec's existing Python/JS/Go/Ruby `weak-crypto` guards — same
requirement (a broken hash primitive is a forgeable signature or an insecure integrity check;
ECB mode leaks structural plaintext patterns), a genuinely different code surface (`java.security`
/ Apache Commons Codec instead of `hashlib`/Node's `crypto`/`crypto/*`/`Digest`), so it extends the
same `8-weak-crypto` checklist item rather than duplicating it. This is agentsec's first Java-
language guard — Java stack detection (`.java` suffix, `java_dirs`/`java_scan_dirs`)
and `strip_java_comments` landed in this same PR to support it.

Pattern verified against Find Security Bugs' real source (`WeakMessageDigestDetector.java`,
rules `WEAK_MESSAGE_DIGEST_MD5`/`WEAK_MESSAGE_DIGEST_SHA1`; `CipherWithNoIntegrityDetector.java`,
its exact `INSECURE_ECB_MODES` regex, rules `ECB_MODE`/`PADDING_ORACLE`) — the class names and
files are cited for provenance; detection logic and test fixtures here are original, developed
independently against the pattern description, not copied or derived from that (Java) source.

Fires HIGH on two distinct shapes, both broken cryptographic primitives:

  * **Weak hash** — `MessageDigest.getInstance("MD5"|"SHA1"|"SHA-1"|"SHA"|"MD4"|"MD2")`, or Apache
    Commons Codec's `DigestUtils.md5*`/`DigestUtils.sha1*` convenience methods. MD5 and SHA-1 are
    collision-broken (SHAttered, 2017) — a signature, token, or integrity check built on either is
    forgeable.
  * **Weak cipher mode** — `Cipher.getInstance("AES")` (the bare transformation string, which
    silently defaults to ECB on Java's built-in providers — the single most common real-world
    Java crypto misconfiguration, because it looks like "just AES"), or an explicit
    `"...(AES|DES(ede)?)/ECB/..."` transformation string. ECB mode encrypts identical plaintext
    blocks to identical ciphertext blocks, leaking structural patterns (the textbook "ECB penguin"
    finding) — CWE-327, the same weakness class as the hash case, a different mechanism.

CWE-327, OWASP:A02 (Cryptographic Failures).

Suppress an audited case (e.g. a content-dedup checksum, not a security use) with:

    MessageDigest.getInstance("MD5");  // security: allow-weak-crypto
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
    java_scan_dirs,
    read,
    rel,
    strip_java_comments,
)

# MessageDigest.getInstance("MD5" | "SHA1" | "SHA-1" | "SHA" | "MD4" | "MD2") — case-sensitive on
# the algorithm name (matches the real JCA provider names; a lowercase "md5" is not a valid JCA
# lookup and would never actually resolve to the weak digest at runtime).
_MESSAGE_DIGEST = re.compile(
    r'\bMessageDigest\s*\.\s*getInstance\s*\(\s*"(?:MD5|MD4|MD2|SHA-?1|SHA)"'
)
# Apache Commons Codec's DigestUtils convenience wrappers (md5Hex, md5, sha1Hex, sha1, getMd5Digest,
# getSha1Digest, ...) — matched on the method-name prefix, since every real method on this class
# for these two algorithms starts with one of these two stems.
_DIGEST_UTILS = re.compile(r"\bDigestUtils\s*\.\s*(?:md5|sha1|getMd5Digest|getSha1Digest)\w*\s*\(")
# Cipher.getInstance("AES") bare — no explicit mode, which silently defaults to ECB on Java's
# built-in SunJCE provider. Anchored to the closing quote (no "/") so an explicit non-ECB mode
# like "AES/GCM/NoPadding" does NOT match this branch.
_CIPHER_BARE_AES = re.compile(r'\bCipher\s*\.\s*getInstance\s*\(\s*"AES"\s*\)')
# Cipher.getInstance("AES/ECB/..." | "DES/ECB/..." | "DESede/ECB/...") — explicit ECB mode.
_CIPHER_ECB = re.compile(r'\bCipher\s*\.\s*getInstance\s*\(\s*"(?:AES|DES(?:ede)?)/ECB/')
_PRAGMA = "security: allow-weak-crypto"


class JavaWeakCryptoGuard(Guard):
    id = "java-weak-crypto"
    title = "No weak / broken cryptography (Java)"
    area = "Crypto & TLS"

    # WeakHash.java: MessageDigest.getInstance("MD5") -> java-weak-crypto/insecure-hash.
    canary_plant = CanaryPlant(
        files={
            "WeakHash.java": (
                "import java.security.MessageDigest;\n\n"
                "class WeakHash {\n"
                "    byte[] checksum(byte[] data) throws Exception {\n"
                '        MessageDigest md = MessageDigest.getInstance("MD5");\n'
                "        return md.digest(data);\n"
                "    }\n"
                "}\n"
            ),
        },
        expects=frozenset({"java-weak-crypto/insecure-hash"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "java" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in java_scan_dirs(root, profile):
            for f in iter_files(d, (".java",)):
                if f in seen:
                    continue
                seen.add(f)
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        # The pragma check runs on the COMMENT-ONLY view of the line — it IS the comment
        # `strip_java_comments` below would blank, and a string quoting it must not count (#424).
        view_lines = comment_view(text, "java").splitlines()  # same length: comments only (#424)
        # `strip_java_comments` preserves length and splitlines() count exactly (tested), so the
        # two line lists always pair up — `strict=True` documents that invariant.
        code_lines = strip_java_comments(text).splitlines()
        for i, (view, line) in enumerate(zip(view_lines, code_lines, strict=True), start=1):
            if _PRAGMA in view:
                continue
            if _MESSAGE_DIGEST.search(line) or _DIGEST_UTILS.search(line):
                out.append(self._hash_finding(root, f, i))
            elif _CIPHER_BARE_AES.search(line) or _CIPHER_ECB.search(line):
                out.append(self._cipher_finding(root, f, i))
        return out

    def _hash_finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title="Broken hash algorithm (MD5/SHA-1) in security-relevant code",
            location=f"{rel(root, f)}:{line}",
            message=(
                "MD5 and SHA-1 are collision-broken (SHAttered, 2017) — a signature, token, or "
                "integrity check built on either is forgeable."
            ),
            remediation=(
                "Replace MD5/SHA-1 with SHA-256 or better (`MessageDigest.getInstance(\"SHA-256\")`). "
                "If this hash is genuinely not security-relevant (content deduplication, a cache key, "
                "an ETag), suppress with `// security: allow-weak-crypto`."
            ),
            rule="java-weak-crypto/insecure-hash",
            standards=["OWASP:A02"],
        )

    def _cipher_finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title="Weak block-cipher mode (ECB, or the bare-AES default that silently means ECB)",
            location=f"{rel(root, f)}:{line}",
            message=(
                "ECB mode encrypts identical plaintext blocks to identical ciphertext blocks, "
                "leaking structural patterns in the plaintext (the \"ECB penguin\" finding). "
                '`Cipher.getInstance("AES")` with no explicit mode silently defaults to ECB on '
                "Java's built-in SunJCE provider — the single most common real-world Java crypto "
                "misconfiguration, because it reads like \"just AES\"."
            ),
            remediation=(
                'Use an authenticated mode instead, e.g. `Cipher.getInstance("AES/GCM/NoPadding")` '
                "with a fresh IV per encryption. If ECB is genuinely required (rare — verify first), "
                "suppress with `// security: allow-weak-crypto`."
            ),
            rule="java-weak-crypto/weak-cipher-mode",
            standards=["OWASP:A02"],
        )
