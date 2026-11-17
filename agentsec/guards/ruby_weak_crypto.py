"""Guard: no weak / broken hash algorithm in Ruby application code (checklist §8).

The Ruby counterpart to agentsec's existing (Python/JS-only) `weak-crypto`/`js-weak-crypto`
guards — same requirement (a broken hash primitive is a forgeable signature or an insecure
integrity check), a genuinely different code surface (Ruby's `Digest` and `OpenSSL::Digest`
modules instead of `hashlib`/Node's `crypto`), so it extends the same `8-weak-crypto` checklist
item rather than duplicating it. This is agentsec's first Ruby-language guard — Ruby
stack detection (`.rb` suffix, `ruby_dirs`/`ruby_scan_dirs`) and `strip_ruby_comments` landed in
this same PR to support it.

Pattern verified against Brakeman's real source (`lib/brakeman/checks/check_weak_hash.rb`,
`Brakeman::CheckWeakHash`) — the class name and file are cited for provenance; detection logic
and test fixtures here are original, developed independently against the pattern description,
not copied or derived from Brakeman's own (Ruby) implementation.

Fires HIGH on:

  * **`Digest::MD5`/`Digest::SHA1`** — `Digest::MD5.hexdigest(...)`, `Digest::MD5.new`,
    `Digest::SHA1.digest(...)`, etc. Any method call on the constant fires; there's no
    "not for security" opt-out in Ruby's `Digest` API the way Python's `usedforsecurity=False`
    exists, so (mirroring Brakeman's own unconditional check) every use fires.
  * **`OpenSSL::Digest::MD5`/`::SHA1`** and the string-argument form `OpenSSL::Digest.new("MD5")`/
    `OpenSSL::Digest::MD5.new` — same broken algorithms via OpenSSL's Ruby binding.

MD5 and SHA-1 are collision-broken (SHAttered, 2017); a signature, token, or integrity check
built on either is forgeable. CWE-327, OWASP:A02 (Cryptographic Failures).

Suppress an audited case (e.g. a content-dedup checksum, not a security use) with:

    Digest::MD5.hexdigest(data)  # security: allow-weak-crypto
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, comment_view, iter_files, read, rel, ruby_scan_dirs, strip_ruby_comments

# `Digest::MD5`/`Digest::SHA1` — any method call on the constant (`.hexdigest`, `.new`,
# `.digest`, `.base64digest`, ...). The left boundary keeps `MyDigest::MD5` (an unrelated
# namespaced constant) from matching a bare substring.
_DIGEST_CONST = re.compile(r"(?<![A-Za-z0-9_])Digest::(?:MD5|SHA1)\b")
# `OpenSSL::Digest::MD5`/`::SHA1` (constant form) or `OpenSSL::Digest.new("MD5"|'SHA1')` /
# `OpenSSL::Digest::MD5.new` (string-argument form).
_OPENSSL_DIGEST_CONST = re.compile(r"(?<![A-Za-z0-9_])OpenSSL::Digest::(?:MD5|SHA1)\b")
_OPENSSL_DIGEST_STRING = re.compile(
    r"\bOpenSSL::Digest(?:::(?:MD5|SHA1))?\s*\.\s*new\s*\(\s*['\"](?:MD5|SHA1)['\"]",
    re.IGNORECASE,
)
_PRAGMA = re.compile(r"#\s*security:\s*allow-weak-crypto")


class RubyWeakCryptoGuard(Guard):
    id = "ruby-weak-crypto"
    title = "No weak / broken cryptography (Ruby)"
    area = "Crypto & TLS"

    # Digest::MD5.hexdigest(data) -> ruby-weak-crypto/insecure-hash.
    canary_plant = CanaryPlant(
        files={
            "checksum.rb": (
                "require 'digest'\n\n"
                "def checksum(data)\n"
                "  Digest::MD5.hexdigest(data)\n"
                "end\n"
            ),
        },
        expects=frozenset({"ruby-weak-crypto/insecure-hash"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "ruby" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in ruby_scan_dirs(root, profile):
            for f in iter_files(d, (".rb",)):
                if f in seen:
                    continue
                seen.add(f)
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        # The pragma check runs on the COMMENT-ONLY view (#424) — it IS the comment `strip_ruby_comments` below
        # would blank, so checking it after stripping would always miss it (checked live: this
        # exact ordering bug was caught by the adversarial self-test before this guard shipped).
        view_lines = comment_view(text, "ruby").splitlines()  # same length: comments only (#424)
        # Blank comments so a documented example in a `#` note never fires — mirrors
        # weak_crypto.py's/js_weak_crypto.py's own comment handling for the same reason.
        # `strip_ruby_comments` preserves length and splitlines() count exactly (tested), so the
        # two line lists always pair up — `strict=True` documents that invariant, not just quiets
        # the linter.
        code_lines = strip_ruby_comments(text).splitlines()
        for i, (view, line) in enumerate(zip(view_lines, code_lines, strict=True), start=1):
            if _PRAGMA.search(view):
                continue
            if _DIGEST_CONST.search(line) or _OPENSSL_DIGEST_CONST.search(line) or _OPENSSL_DIGEST_STRING.search(line):
                out.append(self._finding(root, f, i))
        return out

    def _finding(self, root: Path, f: Path, line: int) -> Finding:
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
                "Replace MD5/SHA-1 with SHA-256 or better (`Digest::SHA256`). If this hash is "
                "genuinely not security-relevant (content deduplication, a cache key, an ETag), "
                "suppress with `# security: allow-weak-crypto`."
            ),
            rule="ruby-weak-crypto/insecure-hash",
            standards=["OWASP:A02"],
        )
