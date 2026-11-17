"""Guard: PHP cURL TLS certificate verification disabled (checklist §8).

    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);

PHP's cURL extension has two options that together control TLS certificate validation on a
`curl_setopt()`/`curl_setopt_array()`-configured handle:

  * `CURLOPT_SSL_VERIFYPEER` — whether the peer's certificate is verified against a trusted CA
    at all. Disabling it (`false`/`0`) accepts ANY certificate, self-signed or not.
  * `CURLOPT_SSL_VERIFYHOST` — whether the certificate's hostname is checked against the URL
    being requested. The correct/strict value is `2` (check the name); `0`/`false` disables the
    check entirely (curl also treats `1` as invalid/deprecated since 7.28.1, but this guard
    only needs to recognize `0`/`false`/`null` as the disabled state — anything else is not our
    concern).

Setting either option to a disabled value defeats TLS's whole purpose: the client will now
accept a certificate from any origin, trusted CA or not, matching hostname or not. This is
functionally identical in spirit to the Python-side `requests.get(url, verify=False)` pattern
this project already guards against (`tls_verify_disabled.py`) and to Go's
`InsecureSkipVerify: true` (`go_tls_verify_disabled.py`) — a textbook man-in-the-middle setup
(CWE-295, Improper Certificate Validation).

Pattern verified against graudit's real signature dictionary (`wireghoul/graudit`,
`signatures/php.db`), which flags `CURLOPT_SSL_VERIFYHOST`/`CURLOPT_SSL_VERIFYPEER` as a known
PHP TLS-downgrade idiom — the regex shape is cited for provenance; detection logic and test
fixtures here are original, developed independently against the pattern description, not copied
from graudit's own (POSIX ERE) implementation.

Fires HIGH on either constant, inside a `curl_setopt(` call, set to a disabled value —
`false`/`FALSE`, `0` (as a whole value, not a digit inside a longer number like `10`), or
`null`/`NULL`:

    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);

`CURLOPT_SSL_VERIFYHOST` set to `2` (the correct strict value) or `CURLOPT_SSL_VERIFYPEER` set
to `true`/`1` does NOT fire — those are the secure configurations.

**Scope decision, stated honestly:** the array-literal form passed to `curl_setopt_array($ch,
[...])` is ALSO covered — each `CURLOPT_SSL_VERIFY(HOST|PEER) => <disabled-value>` entry inside
an array literal fires the same way, matched independently of the surrounding
`curl_setopt_array(` call (so a disabled entry is caught even if the array is built across
several lines, at the cost of not requiring the array to be textually inside a
`curl_setopt_array(...)` call at all — see "Known bypasses").

Suppress an audited case (e.g. a deliberate, already-mitigated internal-CA pinning setup) with:

    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false); // security: allow-php-tls-verify-disabled
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, comment_view, iter_files, php_scan_dirs, read, rel, strip_php_comments

_STANDARDS = ["CWE-295"]

# A disabled value: false/FALSE, a bare 0 (word-boundaried so it doesn't match inside a longer
# number like 10 or 0.5), or null/NULL. PHP is case-insensitive for these keyword literals.
_DISABLED_VALUE = r"(?:false|0|null)"

# curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false) / curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0)
# — the constant name and its value are captured loosely: any argument expression may sit between
# the opening paren and the constant (the handle variable, typically), and the value sits after a
# comma before the closing paren. Case-insensitive so FALSE/False/NULL all match PHP's own
# case-insensitive keyword handling.
_CURL_SETOPT_DISABLED = re.compile(
    r"""curl_setopt\s*\([^;]*?\b(?P<opt>CURLOPT_SSL_VERIFY(?:HOST|PEER))\s*,\s*"""
    rf"""(?P<val>{_DISABLED_VALUE})\b""",
    re.IGNORECASE,
)

# curl_setopt_array($ch, [CURLOPT_SSL_VERIFYPEER => false, ...]) — matched as a standalone
# `CONSTANT => value` array-entry shape (PHP's `=>` key-value arrow), independent of whether the
# enclosing curl_setopt_array( call is on the same line, since the array literal is commonly
# spread across several lines.
_CURL_SETOPT_ARRAY_DISABLED = re.compile(
    rf"""\b(?P<opt>CURLOPT_SSL_VERIFY(?:HOST|PEER))\s*=>\s*(?P<val>{_DISABLED_VALUE})\b""",
    re.IGNORECASE,
)

_PRAGMA = "security: allow-php-tls-verify-disabled"

_MESSAGE = (
    "This cURL option disables TLS certificate verification — the client will accept a "
    "certificate from any origin, whether or not it chains to a trusted CA and whether or "
    "not its hostname matches the URL being requested. A man-in-the-middle attacker "
    "anywhere on the network path can intercept and tamper with the connection undetected "
    "(CWE-295)."
)
_REMEDIATION = (
    "Remove the option (or set CURLOPT_SSL_VERIFYPEER true / CURLOPT_SSL_VERIFYHOST 2, the "
    "secure defaults) and fix the underlying certificate issue: use a correctly-chained "
    "certificate, or if a private internal CA is genuinely in play, point CURLOPT_CAINFO at "
    "a certificate bundle for that CA instead of disabling verification entirely. Suppress "
    "with `// security: allow-php-tls-verify-disabled` only after confirming there is no "
    "alternative."
)


class PhpTlsVerifyDisabledGuard(Guard):
    id = "php-tls-verify-disabled"
    title = "cURL TLS certificate verification disabled (CURLOPT_SSL_VERIFYHOST/VERIFYPEER)"
    area = "Crypto & TLS"

    # CurlTls.php: curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false) ->
    # php-tls-verify-disabled/curl-ssl-verify-disabled.
    canary_plant = CanaryPlant(
        files={
            "CurlTls.php": (
                "<?php\n"
                "function fetchInsecure($url) {\n"
                "    $ch = curl_init($url);\n"
                "    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);\n"
                "    return curl_exec($ch);\n"
                "}\n"
            ),
        },
        expects=frozenset({"php-tls-verify-disabled/curl-ssl-verify-disabled"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "php" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in php_scan_dirs(root, profile):
            for f in iter_files(d, (".php",)):
                if f in seen:
                    continue
                seen.add(f)
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        # The pragma check runs on the COMMENT-ONLY view of the line — it IS the comment
        # `strip_php_comments` below would blank, and a string quoting it must not count (#424).
        view_lines = comment_view(text, "php").splitlines()  # same length: comments only (#424)
        # `strip_php_comments` preserves length and splitlines() count exactly (tested), so the
        # two line lists always pair up — `strict=True` documents that invariant.
        code_lines = strip_php_comments(text).splitlines()
        for i, (view, line) in enumerate(zip(view_lines, code_lines, strict=True), start=1):
            if _PRAGMA in view:
                continue
            if _CURL_SETOPT_DISABLED.search(line) or _CURL_SETOPT_ARRAY_DISABLED.search(line):
                out.append(self._finding(root, f, i))
        return out

    def _finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=_MESSAGE,
            remediation=_REMEDIATION,
            rule="php-tls-verify-disabled/curl-ssl-verify-disabled",
            standards=list(_STANDARDS),
        )
