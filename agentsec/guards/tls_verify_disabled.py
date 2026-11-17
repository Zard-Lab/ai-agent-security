"""Guard: outbound HTTP client TLS certificate verification disabled (§6b, new item).

`requests.get(url, verify=False)` / `httpx.Client(verify=False)` / `session.verify =
False` disable TLS certificate validation on outbound HTTP calls, so the app trusts
whatever server answers the request — a textbook man-in-the-middle setup (CWE-295,
Improper Certificate Validation). This is one of the most common "I'll fix the cert
error later" shortcuts, usually left in after a local self-signed-cert debugging
session, and it silently defeats TLS on every request the client makes afterward.

Named as an explicit in-scope example in LlamaIndex's own security policy ("Disabled
TLS verification in external requests" is a qualifying finding) — the pattern shows up
anywhere a Python app makes outbound HTTP calls, not just in LLM/RAG code.

Fires HIGH on:
  * `requests.get/post/put/delete/patch/head/request(...)` or
    `httpx.get/post/put/delete/patch/head/request(...)` with `verify=False` in the
    call's arguments;
  * `httpx.Client(...)` / `httpx.AsyncClient(...)` constructed with `verify=False`;
  * a `<var>.verify = False` attribute assignment (the `requests.Session()`
    post-construction idiom).

Also fires HIGH on the lower-level idioms that reach the same outcome without a
`verify=False` keyword (CodeQL `py/request-without-cert-validation` covers these
via dataflow; this guard approximates each as a same-line regex):
  * `ssl._create_unverified_context()` — the documented stdlib bypass, used as a
    context passed into `urlopen`/`HTTPSConnection`/etc.;
  * `<ctx>.check_hostname = False` — disables hostname matching on an `ssl.SSLContext`;
  * `<ctx>.verify_mode = ssl.CERT_NONE` — disables the certificate chain check itself;
  * urllib3 `cert_reqs="CERT_NONE"` (or `ssl.CERT_NONE`) on a `PoolManager`/`HTTPSConnectionPool`;
  * aiohttp `ssl=False` (or `verify_ssl=False`, the older deprecated kwarg) on a
    `ClientSession`/`TCPConnector`/request call.

**Express/Node (codeql `js/disabling-certificate-validation`,
`javascript/ql/src/Security/CWE-295/DisablingCertificateValidation.ql`).** Also fires HIGH on:
  * `rejectUnauthorized: false` in an `https`/`tls` options object (`https.request(...)`,
    `new https.Agent(...)`, `tls.connect(...)`, `tls.createServer(...)`) — the Node analog of
    `verify=False`;
  * `process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"` — disables certificate validation
    process-wide for every outbound TLS connection, not just one client.

Suppress an audited case (e.g. a genuinely self-signed internal CA the app has no
other way to trust) with `# security: allow-tls-verify-disabled`. JS/TS files use the
equivalent `// security: allow-tls-verify-disabled` line comment.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    iter_files,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    strip_js_comments,
)

_PRAGMA = re.compile(r"#\s*security:\s*allow-tls-verify-disabled")

_JS_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")
_JS_PRAGMA_TEXT = "security: allow-tls-verify-disabled"
_JS_REJECT_UNAUTHORIZED_FALSE = re.compile(r"\brejectUnauthorized\s*:\s*false\b", re.IGNORECASE)
_JS_NODE_TLS_ENV_DISABLED = re.compile(
    r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0[\"']?"
)

_STANDARDS = ["CWE-295"]

_VERIFY_FALSE = re.compile(r"verify\s*=\s*False")

_HTTP_CALL = re.compile(
    r"\b(?:requests|httpx)\s*\.\s*(?:get|post|put|delete|patch|head|request)\s*\("
)
_CLIENT_CTOR = re.compile(r"\bhttpx\s*\.\s*(?:Client|AsyncClient)\s*\(")
# `<var>.verify = False` is the `requests.Session()` idiom — but `.verify` is an overloaded
# attribute name (schema validators, JWT decoders, custom flags), so this loose form is
# scoped to files that actually import an HTTP client (below), and `self.verify = False`
# is excluded (a class setting its own flag is not a session — sessions are local vars).
_ATTR_ASSIGN = re.compile(r"\b(?!self\b)\w+\s*\.\s*verify\s*=\s*False\b")
# A file-level "this module uses an HTTP client" cue: an import OR a `requests.`/`httpx.`
# usage (e.g. `requests.Session()`). Scopes the loose `.verify = False` form so it can't FP
# in files that never touch requests/httpx.
_HTTP_CUE = re.compile(r"\b(?:import\s+(?:requests|httpx)|from\s+(?:requests|httpx)\b|(?:requests|httpx)\s*\.)")

# stdlib `ssl` module's documented bypass — always a violation wherever it appears.
_SSL_UNVERIFIED_CTX = re.compile(r"\bssl\s*\.\s*_create_unverified_context\s*\(")
# `<ctx>.check_hostname = False` disables hostname matching on an SSLContext.
_CHECK_HOSTNAME_FALSE = re.compile(r"\.\s*check_hostname\s*=\s*False\b")
# `verify_mode = ssl.CERT_NONE` (SSLContext) or `cert_reqs="CERT_NONE"` / `cert_reqs=ssl.CERT_NONE`
# (urllib3 PoolManager/HTTPSConnectionPool) both disable the chain check itself.
_CERT_NONE = re.compile(
    r"\bverify_mode\s*=\s*(?:ssl\s*\.\s*)?CERT_NONE\b"
    r"|\bcert_reqs\s*=\s*(?:[\"']CERT_NONE[\"']|ssl\s*\.\s*CERT_NONE\b)"
)
# aiohttp `ssl=False` / the older deprecated `verify_ssl=False` kwarg on a ClientSession,
# TCPConnector, or request call — scoped to files that actually import aiohttp (below),
# since `ssl=` alone is a plausible kwarg name in unrelated code.
_AIOHTTP_SSL_FALSE = re.compile(r"\b(?:ssl|verify_ssl)\s*=\s*False\b")
_AIOHTTP_CUE = re.compile(r"\b(?:import\s+aiohttp|from\s+aiohttp\b|aiohttp\s*\.)")


class TlsVerifyDisabledGuard(Guard):
    id = "tls-verify-disabled"
    title = "Outbound HTTP client TLS certificate verification disabled"
    area = "Crypto & TLS"

    # requests.get(url, verify=False) -> tls-verify-disabled.
    # ssl._create_unverified_context() -> tls-verify-disabled/ssl-unverified-context.
    # express_tls.js: https.request(..., { rejectUnauthorized: false }) ->
    # fires tls-verify-disabled/reject-unauthorized-false on the JS/Express branch.
    canary_plant = CanaryPlant(
        files={
            "http_client.py": "resp = requests.get(url, verify=False)\n",
            "ssl_client.py": "import ssl\n\nctx = ssl._create_unverified_context()\n",
            "express_tls.js": (
                "const https = require('https');\n"
                "\n"
                "https.request(url, { rejectUnauthorized: false }, callback);\n"
            ),
        },
        expects=frozenset({
            "tls-verify-disabled/reject-unauthorized-false",
            "tls-verify-disabled/ssl-unverified-context",
            "tls-verify-disabled/verify-false",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features or "express" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        if "python" in profile.features:
            seen: set[Path] = set()
            for d in python_scan_dirs(root, profile):
                for f in iter_files(d, (".py",)):
                    if f in seen:
                        continue
                    seen.add(f)
                    out.extend(self._scan(root, f))
        if "express" in profile.features:
            for f in iter_files(root, _JS_SUFFIXES):
                raw = read(f)
                if pragma_present(_JS_PRAGMA_TEXT, raw, dialect=comment_dialect_for(f)):
                    continue
                out.extend(self._scan_js(root, f, strip_js_comments(raw)))
        return out

    def _scan_js(self, root: Path, f: Path, code: str) -> list[Finding]:
        out: list[Finding] = []
        for lineno, line in enumerate(code.splitlines(), start=1):
            if _JS_REJECT_UNAUTHORIZED_FALSE.search(line):
                out.append(self._finding(
                    root, f, lineno,
                    message=(
                        "rejectUnauthorized: false disables TLS certificate verification on "
                        "this outbound connection. The app now trusts whatever server answers "
                        "with no certificate check — a man-in-the-middle attacker on the "
                        "network path can intercept and tamper with the response undetected "
                        "(CWE-295)."
                    ),
                    remediation=(
                        "Remove `rejectUnauthorized: false` and fix the underlying certificate "
                        "issue: install the correct CA bundle, or pass a `ca:` option for a "
                        "genuinely private internal CA. Never disable verification for a "
                        "public-internet endpoint. Suppress with "
                        "`// security: allow-tls-verify-disabled` only after confirming there "
                        "is no alternative."
                    ),
                    rule="tls-verify-disabled/reject-unauthorized-false",
                ))
            elif _JS_NODE_TLS_ENV_DISABLED.search(line):
                out.append(self._finding(
                    root, f, lineno,
                    message=(
                        "Setting NODE_TLS_REJECT_UNAUTHORIZED=0 disables TLS certificate "
                        "verification process-wide, for every outbound TLS connection this "
                        "process makes, not just one client — a man-in-the-middle attacker "
                        "anywhere on the network path can intercept and tamper with any "
                        "outbound request undetected (CWE-295)."
                    ),
                    remediation=(
                        "Remove this assignment. If a private CA is in play, pass it via a "
                        "specific client's `ca:`/`rejectUnauthorized` options instead of "
                        "disabling verification process-wide."
                    ),
                    rule="tls-verify-disabled/reject-unauthorized-false",
                ))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
            return out
        # The loose `<var>.verify = False` form is only trusted in files that import an HTTP
        # client — otherwise `.verify` is likely an unrelated attribute (validator/JWT/flag).
        has_http_client = bool(_HTTP_CUE.search(text))
        has_aiohttp = bool(_AIOHTTP_CUE.search(text))
        for lineno, line in enumerate(text.splitlines(), start=1):
            if line.lstrip().startswith("#"):
                continue
            call_verify_false = (
                (_HTTP_CALL.search(line) or _CLIENT_CTOR.search(line))
                and _VERIFY_FALSE.search(line)
            )
            if call_verify_false or (has_http_client and _ATTR_ASSIGN.search(line)):
                out.append(self._finding(
                    root, f, lineno,
                    message=(
                        "This disables TLS certificate verification on an outbound HTTP "
                        "call. The app now trusts whatever server answers the request "
                        "with no certificate check — a man-in-the-middle attacker on the "
                        "network path can intercept and tamper with the response "
                        "undetected (CWE-295)."
                    ),
                    remediation=(
                        "Remove `verify=False` and fix the underlying certificate issue: "
                        "install the correct CA bundle, or pass `verify=\"/path/to/ca.pem\"` "
                        "for a genuinely private internal CA. Never disable verification "
                        "for a public-internet endpoint. Suppress with "
                        "`# security: allow-tls-verify-disabled` only after confirming "
                        "there is no alternative (e.g. a fully offline/internal-only call)."
                    ),
                    rule="tls-verify-disabled/verify-false",
                ))
                continue
            if _SSL_UNVERIFIED_CTX.search(line):
                out.append(self._finding(
                    root, f, lineno,
                    message=(
                        "ssl._create_unverified_context() builds an SSLContext with "
                        "certificate and hostname checking both disabled. Any code path "
                        "that uses this context for an outbound connection trusts "
                        "whatever server answers, with no MITM detection (CWE-295)."
                    ),
                    remediation=(
                        "Use ssl.create_default_context() (or no explicit context — "
                        "requests/httpx/urllib default to verified TLS) and fix the "
                        "underlying certificate issue instead of bypassing it."
                    ),
                    rule="tls-verify-disabled/ssl-unverified-context",
                ))
                continue
            if _CHECK_HOSTNAME_FALSE.search(line):
                out.append(self._finding(
                    root, f, lineno,
                    message=(
                        "check_hostname = False disables hostname matching on this "
                        "SSLContext — the certificate chain may still be validated, but "
                        "any valid certificate for ANY host will be accepted, defeating "
                        "the point of TLS server identity checks (CWE-295)."
                    ),
                    remediation=(
                        "Remove this assignment and let the context validate hostnames "
                        "normally. If check_hostname must be disabled, verify_mode should "
                        "never be left at CERT_REQUIRED in combination — but the safest fix "
                        "is to not disable it at all."
                    ),
                    rule="tls-verify-disabled/check-hostname-false",
                ))
                continue
            if _CERT_NONE.search(line):
                out.append(self._finding(
                    root, f, lineno,
                    message=(
                        "verify_mode/cert_reqs set to CERT_NONE disables certificate chain "
                        "validation entirely on this SSLContext or urllib3 pool — the "
                        "connection accepts any certificate, or none at all (CWE-295)."
                    ),
                    remediation=(
                        "Use ssl.CERT_REQUIRED (the default) and supply the correct CA "
                        "bundle instead of disabling validation."
                    ),
                    rule="tls-verify-disabled/cert-none",
                ))
                continue
            if has_aiohttp and _AIOHTTP_SSL_FALSE.search(line):
                out.append(self._finding(
                    root, f, lineno,
                    message=(
                        "ssl=False (or the deprecated verify_ssl=False) disables TLS "
                        "certificate verification on this aiohttp client/connector/request "
                        "— the app trusts whatever server answers with no certificate "
                        "check (CWE-295)."
                    ),
                    remediation=(
                        "Remove ssl=False / verify_ssl=False. If a private CA is in play, "
                        "pass an ssl.SSLContext built with that CA instead of disabling "
                        "verification."
                    ),
                    rule="tls-verify-disabled/aiohttp-ssl-false",
                ))
        return out

    def _finding(
        self, root: Path, f: Path, lineno: int, *, message: str, remediation: str, rule: str
    ) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=message,
            remediation=remediation,
            rule=rule,
            standards=list(_STANDARDS),
        )
