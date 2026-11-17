"""Guard: Java `X509TrustManager`/`TrustManager` with an empty (no-op) `checkServerTrusted`/
`checkClientTrusted` body — the classic "trust every certificate" TLS bypass idiom.

    TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
        public void checkClientTrusted(X509Certificate[] chain, String authType) { }
        public void checkServerTrusted(X509Certificate[] chain, String authType) { }
        public X509Certificate[] getAcceptedIssuers() { return null; }
    } };
    SSLContext sc = SSLContext.getInstance("TLS");
    sc.init(null, trustAllCerts, new java.security.SecureRandom());

`javax.net.ssl.X509TrustManager` (and its parent interface `javax.net.ssl.TrustManager`) is Java's
certificate-trust extension point. `checkServerTrusted`/`checkClientTrusted` are supposed to throw
`CertificateException` when the presented chain is untrustworthy; `SSLContext.init()` accepts an
array of `TrustManager`s and hands validation off to them entirely. An implementation whose method
body is empty (or a no-op — a bare `return;`) NEVER throws, so every certificate is unconditionally
accepted: no chain-of-trust check, no expiry check, no hostname binding. This is functionally the
same failure as Go's `InsecureSkipVerify: true` (`go_tls_verify_disabled.py`) and Python's
`requests.get(url, verify=False)` (`tls_verify_disabled.py`) — a client-side TLS verification bypass
— reached through Java's own idiom instead: implementing the validation callback and simply doing
nothing in it, rather than flipping a boolean. CWE-295 (Improper Certificate Validation).

Candidate sourced from graudit's Java bonus rules — its own signature scope is exactly
`checkServerTrusted(`/`checkClientTrusted(`/`TrustManager` appearing together. Reconciled during
this session's research phase against Find Security Bugs' 10 candidate rules and confirmed NOT a
duplicate of anything else in the Java guard build queue (including `java-weak-crypto`, which is a
different code surface — broken hash/cipher primitives, not certificate-trust callbacks). Detection
logic and test fixtures here are original, developed independently against the pattern description,
not copied or derived from graudit's (shell/regex) implementation.

Fires HIGH when a `checkServerTrusted` or `checkClientTrusted` METHOD DEFINITION (i.e. followed by a
`{` body, not a `;` abstract/interface declaration and not a call site like
`defaultTrustManager.checkServerTrusted(chain, authType);`) has a body that — once its own comments
are blanked — contains no real statement at all: empty, or comments only. This is the textbook
"trust everything" TrustManager, almost always paired with `getAcceptedIssuers()` returning `null`
or an empty array and installed via `SSLContext.getInstance(...).init(null, trustAllCerts, ...)`,
but this guard fires on the empty validation method alone — that single method IS the vulnerability,
independent of how the resulting `TrustManager` is later wired into an `SSLContext`.

Detection is regex + a small brace-counter, not an AST — this codebase does dependency-free textual
scanning for every guard, per its zero-runtime-dependency constraint. See `_matching_close_brace`'s
own docstring for what that specifically does not account for.

Suppress an audited case (e.g. a deliberately permissive TrustManager used only in an isolated,
non-production test harness) with:

    public void checkServerTrusted(X509Certificate[] chain, String authType) { } // security: allow-java-tls-verify-disabled
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
    matching_close_paren,
    read,
    rel,
    strip_java_comments,
)

_STANDARDS = ["CWE-295"]

# `checkServerTrusted(` / `checkClientTrusted(` — matched on the method name alone, no
# `TrustManager`/`X509TrustManager` proximity requirement. Like `InsecureSkipVerify` on the Go
# side, these are not generic words: they are the exact, literal method names Java's
# `javax.net.ssl.X509TrustManager` interface declares, with one well-documented,
# security-relevant contract (throw on an untrusted chain). No other JDK interface or common
# third-party API reuses either name for an unrelated purpose. A same-named method on some
# unrelated user interface would itself be a confusing, actively misleading choice — trusting
# the name alone carries negligible added false-positive risk (mirrors go_tls_verify_disabled.py's
# `InsecureSkipVerify` reasoning).
_METHOD_NAME = re.compile(r"\b(?:checkServerTrusted|checkClientTrusted)\s*\(")

_PRAGMA = "security: allow-java-tls-verify-disabled"

_MESSAGE = (
    "This checkServerTrusted/checkClientTrusted implementation has an empty (or comment-only) "
    "body — it never throws CertificateException, so it unconditionally trusts every "
    "certificate chain presented to it. Any TLS connection that installs this TrustManager via "
    "SSLContext.init() has no certificate validation at all: no chain-of-trust check, no expiry "
    "check, no hostname binding. A man-in-the-middle attacker anywhere on the network path can "
    "intercept and tamper with the connection undetected (CWE-295)."
)
_REMEDIATION = (
    "Implement real validation: delegate to the platform default TrustManager "
    "(TrustManagerFactory.getInstance(...).getTrustManagers(), then call its "
    "checkServerTrusted/checkClientTrusted and let a CertificateException propagate), or pin "
    "against a known-good certificate/public key. If a permissive TrustManager is genuinely "
    "needed for an isolated, non-production context, suppress with "
    "`// security: allow-java-tls-verify-disabled` only after confirming it can never reach a "
    "production network path."
)


def _matching_close_brace(text: str, open_idx: int) -> int | None:
    """Index of the `}` matching the `{` at open_idx, by plain nesting count.

    Deliberately NOT quote-aware (unlike `matching_close_paren`, which this module also uses for
    the method's parameter list): a real `X509TrustManager` method body is short and consists of
    validation statements, not string literals containing stray `{`/`}` characters, and a full
    quote-aware walk is not worth the complexity for this shape. The known, documented residual:
    a `{` or `}` inside a string literal WITHIN the method body (e.g. a log message) would desync
    the count — either pulling in trailing code as part of "the body" (harmless: it only makes an
    empty-looking body register as non-empty) or, less commonly, truncating the body early on a
    stray `}` (which could in principle miss real validation code sitting after it and misreport
    the body as empty). This asymmetry is the same class of textual-scanning limitation every
    sibling guard in this codebase accepts (see `strip_java_comments`'s own documented residual on
    Java text blocks); the pragma is the correction for any resulting false positive, not a
    guard limitation to fix later. Returns None on an unbalanced count (never guesses)."""
    depth = 0
    i, n = open_idx, len(text)
    while i < n:
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


class JavaTlsVerifyDisabledGuard(Guard):
    id = "java-tls-verify-disabled"
    title = "Empty TrustManager (checkServerTrusted/checkClientTrusted does not validate)"
    area = "Crypto & TLS"

    # TrustAll.java: an anonymous X509TrustManager whose checkServerTrusted body is empty ->
    # fires java-tls-verify-disabled/empty-trust-manager.
    canary_plant = CanaryPlant(
        files={
            "TrustAll.java": (
                "import javax.net.ssl.X509TrustManager;\n"
                "import java.security.cert.X509Certificate;\n\n"
                "class TrustAll {\n"
                "    X509TrustManager trustAllCerts = new X509TrustManager() {\n"
                "        public void checkClientTrusted(X509Certificate[] chain, String authType) {\n"
                "        }\n"
                "        public void checkServerTrusted(X509Certificate[] chain, String authType) {\n"
                "        }\n"
                "        public X509Certificate[] getAcceptedIssuers() {\n"
                "            return null;\n"
                "        }\n"
                "    };\n"
                "}\n"
            ),
        },
        expects=frozenset({"java-tls-verify-disabled/empty-trust-manager"}),
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
        # `strip_java_comments` below would blank, and a string quoting it must not count (#424). `code` (the
        # comment-stripped copy) is what the method-name/brace scan runs against, so a mention
        # only inside a `//`/`/** */` comment never matches in the first place.
        view_lines = comment_view(text, "java").splitlines()  # same length: comments only (#424)
        code = strip_java_comments(text)
        for m in _METHOD_NAME.finditer(code):
            # The identifier is always immediately followed by "(" per the regex, so the "("
            # itself sits one char before the match end.
            open_paren = m.end() - 1
            close_paren = matching_close_paren(code, open_paren)
            if close_paren is None:
                continue
            # Find whichever comes first after the parameter list: a "{" (a real body — this is
            # a method DEFINITION, possibly after a "throws ..." clause) or a ";" (an abstract
            # interface declaration, or — critically — this is actually a CALL SITE like
            # `defaultTrustManager.checkServerTrusted(chain, authType);`, which always ends in
            # ";" with no body at all). Either way, no ";" reachable before a "{" means there is
            # nothing to inspect here.
            brace_idx = code.find("{", close_paren + 1)
            semi_idx = code.find(";", close_paren + 1)
            if brace_idx == -1:
                continue
            if semi_idx != -1 and semi_idx < brace_idx:
                continue
            close_brace = _matching_close_brace(code, brace_idx)
            if close_brace is None:
                continue
            body = code[brace_idx + 1 : close_brace]
            if body.strip():
                continue  # real statement present — not the empty/no-op shape
            lineno = code[: m.start()].count("\n") + 1
            view_line = view_lines[lineno - 1] if 0 < lineno <= len(view_lines) else ""
            if _PRAGMA in view_line:
                continue
            out.append(self._finding(root, f, lineno))
        return out

    def _finding(self, root: Path, f: Path, lineno: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=_MESSAGE,
            remediation=_REMEDIATION,
            rule="java-tls-verify-disabled/empty-trust-manager",
            standards=list(_STANDARDS),
        )
