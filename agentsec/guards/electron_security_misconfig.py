"""Guard: an Electron app disables a `webPreferences` security control (§6a).

Electron's `BrowserWindow` renderer process is a full browser context wired to Node.js — several
`webPreferences` flags exist specifically to keep that pairing safe, and each one this guard checks
removes a real layer of protection: `webSecurity: false` disables the same-origin policy entirely;
`allowRunningInsecureContent: true` lets the app load HTTP content into an otherwise-HTTPS page
(MITM exposure); `nodeIntegration: true` exposes Node.js APIs (`require`, `fs`, `child_process`,
...) directly to renderer-process JavaScript, turning any XSS in that renderer into remote code
execution; `contextIsolation: false` lets a compromised renderer reach into the Electron-injected
API surface and pollute it; `enableRemoteModule: true` exposes the main-process `remote` module
to the renderer (a classic RCE vector); `sandbox: false` disables the OS-level renderer sandbox;
`enableBlinkFeatures`/`experimentalFeatures: true` turn on not-production-ready browser engine
features. Sourced from njsscan's `security_electron.yaml` rule pack (`ajinabraham/njsscan`, real
Semgrep-syntax rules), verified against the real source — adapted from Semgrep AST patterns to a
same-file regex co-occurrence check (agentsec has no JS AST engine; see the module-level precision
note below). The file is comment-blanked first (via `strip_js_comments`), so a commented-out
`nodeIntegration: true` cannot emit a CRITICAL false positive (PR #407 review). A flag, and the
`new BrowserWindow(`/`webPreferences:` context that opens a file, count only when they are live
code on the shared anchor mask (`js_code_matches`, #1055), tested on the flag's `:` and on the
context's `(` or `:`: a `warn('never set nodeIntegration: true')` next to a safe window no longer
fires CRITICAL, while an object inside a `${...}` substitution still counts.

Fires once per dangerous flag found, CRITICAL for `nodeIntegration`/`enableRemoteModule`/
`contextIsolation`/`webSecurity` (each directly enables renderer-to-Node code execution or
origin-policy bypass), HIGH for `allowRunningInsecureContent`/`sandbox` (MITM / sandbox loss, not
direct code execution), MEDIUM for `enableBlinkFeatures`/`experimentalFeatures` (unstable-feature
exposure, not a direct exploit path).

**Precision note:** this guard checks for the dangerous `key: value` pair anywhere in a file that
also constructs a `BrowserWindow` (or a `webPreferences` object literal) — not a scoped
per-`BrowserWindow`-instance check the way njsscan's real Semgrep AST rules are. A file with
multiple `BrowserWindow` instances, only one of which is misconfigured, still fires once per
dangerous flag rather than localizing which instance. Same file-scoped tradeoff already accepted by
several other JS/TS guards in this codebase (no dataflow engine).

    new BrowserWindow({
      webPreferences: {
        nodeIntegration: true  // security: allow-electron-security-misconfig
      }
    })
"""
from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    iter_files,
    js_code_matches,
    pragma_present,
    read,
    rel,
    strip_js_comments,
)

_PRAGMA = "security: allow-electron-security-misconfig"
_CONTEXT = re.compile(r"new\s+BrowserWindow\s*\(|webPreferences\s*:")


def _flag_colon(m: re.Match[str]) -> int:
    """The `:` of a `_RULES` match's `key: value`, the anchor `js_code_matches` tests (#1055)."""
    return m.start() + m.group().index(":")


def _context_end(m: re.Match[str]) -> int:
    """The last character of a `_CONTEXT` match, the `(` of `new BrowserWindow(` or the `:` of
    `webPreferences:`, the anchor `js_code_matches` tests (#1055)."""
    return m.end() - 1

_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")

# (regex for the dangerous key:value pair, rule slug, severity, human explanation)
_RULES: tuple[tuple[re.Pattern[str], str, Severity, str], ...] = (
    (
        re.compile(r"webSecurity\s*:\s*false"),
        "websecurity-disabled",
        "critical",
        "disables the same-origin policy, allowing execution of insecure code from any domain",
    ),
    (
        re.compile(r"nodeIntegration\s*:\s*true"),
        "nodeintegration-enabled",
        "critical",
        "exposes Node.js APIs directly to renderer JavaScript — an XSS there becomes RCE",
    ),
    (
        re.compile(r"enableRemoteModule\s*:\s*true"),
        "remote-module-enabled",
        "critical",
        "exposes the main-process `remote` module to the renderer — a classic Electron RCE vector",
    ),
    (
        re.compile(r"contextIsolation\s*:\s*false"),
        "contextisolation-disabled",
        "critical",
        "lets a compromised renderer reach the Electron-injected API surface (prototype pollution)",
    ),
    (
        re.compile(r"allowRunningInsecureContent\s*:\s*true"),
        "allow-insecure-content",
        "high",
        "lets the app load content over HTTP, exposing it to man-in-the-middle attacks",
    ),
    (
        re.compile(r"sandbox\s*:\s*false"),
        "sandbox-disabled",
        "high",
        "disables the OS-level renderer sandbox, widening the blast radius of any renderer compromise",
    ),
    (
        re.compile(r"enableBlinkFeatures\s*:"),
        "blink-features-enabled",
        "medium",
        "enables experimental Blink engine features not meant for production apps",
    ),
    (
        re.compile(r"experimentalFeatures\s*:\s*true"),
        "experimental-features-enabled",
        "medium",
        "enables experimental Chromium features not meant for production apps",
    ),
)


# --- Electron-specific rules mined from Electronegativity's CustomArgumentsJSCheck,
# SecurityWarningsDisabledJSCheck, CertificateErrorEventJSCheck, CertificateVerifyProcJSCheck,
# NodeIntegrationJSCheck/HTMLCheck and PermissionRequestHandlerJSCheck. Unlike the webPreferences
# rules above they need no BrowserWindow context: a switch or handler lives in the main process.

_HTML_SUFFIXES = (".html", ".htm", ".jsx", ".tsx", ".vue")

_DANGEROUS_SWITCH = re.compile(
    r"\b(?:appendSwitch|appendArgument)\s*\(\s*['\"](?:--)?"
    r"(?:ignore-certificate-errors|disable-web-security|no-sandbox|allow-running-insecure-content"
    r"|remote-debugging-port|unsafely-treat-insecure-origin-as-secure|allow-file-access-from-files)"
    r"(?![\w-])"
)
_DISABLE_WARNINGS = re.compile(r"\bELECTRON_DISABLE_SECURITY_WARNINGS['\"\]]*\s*[=:]\s*['\"]?(?:true|1)\b")
_CERT_ERROR_HANDLER = re.compile(r"\b(?:on|once|addListener)\s*\(\s*['\"]certificate-error['\"]\s*,")
_CERT_VERIFY_PROC = re.compile(r"\bsetCertificateVerifyProc\s*\(")
_NODE_SUBFRAMES = re.compile(r"\bnodeIntegrationIn(?:SubFrames|Worker)\s*:\s*true\b")
_WEBVIEW_NODE = re.compile(
    r"<webview\b[^>]*?[\s\"'}](?:nodeintegration|nodeintegrationinsubframes)\b"
    r"(?!\s*=\s*[\"']?\{?\s*[\"']?(?:false|0)\b)",
    re.IGNORECASE,
)
_PERMISSION_GRANT_ALL = re.compile(
    r"\bsetPermissionRequestHandler\s*\(\s*(?:async\s*)?(?:function\s*)?"
    r"\(\s*\w+\s*,\s*\w+\s*,\s*(\w+)[^)]*\)\s*(?:=>)?\s*\{?\s*(?:return\s+)?"
    r"(\w+)\s*\(\s*true\s*\)\s*;?\s*\}?\s*\)"
)
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
# A handler that decides anything (a branch, a comparison, a lookup, a false answer) is not
# an unconditional accept.
_DECIDES = re.compile(
    r"\bif\b|\?|[!=]==?|\bswitch\b|&&|\|\||\.(?:startsWith|endsWith|includes|test|match|indexOf|has)\s*\("
    r"|\(\s*(?:false|-\d+)\s*\)"
)
_ACCEPT_TRUE = re.compile(r"\b\w+\s*\(\s*true\s*\)")
_ACCEPT_ZERO = re.compile(r"\b\w+\s*\(\s*0\s*\)")


def _start(m: re.Match[str]) -> int:
    """The first character of a match, the anchor for an identifier-led pattern."""
    return m.start()


def _blank_html_comments(text: str) -> str:
    """Blank `<!-- ... -->` to spaces (newlines kept) so offsets and lines stay aligned."""
    return _HTML_COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group()), text)


def _call_span(mask: str, open_paren: int) -> tuple[int, int] | None:
    """Offsets just inside the parentheses of the call opened at `open_paren` on the string-blanked
    `mask`, or None when it never closes. Strings are blanked so a `)` in one cannot unbalance it."""
    depth = 0
    for i in range(open_paren, min(len(mask), open_paren + 4000)):
        if mask[i] == "(":
            depth += 1
        elif mask[i] == ")":
            depth -= 1
            if depth == 0:
                return open_paren + 1, i
    return None


def _unconditional_accept(
    pattern: re.Pattern[str], accept: re.Pattern[str], text: str, mask: str
) -> bool:
    """True when some live `pattern` match opens a call whose handler never decides and accepts."""
    for m in js_code_matches(pattern, text, mask, anchor=_start):
        span = _call_span(mask, mask.index("(", m.start()))
        if span is None:
            continue
        body = mask[span[0]:span[1]]
        # Past the event name / first argument: only the handler body is judged.
        arrow = body.find("=>")
        fn = body.find("function")
        starts = [i for i in (arrow, fn) if i >= 0]
        body = body[min(starts):] if starts else body
        if accept.search(body) and not _DECIDES.search(body):
            return True
    return False


class ElectronSecurityMisconfigGuard(Guard):
    id = "electron-security-misconfig"
    title = "Electron app disables a webPreferences security control"
    area = "Web & browser"

    # electron_main.js: BrowserWindow with all 8 dangerous webPreferences flags set ->
    # fires all 8 electron-security-misconfig sub-rules. Requires "electron" as a root
    # package.json dependency to turn on the "electron" StackProfile feature.
    canary_plant = CanaryPlant(
        files={
            "electron_main.js": (
                "const { BrowserWindow } = require('electron');\n"
                "const win = new BrowserWindow({\n"
                "  webPreferences: {\n"
                "    nodeIntegration: true,\n"
                "    enableRemoteModule: true,\n"
                "    contextIsolation: false,\n"
                "    webSecurity: false,\n"
                "    allowRunningInsecureContent: true,\n"
                "    sandbox: false,\n"
                "    enableBlinkFeatures: 'ExperimentalCanvasFeatures',\n"
                "    experimentalFeatures: true\n"
                "  }\n"
                "});\n"
            ),
            "electron_main_process.js": (
                "const { app, session } = require('electron');\n"
                "app.commandLine.appendSwitch('ignore-certificate-errors');\n"
                "process.env.ELECTRON_DISABLE_SECURITY_WARNINGS = 'true';\n"
                "app.on('certificate-error', (e, w, u, er, c, cb) => { e.preventDefault(); cb(true); });\n"
                "session.defaultSession.setPermissionRequestHandler((wc, perm, cb) => cb(true));\n"
                "const opts = { webPreferences: { nodeIntegrationInSubFrames: true } };\n"
            ),
            "electron_webview.html": '<webview src="https://example.com" nodeintegration></webview>\n',
        },
        expects=frozenset({
            "electron-security-misconfig/websecurity-disabled",
            "electron-security-misconfig/nodeintegration-enabled",
            "electron-security-misconfig/remote-module-enabled",
            "electron-security-misconfig/contextisolation-disabled",
            "electron-security-misconfig/allow-insecure-content",
            "electron-security-misconfig/sandbox-disabled",
            "electron-security-misconfig/blink-features-enabled",
            "electron-security-misconfig/experimental-features-enabled",
            "electron-security-misconfig/dangerous-command-line-switch",
            "electron-security-misconfig/certificate-error-accept",
            "electron-security-misconfig/permission-handler-grant-all",
            "electron-security-misconfig/webview-node-integration",
            "electron-security-misconfig/security-warnings-disabled",
            "electron-security-misconfig/node-integration-in-subframes",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "electron" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []

        def add(f: Path, severity: Severity, slug: str, title: str, message: str, fix: str) -> None:
            out.append(
                Finding(
                    check_id=self.id,
                    severity=severity,
                    title=title,
                    location=f"{rel(root, f)}",
                    message=message,
                    remediation=(
                        f"{fix} Suppress a reviewed, intentional case with "
                        "`// security: allow-electron-security-misconfig`."
                    ),
                    rule=f"electron-security-misconfig/{slug}",
                    standards=["OWASP:A05"],
                )
            )

        for f in iter_files(root, _SUFFIXES + _HTML_SUFFIXES):
            raw = read(f)
            suffix = f.suffix.lower()
            if pragma_present(_PRAGMA, raw, dialect=comment_dialect_for(f)):
                continue
            if suffix in _HTML_SUFFIXES:
                self._scan_webview(f, raw, add)
            if suffix not in _SUFFIXES:
                continue
            # Blank comments (string-aware) so a commented-out `nodeIntegration: true` — the most
            # trust-damaging place for a CRITICAL false positive — cannot fire (PR #407 review).
            text = strip_js_comments(raw)
            # The context and each flag must be live code (#1055): a flag spelled out in a warning
            # string is not a setting. Every match is tried, so a quoted copy cannot hide a real one.
            mask = strip_js_comments(raw, strip_strings=True, keep_substitutions=True)
            self._scan_main_process(f, text, mask, add)
            if not _CONTEXT.search(text):
                continue
            if not any(js_code_matches(_CONTEXT, text, mask, anchor=_context_end)):
                continue
            for pattern, slug, severity, why in _RULES:
                if not any(js_code_matches(pattern, text, mask, anchor=_flag_colon)):
                    continue
                add(
                    f,
                    severity,
                    slug,
                    "Electron webPreferences disables a security control",
                    f"This Electron `webPreferences` block {why}.",
                    "Remove the dangerous override and use Electron's secure defaults "
                    "(contextIsolation: true, nodeIntegration: false, sandbox: true). If a "
                    "renderer genuinely needs Node.js functionality, expose only the "
                    "specific API via a `contextBridge` preload script instead.",
                )
            if any(js_code_matches(_NODE_SUBFRAMES, text, mask, anchor=_start)):
                add(
                    f,
                    "high",
                    "node-integration-in-subframes",
                    "Electron enables Node.js integration in sub-frames or workers",
                    "`nodeIntegrationInSubFrames`/`nodeIntegrationInWorker: true` hands Node.js APIs "
                    "to every embedded frame or worker, so any XSS or third-party iframe becomes RCE.",
                    "Remove the flag; keep Node access in the main process or a preload "
                    "`contextBridge` API.",
                )
        return out

    @staticmethod
    def _scan_webview(f: Path, raw: str, add: Callable[..., None]) -> None:
        text = _blank_html_comments(raw)
        if f.suffix.lower() in (".jsx", ".tsx"):
            text = strip_js_comments(text)
        if _WEBVIEW_NODE.search(text):
            add(
                f,
                "high",
                "webview-node-integration",
                "Electron <webview> enables Node.js integration",
                "A `<webview>` with `nodeintegration`/`nodeintegrationinsubframes` gives the "
                "embedded page Node.js APIs, so any content it loads can run code on the host.",
                "Drop the attribute and expose only what the guest needs through a preload script.",
            )

    @staticmethod
    def _scan_main_process(f: Path, text: str, mask: str, add: Callable[..., None]) -> None:
        if any(js_code_matches(_DANGEROUS_SWITCH, text, mask, anchor=_start)):
            add(
                f,
                "high",
                "dangerous-command-line-switch",
                "Electron appends a dangerous Chromium command-line switch",
                "This `appendSwitch`/`appendArgument` call turns off a Chromium protection "
                "(certificate checks, same-origin policy, sandbox, mixed-content blocking, file "
                "access rules) or opens a remote debugging port for the whole app.",
                "Remove the switch from production code paths; for local debugging gate it behind "
                "a dev-only build flag.",
            )
        if any(js_code_matches(_DISABLE_WARNINGS, text, mask, anchor=_start, literal_ok=True)):
            add(
                f,
                "low",
                "security-warnings-disabled",
                "Electron security warnings are switched off",
                "`ELECTRON_DISABLE_SECURITY_WARNINGS` hides Electron's own console warnings about "
                "insecure settings, so misconfigurations stop being reported.",
                "Remove the variable and fix the warnings it was hiding.",
            )
        if _unconditional_accept(_CERT_ERROR_HANDLER, _ACCEPT_TRUE, text, mask) or _unconditional_accept(
            _CERT_VERIFY_PROC, _ACCEPT_ZERO, text, mask
        ):
            add(
                f,
                "high",
                "certificate-error-accept",
                "Electron accepts every TLS certificate error",
                "This `certificate-error` handler or `setCertificateVerifyProc` callback accepts "
                "the certificate without checking it, so any network attacker can impersonate a "
                "server.",
                "Reject by default (`callback(false)` / `callback(-3)`); if a dev host must be "
                "trusted, compare the exact host and pinned fingerprint before accepting.",
            )
        for m in js_code_matches(_PERMISSION_GRANT_ALL, text, mask, anchor=_start):
            if m.group(1) == m.group(2):
                add(
                    f,
                    "medium",
                    "permission-handler-grant-all",
                    "Electron grants every permission request",
                    "This `setPermissionRequestHandler` only calls its callback with `true`, so any "
                    "page can use the camera, microphone, geolocation and notifications.",
                    "Allow only the specific permissions and origins the app needs and answer "
                    "`false` for the rest.",
                )
                break
