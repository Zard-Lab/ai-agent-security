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
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity

from .base import (
    CanaryPlant,
    Guard,
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
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "electron" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            raw = read(f)
            if pragma_present(_PRAGMA, raw, dialect="js"):
                continue
            # Blank comments (string-aware) so a commented-out `nodeIntegration: true` — the most
            # trust-damaging place for a CRITICAL false positive — cannot fire (PR #407 review).
            text = strip_js_comments(raw)
            if not _CONTEXT.search(text):
                continue
            # The context and each flag must be live code (#1055): a flag spelled out in a warning
            # string is not a setting. Every match is tried, so a quoted copy cannot hide a real one.
            mask = strip_js_comments(raw, strip_strings=True, keep_substitutions=True)
            if not any(js_code_matches(_CONTEXT, text, mask, anchor=_context_end)):
                continue
            for pattern, slug, severity, why in _RULES:
                if not any(js_code_matches(pattern, text, mask, anchor=_flag_colon)):
                    continue
                out.append(
                    Finding(
                        check_id=self.id,
                        severity=severity,
                        title="Electron webPreferences disables a security control",
                        location=f"{rel(root, f)}",
                        message=f"This Electron `webPreferences` block {why}.",
                        remediation=(
                            "Remove the dangerous override and use Electron's secure defaults "
                            "(contextIsolation: true, nodeIntegration: false, sandbox: true). If a "
                            "renderer genuinely needs Node.js functionality, expose only the "
                            "specific API via a `contextBridge` preload script instead. Suppress a "
                            "reviewed, intentional case with "
                            "`// security: allow-electron-security-misconfig`."
                        ),
                        rule=f"electron-security-misconfig/{slug}",
                        standards=["OWASP:A05"],
                    )
                )
        return out
