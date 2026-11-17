from __future__ import annotations

import pytest

from agentsec.guards.electron_security_misconfig import ElectronSecurityMisconfigGuard
from tests.guards._common import *  # noqa: F401,F403


def test_electron_security_misconfig_flags_all_dangerous_flags(tmp_path: Path) -> None:
    (tmp_path / "main.js").write_text(
        "const { BrowserWindow } = require('electron');\n"
        "const win = new BrowserWindow({\n"
        "  webPreferences: {\n"
        "    nodeIntegration: true,\n"
        "    contextIsolation: false,\n"
        "    webSecurity: false,\n"
        "    allowRunningInsecureContent: true,\n"
        "    enableBlinkFeatures: 'ExperimentalCanvasFeatures',\n"
        "    experimentalFeatures: true\n"
        "  }\n"
        "});\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"electron"})
    findings = ElectronSecurityMisconfigGuard().run(tmp_path, profile)
    rules = {f.rule for f in findings}
    assert rules == {
        "electron-security-misconfig/websecurity-disabled",
        "electron-security-misconfig/nodeintegration-enabled",
        "electron-security-misconfig/contextisolation-disabled",
        "electron-security-misconfig/allow-insecure-content",
        "electron-security-misconfig/blink-features-enabled",
        "electron-security-misconfig/experimental-features-enabled",
    }
    severities = {f.rule: f.severity for f in findings}
    assert severities["electron-security-misconfig/websecurity-disabled"] == "critical"
    assert severities["electron-security-misconfig/nodeintegration-enabled"] == "critical"
    assert severities["electron-security-misconfig/contextisolation-disabled"] == "critical"
    assert severities["electron-security-misconfig/allow-insecure-content"] == "high"
    assert severities["electron-security-misconfig/blink-features-enabled"] == "medium"
    assert severities["electron-security-misconfig/experimental-features-enabled"] == "medium"


def test_electron_security_misconfig_silent_with_safe_defaults(tmp_path: Path) -> None:
    (tmp_path / "main.js").write_text(
        "const { BrowserWindow } = require('electron');\n"
        "const win = new BrowserWindow({\n"
        "  webPreferences: {\n"
        "    nodeIntegration: false,\n"
        "    contextIsolation: true,\n"
        "    webSecurity: true,\n"
        "    sandbox: true\n"
        "  }\n"
        "});\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"electron"})
    assert ElectronSecurityMisconfigGuard().run(tmp_path, profile) == []


def test_electron_security_misconfig_silent_without_browserwindow_context(tmp_path: Path) -> None:
    (tmp_path / "config.js").write_text(
        "// unrelated module, no BrowserWindow or webPreferences anywhere\n"
        "module.exports = { nodeIntegration: true, webSecurity: false };\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"electron"})
    assert ElectronSecurityMisconfigGuard().run(tmp_path, profile) == []


def test_electron_security_misconfig_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "main.js").write_text(
        "// security: allow-electron-security-misconfig\n"
        "const win = new BrowserWindow({\n"
        "  webPreferences: { nodeIntegration: true, webSecurity: false }\n"
        "});\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"electron"})
    assert ElectronSecurityMisconfigGuard().run(tmp_path, profile) == []


def test_electron_security_misconfig_not_applies_without_feature(tmp_path: Path) -> None:
    (tmp_path / "main.js").write_text(
        "const win = new BrowserWindow({\n"
        "  webPreferences: { nodeIntegration: true, webSecurity: false }\n"
        "});\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features=set())
    assert not ElectronSecurityMisconfigGuard().applies(profile)


def test_electron_security_misconfig_silent_on_commented_flag(tmp_path: Path) -> None:
    # Regression (PR #407 review #1): a commented-out dangerous flag must NOT emit a CRITICAL FP.
    (tmp_path / "main.js").write_text(
        "new BrowserWindow({ webPreferences: { nodeIntegration: false } });\n"
        "// nodeIntegration: true was here before the fix\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"electron"})
    assert ElectronSecurityMisconfigGuard().run(tmp_path, profile) == []


def test_electron_security_misconfig_flags_remote_module_and_sandbox(tmp_path: Path) -> None:
    # Regression (PR #407 review #3): enableRemoteModule (RCE vector) and sandbox:false are now
    # detected — previously the code claimed them in docs but implemented other flags.
    (tmp_path / "main.js").write_text(
        "new BrowserWindow({ webPreferences: { sandbox: false, enableRemoteModule: true } });\n",
        encoding="utf-8",
    )
    findings = ElectronSecurityMisconfigGuard().run(tmp_path, mkprofile(tmp_path, features={"electron"}))
    slugs = {f.rule for f in findings}
    assert "electron-security-misconfig/remote-module-enabled" in slugs
    assert "electron-security-misconfig/sandbox-disabled" in slugs


def test_electron_security_misconfig_regex_literal_does_not_swallow_flag(tmp_path: Path) -> None:
    # Regression (PR #407 fixup review, CRITICAL): a regex literal earlier on the line (`/\//g`, a
    # path-normalizer common in Express) must NOT cause the CRITICAL nodeIntegration flag to be
    # blanked away as a comment.
    (tmp_path / "main.js").write_text(
        "const re = /\\//g; "
        "new BrowserWindow({ webPreferences: { nodeIntegration: true } });\n",
        encoding="utf-8",
    )
    findings = ElectronSecurityMisconfigGuard().run(tmp_path, mkprofile(tmp_path, features={"electron"}))
    assert any(f.rule == "electron-security-misconfig/nodeintegration-enabled" for f in findings)


def test_electron_security_misconfig_regex_after_if_paren_does_not_swallow_flag(tmp_path: Path) -> None:
    # Regression (PR #407 r3, CRITICAL): a regex right after an `if (...)` head must not be misread as
    # division and blank the CRITICAL flag on the same line.
    (tmp_path / "main.js").write_text(
        "if (isApi) /\\//.test(req.path); "
        "new BrowserWindow({ webPreferences: { nodeIntegration: true } });\n",
        encoding="utf-8",
    )
    findings = ElectronSecurityMisconfigGuard().run(tmp_path, mkprofile(tmp_path, features={"electron"}))
    assert any(f.rule == "electron-security-misconfig/nodeintegration-enabled" for f in findings)


# --- #1055: a flag and the BrowserWindow context count only when they are live code ---------------

_SAFE_WINDOW = "const win = new BrowserWindow({ webPreferences: { sandbox: true } });\n"
_UNSAFE_WINDOW = "new BrowserWindow({ webPreferences: { nodeIntegration: true } })"


def _run_electron(tmp_path: Path, src: str) -> list[str]:
    (tmp_path / "main.js").write_text(src, encoding="utf-8")
    return [f.rule for f in ElectronSecurityMisconfigGuard().run(tmp_path, mkprofile(tmp_path, features={"electron"}))]


@pytest.mark.parametrize(
    "src",
    [
        # The RCA's FP: one warning string next to a safe window fired two CRITICALs.
        _SAFE_WINDOW + "warn('never set nodeIntegration: true or contextIsolation: false');\n",
        _SAFE_WINDOW + "warn(`never set nodeIntegration: true or contextIsolation: false`);\n",
        # The context only in a string does not open the file for a bare options object.
        "log('new BrowserWindow( takes webPreferences: {...}');\nconst prefs = { nodeIntegration: true };\n",
    ],
)
def test_electron_flag_or_context_spelled_in_a_string_stays_silent(tmp_path: Path, src: str) -> None:
    assert _run_electron(tmp_path, src) == []


@pytest.mark.parametrize(
    "src",
    [
        "const win = " + _UNSAFE_WINDOW + ";\n",
        # The real window nested in a `${...}` substitution is code: the shortcut-separating case.
        "const label = `${" + _UNSAFE_WINDOW + "}`;\n",
        # A quoted copy earlier on the line must not hide the real flag after it.
        "warn('nodeIntegration: true'); const win = " + _UNSAFE_WINDOW + ";\n",
    ],
)
def test_electron_real_flag_still_fires(tmp_path: Path, src: str) -> None:
    assert _run_electron(tmp_path, src) == ["electron-security-misconfig/nodeintegration-enabled"]


def test_electron_pragma_still_suppresses_a_code_anchored_flag(tmp_path: Path) -> None:
    src = "warn('nodeIntegration: true'); const win = " + _UNSAFE_WINDOW + ";\n"
    assert len(_run_electron(tmp_path, src)) == 1
    assert _run_electron(tmp_path, src + "// security: allow-electron-security-misconfig\n") == []
