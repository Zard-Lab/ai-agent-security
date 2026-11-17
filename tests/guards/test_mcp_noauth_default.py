"""Tests for McpNoauthDefaultGuard — planted-violation + FP-bait."""
from __future__ import annotations

import pytest

from agentsec.guards.mcp_noauth_default import McpNoauthDefaultGuard
from tests._timing import assert_growth
from tests.guards._common import *  # noqa: F401,F403


def _mcp_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp", "python"}, python_dirs=["."])


def test_fail_open_auth_fires(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "from mcp.server import Server\n"
        "import os\n\n"
        "SECRET = os.environ.get('MCP_SECRET')\n\n"
        "def is_authorized(token):\n"
        "    if not SECRET:\n"
        "        return True\n"
        "    return token == SECRET\n",
        encoding="utf-8",
    )
    findings = McpNoauthDefaultGuard().run(tmp_path, _mcp_prof(tmp_path))
    hit = next(f for f in findings if f.rule == "mcp-noauth-default/fail-open-auth")
    assert hit.severity == "critical"


def test_fail_closed_auth_is_safe(tmp_path: Path) -> None:
    """FP-bait: an auth function that returns False (fails closed) on empty secret is safe."""
    (tmp_path / "server.py").write_text(
        "from mcp.server import Server\n"
        "import os\n\n"
        "SECRET = os.environ.get('MCP_SECRET')\n\n"
        "def is_authorized(token):\n"
        "    if not SECRET:\n"
        "        return False\n"
        "    return token == SECRET\n",
        encoding="utf-8",
    )
    findings = McpNoauthDefaultGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_required_secret_no_default_is_safe(tmp_path: Path) -> None:
    """FP-bait: os.environ['X'] with no default raises KeyError if unset -- not a fail-open shape."""
    (tmp_path / "server.py").write_text(
        "from mcp.server import Server\n"
        "import os\n\n"
        "SECRET = os.environ['MCP_SECRET']\n\n"
        "def is_authorized(token):\n"
        "    return token == SECRET\n",
        encoding="utf-8",
    )
    findings = McpNoauthDefaultGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_placeholder_secret_literal_fires(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "from mcp.server import Server\n"
        "MCP_SECRET = 'changeme'\n",
        encoding="utf-8",
    )
    findings = McpNoauthDefaultGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-noauth-default/placeholder-secret" for f in findings)


def test_real_secret_literal_is_safe(tmp_path: Path) -> None:
    """FP-bait: a non-placeholder literal secret value is a different, unrelated problem
    (hardcoded-secret guards' job), not this shape."""
    (tmp_path / "server.py").write_text(
        "from mcp.server import Server\n"
        "MCP_SECRET = 'sk-live-abcdefghijklmnopqrstuvwxyz'\n",
        encoding="utf-8",
    )
    findings = McpNoauthDefaultGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_empty_default_env_secret_fires(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "from mcp.server import Server\n"
        "import os\n"
        "MCP_SECRET = os.environ.get('MCP_SECRET', '')\n",
        encoding="utf-8",
    )
    findings = McpNoauthDefaultGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-noauth-default/empty-default-secret" for f in findings)


def test_warn_only_gate_on_nonloopback_bind_fires(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "from mcp.server import Server\n"
        "import os, logging\n"
        "logger = logging.getLogger(__name__)\n"
        "SECRET = os.environ.get('MCP_SECRET')\n"
        "if not SECRET:\n"
        "    logger.warning('no secret configured')\n"
        "uvicorn.run(app, host='0.0.0.0')\n",
        encoding="utf-8",
    )
    findings = McpNoauthDefaultGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-noauth-default/warn-only-auth-gate" for f in findings)


def test_warn_only_gate_on_loopback_bind_is_safe(tmp_path: Path) -> None:
    """FP-bait: the same warn-only gate on a loopback-bound server is out of scope."""
    (tmp_path / "server.py").write_text(
        "from mcp.server import Server\n"
        "import os, logging\n"
        "logger = logging.getLogger(__name__)\n"
        "SECRET = os.environ.get('MCP_SECRET')\n"
        "if not SECRET:\n"
        "    logger.warning('no secret configured')\n"
        "uvicorn.run(app, host='127.0.0.1')\n",
        encoding="utf-8",
    )
    findings = McpNoauthDefaultGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_auth_disabled_config_fires(tmp_path: Path) -> None:
    (tmp_path / "mcp-config.yaml").write_text(
        "mcp:\n  bind: 0.0.0.0\nauth:\n  enabled: false\n",
        encoding="utf-8",
    )
    findings = McpNoauthDefaultGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-noauth-default/auth-disabled-config" for f in findings)


def test_placeholder_secret_config_fires(tmp_path: Path) -> None:
    (tmp_path / "mcp-config.json").write_text(
        '{"mcp": true, "bind": "0.0.0.0", "api_key": "changeme"}\n',
        encoding="utf-8",
    )
    findings = McpNoauthDefaultGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-noauth-default/placeholder-secret-config" for f in findings)


def test_json_schema_document_is_not_a_live_config(tmp_path: Path) -> None:
    # (Dean's review corpus-scan review): reproduces the real FP found on
    # fastmcp's docs/assets/schemas/mcp_server_config/v1.json -- a JSON Schema's own
    # "examples" array illustrating the env-var dict's SHAPE ("API_KEY": "secret") is not a
    # deployed credential, and "0.0.0.0" inside a field's own description/examples is not a
    # live bind address. Same content that would fire `placeholder-secret-config` without
    # the $schema/$defs/$id/$ref exclusion.
    (tmp_path / "mcp_server_config_schema.json").write_text(
        '{\n'
        '  "$defs": {"Deployment": {"type": "object"}},\n'
        '  "$id": "https://example.com/schemas/mcp_server_config/v1.json",\n'
        '  "title": "McpServerConfig",\n'
        '  "type": "object",\n'
        '  "properties": {\n'
        '    "host": {"description": "Bind address, e.g. 0.0.0.0", "type": "string"},\n'
        '    "env": {\n'
        '      "description": "Environment variables for the mcp server process",\n'
        '      "examples": [{"api_key": "changeme"}]\n'
        '    }\n'
        '  }\n'
        '}\n',
        encoding="utf-8",
    )
    assert McpNoauthDefaultGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_pragma_suppresses_finding(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "# security: allow-mcp-noauth-default\n"
        "from mcp.server import Server\n"
        "import os\n"
        "SECRET = os.environ.get('MCP_SECRET')\n"
        "def is_authorized(token):\n"
        "    if not SECRET:\n"
        "        return True\n"
        "    return token == SECRET\n",
        encoding="utf-8",
    )
    findings = McpNoauthDefaultGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_guard_not_applicable_without_mcp_feature(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert McpNoauthDefaultGuard().applies(prof) is False


# --------------------------------------------------------------------------- PR #963 review round
def _run_cfg(tmp_path: Path, name: str, text: str) -> list[str]:
    (tmp_path / name).write_text(text, encoding="utf-8")
    return [f.rule for f in McpNoauthDefaultGuard().run(tmp_path, _mcp_prof(tmp_path))]


_LIVE_CFG = '{"mcp": true, "bind": "0.0.0.0", "api_key": "changeme"'


def test_real_config_carrying_dollar_schema_still_fires(tmp_path: Path) -> None:
    """The `$schema` exclusion used to drop the whole file. Editors want `$schema` in real configs
    (schemastore, VS Code / Claude Code settings), so a live config that carries it must fire."""
    rules = _run_cfg(
        tmp_path,
        "config.json",
        _LIVE_CFG + ', "$schema": "https://json.schemastore.org/mcp-config.json"}',
    )
    assert rules == ["mcp-noauth-default/placeholder-secret-config"]


def test_real_config_with_json_schema_org_dollar_schema_still_fires(tmp_path: Path) -> None:
    """Even a json-schema.org `$schema` is not enough on its own: no `properties`/`$defs` means it
    describes no fields, so it is a config."""
    rules = _run_cfg(
        tmp_path,
        "config.json",
        _LIVE_CFG + ', "$schema": "https://json-schema.org/draft/2020-12/schema"}',
    )
    assert rules == ["mcp-noauth-default/placeholder-secret-config"]


def test_schema_document_with_meta_schema_examples_and_defaults_is_silent(tmp_path: Path) -> None:
    """FP-bait (fastmcp docs schema shape): a real schema document with a json-schema.org
    `$schema`, `examples` AND `default` subtrees carrying placeholder secrets stays silent."""
    text = (
        '{"$schema": "https://json-schema.org/draft/2020-12/schema",\n'
        ' "title": "mcp server config", "type": "object",\n'
        ' "properties": {\n'
        '   "host": {"type": "string", "description": "bind, e.g. 0.0.0.0"},\n'
        '   "env": {"type": "object", "default": {"API_KEY": "secret"},\n'
        '           "examples": [{"API_KEY": "secret"}]}\n'
        ' }}\n'
    )
    assert _run_cfg(tmp_path, "mcp_server_config.json", text) == []


def test_schema_document_still_reports_secret_outside_examples(tmp_path: Path) -> None:
    """Narrowing pin: only the `examples`/`default` subtrees are skipped. A placeholder secret that
    sits elsewhere in the same file (here a top-level key) is still reported."""
    text = (
        '{"$schema": "https://json-schema.org/draft/2020-12/schema",\n'
        ' "mcp": true, "properties": {"host": {"description": "bind 0.0.0.0"}},\n'
        ' "api_key": "changeme"}\n'
    )
    assert _run_cfg(tmp_path, "config.json", text) == ["mcp-noauth-default/placeholder-secret-config"]


def test_property_named_default_is_not_stripped(tmp_path: Path) -> None:
    """A schema property literally called `default` is a field definition, not an example value."""
    text = (
        '{"mcp": true, "$defs": {}, "properties": {"default": {"api_key": "changeme"}},\n'
        ' "host": "0.0.0.0"}\n'
    )
    assert _run_cfg(tmp_path, "x.json", text) == ["mcp-noauth-default/placeholder-secret-config"]


def test_auth_disabled_config_fires_on_quoted_json_nested(tmp_path: Path) -> None:
    """The guard's own docstring example: quoted JSON keys never matched."""
    rules = _run_cfg(
        tmp_path,
        "mcp.json",
        '{"mcpServers": {"app": {"url": "http://0.0.0.0:8080/mcp", "auth": {"enabled": false}}}}',
    )
    assert rules == ["mcp-noauth-default/auth-disabled-config"]


def test_auth_disabled_config_fires_on_quoted_json_flag(tmp_path: Path) -> None:
    rules = _run_cfg(tmp_path, "mcp.json", '{"mcp": true, "bind": "0.0.0.0", "disable_auth": true}')
    assert rules == ["mcp-noauth-default/auth-disabled-config"]


def test_auth_disabled_config_yaml_still_fires(tmp_path: Path) -> None:
    rules = _run_cfg(tmp_path, "mcp.yaml", "mcp: true\nbind: 0.0.0.0\nauth:\n  enabled: false\n")
    assert rules == ["mcp-noauth-default/auth-disabled-config"]


def test_auth_config_with_sibling_disabled_feature_is_silent(tmp_path: Path) -> None:
    """FP-bait for the widened quoted-key match: `auth` is configured, and an unrelated sibling
    object switches something else off. The look-through to `enabled` must not cross a brace."""
    text = (
        '{"mcp": true, "bind": "0.0.0.0", "auth": {"type": "bearer"}, '
        '"cache": {"enabled": false}, "disable_auth": false}'
    )
    assert _run_cfg(tmp_path, "mcp.json", text) == []


def test_auth_enabled_true_json_is_silent(tmp_path: Path) -> None:
    text = '{"mcp": true, "bind": "0.0.0.0", "auth": {"enabled": true}, "no_auth": false}'
    assert _run_cfg(tmp_path, "mcp.json", text) == []


def test_config_scan_stays_linear_on_long_near_miss_run(tmp_path: Path) -> None:
    """Performance pin: `_CFG_AUTH_DISABLED_RE`'s lazy prefix measured ~4x per doubling on a benign
    `auth_something_unrelated ...` run inside a matching config (14 KB took seconds, ~60 KB
    exhausted the 60 s per-guard budget). Growth ratio, not wall clock (tests/_timing.py)."""

    def scan(n: int) -> None:
        root = tmp_path / str(n)
        root.mkdir(exist_ok=True)
        body = "auth_something_unrelated_value_here " * n
        (root / "c.json").write_text(
            '{"mcp": true, "bind": "0.0.0.0", "notes": "' + body + '"}', encoding="utf-8"
        )
        assert McpNoauthDefaultGuard().run(root, _mcp_prof(root)) == []

    assert_growth(scan, [400, 800, 1600, 3200], expected="linear")


def test_config_scan_stays_linear_on_long_word_run(tmp_path: Path) -> None:
    """Same pin for `_CFG_SECRET_KV_RE`: a long `[\\w-]` run with no secret keyword used to be
    re-scanned from every position inside it."""

    def scan(n: int) -> None:
        root = tmp_path / str(n)
        root.mkdir(exist_ok=True)
        (root / "c.json").write_text(
            '{"mcp": true, "bind": "0.0.0.0", "notes": "' + "a" * n + '"}', encoding="utf-8"
        )
        assert McpNoauthDefaultGuard().run(root, _mcp_prof(root)) == []

    assert_growth(scan, [5_000, 20_000, 80_000, 320_000], expected="linear")


def test_deeply_nested_schema_file_does_not_zero_the_guard(tmp_path: Path) -> None:
    """A hostile deep-nesting JSON file raised RecursionError out of the loader and the whole guard
    was reported as errored, losing the real finding next to it."""
    (tmp_path / "deep.json").write_text('{"$schema": ' + '[' * 200_000 + ']' * 200_000 + "}", encoding="utf-8")
    rules = _run_cfg(tmp_path, "config.json", _LIVE_CFG + "}")
    assert rules == ["mcp-noauth-default/placeholder-secret-config"]


def test_mcp_noauth_default_pragma_quoted_in_a_string_does_not_suppress(tmp_path: Path) -> None:
    # #424 E6 (#1000): the .py site reads the Python comment view, so a docstring quoting the
    # pragma is content. Only a real `#` comment (`test_pragma_suppresses_finding`) opts out.
    (tmp_path / "server.py").write_text(
        '"""Opt out of this check: add # security: allow-mcp-noauth-default."""\n'
        "from mcp.server import Server\n"
        "import os\n"
        "SECRET = os.environ.get('MCP_SECRET')\n"
        "def is_authorized(token):\n"
        "    if not SECRET:\n"
        "        return True\n"
        "    return token == SECRET\n",
        encoding="utf-8",
    )
    findings = McpNoauthDefaultGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert [f.rule for f in findings] == ["mcp-noauth-default/fail-open-auth"]


_YAML_CFG = "mcp: true\nbind: 0.0.0.0\nauth:\n  enabled: false\n"


def test_mcp_noauth_default_pragma_comment_suppresses_yaml(tmp_path: Path) -> None:
    # #424 E6 (#1000): reach is unchanged. A real YAML `#` comment anywhere in the config still
    # silences the whole file (the same fixture fires without it, so this cannot pass vacuously).
    assert _run_cfg(tmp_path, "mcp.yaml", _YAML_CFG) == ["mcp-noauth-default/auth-disabled-config"]
    assert _run_cfg(tmp_path, "mcp.yaml", "# security: allow-mcp-noauth-default\n" + _YAML_CFG) == []


def test_mcp_noauth_default_pragma_quoted_in_a_string_does_not_suppress_yaml(tmp_path: Path) -> None:
    # #424 E6 (#1000): the config site reads YAML under the yaml comment view, so a quoted scalar
    # quoting the pragma is content. Only a real comment (`..._pragma_comment_suppresses_yaml`) opts out.
    rules = _run_cfg(
        tmp_path,
        "mcp.yaml",
        'description: "opt out with # security: allow-mcp-noauth-default"\n' + _YAML_CFG,
    )
    assert rules == ["mcp-noauth-default/auth-disabled-config"]


_TOML_CFG = 'mcp = true\nbind = "0.0.0.0"\napi_key = "changeme"\n'


def test_mcp_noauth_default_pragma_comment_suppresses_toml(tmp_path: Path) -> None:
    # #424 E6 (#1000): reach is unchanged. A real TOML `#` comment anywhere in the config still
    # silences the whole file (the same fixture fires without it, so this cannot pass vacuously).
    assert _run_cfg(tmp_path, "mcp.toml", _TOML_CFG) == ["mcp-noauth-default/placeholder-secret-config"]
    assert _run_cfg(tmp_path, "mcp.toml", "# security: allow-mcp-noauth-default\n" + _TOML_CFG) == []


def test_mcp_noauth_default_pragma_quoted_in_a_string_does_not_suppress_toml(tmp_path: Path) -> None:
    # #424 E6 (#1000): TOML reads under the quote-aware hash view, so a `#` inside a string value is
    # content. Only a real comment (`..._pragma_comment_suppresses_toml`) opts out.
    rules = _run_cfg(
        tmp_path,
        "mcp.toml",
        'description = "opt out with # security: allow-mcp-noauth-default"\n' + _TOML_CFG,
    )
    assert rules == ["mcp-noauth-default/placeholder-secret-config"]


@pytest.mark.parametrize("prefix", _VENDORED_PREFIXES)
def test_vendored_copy_is_never_scanned_but_first_party_still_fires(tmp_path: Path, prefix: str) -> None:
    """#1042: the Python half enumerates through the shared walker, not a bare `rglob`, so a
    fail-open `is_authorized` inside `.venv/site-packages` is never reported, while the same code
    in first-party source still fires."""
    plant = McpNoauthDefaultGuard.canary_plant
    assert plant is not None
    canary = plant.files["server.py"]
    _plant(tmp_path, f"{prefix}/server.py", canary)
    _plant(tmp_path, "app/server.py", canary)
    findings = McpNoauthDefaultGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert {f.location.replace("\\", "/").rsplit(":", 1)[0] for f in findings} == {"app/server.py"}


def test_gitignored_python_file_is_not_scanned_but_a_tracked_neighbour_still_fires(tmp_path: Path) -> None:
    """#1044 review M1: through the shared walker this guard honours `.gitignore`, like every sibling
    Python guard (the old `rglob` did not). Pinned in both directions: the ignored file is silent, a
    tracked file with the same code in the same dir still fires."""
    plant = McpNoauthDefaultGuard.canary_plant
    assert plant is not None
    canary = plant.files["server.py"]
    _plant(tmp_path, ".gitignore", "app/scratch_server.py\n")
    _plant(tmp_path, "app/scratch_server.py", canary)
    _plant(tmp_path, "app/server.py", canary)
    findings = McpNoauthDefaultGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert {f.location.replace("\\", "/").rsplit(":", 1)[0] for f in findings} == {"app/server.py"}
