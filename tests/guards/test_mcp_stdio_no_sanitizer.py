"""Tests for McpStdioNoSanitizerGuard — planted-violation + FP-bait."""
from __future__ import annotations

from agentsec.guards.mcp_stdio_no_sanitizer import McpStdioNoSanitizerGuard
from tests.guards._common import *  # noqa: F401,F403


def _mcp_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp", "python"}, python_dirs=["."])


def test_stdio_with_no_sanitizer_fires(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["mcp"]\n', encoding="utf-8",
    )
    (tmp_path / "server.py").write_text(
        "import subprocess\n"
        "from mcp.server.stdio import StdioServerTransport\n\n"
        "def run_tool(cmd):\n"
        "    transport = StdioServerTransport()\n"
        "    transport.serve()\n"
        "    subprocess.run(cmd)\n",
        encoding="utf-8",
    )
    findings = McpStdioNoSanitizerGuard().run(tmp_path, _mcp_prof(tmp_path))
    hit = next(f for f in findings if f.rule == "mcp-stdio-no-sanitizer/no-sanitizer")
    assert hit.severity == "medium"


def test_shlex_sanitizer_present_is_safe(tmp_path: Path) -> None:
    """FP-bait: a real shlex.quote call anywhere in a STDIO-using file clears it."""
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["mcp"]\n', encoding="utf-8",
    )
    (tmp_path / "server.py").write_text(
        "import shlex, subprocess\n"
        "from mcp.server.stdio import StdioServerTransport\n\n"
        "def run(cmd):\n"
        "    safe = shlex.quote(cmd)\n"
        "    transport = StdioServerTransport()\n"
        "    transport.serve()\n"
        "    subprocess.run(safe)\n",
        encoding="utf-8",
    )
    findings = McpStdioNoSanitizerGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_allowlist_marker_present_is_safe(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["mcp"]\n', encoding="utf-8",
    )
    (tmp_path / "server.py").write_text(
        "import subprocess\n"
        "from mcp.server.stdio import StdioServerTransport\n\n"
        "ALLOWED_COMMANDS = {'ls', 'cat'}\n"
        "transport = StdioServerTransport()\n"
        "subprocess.run(ALLOWED_COMMANDS)\n",
        encoding="utf-8",
    )
    findings = McpStdioNoSanitizerGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_http_transport_optout_is_safe(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["mcp"]\n', encoding="utf-8",
    )
    (tmp_path / "server.py").write_text(
        "import subprocess\n"
        "from mcp.server.stdio import StdioServerTransport\n\n"
        "transports = ['http']\n"
        "transport = StdioServerTransport()\n"
        "subprocess.run(['tool'])\n",
        encoding="utf-8",
    )
    findings = McpStdioNoSanitizerGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_sdk_not_declared_is_safe(tmp_path: Path) -> None:
    """FP-bait: the STDIO marker string appears, but no manifest declares the SDK at all
    (e.g. a false-positive-shaped identifier in unrelated code) -- no finding."""
    (tmp_path / "server.py").write_text(
        "class StdioServerTransport:\n    pass\n", encoding="utf-8",
    )
    findings = McpStdioNoSanitizerGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_no_stdio_usage_is_safe(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["mcp"]\n', encoding="utf-8",
    )
    (tmp_path / "server.py").write_text(
        "from mcp.server.sse import SSEServerTransport\n", encoding="utf-8",
    )
    findings = McpStdioNoSanitizerGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_pragma_suppresses_finding(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["mcp"]\n', encoding="utf-8",
    )
    (tmp_path / "server.py").write_text(
        "# security: allow-mcp-stdio-no-sanitizer\n"
        "import subprocess\n"
        "from mcp.server.stdio import StdioServerTransport\n"
        "transport = StdioServerTransport()\n"
        "subprocess.run(['tool'])\n",
        encoding="utf-8",
    )
    findings = McpStdioNoSanitizerGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_guard_not_applicable_without_mcp_feature(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert McpStdioNoSanitizerGuard().applies(prof) is False


# --------------------------------------------------------------------------- PR #963 review round
_STDIO_SERVER = (
    "from mcp.server.stdio import StdioServerTransport\n"
    "from sanitize import quote_arg\n\n"
    "transport = StdioServerTransport()\n"
    "import subprocess\n\n"
    "def run_tool(cmd):\n"
    "    subprocess.run([cmd])\n"
)


def _repo(tmp_path: Path, files: dict[str, str]) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["mcp"]\n', encoding="utf-8"
    )
    for name, text in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _run(tmp_path: Path) -> list[str]:
    found = McpStdioNoSanitizerGuard().run(tmp_path, _mcp_prof(tmp_path))
    return [f.location.replace("\\", "/") for f in found]


def test_sanitizer_in_a_different_file_than_the_stdio_server_clears_it(tmp_path: Path) -> None:
    """The review's repro: `shlex.quote` lives in `sanitize.py`, which the STDIO `server.py` imports.
    The docs say the whole repo is searched, so this is covered."""
    _repo(tmp_path, {
        "server.py": _STDIO_SERVER,
        "sanitize.py": "import shlex\n\ndef quote_arg(x):\n    return shlex.quote(x)\n",
    })
    assert _run(tmp_path) == []


def test_without_the_helper_module_the_same_server_still_fires(tmp_path: Path) -> None:
    _repo(tmp_path, {"server.py": _STDIO_SERVER})
    assert _run(tmp_path) == ["server.py:1"]


def test_sanitizer_only_in_a_test_file_does_not_vouch_for_production(tmp_path: Path) -> None:
    """Narrowing pin: a `shlex.split` in a test is not a control on the production server."""
    _repo(tmp_path, {
        "server.py": _STDIO_SERVER,
        "tests/test_helpers.py": "import shlex\n\ndef test_x():\n    assert shlex.split('a b')\n",
    })
    assert _run(tmp_path) == ["server.py:1"]


def test_web_allowlists_elsewhere_are_not_an_argv_control(tmp_path: Path) -> None:
    """FP-bait for the whole-repo widening: `ALLOWED_HOSTS` / `ALLOWED_ORIGINS` are not sanitizers."""
    _repo(tmp_path, {
        "server.py": _STDIO_SERVER,
        "settings.py": "ALLOWED_HOSTS = ['*']\nALLOWED_ORIGINS = []\nWHITELIST_CORS_ORIGINS = []\n",
    })
    assert _run(tmp_path) == ["server.py:1"]


def test_command_allowlist_in_another_file_clears_it(tmp_path: Path) -> None:
    _repo(tmp_path, {
        "server.py": _STDIO_SERVER,
        "policy.py": "ALLOWED_BINARIES = ('git', 'ls')\n",
    })
    assert _run(tmp_path) == []


def test_config_file_stdio_opt_out_clears_it(tmp_path: Path) -> None:
    _repo(tmp_path, {"server.py": _STDIO_SERVER, "config/mcp.yaml": "stdio_disabled: true\n"})
    assert _run(tmp_path) == []


def test_pragma_in_a_test_or_example_path_still_counts(tmp_path: Path) -> None:
    """A user's own opt-out is honoured wherever it sits (CLAUDE.md rule 4)."""
    _repo(tmp_path, {
        "server.py": _STDIO_SERVER,
        "examples/NOTES.py": "# security: allow-mcp-stdio-no-sanitizer\n",
    })
    assert _run(tmp_path) == []


def test_monorepo_sanitizer_in_one_package_does_not_vouch_for_another(tmp_path: Path) -> None:
    """Each package with a manifest declaring the SDK is its own project: `pkg_a` sanitizes,
    `pkg_b` does not, so only `pkg_b` fires."""
    manifest = '[project]\nname = "x"\ndependencies = ["mcp"]\n'
    for pkg in ("pkg_a", "pkg_b"):
        (tmp_path / pkg).mkdir()
        (tmp_path / pkg / "pyproject.toml").write_text(manifest, encoding="utf-8")
        (tmp_path / pkg / "server.py").write_text(_STDIO_SERVER, encoding="utf-8")
    (tmp_path / "pkg_a" / "sanitize.py").write_text("import shlex\nq = shlex.quote\nx = shlex.quote('a')\n", encoding="utf-8")
    assert _run(tmp_path) == ["pkg_b/server.py:1"]


def test_manifest_under_a_test_path_does_not_create_a_project(tmp_path: Path) -> None:
    """A fixture manifest declaring the SDK must not make an undeclared repo scannable."""
    (tmp_path / "tests" / "fixtures").mkdir(parents=True)
    (tmp_path / "tests" / "fixtures" / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["mcp"]\n', encoding="utf-8"
    )
    (tmp_path / "server.py").write_text(_STDIO_SERVER, encoding="utf-8")
    assert _run(tmp_path) == []


def test_finding_line_points_at_the_stdio_marker(tmp_path: Path) -> None:
    _repo(tmp_path, {
        "server.py": "import os\n\n\nfrom mcp.server.stdio import stdio_server\n",
        "other.py": "def run():\n    pass\n\n\nx = 1\n\nstdio_client(1)\n",
    })
    assert sorted(_run(tmp_path)) == ["other.py:7", "server.py:4"]


def test_server_only_with_no_spawn_anywhere_is_safe(tmp_path: Path) -> None:
    """The review's repro (a corpus's own reference implementations, e.g. the `time` server):
    a STDIO server that implements every tool in-process, never spawning a subprocess, builds no
    argv to sanitize. Round-2's per-package scoping fix took this shape from 0 to 7 findings on a
    real corpus with none of them spawning anything."""
    _repo(tmp_path, {
        "server.py": (
            "from mcp.server.stdio import StdioServerTransport\n\n"
            "transport = StdioServerTransport()\n\n"
            "def get_current_time(tz):\n"
            "    import datetime\n"
            "    return datetime.datetime.now(tz).isoformat()\n"
        ),
    })
    assert _run(tmp_path) == []


def test_server_with_a_real_spawn_elsewhere_in_the_project_still_fires(tmp_path: Path) -> None:
    """Direction traded against: a real process-spawn call anywhere in the project is launcher
    evidence, even in a different file than the STDIO transport itself."""
    _repo(tmp_path, {
        "server.py": (
            "from mcp.server.stdio import StdioServerTransport\n\n"
            "transport = StdioServerTransport()\n"
        ),
        "tools.py": "import subprocess\n\ndef run_tool(cmd):\n    subprocess.run(cmd)\n",
    })
    assert _run(tmp_path) == ["server.py:1"]


def test_client_side_stdio_api_counts_as_launcher_evidence_with_no_spawn_call(tmp_path: Path) -> None:
    """A client-side STDIO API (`StdioClientTransport`/`stdio_client`/`StdioServerParameters`) IS
    the launcher: it passes a configured command to process creation by design, with no separate
    `subprocess`/`child_process` call visible in this project's own source."""
    _repo(tmp_path, {
        "client.py": (
            "from mcp.client.stdio import StdioServerParameters, stdio_client\n\n"
            "params = StdioServerParameters(command=cmd, args=args)\n"
        ),
    })
    assert _run(tmp_path) == ["client.py:1"]


def test_test_harness_that_launches_the_server_is_not_launcher_evidence(tmp_path: Path) -> None:
    """The review's repro (`modelcontextprotocol/servers`' filesystem and sequentialthinking
    packages): the server is server-only, and the only client-side STDIO API is in its own test
    harness, which launches the server under test. A test launching the product is not the
    product launching a configured command."""
    _repo(tmp_path, {
        "server.py": "from mcp.server.stdio import stdio_server\n\ndef now():\n    return 1\n",
        "tests/test_server.py": (
            "from mcp.client.stdio import StdioServerParameters, stdio_client\n\n"
            "params = StdioServerParameters(command='python', args=['server.py'])\n"
        ),
        "src/__tests__/server.test.ts": (
            'import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";\n'
        ),
    })
    assert _run(tmp_path) == []


def test_product_launcher_next_to_a_test_harness_still_fires(tmp_path: Path) -> None:
    """Direction traded against: skipping test paths for launcher evidence must not hide a real
    launcher in product source."""
    _repo(tmp_path, {
        "server.py": "from mcp.server.stdio import stdio_server\n\ndef now():\n    return 1\n",
        "tests/test_server.py": "from mcp.client.stdio import stdio_client\n",
        "launcher.py": "import subprocess\n\ndef run_tool(cmd):\n    subprocess.run(cmd)\n",
    })
    assert _run(tmp_path) == ["server.py:1"]


def test_deeply_nested_package_json_does_not_zero_the_guard(tmp_path: Path) -> None:
    """A hostile deep `package.json` used to raise RecursionError; the real STDIO finding survives."""
    _repo(tmp_path, {
        "server.py": _STDIO_SERVER,
        "sub/package.json": '{"dependencies": ' + '[' * 200_000 + ']' * 200_000 + "}",
    })
    assert _run(tmp_path) == ["server.py:1"]


# --------------------------------------------------------------------------- #424 E6 (#1000)
# The opt-out is PROJECT-wide: the pragma in ANY file under the project clears every STDIO file,
# so each fixture below puts it in a SEPARATE file from the `server.py` it would silence.
_PYPROJECT_SDK = '[project]\nname = "x"\ndependencies = ["mcp"]\n'


def test_mcp_stdio_no_sanitizer_pragma_quoted_in_a_string_does_not_suppress_py(tmp_path: Path) -> None:
    # #424 E6 (#1000): the project-wide opt-out reads each .py file's python comment view, so a string
    # in another module quoting the pragma is content. A real `#` comment there
    # (`test_pragma_in_a_test_or_example_path_still_counts`) opts the project out.
    _repo(tmp_path, {
        "server.py": _STDIO_SERVER,
        "notes.py": 'HELP = "opt out with # security: allow-mcp-stdio-no-sanitizer"\n',
    })
    assert _run(tmp_path) == ["server.py:1"]


def test_mcp_stdio_no_sanitizer_pragma_quoted_in_a_string_does_not_suppress_yaml(tmp_path: Path) -> None:
    # #424 E6 (#1000): a config file's opt-out reads the yaml comment view, so a quoted scalar carrying
    # the pragma is content. A real `#` comment there (`..._pragma_comment_suppresses_yaml`) opts out.
    _repo(tmp_path, {
        "server.py": _STDIO_SERVER,
        "config/mcp.yaml": 'description: "opt out with # security: allow-mcp-stdio-no-sanitizer"\n',
    })
    assert _run(tmp_path) == ["server.py:1"]


def test_mcp_stdio_no_sanitizer_pragma_quoted_in_a_string_does_not_suppress_toml(tmp_path: Path) -> None:
    # #424 E6 (#1000): the project manifest is searched too and reads the hash comment view, so a TOML
    # string carrying the pragma is content. A real `#` comment there (`..._pragma_comment_suppresses_toml`) opts out.
    _repo(tmp_path, {"server.py": _STDIO_SERVER})
    (tmp_path / "pyproject.toml").write_text(
        _PYPROJECT_SDK + 'description = "opt out with # security: allow-mcp-stdio-no-sanitizer"\n',
        encoding="utf-8",
    )
    assert _run(tmp_path) == ["server.py:1"]


def test_mcp_stdio_no_sanitizer_pragma_comment_suppresses_yaml(tmp_path: Path) -> None:
    _repo(tmp_path, {"server.py": _STDIO_SERVER, "config/mcp.yaml": "transport: stdio\n"})
    assert _run(tmp_path) == ["server.py:1"]
    (tmp_path / "config" / "mcp.yaml").write_text(
        "# security: allow-mcp-stdio-no-sanitizer\ntransport: stdio\n", encoding="utf-8"
    )
    assert _run(tmp_path) == []


def test_mcp_stdio_no_sanitizer_pragma_comment_suppresses_toml(tmp_path: Path) -> None:
    _repo(tmp_path, {"server.py": _STDIO_SERVER})
    assert _run(tmp_path) == ["server.py:1"]
    (tmp_path / "pyproject.toml").write_text(
        _PYPROJECT_SDK + "# security: allow-mcp-stdio-no-sanitizer\n", encoding="utf-8"
    )
    assert _run(tmp_path) == []
