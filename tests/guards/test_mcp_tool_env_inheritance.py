from __future__ import annotations

from agentsec.guards.mcp_tool_env_inheritance import McpToolEnvInheritanceGuard
from tests.guards._common import *  # noqa: F401,F403


def _mcp_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp", "llm", "python"}, python_dirs=["."])


def test_fires_on_stdio_server_parameters_os_environ(tmp_path: Path) -> None:
    (tmp_path / "launcher.py").write_text(
        "from mcp import StdioServerParameters\n"
        "\n"
        "params = StdioServerParameters(command='npx', args=['-y', 'server'], env=os.environ)\n",
        encoding="utf-8",
    )
    findings = McpToolEnvInheritanceGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "mcp-tool-env-inheritance/full-env-forwarded"
    assert findings[0].severity == "high"


def test_fires_on_multiline_call_with_env_copy(tmp_path: Path) -> None:
    # env= on its own line, several lines below the call opener — the context-window match.
    (tmp_path / "launcher.py").write_text(
        "from mcp import StdioServerParameters\n"
        "\n"
        "params = StdioServerParameters(\n"
        "    command='npx',\n"
        "    args=['-y', '@modelcontextprotocol/server-filesystem'],\n"
        "    env=os.environ.copy(),\n"
        ")\n",
        encoding="utf-8",
    )
    findings = McpToolEnvInheritanceGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert len(findings) == 1


def test_fires_on_subprocess_popen_dict_os_environ(tmp_path: Path) -> None:
    (tmp_path / "spawn.py").write_text(
        "import os, subprocess\n"
        "proc = subprocess.Popen(['mcp-server'], env=dict(os.environ))\n",
        encoding="utf-8",
    )
    findings = McpToolEnvInheritanceGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert len(findings) == 1


def test_fires_on_env_spread_merge(tmp_path: Path) -> None:
    # The common "I just want to add one var" mistake — spreads everything first.
    (tmp_path / "spawn.py").write_text(
        "import os, subprocess\n"
        "proc = subprocess.run(['mcp-server'], env={**os.environ, 'TOOL_MODE': 'strict'})\n",
        encoding="utf-8",
    )
    findings = McpToolEnvInheritanceGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert len(findings) == 1


def test_silent_on_no_env_kwarg(tmp_path: Path) -> None:
    # FP-bait: StdioServerParameters with no env= at all relies on the SDK's own safe default.
    (tmp_path / "launcher.py").write_text(
        "from mcp import StdioServerParameters\n"
        "\n"
        "params = StdioServerParameters(command='npx', args=['-y', 'server'])\n",
        encoding="utf-8",
    )
    assert McpToolEnvInheritanceGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_silent_on_scoped_env_dict(tmp_path: Path) -> None:
    # FP-bait: an explicit, minimal env dict is exactly the recommended fix.
    (tmp_path / "spawn.py").write_text(
        "import os, subprocess\n"
        "proc = subprocess.Popen(['mcp-server'], env={'PATH': os.environ['PATH']})\n",
        encoding="utf-8",
    )
    assert McpToolEnvInheritanceGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_silent_on_env_none(tmp_path: Path) -> None:
    (tmp_path / "spawn.py").write_text(
        "import subprocess\n"
        "proc = subprocess.Popen(['mcp-server'], env=None)\n",
        encoding="utf-8",
    )
    assert McpToolEnvInheritanceGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_silent_on_unrelated_subprocess_call(tmp_path: Path) -> None:
    # FP-bait: a normal subprocess call with no env= kwarg at all must not fire — flagging
    # every subprocess call with implicit inheritance would be immense noise (git, ffmpeg, ...).
    (tmp_path / "build.py").write_text(
        "import subprocess\n"
        "subprocess.run(['git', 'status'], capture_output=True)\n",
        encoding="utf-8",
    )
    assert McpToolEnvInheritanceGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "launcher.py").write_text(
        "# security: allow-mcp-tool-env-inheritance\n"
        "from mcp import StdioServerParameters\n"
        "\n"
        "params = StdioServerParameters(command='npx', args=['-y', 'server'], env=os.environ)\n",
        encoding="utf-8",
    )
    assert McpToolEnvInheritanceGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_not_applicable_without_mcp_feature(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"python", "llm"})
    assert McpToolEnvInheritanceGuard().applies(profile) is False


def test_applicable_with_mcp_feature(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"mcp", "python"})
    assert McpToolEnvInheritanceGuard().applies(profile) is True


# --- #374 review fixes ------------------------------------------------------------------------

def test_fires_on_spread_not_first(tmp_path: Path) -> None:
    # #374 review: the `**os.environ` spread need not be the FIRST key in the dict.
    (tmp_path / "m.py").write_text(
        "import subprocess, os\n"
        'subprocess.run(["tool"], env={"EXTRA": "1", **os.environ})\n',
        encoding="utf-8",
    )
    findings = McpToolEnvInheritanceGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert len(findings) == 1 and findings[0].rule == "mcp-tool-env-inheritance/full-env-forwarded"


def test_fires_on_async_create_subprocess(tmp_path: Path) -> None:
    # #374 review: async subprocess spawning is idiomatic in agent tool code.
    (tmp_path / "m.py").write_text(
        "import asyncio, os\n"
        'async def go():\n'
        '    await asyncio.create_subprocess_exec("tool", env=os.environ)\n'
        '    await asyncio.create_subprocess_shell("tool", env=os.environ.copy())\n',
        encoding="utf-8",
    )
    findings = McpToolEnvInheritanceGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert len(findings) == 2


def test_fires_on_from_os_import_bare_environ(tmp_path: Path) -> None:
    # #374 review: `from os import environ` makes a bare `env=environ` full-env — caught, but only
    # when that import is present in the file.
    (tmp_path / "m.py").write_text(
        "import subprocess\n"
        "from os import environ\n"
        'subprocess.run(["tool"], env=environ)\n',
        encoding="utf-8",
    )
    findings = McpToolEnvInheritanceGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert len(findings) == 1


def test_silent_on_bare_environ_without_os_import(tmp_path: Path) -> None:
    # FP-safety for the above: a local named `environ` that is NOT os.environ must stay silent.
    (tmp_path / "m.py").write_text(
        "import subprocess\n"
        'environ = {"PATH": "/bin"}\n'
        'subprocess.run(["tool"], env=environ)\n',
        encoding="utf-8",
    )
    assert McpToolEnvInheritanceGuard().run(tmp_path, _mcp_prof(tmp_path)) == []
