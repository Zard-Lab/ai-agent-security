from __future__ import annotations

import pytest

from agentsec.guards.mcp_unsafe_auth_url_launch import McpUnsafeAuthUrlLaunchGuard
from tests.guards._common import *  # noqa: F401,F403

_MCP_IMPORT = "from mcp.server import Server\n"


def _mcp_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp", "python"}, python_dirs=["."])


def test_browser_open_fires_without_scheme_check(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        _MCP_IMPORT + "import webbrowser\n\n"
        "def start_login(auth_url):\n"
        "    webbrowser.open(auth_url)\n",
        encoding="utf-8",
    )
    findings = McpUnsafeAuthUrlLaunchGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-unsafe-auth-url-launch/browser-opener-no-scheme-check" for f in findings)


def test_browser_open_fires_on_startfile(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        _MCP_IMPORT + "import os\n\n"
        "def start_login(authorization_endpoint):\n"
        "    os.startfile(authorization_endpoint)\n",
        encoding="utf-8",
    )
    findings = McpUnsafeAuthUrlLaunchGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-unsafe-auth-url-launch/browser-opener-no-scheme-check" for f in findings)


def test_browser_open_silent_with_scheme_check(tmp_path: Path) -> None:
    """FP-bait: a scheme check anywhere in the file silences the finding."""
    (tmp_path / "auth.py").write_text(
        _MCP_IMPORT + "import webbrowser\n\n"
        "def start_login(auth_url):\n"
        "    if not auth_url.startswith('https://'):\n"
        "        raise ValueError('unsafe scheme')\n"
        "    webbrowser.open(auth_url)\n",
        encoding="utf-8",
    )
    findings = McpUnsafeAuthUrlLaunchGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-unsafe-auth-url-launch/browser-opener-no-scheme-check" for f in findings)


def test_browser_open_silent_with_urlparse_scheme_check(tmp_path: Path) -> None:
    """FP-bait (H3, PR #1053 review): a `urlparse(...).scheme` comparison is an equally valid
    mitigation that the original `.startswith("https")`-only check missed entirely."""
    (tmp_path / "auth.py").write_text(
        _MCP_IMPORT + "import webbrowser\n"
        "from urllib.parse import urlparse\n\n"
        "def start_login(auth_url):\n"
        "    if urlparse(auth_url).scheme != 'https':\n"
        "        raise ValueError('unsafe scheme')\n"
        "    webbrowser.open(auth_url)\n",
        encoding="utf-8",
    )
    findings = McpUnsafeAuthUrlLaunchGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-unsafe-auth-url-launch/browser-opener-no-scheme-check" for f in findings)


def test_browser_open_silent_on_unrelated_call(tmp_path: Path) -> None:
    """FP-bait: a webbrowser.open() call with no auth-flow-shaped argument must not fire."""
    (tmp_path / "docs.py").write_text(
        _MCP_IMPORT + "import webbrowser\n\n"
        "def open_docs(path):\n"
        "    webbrowser.open(path)\n",
        encoding="utf-8",
    )
    findings = McpUnsafeAuthUrlLaunchGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-unsafe-auth-url-launch/browser-opener-no-scheme-check" for f in findings)


def test_browser_open_silent_on_bare_url_argument(tmp_path: Path) -> None:
    """FP-bait (H3, PR #1053 review): a bare `url`/`server_url` argument has nothing tying it
    to an OAuth flow — `endpoint`/`url` were dropped from the hint, `auth`/`oauth` remain."""
    (tmp_path / "auth.py").write_text(
        _MCP_IMPORT + "import webbrowser\n\n"
        "def open_page(url):\n"
        "    webbrowser.open(url)\n",
        encoding="utf-8",
    )
    findings = McpUnsafeAuthUrlLaunchGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-unsafe-auth-url-launch/browser-opener-no-scheme-check" for f in findings)


def test_browser_open_silent_without_file_level_mcp_marker(tmp_path: Path) -> None:
    """FP-bait (H3, PR #1053 review): the same unsafe shape in a file with no MCP SDK import
    must not fire, even though the repo-wide StackProfile carries the `mcp` feature."""
    (tmp_path / "web.py").write_text(
        "import webbrowser\n\n"
        "def start_login(auth_url):\n"
        "    webbrowser.open(auth_url)\n",
        encoding="utf-8",
    )
    findings = McpUnsafeAuthUrlLaunchGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-unsafe-auth-url-launch/browser-opener-no-scheme-check" for f in findings)


def test_shell_open_fires_on_subprocess_run(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        _MCP_IMPORT + "import subprocess\n\n"
        "def start_login_fallback(auth_url):\n"
        "    subprocess.run(f'open {auth_url}', shell=True)\n",
        encoding="utf-8",
    )
    findings = McpUnsafeAuthUrlLaunchGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-unsafe-auth-url-launch/auth-url-opened-via-shell" for f in findings)


def test_shell_open_fires_on_os_system(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        _MCP_IMPORT + "import os\n\n"
        "def start_login_fallback(authorization_url):\n"
        "    os.system(f'start {authorization_url}')\n",
        encoding="utf-8",
    )
    findings = McpUnsafeAuthUrlLaunchGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-unsafe-auth-url-launch/auth-url-opened-via-shell" for f in findings)


def test_shell_open_silent_on_argv_list_form(tmp_path: Path) -> None:
    """FP-bait (H3, PR #1053 review), the important one: the recommended-safe argv/list form —
    `subprocess.run(['xdg-open', auth_url])` — passes no string to a shell at all and must not
    fire, unlike the shell-string form above."""
    (tmp_path / "auth.py").write_text(
        _MCP_IMPORT + "import subprocess\n\n"
        "def start_login_fallback(auth_url):\n"
        "    subprocess.run(['xdg-open', auth_url])\n",
        encoding="utf-8",
    )
    findings = McpUnsafeAuthUrlLaunchGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-unsafe-auth-url-launch/auth-url-opened-via-shell" for f in findings)


def test_shell_open_silent_on_argv_list_form_with_extra_kwarg(tmp_path: Path) -> None:
    """FP-bait (H3, PR #1053 review): the argv/list form stays safe even with another keyword
    argument alongside it (`check=True`), as long as `shell=True` is not also present."""
    (tmp_path / "auth.py").write_text(
        _MCP_IMPORT + "import subprocess\n\n"
        "def start_login_fallback(auth_url):\n"
        "    subprocess.run(['git', 'clone', auth_url], check=True)\n",
        encoding="utf-8",
    )
    findings = McpUnsafeAuthUrlLaunchGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-unsafe-auth-url-launch/auth-url-opened-via-shell" for f in findings)


def test_shell_open_silent_on_unrelated_subprocess_call(tmp_path: Path) -> None:
    """FP-bait: a subprocess call with no auth-url-shaped argument must not fire."""
    (tmp_path / "build.py").write_text(
        _MCP_IMPORT + "import subprocess\n\n"
        "def run_build(cmd):\n"
        "    subprocess.run(cmd, shell=True)\n",
        encoding="utf-8",
    )
    findings = McpUnsafeAuthUrlLaunchGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-unsafe-auth-url-launch/auth-url-opened-via-shell" for f in findings)


def test_shell_open_silent_without_file_level_mcp_marker(tmp_path: Path) -> None:
    """FP-bait (H3, PR #1053 review): the same unsafe shell-string shape in a file with no MCP
    SDK import must not fire."""
    (tmp_path / "web.py").write_text(
        "import subprocess\n\n"
        "def start_login_fallback(auth_url):\n"
        "    subprocess.run(f'open {auth_url}', shell=True)\n",
        encoding="utf-8",
    )
    findings = McpUnsafeAuthUrlLaunchGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-unsafe-auth-url-launch/auth-url-opened-via-shell" for f in findings)


_SHELL_RULE = "mcp-unsafe-auth-url-launch/auth-url-opened-via-shell"
_BROWSER_RULE = "mcp-unsafe-auth-url-launch/browser-opener-no-scheme-check"


def _shell_call_findings(tmp_path: Path, call: str) -> list[Finding]:
    (tmp_path / "auth.py").write_text(
        _MCP_IMPORT + "import subprocess\n\n"
        "def start_login(auth_url):\n"
        f"    {call}\n",
        encoding="utf-8",
    )
    return McpUnsafeAuthUrlLaunchGuard().run(tmp_path, _mcp_prof(tmp_path))


@pytest.mark.parametrize("call", [
    "subprocess.run(['cmd', '/c', 'start', auth_url])",
    "subprocess.run(['cmd.exe', '/c', 'start', '', auth_url])",
    r"subprocess.run(['C:\\Windows\\System32\\cmd.exe', '/c', 'start', auth_url])",
    "subprocess.run(['powershell', '-Command', f'Start-Process {auth_url}'])",
    "subprocess.Popen(['pwsh', '-c', f'Start-Process {auth_url}'])",
    "subprocess.run(['sh', '-c', f'open {auth_url}'])",
    "subprocess.run(['/bin/bash', '-c', f'xdg-open {auth_url}'])",
    "subprocess.run(args=['cmd', '/c', 'start', auth_url])",
])
def test_shell_open_fires_on_argv_list_that_invokes_a_shell_interpreter(tmp_path: Path, call: str) -> None:
    """Round-2 review H1 (#1053): the argv-list exemption must not cover a list whose program IS a
    shell. `cmd /c start <url>` re-parses the URL, so a `&` in an attacker-supplied authorization
    URL is command injection on Windows (the CVE-2025-6514 class this guard exists for). All of
    these fired before the argv exemption landed and no other guard reports the cmd/PowerShell
    forms."""
    assert any(f.rule == _SHELL_RULE for f in _shell_call_findings(tmp_path, call))


@pytest.mark.parametrize("call", [
    "subprocess.run(['cmdline-tool', auth_url])",
    "subprocess.run(['sha256sum', auth_url])",
    "subprocess.run(['/usr/bin/open', auth_url])",
    "subprocess.run(args=['xdg-open', auth_url])",
])
def test_shell_open_silent_on_argv_list_of_a_non_shell_program(tmp_path: Path, call: str) -> None:
    """FP-bait for the shell-interpreter check: a program whose name merely STARTS with `cmd`/`sh`,
    or a path-qualified non-shell opener, passes no string to a shell. The `args=` keyword spelling
    of the safe list is the same call as the positional one (round-2 review M3)."""
    assert not any(f.rule == _SHELL_RULE for f in _shell_call_findings(tmp_path, call))


def test_shell_open_fires_on_argv_list_with_shell_true(tmp_path: Path) -> None:
    """A list with `shell=True` hands its first element to the shell as a command string, so an
    f-string there is injectable. Pins the `_SHELL_TRUE` branch, which no test reached before."""
    call = "subprocess.run([f'xdg-open {auth_url}'], shell=True)"
    assert any(f.rule == _SHELL_RULE for f in _shell_call_findings(tmp_path, call))


def _browser_open_findings(tmp_path: Path, arg: str) -> list[Finding]:
    (tmp_path / "auth.py").write_text(
        _MCP_IMPORT + "import webbrowser\n\n"
        "def start_login(ctx):\n"
        f"    webbrowser.open({arg})\n",
        encoding="utf-8",
    )
    return McpUnsafeAuthUrlLaunchGuard().run(tmp_path, _mcp_prof(tmp_path))


@pytest.mark.parametrize("arg", ["author_page", "authority", "authors_url"])
def test_browser_open_silent_on_auth_lookalike_names(tmp_path: Path, arg: str) -> None:
    """FP-bait (round-2 review L1): `auth` inside an unrelated word (`author`, `authority`) is not
    an OAuth hint."""
    assert not any(f.rule == _BROWSER_RULE for f in _browser_open_findings(tmp_path, arg))


@pytest.mark.parametrize("arg", [
    "auth_url", "oauth_url", "authorization_url", "authorize_url", "authUrl", "server_auth_url",
    "AUTH_URL", "self.auth_url", "f'{base}/oauth/authorize'",
])
def test_browser_open_fires_on_auth_segment_names(tmp_path: Path, arg: str) -> None:
    """The narrowing in L1 must keep every real auth-flow spelling: snake, camel and screaming
    case, a prefix segment (`server_auth_url`), an attribute, and an inline OAuth path."""
    assert any(f.rule == _BROWSER_RULE for f in _browser_open_findings(tmp_path, arg))


@pytest.mark.parametrize("arg", [
    "authurl", "oauthurl", "authlink", "AUTHURL", "googleauth_url", "reauth_url",
])
def test_browser_open_fires_on_concatenated_and_prefixed_auth_names(tmp_path: Path, arg: str) -> None:
    """Round-3 review M2 + L1 (#1053): the L1 narrowing silenced a lowercase `url`/`uri`/`link`
    written straight after `auth` (`authurl`, `oauthurl`) and a vendor prefix (`googleauth_url`),
    all of which fired before it. The guard's own shell rule treats `authurl` as an auth URL."""
    assert any(f.rule == _BROWSER_RULE for f in _browser_open_findings(tmp_path, arg))


@pytest.mark.parametrize("arg", ["author_url", "authority_url", "authenticated_url"])
def test_browser_open_silent_when_url_follows_a_longer_auth_word(tmp_path: Path, arg: str) -> None:
    """FP-bait for M2: `url` counts only directly after `auth`/`authorize`/`authorization`, so a
    longer word (`author`, `authority`, `authenticated`) followed by `_url` stays silent."""
    assert not any(f.rule == _BROWSER_RULE for f in _browser_open_findings(tmp_path, arg))


@pytest.mark.parametrize("call", [
    "subprocess.run(['bash.exe', '-c', f'start {auth_url}'])",
    "subprocess.run(['/usr/bin/env', 'sh', '-c', f'open {auth_url}'])",
    "subprocess.run(['env', 'bash', '-c', f'xdg-open {auth_url}'])",
    "subprocess.run(['wsl', 'bash', '-c', f'xdg-open {auth_url}'])",
    "subprocess.run(['busybox', 'sh', '-c', f'open {auth_url}'])",
    "subprocess.run(['fish', '-c', f'open {auth_url}'])",
    "subprocess.run(['tcsh', '-c', f'open {auth_url}'])",
])
def test_shell_open_fires_on_launcher_wrapped_or_extra_shells(tmp_path: Path, call: str) -> None:
    """Round-3 review L2 (#1053): a shell reached through `env`/`wsl`/`busybox`, a `.exe` bash, and
    the fish/csh family hand the URL to a shell exactly like `sh -c`."""
    assert any(f.rule == _SHELL_RULE for f in _shell_call_findings(tmp_path, call))


@pytest.mark.parametrize("call", [
    "subprocess.run(['env', 'xdg-open', auth_url])",
    "subprocess.run(['wsl', 'xdg-open', auth_url])",
    "subprocess.run(['envoy', auth_url])",
    "subprocess.run(['fishy-tool', auth_url])",
])
def test_shell_open_silent_on_launcher_running_a_non_shell_program(tmp_path: Path, call: str) -> None:
    """FP-bait for L2: a launcher that runs a non-shell program passes no string to a shell, and a
    program whose name merely starts with `env`/`fish` is not a launcher or a shell."""
    assert not any(f.rule == _SHELL_RULE for f in _shell_call_findings(tmp_path, call))


def test_mcp_unsafe_auth_url_launch_applies_gate() -> None:
    p = mkprofile(Path("."), features={"python"})
    assert not McpUnsafeAuthUrlLaunchGuard().applies(p)
    p_mcp = mkprofile(Path("."), features={"python", "mcp"})
    assert McpUnsafeAuthUrlLaunchGuard().applies(p_mcp)


def test_mcp_unsafe_auth_url_launch_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        "# security: allow-mcp-unsafe-auth-url-launch\n"
        + _MCP_IMPORT
        + "import webbrowser\n\n"
        "def start_login(auth_url):\n"
        "    webbrowser.open(auth_url)\n",
        encoding="utf-8",
    )
    assert McpUnsafeAuthUrlLaunchGuard().run(tmp_path, _mcp_prof(tmp_path)) == []
