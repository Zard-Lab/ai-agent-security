from __future__ import annotations

import pytest

from agentsec.guards.cron_systemd_persistence_write import CronSystemdPersistenceWriteGuard
from tests._timing import assert_growth
from tests.guards._common import *  # noqa: F401,F403


def _prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"python"}, python_dirs=["."])


# --- system-wide-cron-systemd-reference --------------------------------------------------------


def test_fires_on_etc_cron_d_reference_with_nearby_write(tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text(
        "path = '/etc/cron.d/myjob'\n"
        "with open(path, 'w') as f:\n"
        "    f.write(CRON_LINE)\n",
        encoding="utf-8",
    )
    findings = CronSystemdPersistenceWriteGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "cron-systemd-persistence-write/system-wide-cron-systemd-reference" for f in findings)
    assert all(f.severity == "high" for f in findings)


def test_fires_on_systemd_system_unit_reference_with_nearby_write(tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text(
        "unit_path = '/lib/systemd/system/myservice.service'\n"
        "open(unit_path, 'w').write(UNIT_CONTENT)\n",
        encoding="utf-8",
    )
    findings = CronSystemdPersistenceWriteGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "cron-systemd-persistence-write/system-wide-cron-systemd-reference" for f in findings)


def test_fires_on_var_spool_cron_reference_with_nearby_write(tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text(
        "crontab_path = '/var/spool/cron/crontabs/root'\n"
        "with open(crontab_path, 'a') as f:\n"
        "    f.write(CRON_LINE)\n",
        encoding="utf-8",
    )
    findings = CronSystemdPersistenceWriteGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "cron-systemd-persistence-write/system-wide-cron-systemd-reference" for f in findings)


def test_etc_systemd_bare_reference_in_help_text_does_not_fire(tmp_path: Path) -> None:
    # FP fix: a bare /etc/systemd/ string in argparse help text (or any string
    # literal with no nearby write) must not fire HIGH -- only comments and triple-quoted
    # docstrings are stripped before the scan, so this used to fire on the literal alone.
    (tmp_path / "cli.py").write_text(
        "import argparse\n"
        "parser = argparse.ArgumentParser()\n"
        "parser.add_argument('--unit-dir', help='e.g. /etc/systemd/system/ on most distros')\n",
        encoding="utf-8",
    )
    assert CronSystemdPersistenceWriteGuard().run(tmp_path, _prof(tmp_path)) == []


def test_etc_cron_d_reference_without_write_does_not_fire(tmp_path: Path) -> None:
    # FP bait: logging/printing a system-wide path with no write nearby is not persistence.
    (tmp_path / "diagnostics.py").write_text(
        "path = '/etc/cron.d/myjob'\n"
        "print(f'checked {path}')\n",
        encoding="utf-8",
    )
    assert CronSystemdPersistenceWriteGuard().run(tmp_path, _prof(tmp_path)) == []


# --- user-level-persistence-write ---------------------------------------------------------------


def test_fires_on_launchagents_write(tmp_path: Path) -> None:
    (tmp_path / "persist.py").write_text(
        "import os\n"
        "def install():\n"
        "    path = os.path.expanduser('~/Library/LaunchAgents/com.evil.plist')\n"
        "    with open(path, 'w') as f:\n"
        "        f.write(PLIST_CONTENT)\n",
        encoding="utf-8",
    )
    findings = CronSystemdPersistenceWriteGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "cron-systemd-persistence-write/user-level-persistence-write" for f in findings)


def test_fires_on_windows_startup_folder_write(tmp_path: Path) -> None:
    (tmp_path / "persist.py").write_text(
        "path = r'C:\\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.lnk'\n"
        "open(path, 'w').write(payload)\n",
        encoding="utf-8",
    )
    findings = CronSystemdPersistenceWriteGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "cron-systemd-persistence-write/user-level-persistence-write" for f in findings)


def test_fires_on_js_fs_writefile_to_launchdaemons(tmp_path: Path) -> None:
    (tmp_path / "persist.js").write_text(
        "const path = '/Library/LaunchDaemons/com.evil.plist';\n"
        "fs.writeFileSync(path, plistContent);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = CronSystemdPersistenceWriteGuard().run(tmp_path, profile)
    assert any(f.rule == "cron-systemd-persistence-write/user-level-persistence-write" for f in findings)


def test_launchagents_read_without_write_does_not_fire(tmp_path: Path) -> None:
    # FP bait: an installer merely CHECKING what autostart entries already exist (a read, no
    # write nearby) is ordinary -- only the write is the persistence signal.
    (tmp_path / "check.py").write_text(
        "import os\n"
        "path = os.path.expanduser('~/Library/LaunchAgents')\n"
        "existing = os.listdir(path)\n",
        encoding="utf-8",
    )
    assert CronSystemdPersistenceWriteGuard().run(tmp_path, _prof(tmp_path)) == []


def test_unrelated_file_write_does_not_fire(tmp_path: Path) -> None:
    (tmp_path / "ordinary.py").write_text(
        "with open('output.txt', 'w') as f:\n"
        "    f.write('hello')\n",
        encoding="utf-8",
    )
    assert CronSystemdPersistenceWriteGuard().run(tmp_path, _prof(tmp_path)) == []


# --- write-mode recognition (PR #1093 round 2) --------------------------------------------------


def test_fires_on_launchagents_write_with_encoding_kwarg(tmp_path: Path) -> None:
    # Round-2 H1: the mode check required the mode literal to be the LAST argument, so the
    # `encoding="utf-8"` form this repo's own CLAUDE.md mandates stopped counting as a write.
    (tmp_path / "persist.py").write_text(
        "import os\n"
        "path = os.path.expanduser('~/Library/LaunchAgents/com.evil.plist')\n"
        "with open(path, 'w', encoding='utf-8') as f:\n"
        "    f.write(PLIST_CONTENT)\n",
        encoding="utf-8",
    )
    findings = CronSystemdPersistenceWriteGuard().run(tmp_path, _prof(tmp_path))
    assert [f.rule for f in findings] == ["cron-systemd-persistence-write/user-level-persistence-write"]


def test_fires_on_etc_systemd_write_with_encoding_kwarg(tmp_path: Path) -> None:
    (tmp_path / "persist.py").write_text(
        "open('/etc/systemd/system/evil.service', 'w', encoding='utf-8').write(UNIT)\n",
        encoding="utf-8",
    )
    findings = CronSystemdPersistenceWriteGuard().run(tmp_path, _prof(tmp_path))
    assert [f.rule for f in findings] == ["cron-systemd-persistence-write/system-wide-cron-systemd-reference"]


def test_fires_on_mode_keyword_and_binary_nested_path_writes(tmp_path: Path) -> None:
    # `mode=` as a keyword, and a binary-mode write whose path is built by a nested call (the
    # nested-paren case the balanced-paren walk exists for; it had no test).
    (tmp_path / "kw.py").write_text(
        "p = os.path.expanduser('~/.config/systemd/user/evil.service')\n"
        "open(p, mode='w').write(UNIT)\n",
        encoding="utf-8",
    )
    (tmp_path / "nested.py").write_text(
        "with open(os.path.expanduser('~/Library/LaunchAgents/x.plist'), 'wb') as f:\n"
        "    plistlib.dump(d, f)\n",
        encoding="utf-8",
    )
    findings = CronSystemdPersistenceWriteGuard().run(tmp_path, _prof(tmp_path))
    assert sorted(f.location for f in findings) == ["kw.py:1", "nested.py:1"]


def test_fires_on_exclusive_create_and_update_modes(tmp_path: Path) -> None:
    # `"x"` (exclusive create) and `"r+"` (update) both write; round-3 L5 found neither tested.
    (tmp_path / "x.py").write_text("open('/etc/cron.d/job', 'x').write(LINE)\n", encoding="utf-8")
    (tmp_path / "rplus.py").write_text("open('/etc/cron.d/job', 'r+').write(LINE)\n", encoding="utf-8")
    findings = CronSystemdPersistenceWriteGuard().run(tmp_path, _prof(tmp_path))
    assert sorted(f.location for f in findings) == ["rplus.py:1", "x.py:1"]


def test_open_for_reading_with_kwargs_does_not_fire(tmp_path: Path) -> None:
    # FP bait for the widened mode check: read modes, with trailing kwargs or as `mode=`, and a
    # 'w' that is an argument of a NESTED call rather than open()'s own mode, stay silent.
    (tmp_path / "check.py").write_text(
        "p = os.path.expanduser('~/Library/LaunchAgents/com.example.plist')\n"
        "with open(p, 'r', encoding='utf-8') as f:\n"
        "    existing = f.read()\n"
        "raw = open(p, mode='rb').read()\n"
        "other = open(os.path.join(p, 'w'), 'r').read()\n",
        encoding="utf-8",
    )
    assert CronSystemdPersistenceWriteGuard().run(tmp_path, _prof(tmp_path)) == []


@pytest.mark.slow
def test_scan_is_linear_on_unclosed_open_calls_near_persistence_paths(tmp_path: Path) -> None:
    # Round-2 M4: every `open(` in each path line's window was walked to the window end when it
    # never closed, re-walking the same text for each of the five lines whose window shares it
    # (2000 lines of `open(` x50 beside a system path: 100 s, against 0.19 s at the round-1 code).
    sizes = (250, 500, 1000, 2000)
    guard = CronSystemdPersistenceWriteGuard()
    files: dict[int, Path] = {}
    for n in sizes:
        d = tmp_path / str(n)
        d.mkdir()
        files[n] = d / "hostile.py"
        files[n].write_text(("y = '/etc/systemd/x' " + "open(" * 50 + "\n") * n, encoding="utf-8")

    def scan(n: int) -> None:
        guard._scan(files[n].parent, files[n])

    assert_growth(scan, sizes, expected="linear")
    # The work was still done: a real write appended to the same hostile file still fires.
    files[250].write_text(files[250].read_text(encoding="utf-8") + "open('/etc/cron.d/j', 'w')\n", encoding="utf-8")
    # (The two hostile path lines just above it are inside its window, so they fire too.)
    assert [f.location for f in guard._scan(files[250].parent, files[250])] == [
        "hostile.py:249", "hostile.py:250", "hostile.py:251"
    ]


# --- docstring self-reference / pragma / applies ------------------------------------------------


def test_docstring_prose_alone_does_not_fire(tmp_path: Path) -> None:
    (tmp_path / "notes.py").write_text(
        '"""Discusses /etc/cron.d/, /var/spool/cron/, /etc/systemd/, /lib/systemd/system/, '
        'LaunchAgents, LaunchDaemons, and the Windows Start Menu/Programs/Startup folder, all '
        'in prose."""\n'
        "def run():\n"
        "    return None\n",
        encoding="utf-8",
    )
    assert CronSystemdPersistenceWriteGuard().run(tmp_path, _prof(tmp_path)) == []


def test_pragma_silences_all_rules(tmp_path: Path) -> None:
    (tmp_path / "persist.py").write_text(
        "# security: allow-cron-systemd-persistence-write\n"
        "path = '/etc/cron.d/myjob'\n"
        "open(os.path.expanduser('~/Library/LaunchAgents/com.evil.plist'), 'w').write(x)\n",
        encoding="utf-8",
    )
    assert CronSystemdPersistenceWriteGuard().run(tmp_path, _prof(tmp_path)) == []


def test_applies_requires_python_js_or_ts(tmp_path: Path) -> None:
    guard = CronSystemdPersistenceWriteGuard()
    assert guard.applies(mkprofile(tmp_path, features={"python"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"javascript"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"typescript"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"docker"})) is False
