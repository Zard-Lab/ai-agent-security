"""Tests for the keylogging-pattern guard."""
from __future__ import annotations

from agentsec.guards.keylogging_pattern import KeyloggingPatternGuard
from tests.guards._common import *  # noqa: F401,F403


def test_fires_on_pynput_listener_with_file_write(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "from pynput import keyboard\n"
        "def on_press(key):\n"
        "    with open('keys.log', 'a') as f:\n"
        "        f.write(str(key))\n"
        "listener = keyboard.Listener(on_press=on_press)\n",
        encoding="utf-8",
    )
    findings = KeyloggingPatternGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "keylogging-pattern/pynput-capture-write" for f in findings)


def test_fires_on_pyhook_alone(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import pyHook\nhm = pyHook.HookManager()\n", encoding="utf-8"
    )
    findings = KeyloggingPatternGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "keylogging-pattern/pyhook-capture" for f in findings)


def test_fires_on_js_iohook(tmp_path: Path) -> None:
    (tmp_path / "t.js").write_text(
        "const iohook = require('iohook');\niohook.start();\n", encoding="utf-8"
    )
    findings = KeyloggingPatternGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert any(f.rule == "keylogging-pattern/iohook-capture" for f in findings)


def test_passes_pynput_listener_without_file_write(tmp_path: Path) -> None:
    # A hotkey-only use (no file write) -- pynput/keyboard libs have legitimate hotkey uses.
    (tmp_path / "t.py").write_text(
        "from pynput import keyboard\n"
        "def on_press(key):\n"
        "    if key == keyboard.Key.esc:\n"
        "        print('escape pressed')\n"
        "listener = keyboard.Listener(on_press=on_press)\n",
        encoding="utf-8",
    )
    assert KeyloggingPatternGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_passes_bare_import_no_capture_call(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import keyboard\nkeyboard.send('ctrl+c')\n", encoding="utf-8"
    )
    assert KeyloggingPatternGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_pragma_suppresses_whole_file(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "# security: allow-keylogging-pattern\n"
        "import pyHook\nhm = pyHook.HookManager()\n",
        encoding="utf-8",
    )
    assert KeyloggingPatternGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_does_not_apply_with_no_relevant_stack(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features=set())
    assert KeyloggingPatternGuard().applies(prof) is False


def test_finding_is_anchored_at_the_listener_line(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "from pynput import keyboard\n"
        "def on_press(key):\n"
        "    with open('keys.log', 'a') as f:\n"
        "        f.write(str(key))\n"
        "listener = keyboard.Listener(on_press=on_press)\n",
        encoding="utf-8",
    )
    findings = KeyloggingPatternGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["keylogging-pattern/pynput-capture-write"]
    assert findings[0].location.endswith("t.py:5")


def test_fires_on_evdev_capture_with_file_write(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "from evdev import InputDevice\n"
        "dev = InputDevice('/dev/input/event0')\n"
        "out = open('/tmp/k', 'a')\n"
        "for ev in dev.read_loop():\n"
        "    out.write(str(ev))\n",
        encoding="utf-8",
    )
    findings = KeyloggingPatternGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["keylogging-pattern/low-level-input-capture-write"]
    assert findings[0].location.endswith("t.py:2")


def test_passes_hotkey_listener_that_appends_to_a_list(tmp_path: Path) -> None:
    # list.append is not persisting anything: a hotkey tool keeping an in-memory history.
    (tmp_path / "t.py").write_text(
        "from pynput import keyboard\n"
        "hist = []\n"
        "def on_press(key):\n"
        "    hist.append(key)\n"
        "listener = keyboard.Listener(on_press=on_press)\n",
        encoding="utf-8",
    )
    assert KeyloggingPatternGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_passes_evdev_device_list_append(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "from evdev import InputDevice, list_devices\n"
        "devs = []\n"
        "for p in list_devices():\n"
        "    devs.append(InputDevice(p))\n",
        encoding="utf-8",
    )
    assert KeyloggingPatternGuard().run(tmp_path, _pyprof(tmp_path)) == []
