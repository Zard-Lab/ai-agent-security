"""Guard: no keylogging/input-capture library wired to a file write (checklist §8, new item).

A keylogger installs a low-level keyboard/input hook and persists captured keystrokes:
the classic credential-harvesting payload a malicious dependency, AI-agent skill, or
compromised contribution would ship. Adapted from Datadog GuardDog's
`threat-runtime-keylogging` source-code rule (GuardDog screens third-party packages;
this guard applies the same signatures to the target app's own source). GuardDog's own
metadata rates the underlying signal `specificity=low` (several of its individual
strings are common outside malware (a legitimate hotkey library, an analytics event
named "keypress")), so this guard requires an actual LIBRARY-LEVEL capture call, not a
bare import, and most of its patterns additionally require pairing with a file-write
call in the same file (the "capture AND persist" combination that is actually
suspicious; a hotkey listener alone is ordinary).

Fires on Python/JS source when `python`/`javascript`/`typescript` is detected.
Suppress an audited case (a legitimate accessibility tool, a QA input-replay harness)
with a whole-file pragma comment anywhere in the file:

    # security: allow-keylogging-pattern
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    read,
    rel,
    strip_js_comments,
    strip_python_strings,
)

_JS_SUFFIXES = (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")
_PY_SUFFIXES = (".py", ".pyi")

# Python capture-call libraries (require the actual listener/hook call, not a bare import:
# `pynput`/`keyboard` both have legitimate hotkey-only uses).
_PY_PYNPUT_ON_PRESS = re.compile(r"\bon_press\b")
_PY_PYNPUT_LISTENER = re.compile(r"\bkeyboard\s*\.\s*Listener\s*\(")
_PY_KEYBOARD_HOOK = re.compile(r"\bkeyboard\s*\.\s*(?:hook|on_press)\s*\(")
_PY_PYHOOK = re.compile(r"\bpyHook\s*\.\s*HookManager\s*\(|import\s+pyHook\b")
_PY_EVDEV = re.compile(r"\bInputDevice\s*\(")
_PY_XLIB_RECORD = re.compile(r"\brecord\s*\.\s*create_context\s*\(")

# JS capture-call libraries.
_JS_IOHOOK_START = re.compile(r"\biohook\s*\.\s*start\s*\(")
_JS_KEYPRESS_REQUIRE = re.compile(r"require\s*\(\s*['\"]keypress['\"]\s*\)")
_JS_KEY_SENDER = re.compile(r"node-key-sender|node-global-key-listener")

# File-write pairing (required alongside pynput/evdev/xlib signals; iohook/keypress/
# pyhook already count on their own: library choice alone there is high-signal). `.append(`
# is deliberately NOT a write: `list.append` is in nearly every file, so pairing with it made
# "capture AND persist" vacuous (a hotkey history list, an evdev device list; PR #1048 review).
_PY_FILE_WRITE = re.compile(r"\.\s*write\s*\(")
_JS_FS_WRITE = re.compile(r"fs\s*\.\s*(?:writeFile|appendFile)\s*\(")

_PRAGMA = re.compile(r"security:\s*allow-keylogging-pattern")
_STANDARDS = ["OWASP:A08", "CWE-311"]


def _first_line(code: str, *patterns: re.Pattern[str]) -> int:
    """1-based line of the earliest match of any pattern: the capture call a finding anchors on."""
    starts = [m.start() for p in patterns if (m := p.search(code)) is not None]
    return code.count("\n", 0, min(starts)) + 1 if starts else 1


class KeyloggingPatternGuard(Guard):
    id = "keylogging-pattern"
    title = "No keylogging/input-capture library wired to a persisted-output write"
    area = "Code safety"

    # keylog.py: pynput Listener(on_press=...) + open(...).write(...) -> fires
    # keylogging-pattern/pynput-capture-write (HIGH).
    canary_plant = CanaryPlant(
        files={
            "keylog.py": (
                "from pynput import keyboard\n"
                "def on_press(key):\n"
                "    with open('keys.log', 'a') as f:\n"
                "        f.write(str(key))\n"
                "listener = keyboard.Listener(on_press=on_press)\n"
                "listener.start()\n"
            ),
        },
        expects=frozenset({"keylogging-pattern/pynput-capture-write"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return bool({"python", "javascript", "typescript"} & profile.features)

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for f in iter_files(root, _PY_SUFFIXES + _JS_SUFFIXES):
            if f in seen:
                continue
            seen.add(f)
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        suffix = f.suffix.lower()
        text = read(f)
        if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
            return []

        if suffix in _PY_SUFFIXES:
            code = strip_python_strings(text, filename=f)
            code = "\n".join(
                ln if not ln.lstrip().startswith("#") else "" for ln in code.splitlines()
            )
            return self._scan_python(root, f, code)
        code = strip_js_comments(text, strip_strings=False)
        return self._scan_js(root, f, code)

    def _scan_python(self, root: Path, f: Path, code: str) -> list[Finding]:
        # High-signal on their own: a bona fide OS-level hook library.
        if _PY_PYHOOK.search(code):
            line = _first_line(code, _PY_PYHOOK)
            return [self._finding(root, f, line, "pyhook-capture", "Imports/uses `pyHook`'s Windows global keyboard hook manager.")]
        if (_PY_PYNPUT_LISTENER.search(code) and _PY_PYNPUT_ON_PRESS.search(code)) or _PY_KEYBOARD_HOOK.search(code):
            if _PY_FILE_WRITE.search(code):
                line = _first_line(code, _PY_PYNPUT_LISTENER, _PY_KEYBOARD_HOOK)
                return [self._finding(root, f, line, "pynput-capture-write", "A keyboard listener/hook is installed AND the file also writes output with `.write(`: capture-and-persist, the classic keylogger shape.")]
            return []
        # evdev / Xlib record: capture call alone is a weaker signal, require persistence too.
        if (_PY_EVDEV.search(code) or _PY_XLIB_RECORD.search(code)) and _PY_FILE_WRITE.search(code):
            line = _first_line(code, _PY_EVDEV, _PY_XLIB_RECORD)
            return [self._finding(root, f, line, "low-level-input-capture-write", "A low-level input-device/X11 record capture is paired with a `.write(` call in the same file.")]
        return []

    def _scan_js(self, root: Path, f: Path, code: str) -> list[Finding]:
        if _JS_IOHOOK_START.search(code) or _JS_KEY_SENDER.search(code):
            line = _first_line(code, _JS_IOHOOK_START, _JS_KEY_SENDER)
            return [self._finding(root, f, line, "iohook-capture", "Installs a global input-hook library (`iohook`/`node-key-sender`/`node-global-key-listener`).")]
        if _JS_KEYPRESS_REQUIRE.search(code) and _JS_FS_WRITE.search(code):
            line = _first_line(code, _JS_KEYPRESS_REQUIRE)
            return [self._finding(root, f, line, "keypress-capture-write", "The `keypress` input-capture library is paired with a filesystem write in the same file.")]
        return []

    def _finding(self, root: Path, f: Path, line: int, rule_suffix: str, message: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=message,
            remediation=(
                "Remove the input-capture code. If this is a legitimate accessibility tool or "
                "QA input-replay harness, mark it with the inline suppress pragma."
            ),
            rule=f"keylogging-pattern/{rule_suffix}",
            standards=list(_STANDARDS),
        )
