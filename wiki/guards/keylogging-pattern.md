---
type: Guard
title: "keylogging-pattern"
description: "No keylogging/input-capture library wired to a persisted-output write."
timestamp: "2026-10-07T00:00:00Z"
guard_id: "keylogging-pattern"
checklist_section: ["8"]
standards: ["OWASP:A08"]
---

# No keylogging/input-capture library wired to a persisted-output write

_Author, 2026-10-07_

---

## The threat

A keylogger installs a low-level keyboard/input hook and persists captured
keystrokes: the classic credential-harvesting payload a malicious dependency,
AI-agent skill, or compromised contribution would ship. OWASP:A08 (Software and Data
Integrity Failures), CWE-311 (Missing Encryption of Sensitive Data, in the sense of
plaintext credential capture).

## Why this guard fits the stack

Adapted from Datadog GuardDog's `threat-runtime-keylogging` source-code rule.
GuardDog's own metadata rates this signal `specificity=low` (several of its
individual strings (a hotkey library import, an analytics event literally named
"keypress") are common outside malware), so this guard requires an actual
library-level capture call, not a bare import, and most patterns additionally
require pairing with a file-write in the same file:

```python
from pynput import keyboard
def on_press(key):
    with open("keys.log", "a") as f:
        f.write(str(key))                      # capture + persist -> fires
listener = keyboard.Listener(on_press=on_press)
```

```python
import keyboard
keyboard.send("ctrl+c")                        # ordinary hotkey use, silent
```

## Detection design

1. `applies()` gates on `python`, `javascript`, or `typescript` in `profile.features`.
2. Scans `.py`/`.pyi`/`.js`/`.ts`/`.jsx`/`.tsx`/`.mjs`/`.cjs`.
3. High-signal on their own (an OS-level hook/library choice with no other
   legitimate use): `pyHook.HookManager()`, `iohook.start()`, `node-key-sender`,
   `node-global-key-listener`.
4. Requires pairing with a file write (Python `.write(`; JS `fs.writeFile`/
   `fs.appendFile`) in the same file: `pynput`'s `Listener(on_press=...)` +
   `on_press`, `keyboard.hook(`/`keyboard.on_press(`, `evdev`'s `InputDevice(`,
   `Xlib`'s `record.create_context(`, and the `keypress` npm library. `.append(` is not a
   write: `list.append` is in nearly every file, so counting it made the pairing vacuous
   (a hotkey tool's history list, an evdev device list; PR #1048 review).
5. The finding is anchored at the capture call's line (the listener, hook, device or
   library call), so a baseline or triage entry can be line-scoped.
6. Suppress an audited case with a whole-file pragma comment anywhere in the file:
   `# security: allow-keylogging-pattern`.
7. All rules emit `severity="high"`, standards `["OWASP:A08", "CWE-311"]`.

## When NOT to flag

A bare import of `keyboard`/`pynput` with no listener/hook call, or a listener used
only for a hotkey (no file write anywhere in the file), never fires: those are
ordinary, legitimate uses of the same libraries.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_pynput_listener_with_file_write` | capture + file write pairing fires |
| `test_fires_on_pyhook_alone` | `pyHook.HookManager()` fires on its own |
| `test_fires_on_js_iohook` | `iohook.start()` fires |
| `test_passes_pynput_listener_without_file_write` | hotkey-only use, no write, stays silent |
| `test_passes_bare_import_no_capture_call` | bare `import keyboard` + `.send()` stays silent |
| `test_finding_is_anchored_at_the_listener_line` | the finding carries the `keyboard.Listener(` line |
| `test_fires_on_evdev_capture_with_file_write` | `InputDevice(...)` + `.write(` fires at the device line |
| `test_passes_hotkey_listener_that_appends_to_a_list` | listener + `hist.append(key)` stays silent |
| `test_passes_evdev_device_list_append` | `devs.append(InputDevice(p))` stays silent |
| `test_pragma_suppresses_whole_file` | whole-file pragma suppresses |
| `test_does_not_apply_with_no_relevant_stack` | `applies()` is `False` with no relevant feature |

## Known bypasses

Writing the captured input to a network socket or an in-memory buffer later
exfiltrated (rather than a direct file write) evades the pairing requirement, as does
building the output path or the write call via an aliased/indirect function. This is
a signature match on the most common concrete libraries, not a data-flow analysis.

## What this guard does NOT prove

A clean scan does not rule out input capture via a less common library, a custom
low-level hook implemented without a named library, or capture that persists via a
mechanism other than a direct file write.

# Citations

[1] agentsec checklist item `8-keylogging-pattern` (§8)
[2] OWASP:A08
[3] CWE-311
[4] Datadog GuardDog `threat-runtime-keylogging`: https://github.com/DataDog/guarddog
