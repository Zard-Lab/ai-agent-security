---
type: Guard
title: "cron-systemd-persistence-write"
description: "No code writes a cron entry, systemd unit, macOS LaunchAgent/Daemon, or Windows Startup-folder file — OS-level persistence outside shell-config/registry targets."
timestamp: "2026-10-19T00:00:00Z"
guard_id: "cron-systemd-persistence-write"
checklist_section: ["8"]
standards: ["OWASP:A08", "CWE-506"]
---

# No code writes a cron entry, systemd unit, macOS LaunchAgent/Daemon, or Windows Startup-folder file

_Author — 2026-10-18_

---

## The threat

Writing a cron job, a systemd unit, a macOS LaunchAgent/LaunchDaemon plist, or a file into the
Windows Start Menu's Startup folder is how malware survives a reboot without touching a shell
profile — a backdoored dependency or AI-agent skill plants itself so it restarts
automatically.

WHO reaches this: any package install, AI-agent skill, or contribution that ships this code.
WHAT privilege / TO WHAT EFFECT: automatic re-execution on every reboot/login, with no further
trigger needed. Standards: OWASP:A08 (Software and Data Integrity Failures), CWE-506 (Embedded
Malicious Code). MITRE ATT&CK T1053.003 (Scheduled Task/Job: Cron), T1547.011 (Boot or Logon
Autostart Execution: Plist Modification).

## Why it's often introduced / why no existing agentsec guard covers this

**Sibling to `autostart-persistence-mechanism` (held, unmerged PR #1048 at the time this guard
was written), not a duplicate.** Read that guard's real source before building this one: it
already covers shell-config writes (`.bashrc`/`.bash_profile`/`.profile`/`.zshrc`/
`/etc/rc.local`) and the Windows registry Run/RunOnce key. Grepped every guard on `origin/main`
for `systemd`/`cron`/`LaunchAgent`/`LaunchDaemon` before building anything — every hit was
incidental (a Kubernetes CronJob resource-type reference, a zip-slip example mentioning cron
as an attack target, a Docker-Compose bind-mount guard naming `/etc/cron.d` as one of several
sensitive HOST paths a misconfigured mount exposes) — none of them detect APPLICATION CODE
writing a cron/systemd/macOS/Windows-startup-folder persistence entry directly. This guard
fills that gap. Built as an independent guard rather than extending the held sibling, since
that guard's file does not exist on `origin/main` yet; a future session should fold the two
together once PR #1048 merges, rather than carrying two separate "persistence" guards
indefinitely.

## Detection design

Ported from `rakshit-737/warden-supply-chain-security`'s `warden-python.yml` semgrep rule
(`warden.malicious_behavior.persistence-write`, fetched and read in full). Two tiers,
mirroring the held sibling guard's own structure:

**`system-wide-cron-systemd-reference` (HIGH).** A literal reference to `/etc/cron.d/`
(`.daily`/`.hourly`/`.weekly`/`.monthly`), `/var/spool/cron/`, `/etc/systemd/`, or
`/lib/systemd/system/`(`/usr/lib/systemd/system/`), with a file WRITE nearby (the same write
check as the tier below). These are root-owned, system-wide locations. A bare reference used to
fire on its own, which put HIGH findings on argparse help text, log messages and `os.listdir`
calls (PR #1093 review, round 1), because only comments and triple-quoted strings are blanked
before the scan; ordinary string literals are not.

**`user-level-persistence-write` (HIGH).** An actual file WRITE targeting a path containing
`LaunchAgents`/`LaunchDaemons`, a user-level systemd unit directory (`~/.config/systemd/user/`),
or the Windows `Start Menu/Programs/Startup` folder. Reading these paths has ordinary uses (an
installer checking what autostart entries already exist); it is the WRITE that is the
persistence signal.

1. **`applies()` gate:** `{"python", "javascript", "typescript"} & profile.features`.
2. **Files scanned:** `.py`/`.js`/`.ts`/`.jsx`/`.tsx`/`.mjs`/`.cjs`, `is_nonproduct_path`
   filtered.
3. **Docstring-safe:** Python files go through `strip_python_strings` (blanks only triple-
   quoted docstrings, never an ordinary string literal) so this guard's own module docstring
   — which names every trigger path in prose — does not self-fire.
4. **"Nearby":** the write must open and close within two lines before or after the path's
   line (lines `i-2` to `i+2`).
5. **What counts as a write.** Python: an `open(...)` call whose mode, read from `open()`'s own
   top-level arguments (the second positional argument or a `mode=` keyword, in any position),
   carries `w`, `a`, `x` or `+`, text or binary. So `open(p, "w", encoding="utf-8")`,
   `open(p, mode="w")` and `open(os.path.expanduser("~/Library/LaunchAgents/x.plist"), "wb")`
   all count, and a `"w"` passed to a nested call (`open(os.path.join(p, "w"), "r")`) does not.
   Every `open(` call's matching `)` comes from one `close_paren_map` pass per file, so a file of
   unclosed calls stays linear. JS: `fs.writeFile`/`fs.appendFile` (or their `Sync` forms).

**Inline opt-out pragma:** `# security: allow-cron-systemd-persistence-write`.

## When NOT to flag

- **A read of a LaunchAgents/LaunchDaemons/startup-folder path with no write nearby** —
  ordinary autostart-entry inspection, including `open(p, "r", encoding="utf-8")` and
  `open(p, mode="rb")`.
- **A system-wide cron/systemd path with no write nearby** — help text, a log message, an
  `os.listdir` of the directory.
- **An unrelated file write** that has nothing to do with any of the fixed paths.

Use the pragma `# security: allow-cron-systemd-persistence-write` for a legitimate
provisioning or deployment tool.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_etc_cron_d_reference_with_nearby_write` | `/etc/cron.d/myjob` + an `open(path, "w")` — fires HIGH |
| `test_fires_on_systemd_system_unit_reference_with_nearby_write` | `/lib/systemd/system/myservice.service` + a write — fires |
| `test_fires_on_var_spool_cron_reference_with_nearby_write` | `/var/spool/cron/crontabs/root` + an append — fires |
| `test_etc_systemd_bare_reference_in_help_text_does_not_fire` | FP-bait: `/etc/systemd/system/` in argparse help text — silent |
| `test_etc_cron_d_reference_without_write_does_not_fire` | FP-bait: `/etc/cron.d/` printed, no write — silent |
| `test_fires_on_launchagents_write` | a plist write under `~/Library/LaunchAgents` — fires |
| `test_fires_on_launchagents_write_with_encoding_kwarg` | `open(path, "w", encoding="utf-8")` — fires |
| `test_fires_on_etc_systemd_write_with_encoding_kwarg` | the system-wide tier with `encoding=` — fires |
| `test_fires_on_mode_keyword_and_binary_nested_path_writes` | `mode="w"`, and `"wb"` with the path built by a nested `expanduser(...)` — fire |
| `test_fires_on_exclusive_create_and_update_modes` | `"x"` and `"r+"` modes are writes — fire |
| `test_open_for_reading_with_kwargs_does_not_fire` | FP-bait: `"r"` with `encoding=`, `mode="rb"`, and a `"w"` inside a nested call — silent |
| `test_scan_is_linear_on_unclosed_open_calls_near_persistence_paths` | (slow) 2000 lines of unclosed `open(` beside a system path scan in linear time; a real write appended still fires |
| `test_fires_on_windows_startup_folder_write` | a write into the Windows Startup folder — fires |
| `test_fires_on_js_fs_writefile_to_launchdaemons` | JS `fs.writeFileSync` to `LaunchDaemons` — fires |
| `test_launchagents_read_without_write_does_not_fire` | FP-bait: a read, no write nearby — silent |
| `test_unrelated_file_write_does_not_fire` | FP-bait: an ordinary file write — silent |
| `test_docstring_prose_alone_does_not_fire` | FP-bait: every trigger path mentioned only in a docstring — silent |
| `test_pragma_silences_all_rules` | the inline pragma silences every rule |
| `test_applies_requires_python_js_or_ts` | `applies()` gate |

## Known bypasses

- **Dynamic path construction.** A path assembled from concatenated variables rather than a
  literal string is not recognized.
- **Fixed vocabulary.** A persistence location not in the fixed list (e.g. a Linux desktop
  `.desktop` autostart file under `~/.config/autostart/`, already covered by the held
  sibling's `system-wide-startup-reference` tier) is not this guard's concern.
- **No variable threading for the write check.** The two-lines-either-side window around the
  path reference, not dataflow, decides whether a nearby write targets that same path. So a
  path constant whose write sits further away is missed, and an unrelated write that happens to
  sit within two lines of a path mention still fires.
- **Write vocabulary.** Only `open(...)` (so `plistlib.dump(d, open(p, "wb"))` counts, through
  its `open`) and the JS `fs.writeFile`/`fs.appendFile` family are writes. `Path.write_text`/
  `write_bytes`, `Path.open("w")` (the mode is that method's FIRST argument; `p.open(mode="w")`
  does count), `os.open(path, os.O_WRONLY | os.O_CREAT)`, `shutil.copy*`, JS
  `fs.promises.writeFile`, and `crontab`/`systemctl` invocations are not recognized.
- **Size cap.** An `open(...)` call longer than 4 KB is skipped (a cap that keeps a hostile file
  of nested calls bounded; #1112), so a write whose path literal alone exceeds that is missed.

## What this guard does NOT prove

- That flagged code is actually malicious — a genuine provisioning tool trips the same
  signals; this guard surfaces the capability for human review.
- That the companion locations (`autostart-persistence-mechanism`'s shell-config/registry
  targets) are also covered — see that guard for those.

# Citations

[1] agentsec checklist item `8-cron-systemd-persistence-write` (§8)
[2] OWASP:A08, CWE-506
[3] MITRE ATT&CK T1053.003, T1547.011
[4] rakshit-737/warden-supply-chain-security `warden-python.yml` (`persistence-write`)
[5] sibling guard: `autostart-persistence-mechanism` (held, PR #1048 — shell-config/registry targets)
