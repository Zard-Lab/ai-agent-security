---
type: Guard
title: "destructive-filesystem-command"
description: "No hardcoded destructive filesystem-wipe command targeting a root/home/device path."
timestamp: "2026-10-07T00:00:00Z"
guard_id: "destructive-filesystem-command"
checklist_section: ["8"]
standards: ["OWASP:A01"]
---

# No hardcoded destructive filesystem-wipe command

_Author, 2026-10-07_

---

## The threat

A literal command that recursively deletes or overwrites an entire root-level
directory, home directory, or raw disk device (`rm -rf /`, `shutil.rmtree('/')`,
`dd if=/dev/zero of=/dev/sda`) is the classic sabotage payload: a disgruntled-insider
action or a supply-chain-planted destructive trigger with no legitimate reason to
target the filesystem root or a whole disk. OWASP:A01 (Broken Access Control, in the
sense of an unchecked destructive capability), CWE-732 (Incorrect Permission
Assignment for Critical Resource).

## Why this guard fits the stack

Adapted from Datadog GuardDog's `threat-filesystem-destruction` source-code rule.
GuardDog screens third-party packages; this guard applies the same signatures to the
target application's own source: deliberately scoped to ROOT-LEVEL/whole-device
targets only, never ordinary subdirectory cleanup:

```python
shutil.rmtree('/')              # fires: whole filesystem root
shutil.rmtree(tempfile_dir)      # ordinary, silent
```

## Detection design

1. `applies()` gates on `python`, `javascript`, or `typescript` in `profile.features`.
2. Scans `.py`/`.pyi`/`.js`/`.ts`/`.jsx`/`.tsx`/`.mjs`/`.cjs`/`.sh`/`.bash`/`.zsh`.
3. Seven root/home/device-scoped shapes: `rm -rf /`, `rm -rf /home`|`/Users`,
   `rmtree('/')`, `rmtree('~')`/`rmtree(os.path.expanduser('~'))` (the argument must be
   exactly `'~'` or `'~/'`: a subpath or a variable is ordinary cache cleanup), Node's
   `rimraf('/')`, `dd if=/dev/zero|urandom of=/dev/...`, `shred` against a raw device.
4. Suppress an audited case with a whole-file pragma comment anywhere in the file:
   `# security: allow-destructive-filesystem-command`.
5. All rules emit `severity="high"`, standards `["OWASP:A01", "CWE-732"]`.

## When NOT to flag

Any deletion scoped to a specific, non-root subdirectory (`rm -rf ./build`,
`shutil.rmtree(tempdir)`, `rm -rf /tmp/myapp-cache`,
`shutil.rmtree(os.path.expanduser('~/.cache/myapp'))`, `rmtree(os.path.expanduser(path))`)
never fires. It's the destination, not the destructive verb, that is the signal.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_rm_rf_root` | `rm -rf /` fires |
| `test_fires_on_rm_rf_home` | `rm -rf /home` fires |
| `test_fires_on_rmtree_root` | `rmtree('/')` fires |
| `test_fires_on_rmtree_expanduser` | `rmtree(os.path.expanduser('~'))` fires |
| `test_fires_on_rmtree_expanduser_of_the_home_dir_itself` | `expanduser('~')`, `("~/")`, `('~/')` fire at the call line |
| `test_passes_rmtree_expanduser_of_a_subpath_or_variable` | `expanduser('~/.cache/myapp')`, a `~/projects/...` subpath, `expanduser(path)`, an f-string subpath stay silent |
| `test_fires_on_dd_wipe` | `dd if=/dev/zero of=/dev/sda` fires |
| `test_passes_ordinary_subdirectory_cleanup` | scoped `rm -rf` stays silent |
| `test_passes_ordinary_rmtree_tempdir` | `rmtree(tempdir_var)` stays silent |
| `test_pragma_suppresses_whole_file` | whole-file pragma suppresses |
| `test_does_not_apply_with_no_relevant_stack` | `applies()` is `False` with no relevant feature |

## Known bypasses

Building the destructive path from a variable rather than a literal (`target = "/"`
then `rmtree(target)`), or using a less common deletion API, evades the regex. This is
a signature match on the most common literal shapes, not a data-flow analysis.

## What this guard does NOT prove

A clean scan does not rule out destructive behavior scoped to a non-root path that is
still damaging in context (e.g. wiping the application's own data directory). This
guard only covers root/home/whole-device-level destruction.

# Citations

[1] agentsec checklist item `8-destructive-filesystem-command` (§8)
[2] OWASP:A01
[3] CWE-732
[4] Datadog GuardDog `threat-filesystem-destruction`: https://github.com/DataDog/guarddog
