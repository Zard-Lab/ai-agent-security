---
type: Guard
title: "insecure-file-permissions"
description: "os.chmod() grants overly-permissive group/other access."
timestamp: "2026-07-01T21:46:27+08:00"
guard_id: "insecure-file-permissions"
checklist_section: ["8"]
standards: ["OWASP:A01"]
---

# os.chmod() grants overly-permissive group/other access

_Author — 2026-07-01_

---

## The threat

```python
os.chmod("/etc/app/secrets.env", 0o666)   # group AND other can write it
os.chmod(upload_path, 0o777)              # anyone can read/write/execute it
```

A chmod call that grants write (or execute) permission to a file's group or other bits
widens access to more principals than almost any application file needs. CWE-276
(Incorrect Default Permissions), OWASP:A01 (Broken Access Control). A common way for a
secrets file, an uploaded artifact, or a generated config to end up world-writable —
any co-located process or user on the host can then modify it.

## Why it's often introduced

`0o777` is the fastest way to make a "permission denied" error go away during
development, and it's easy to forget to narrow it back down before shipping:

```python
def save_upload(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)
    os.chmod(path, 0o777)   # "just make it work" left in
```

## Detection design

1. **applies() gate:** `"python" in profile.features` — runs on any Python codebase.

2. **Files scanned:** All `.py` files via `iter_files(d, (".py",))` from
   `python_scan_dirs`. Non-product paths (tests, fixtures) skipped via
   `is_nonproduct_path`.

3. **Pattern (`group-or-other-write`, HIGH):** Same-line check. Matches
   `os.chmod(`/`os.lchmod(`/`os.fchmod(` (`_CHMOD_CALL`), then inspects the argument
   text (`_grants_group_or_other_access`):
   - If it contains a `stat` module constant that grants group/other write or full
     access (`stat.S_IWGRP`, `stat.S_IXGRP`, `stat.S_IWOTH`, `stat.S_IXOTH`,
     `stat.S_IRWXO`, `stat.S_IRWXG`) → fire.
   - Otherwise, if it contains an octal mode literal (`0o666`, `0666`, `0o4600`, ...),
     take the **last two digits** (group and other — a 4-digit literal's first digit
     is the setuid/setgid/sticky nibble, not owner/group/other) and check whether
     either digit's value is in `{1, 2, 3, 5, 6, 7}` (anything granting write or
     execute; `0` = none, `4` = read-only). If so → fire.

4. **Inline opt-out pragma:** `# security: allow-insecure-permissions`

5. **Severity and rule:** `"high"`, rule
   `"insecure-file-permissions/group-or-other-write"`, standards
   `["OWASP:A01", "CWE-276"]`.

## When NOT to flag

- `0o640` (owner rw, group read-only, other none), `0o600` (owner rw only), or `0o644`
  (owner rw, group/other read-only) — none grant write or execute beyond the owner.
- A 4-digit literal like `0o4600` (setuid + owner-only rw) — the group/other digits
  (`00`) are still restrictive; the guard correctly reads only the last two digits.
- An audited, genuinely-shared directory suppressed with the inline pragma.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_0o777` | Fires: `0o777` — full read/write/execute for everyone |
| `test_fires_on_0o666` | Fires: `0o666` — group and other can write |
| `test_fires_on_stat_constant` | Fires: `stat.S_IRWXO` |
| `test_passes_0o640` | Silent: `0o640` — group read-only, other none |
| `test_passes_0o600` | Silent: `0o600` — owner-only |
| `test_passes_0o644` | Silent: `0o644` — group/other read-only |
| `test_passes_setuid_owner_only` | Silent: `0o4600` — setuid bit, group/other still `00` |
| `test_pragma_opt_out` | Silent: inline `# security: allow-insecure-permissions` pragma |

## Known bypasses

- A mode value built from a variable or computed expression (`os.chmod(path, mode)`
  where `mode` is assigned elsewhere) is not detected — the guard requires the octal
  literal or `stat` constant to appear directly in the call's argument text.
- `os.chmod()` called via a reassigned alias, or through `pathlib.Path.chmod()`
  (a different call shape entirely) evades the `os.chmod`/`lchmod`/`fchmod` regex.
- A decimal (non-octal-prefixed) integer that happens to equal an insecure mode in
  octal interpretation but is written without the `0o`/`0` prefix convention isn't
  matched by `_OCTAL_LITERAL`.

## What this guard does NOT prove

- That the file being chmod'd is actually sensitive — a genuinely shared, low-risk
  directory (e.g. a public static-assets folder) may legitimately need `0o777` and
  should use the pragma.
- That the file's permissions aren't further restricted by a `umask` or by the
  underlying filesystem's ACLs at write time.

# Citations

[1] agentsec checklist item `8-insecure-file-permissions` (§8)
[2] OWASP:A01
