---
type: Guard
title: "compose-tmpfs-insecure-options"
description: "Docker-compose tmpfs mount re-enables exec/suid/dev."
timestamp: "2026-08-16T10:56:38+08:00"
guard_id: "compose-tmpfs-insecure-options"
checklist_section: ["6c"]
standards: ["CWE-732", "OWASP:A05"]
---

# Docker-compose tmpfs mount re-enables exec/suid/dev

_Author — Marconi, 2026-08-16_

---

## The threat

Docker mounts every tmpfs with `noexec,nosuid,nodev` by default. Passing `exec`, `suid`,
or `dev` removes that protection — a deliberate weakening of a secure default that turns a
writable in-memory mount into a place to stage and run dropped payloads, especially under
a `read_only: true` root filesystem where `/tmp` is otherwise the only writable path.
CWE-732 (Incorrect Permission Assignment), OWASP:A05.

## Why this guard fits the stack

`read_only: true` + a `tmpfs:` mount for scratch space is a common hardening pattern this
project already partially covers (`6c-readonly-container-fs`); this guard closes the
adjacent gap of a tmpfs mount that quietly re-opens what the read-only root was meant to
close:

```yaml
services:
  app:
    tmpfs:
      - /tmp:exec
```

Sourced from compose-lint's `TmpfsInsecureOptionsRule` (`CL-0022`).

## Detection design

1. `applies()` gate — `"docker" in profile.features`.
2. Scans every `docker-compose*.yml`/`.yaml` file via `iter_files_named`, skipping
   `is_dev_compose_file` files.
3. Uses `iter_compose_services()`, then handles both compose `tmpfs:` forms: a scalar
   single-line value (`tmpfs: /tmp:exec`) and a list of strings
   (`tmpfs:\n  - /tmp:exec`). The long `volumes:` form (`- type: tmpfs`) keeps the secure
   defaults and cannot express these tokens — out of scope, matching the real source.
4. `_insecure_options()` splits the entry's option string (after the first `:`) on `,` and
   checks whole-token membership against `{exec, suid, dev}` — matching whole
   comma-separated tokens so the secure `noexec` is never mistaken for the insecure `exec`.
5. Inline opt-out: `# security: allow-compose-tmpfs-insecure-options` anywhere in the file.
6. Severity: `low`. Rule id: `compose-tmpfs-insecure-options/secure-default-removed`.
   Standards: `["OWASP:A05", "CWE-732"]`.

## When NOT to flag

- A `tmpfs:` entry with no options, or only benign options (`size=100m`).
- The long `volumes:` `type: tmpfs` form.
- An audited case, suppressed with `# security: allow-compose-tmpfs-insecure-options`.

## Tests

| Test | What it checks |
|---|---|
| `test_list_form_exec_fires` | Positive: list-form `/tmp:exec` fires (**verified_by**). |
| `test_scalar_form_suid_fires` | Positive: scalar-form `tmpfs: /tmp:suid` fires. |
| `test_dev_option_fires` | Positive: `dev` among multiple comma-separated options fires. |
| `test_secure_default_options_silent` | FP-bait: `size=100m` only → silent. |
| `test_bare_tmpfs_path_silent` | FP-bait: no options at all → silent. |
| `test_pragma_silences` | Suppress pragma → silent. |
| `test_applies_gate` / `test_applies_with_docker` | `applies()` gate. |

## Known bypasses

- **The long `volumes:` `type: tmpfs` form** cannot express these options at all in real
  Compose, so it is correctly out of scope, not a gap.
- **Variable indirection** in the options string is not resolved.

## What this guard does NOT prove

A silent guard does not confirm the applied deployment matches the source. This is a
presence-based, source-only check.

# Citations

[1] agentsec checklist item `6c-compose-tmpfs-insecure-options` (§6c)
[2] CWE-732
[3] OWASP:A05
