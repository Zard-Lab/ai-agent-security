---
type: Guard
title: "compose-sensitive-host-mount"
description: "Docker-compose bind mount of a sensitive host path."
timestamp: "2026-08-16T10:56:38+08:00"
guard_id: "compose-sensitive-host-mount"
checklist_section: ["6c"]
standards: ["CIS:Docker", "CWE-200", "OWASP:A05"]
---

# Docker-compose bind mount of a sensitive host path

_Author — Marconi, 2026-08-16_

---

## The threat

Mounting `/sys`, `/dev`, a whole home-directory tree, or a known credential directory
inside a home directory (`.ssh`, `.docker`, `.aws`, `.kube`, `.gnupg`) into a container
discloses host kernel interfaces, devices, or credentials to it — without the host-root
*write* access `compose-writable-host-root-mount` covers. A read-only mount of a
root-equivalent path is also disclosure rather than takeover, and lands here rather than
there. CWE-200 (Exposure of Sensitive Information), OWASP:A05.

## Why this guard fits the stack

The companion of `compose-writable-host-root-mount`, covering the disclosure-only half of
the same bind-mount risk surface:

```yaml
services:
  app:
    volumes:
      - /home:/host-home
```

Sourced from compose-lint's `SensitiveMountRule` (`CL-0013`), simplified: the real source
also excludes a handful of inert `/dev/*` bit-bucket devices and a `/run`/`/var/run`
runtime-directory descent tier not reproduced here (documented as a known gap below).

## Detection design

1. `applies()` gate — `"docker" in profile.features`.
2. Scans every `docker-compose*.yml`/`.yaml` file via `iter_files_named`, skipping
   `is_dev_compose_file` files.
3. Uses `iter_compose_services()` + an indent-tracked `volumes:` walk, same shape as
   `compose-writable-host-root-mount`. Imports and reuses that guard's
   `match_root_equivalent()`/`normalize_host_path()` helpers directly rather than
   duplicating the path table.
4. For each bind mount: `/sys` or `/dev` (by descent, excluding the inert devices
   `/dev/null`/`/dev/zero`/`/dev/full`/`/dev/random`/`/dev/urandom`) fires. `/home` itself
   or a whole user's home directory (`/home/<user>`, exactly 3 path segments) fires. A
   known credential directory nested one level under a user's home
   (`/home/<user>/.ssh`, `.docker`, `.aws`, `.kube`, `.gnupg`) fires. A deeper application
   directory under a home tree (`/home/alice/projects/app/data`) does NOT fire — depth is
   what separates host-user-data exposure from an ordinary application directory (the same
   distinction the real source's own corpus measurement found necessary: 4,598 findings
   across 1,712 files on a naive descent match, none of them real).
   A root-equivalent path (see the sibling guard) mounted `:ro` also fires here.
5. Inline opt-out: `# security: allow-sensitive-host-mount` anywhere in the file.
6. Severity: `high`. Rule id: `compose-sensitive-host-mount/sensitive-path`.
   Standards: `["OWASP:A05", "CWE-200", "CIS:Docker"]`.

## When NOT to flag

- An inert `/dev/*` bit-bucket device (`/dev/null`, etc.) — discloses nothing.
- A project directory nested under a home tree that isn't a whole home dir or a known
  credential directory.
- A root-equivalent path mounted writable (not `:ro`) — `compose-writable-host-root-
  mount`'s territory, priced higher (critical, not high).
- An audited case, suppressed with `# security: allow-sensitive-host-mount`.

## Tests

| Test | What it checks |
|---|---|
| `test_home_root_fires` | Positive: `/home` itself fires (**verified_by**). |
| `test_ssh_credential_dir_fires` | Positive: `/home/alice/.ssh` fires. |
| `test_dev_bind_fires` | Positive: `/dev` fires. |
| `test_readonly_root_equivalent_fires` | Positive: `/etc:ro` fires here, not on the writable-mount guard. |
| `test_inert_dev_null_does_not_fire` | FP-bait: `/dev/null` → silent. |
| `test_app_project_dir_under_home_does_not_fire` | FP-bait: a nested project dir under `/home` → silent. |
| `test_pragma_silences` | Suppress pragma → silent. |
| `test_applies_gate` / `test_applies_with_docker` | `applies()` gate. |

## Known bypasses

- **Long-syntax volumes** are not parsed, same as the sibling guard.
- **`/run`/`/var/run` runtime-directory descendants** (the real source's own separate
  tier, e.g. `/var/run/dbus`, `/var/run/libvirt/libvirt-sock`) are not reproduced here —
  a real, narrower gap versus the upstream source, left for a future extension.
- **Variable indirection** — only a literal host path is matched.

## What this guard does NOT prove

A silent guard does not confirm the applied deployment matches the source, or that a
templated compose file doesn't introduce the mount at deploy time. This is a
presence-based, source-only check.

# Citations

[1] agentsec checklist item `6c-compose-sensitive-host-mount` (§6c)
[2] CIS:Docker
[3] CWE-200
[4] OWASP:A05
