---
type: Guard
title: "compose-shared-mount-propagation"
description: "Docker-compose volume using shared mount propagation."
timestamp: "2026-08-16T10:56:38+08:00"
guard_id: "compose-shared-mount-propagation"
checklist_section: ["6c"]
standards: ["CIS:Docker", "CWE-668"]
---

# Docker-compose volume using shared mount propagation

_Author — Marconi, 2026-08-16_

---

## The threat

Shared mount propagation (`shared`/`rshared`) lets a mount created inside a container
appear on the host filesystem and vice versa, breaking mount-namespace isolation between
the container and the host. `slave`/`rslave` propagate host-to-container only and are not
flagged — the risk this guard targets is specifically a container's own mount events
reaching the host (or a sibling container sharing the same propagated tree). CWE-668
(Exposure of Resource to Wrong Sphere), CIS Docker Benchmark 5.20.

## Why this guard fits the stack

An unusual but real misconfiguration: a service explicitly opting into `shared`
propagation, usually copied from a Kubernetes or systemd example without understanding
the isolation trade-off:

```yaml
services:
  app:
    volumes:
      - /host/path:/container/path:shared
```

Sourced from compose-lint's `SharedMountRule` (`CL-0017`).

## Detection design

1. `applies()` gate — `"docker" in profile.features`.
2. Scans every `docker-compose*.yml`/`.yaml` file via `iter_files_named`, skipping
   `is_dev_compose_file` files.
3. Uses `iter_compose_services()`, then walks `volumes:` handling BOTH forms:
   - **Short syntax**: the last colon-separated segment is checked for a `shared`/
     `rshared` token (comma-split, so `:ro,shared` is also caught).
   - **Long syntax**: a `- type: bind` entry followed by nested `source:`/`target:`/
     `bind:` keys; when a `bind:` sub-block is entered, its `propagation:` value is
     checked against the same shared-propagation set.
4. Inline opt-out: `# security: allow-compose-shared-mount-propagation` anywhere in the
   file.
5. Severity: `low`. Rule id: `compose-shared-mount-propagation/shared-propagation`.
   Standards: `["CWE-668", "CIS:Docker"]`.

## When NOT to flag

- `slave`/`rslave` propagation (host-to-container only — the risk direction this guard
  covers is container-to-host).
- A plain bind mount with no propagation option at all.
- An audited case, suppressed with `# security: allow-compose-shared-mount-propagation`.

## Tests

| Test | What it checks |
|---|---|
| `test_short_syntax_shared_fires` | Positive: short-syntax `:shared` fires (**verified_by**). |
| `test_short_syntax_rshared_fires` | Positive: `:rshared` fires. |
| `test_long_syntax_bind_propagation_shared_fires` | Positive: long-syntax `bind.propagation: shared` fires. |
| `test_slave_propagation_not_flagged` | FP-bait: `:slave` → silent (wrong risk direction). |
| `test_plain_bind_mount_silent` | FP-bait: no propagation option → silent. |
| `test_pragma_silences` | Suppress pragma → silent. |
| `test_applies_gate` / `test_applies_with_docker` | `applies()` gate. |

## Known bypasses

- **A flow-style (`{...}`) long-syntax volume entry on one line** is not parsed — only the
  block (multi-line) long-syntax form is handled.
- **Variable indirection** in the propagation value is not resolved.

## What this guard does NOT prove

A silent guard does not confirm the applied deployment matches the source. This is a
presence-based, source-only check.

# Citations

[1] agentsec checklist item `6c-compose-shared-mount-propagation` (§6c)
[2] CIS:Docker
[3] CWE-668
