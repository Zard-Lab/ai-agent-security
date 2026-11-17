---
type: Guard
title: "compose-writable-host-root-mount"
description: "Docker-compose bind mount of a root-equivalent host path, writable."
timestamp: "2026-08-16T10:56:38+08:00"
guard_id: "compose-writable-host-root-mount"
checklist_section: ["6c"]
standards: ["CIS:Docker", "CWE-269", "OWASP:A05"]
---

# Docker-compose bind mount of a root-equivalent host path, writable

_Author — Marconi, 2026-08-16_

---

## The threat

A docker-compose bind mount of `/etc`, `/root`, `/boot`, `/proc`, the container store
(`/var/lib/docker`, `/var/lib/containerd`), or `/var/lib` itself, without `:ro`, gives the
container host root through ordinary file writes — no exploit or escape technique
required. Writing `/etc/cron.d` schedules a root job on the host's next tick; writing
`authorized_keys` under `/root` grants host SSH access; writing into `/var/lib/docker`
tampers with another container's image layers, escaping on that container's next start.
CWE-269 (Improper Privilege Management), OWASP:A05.

## Why this guard fits the stack

Compose is the default local/small-deployment orchestrator for this project's target
stack, and a host bind is often reached for casually to "just share a host directory":

```yaml
services:
  app:
    volumes:
      - /etc:/host-etc
```

Sourced from compose-lint's `WritableHostRootMountRule` (`CL-0025`). The `/var/lib` exact-
vs-descent distinction is reproduced verbatim from the real fetched source: matched over a
5,417-file corpus, a naive descent match on `/var/lib` produced 25 hits, 24 of which were
an application's own state directory (`/var/lib/mysql`, `/var/lib/postgresql/data`, …) and
exactly one was a real bare `/var/lib` mount — so it is matched *exactly*, not by descent.

## Detection design

1. `applies()` gate — `"docker" in profile.features`.
2. Scans every `docker-compose*.yml`/`.yaml` file via `iter_files_named`, skipping
   `is_dev_compose_file` files (matching the project's other compose guards).
3. Uses the new shared `iter_compose_services()` helper (`agentsec/guards/base.py`) to
   isolate each service block, then walks its `volumes:` list with an indent-tracked scan
   (mirroring `compose_db_port_exposed.py`'s `ports:` tracker).
4. Each short-syntax entry (`- <host>:<container>[:opts]`) is split; only a real host path
   (`/`, `./`, or `../` prefixed) is inspected — a bare name (`pgdata:/var/lib/...`) is a
   named volume, out of scope. An `:ro`-suffixed entry is skipped (disclosure, not a
   writable takeover — `compose-sensitive-host-mount`'s territory).
5. `match_root_equivalent()` matches the host path by descent against
   `ROOT_EQUIVALENT_PATHS`, or exactly against `ROOT_EQUIVALENT_EXACT_PATHS` (`/var/lib`
   only). A whole-root mount (`-v /:/host`) is deliberately excluded — it exposes the
   Docker daemon socket in either read/write mode and is `compose-db-port-exposed`'s
   sibling `docker-socket-access`'s territory.
6. Inline opt-out: `# security: allow-writable-host-root-mount` anywhere in the file.
7. Severity: `critical`. Rule id: `compose-writable-host-root-mount/host-root-equivalent`.
   Standards: `["OWASP:A05", "CWE-269", "CIS:Docker"]`.

## When NOT to flag

- The mount is suffixed `:ro` (read-only — a disclosure risk, not a takeover).
- The host path is a relative path (`./data`) or a named volume.
- The host path is `/var/lib/<anything-other-than-docker-or-containerd>` — an
  application's own state directory, not the container store.
- A whole-root mount (`/`) — a different guard's territory, mode-independent.
- An audited case, suppressed with `# security: allow-writable-host-root-mount`.

## Tests

| Test | What it checks |
|---|---|
| `test_writable_etc_mount_fires` | Positive: `/etc` writable fires (**verified_by**). |
| `test_writable_var_lib_exact_fires` | Positive: bare `/var/lib` fires. |
| `test_var_lib_mysql_does_not_fire` | FP-bait: `/var/lib/mysql` (an app data dir) → silent. |
| `test_readonly_root_equivalent_does_not_fire` | FP-bait: `:ro` on `/etc` → silent (this guard's not it). |
| `test_relative_bind_does_not_fire` | FP-bait: `./data` → silent. |
| `test_named_volume_does_not_fire` | FP-bait: `pgdata:...` → silent. |
| `test_whole_root_mount_out_of_scope` | A whole-root mount → silent (a different guard's territory). |
| `test_pragma_silences` | Suppress pragma → silent. |
| `test_applies_gate` / `test_applies_with_docker` | `applies()` gate. |

## Known bypasses

- **Long-syntax volumes** (`- type: bind, source: /etc, target: /host-etc`) are not
  parsed — only the short-syntax scalar form is scanned, matching this project's existing
  compose guards' documented gap.
- **Variable indirection**: `- ${HOST_ETC}:/host-etc` where the variable resolves to
  `/etc` at deploy time — only a literal host path is matched.
- **A path reached indirectly through a symlink inside an already-mounted directory** is
  not detectable from static YAML at all.

## What this guard does NOT prove

A silent guard does not confirm the applied deployment matches the source (drift), or
that a compose file generated/templated at deploy time doesn't introduce the mount. This
is a presence-based, source-only check.

# Citations

[1] agentsec checklist item `6c-compose-writable-host-root-mount` (§6c)
[2] CIS:Docker
[3] CWE-269
[4] OWASP:A05
