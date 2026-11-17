---
type: Research
title: compose-lint — Docker Compose Security Patterns
description: Statically-detectable Docker Compose misconfiguration patterns distilled from compose-lint's rule catalog, covering root-equivalent and sensitive host bind mounts, credential-shaped environment literals, inline connection-string credentials, missing resource limits, image digest pinning, tmpfs option hardening, mount propagation, and disabled logging.
tags: [research, docker, compose, container, credentials, mounts]
timestamp: "2026-08-16T00:00:00Z"
---

# compose-lint — Docker Compose Security Patterns

## What this covers

[compose-lint](https://github.com/tmatens/compose-lint) is a security-focused Docker
Compose linter grounded in OWASP and the CIS Docker Benchmark. Its 27 real rule modules
(`src/compose_lint/rules/CL0001*.py` through `CL0030*.py`) are exceptionally
well-engineered single-file checks — each with extensive documented false-positive
avoidance, ReDoS-bounded regex, and citations back to corpus measurement (e.g. "24 of 25
naive matches were an application data directory, not the container store"). This
document distills the nine patterns that closed a genuine agentsec gap: Docker Compose had
port/DNS coverage and privileged-flag detection, but nothing that inspected `volumes:`,
`environment:`, `deploy.resources`, `tmpfs:`, or `logging:` for the misconfigurations
below.

## Bind mounts — host-root-equivalent and sensitive paths

| Pattern | What it catches | Detection approach |
|---|---|---|
| A writable bind mount of `/etc`, `/root`, `/boot`, `/proc`, the container store (`/var/lib/docker`, `/var/lib/containerd`), or exactly `/var/lib` | Writing there is host root through ordinary file writes — no exploit required (`/etc/cron.d` schedules a root job, `/root/.ssh/authorized_keys` grants host SSH, `/var/lib/docker` writes tamper with every other container's image layers) | Short-syntax volume scan; `/var/lib` matched EXACTLY (not by descent) — `/var/lib/mysql` is an application's own data directory, not the container store |
| A bind mount of `/sys`, `/dev` (excluding inert bit-bucket devices), a whole home-directory tree, a home credential directory (`.ssh`/`.docker`/`.aws`/`.kube`/`.gnupg`), or a `:ro` mount of a root-equivalent path | Discloses host kernel interfaces, devices, or credentials without granting host-root write | Same volume scan, disclosure-tier path table; a nested application directory under a home tree (depth > 1 segment past the credential-dir check) is NOT flagged |

The `/var/lib` exact-vs-descent distinction is the standout engineering detail: matched
over compose-lint's own 5,417-file corpus, a naive descent match on `/var/lib` produced 25
hits, 24 of which were an application's own state directory and exactly 1 was a real
container-store exposure.

## Environment credentials

| Pattern | What it catches | Detection approach |
|---|---|---|
| A credential-shaped `environment:` key (`PASSWORD`, `TOKEN`, `SECRET`, `API_KEY`, `ACCESS_KEY`, `PRIVATE_KEY`, `_PASS`, `_PWD`, `_DSN`, …) holding a literal value | Env vars are exposed via `docker inspect`, `/proc/<pid>/environ`, `docker compose config`, process listings, and CI logs | Substring/suffix keyword match on the key name, exempting `*_FILE` (the documented secrets-file convention), boolean-toggle values, and a quantity/lifetime-knob family (`TOKEN_TTL_MINUTES: 30` is a duration, not a token) |
| An inline `scheme://user:password@host` credential embedded in ANY environment value, regardless of key name | `DATABASE_URL`, `MONGO_URL`, `REDIS_URL` and similar connection strings routinely carry a literal password even when the key-name check above wouldn't catch it | Bounded userinfo regex (length-capped to stay linear on an adversarial value); a pure `${VAR}` reference password is exempt (parameterized), a defaulted reference (`${VAR:-hunter2}`) still fires |

Both credential patterns share the same exposure surface and the same "is this actually a
literal, or a parameterized reference" judgment call — deliberately split into two guards
(key-name-driven vs. value-shape-driven) rather than one, matching compose-lint's own
two-rule split, since a real compose file can trip either independently.

## Runtime hardening

| Pattern | What it catches | Detection approach |
|---|---|---|
| A service declaring neither a memory nor a CPU limit | Docker imposes no bound by default — a single runaway or compromised service exhausts the host, starving every other container on it | Flat text search per service for `mem_limit:`/`deploy.resources.limits.memory:` and `cpus:`/`cpu_quota:`/`deploy.resources.limits.cpus:` |
| A `tmpfs:` mount re-enabling `exec`, `suid`, or `dev` | Docker mounts tmpfs `noexec,nosuid,nodev` by default; re-enabling any of them turns a writable in-memory mount into a place to stage and run dropped payloads | Comma-token match on the option string after the mount path, both the scalar and list `tmpfs:` forms |
| A `volumes:` entry using `shared`/`rshared` mount propagation | Lets a mount created inside the container appear on the host and vice versa, breaking mount-namespace isolation | Short-syntax suffix match + long-syntax `bind.propagation:` key match; `slave`/`rslave` (host→container only) are correctly not flagged |
| A service `logging:` block with `driver: none` | Disables all log collection — no forensic trail for an incident on that service | Nested-block attribute match |
| A service `image:` pinned to a real version tag but no `@sha256:` digest | A tag can be silently overwritten on the registry — a pull today and next week aren't guaranteed to return the same bytes | Tag extraction (registry-host-with-port aware), skipping mutable-by-convention tags (`latest`/`edge`/`stable`/…) already covered by a sibling Dockerfile-side guard |

## Coverage summary

| Category | Detection technique | Coverage |
|---|---|---|
| Writable host-root-equivalent mount | Short-syntax path-table match | `/etc`/`/root`/`/boot`/`/proc`/`/var/lib/docker`/`/var/lib/containerd` by descent, `/var/lib` exactly; long-syntax volumes and variable-indirected paths are out of scope |
| Sensitive host mount | Short-syntax path-table match | `/sys`/`/dev`/home-tree/credential-dirs/`:ro` root-equivalent covered; the real source's separate `/run`/`/var/run` runtime-directory tier is not reproduced |
| Credential-shaped env key | Keyword pattern + exemption set | A representative subset of the real source's quantity-knob exemption list; an unrecognized key naming convention is invisible (naming-convention check, not entropy/content scanning) |
| Connection-string credential | Bounded regex on env values | A defaulted `${VAR:-default}` password is not resolved to its literal fallback (a real, documented divergence from the upstream source) |
| Resource limits | Flat per-service keyword presence | Does not reproduce the real source's `0`-means-unbounded nuance or interpolation-default resolution |
| Image digest pinning | Tag extraction, registry-port aware | `build:`-context images and variable-indirected `image:` refs are out of scope |
| tmpfs insecure options | Comma-token match | Only the short `tmpfs:` form — the long `volumes: type: tmpfs` form cannot express these options in real Compose, so it is correctly out of scope |
| Shared mount propagation | Suffix/attribute match | Short and multi-line long syntax covered; single-line flow-style long syntax is not |
| Logging disabled | Nested-block attribute match | `driver: none` literal covered; variable-indirected driver values are not |

## Examples

```yaml
# FLAGGED: writable host-root-equivalent mount
services:
  app:
    volumes:
      - /etc:/host-etc

# SAFE: /var/lib/mysql is an application data dir, not the container store
services:
  db:
    volumes:
      - /var/lib/mysql:/var/lib/mysql

# FLAGGED: credential-shaped env key, literal value
services:
  app:
    environment:
      DB_PASSWORD: hunter2

# SAFE: routed through Compose secrets
services:
  app:
    environment:
      DB_PASSWORD_FILE: /run/secrets/db_password

# FLAGGED: inline credential in a connection string
services:
  app:
    environment:
      DATABASE_URL: postgresql://admin:hunter2@db:5432/app

# FLAGGED: no memory or CPU bound
services:
  app:
    image: myapp
    command: ["sleep", "infinity"]

# FLAGGED: tag pinned but no digest
services:
  app:
    image: myapp:1.4.2

# FLAGGED: tmpfs mount re-enables exec
services:
  app:
    tmpfs:
      - /tmp:exec

# FLAGGED: logging disabled entirely
services:
  app:
    logging:
      driver: none
```

## Citations
[1] [compose-lint: WritableHostRootMountRule (CL-0025)](https://raw.githubusercontent.com/tmatens/compose-lint/main/src/compose_lint/rules/CL0025_writable_host_root.py)
[2] [compose-lint: SensitiveMountRule (CL-0013)](https://raw.githubusercontent.com/tmatens/compose-lint/main/src/compose_lint/rules/CL0013_sensitive_mount.py)
[3] [compose-lint: CredentialEnvKeysRule (CL-0020)](https://raw.githubusercontent.com/tmatens/compose-lint/main/src/compose_lint/rules/CL0020_credential_env_keys.py)
[4] [compose-lint: ConnectionStringCredentialsRule (CL-0021)](https://raw.githubusercontent.com/tmatens/compose-lint/main/src/compose_lint/rules/CL0021_connection_string_credentials.py)
[5] [compose-lint: ResourceLimitsRule (CL-0026)](https://raw.githubusercontent.com/tmatens/compose-lint/main/src/compose_lint/rules/CL0026_resource_limits.py)
[6] [compose-lint: ImageNoDigestRule (CL-0019)](https://raw.githubusercontent.com/tmatens/compose-lint/main/src/compose_lint/rules/CL0019_image_no_digest.py)
[7] [compose-lint: TmpfsInsecureOptionsRule (CL-0022)](https://raw.githubusercontent.com/tmatens/compose-lint/main/src/compose_lint/rules/CL0022_tmpfs_insecure_options.py)
[8] [compose-lint: SharedMountRule (CL-0017)](https://raw.githubusercontent.com/tmatens/compose-lint/main/src/compose_lint/rules/CL0017_shared_mount.py)
[9] [compose-lint: LoggingDisabledRule (CL-0014)](https://raw.githubusercontent.com/tmatens/compose-lint/main/src/compose_lint/rules/CL0014_logging_disabled.py)
