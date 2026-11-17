---
type: Guard
title: "dockerfile-workdir-sensitive-path"
description: "Dockerfile WORKDIR points to a sensitive system directory."
timestamp: "2026-11-04T00:00:00Z"
guard_id: "dockerfile-workdir-sensitive-path"
checklist_section: ["6c"]
standards: ["OWASP:A05", "CWE-668"]
---

# Dockerfile WORKDIR points to a sensitive system directory

_Author — 2026-11-04_

---

## The threat

**CWE-668 (Exposure of Resource to Wrong Sphere), OWASP:A05 (Security Misconfiguration).**
Setting the container's default working directory to a system-critical or host-adjacent path
raises the blast radius of anything that later writes a RELATIVE path there. **Who reaches
it:** an entrypoint script, a later build step, or an attacker who achieves code execution
inside the running container, any of which may write a relative path without realizing the
CWD is `/etc` or `/root` rather than an isolated application tree. **With what privilege:**
whatever the process already has — this guard does not grant privilege, it widens the damage
a relative-path write can do once something else goes wrong. **To what effect:** an
accidental or malicious write/overwrite inside a system directory that would otherwise be
confined to an application-owned tree.

Mined from `cr0hn/dockerfile-security`'s declarative rule catalog (`security.yaml` sec-002),
cross-checked against agentsec's real guard source: no existing guard inspects a
Dockerfile `WORKDIR` target at all — `docker-socket-access` is scoped narrowly to
`/var/run/docker.sock`, a different (though related) surface.

## Why it's often introduced

A Dockerfile that never explicitly sets a dedicated app directory inherits whatever the base
image's own default is, or a maintenance/debug stage sets `WORKDIR /` to "just get to the
root and poke around," and the line survives into the shipped image:

```dockerfile
FROM debian:bookworm-slim
WORKDIR /root          # left over from an interactive debug session
COPY . .                # now relative to /root, not an app directory
```

## Detection design

1. **`applies()` gate** — `"docker" in profile.features`.
2. **Files scanned** — every Dockerfile found by `iter_dockerfiles(root)`, with backslash
   line-continuations joined via `join_dockerfile_continuations()` first.
3. **Pattern** — `WORKDIR` whose entire argument is exactly `/`, `/root`, `/bin`, `/sbin`,
   `/usr`, `/etc`, `/sys`, or `/proc` (anchored with `^...$`, case-insensitive on the
   instruction keyword). The same bare path written quoted or with a trailing slash
   (`"/root"`, `/etc/`, `'/'`) also matches, since Docker resolves it to the same directory. A
   subdirectory of any of these (`/etc/myapp`) does NOT match — mirrors the source rule's own
   anchoring, which targets the bare system directory itself, not anything nested under it.
4. **Opt-out pragma** — `# security: allow-dockerfile-workdir-sensitive-path` anywhere in the
   file (whole-file reach) silences this check.
5. **Severity / rule / standards** — MEDIUM, `dockerfile-workdir-sensitive-path/
   sensitive-workdir`, standards `["OWASP:A05", "CWE-668"]`.

## When NOT to flag

- `WORKDIR /app` — the ordinary, overwhelmingly common case. Not flagged.
- `WORKDIR /etc/myapp` — a subdirectory of a sensitive path is not the bare system directory
  itself. Not flagged (see the anchoring note above).
- A documented, reviewed base-image-maintenance stage that legitimately operates at `/`:
  suppress with `# security: allow-dockerfile-workdir-sensitive-path`.

## Tests

| Test | What it checks |
|---|---|
| `test_sensitive_workdir_fires` | `WORKDIR /root` fires MEDIUM |
| `test_bare_root_workdir_fires` | `WORKDIR /` fires MEDIUM |
| `test_etc_workdir_fires` | `WORKDIR /etc` fires MEDIUM |
| `test_quoted_or_trailing_slash_sensitive_workdir_fires` | `"/root"`, `/root/`, `'/etc/'`, `"/"`, `/usr/` fire MEDIUM |
| `test_quoted_or_slashed_ordinary_workdir_stays_silent` | FP-bait: `"/app"`, `/rootfs`, `/root/app`, `'/etc/myapp/'`, an unbalanced `"/root`, `/usr/src/app/` stay silent |
| `test_app_workdir_stays_silent` | FP-bait: `WORKDIR /app`, the ordinary case, stays silent |
| `test_etc_subdirectory_stays_silent` | FP-bait: `WORKDIR /etc/myapp` (a subdirectory, not the bare path) stays silent |
| `test_pragma_silences` | the pragma silences the finding |
| `test_applies_gate` | `docker` on, `python`-only off |

## Known bypasses

- **A path built via `ARG`/build-time variable substitution** (`WORKDIR ${APP_DIR}`) rather
  than a literal sensitive path — not tracked, since the final resolved value is unknown
  statically.
- **A sensitive directory reached via a symlink** created earlier in the build and targeted by
  a *different*, non-matching `WORKDIR` argument — out of this guard's lexical, Dockerfile-text
  scope.

## What this guard does NOT prove

A silent guard does not mean every write inside the container is safely confined — only that
no `WORKDIR` instruction's literal argument is one of the 8 listed bare system paths. A later
`cd`/relative-path write inside a `RUN` or entrypoint script that targets a sensitive directory
EXPLICITLY (not via the inherited `WORKDIR`) is a different pattern this guard does not check.

# Citations

[1] agentsec checklist item `6c-dockerfile-workdir-sensitive-path` (§6c)
[2] OWASP:A05
[3] CWE-668
