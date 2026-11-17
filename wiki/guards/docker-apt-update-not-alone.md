---
type: Guard
title: "docker-apt-update-not-alone"
description: "Dockerfile updates package index in a layer separate from install."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "docker-apt-update-not-alone"
checklist_section: ["5"]
standards: ["CIS:Docker", "OWASP:A06"]
---

# Dockerfile updates package index in a layer separate from install

## What it detects

A Dockerfile `RUN` instruction whose command updates the package index (`apt-get update`,
`apt update`, `yum update`, `dnf update`, `apk update`) but does not also install anything
(`install`/`upgrade`/`add`/`dist-upgrade`/`reinstall`/`groupinstall`/`localinstall`) in that
same instruction.

## Why it matters

Each `RUN` instruction becomes its own Docker image layer, and Docker caches layers
independently based on the instruction's own content and everything before it. If
`apt-get update` runs in one `RUN` layer and `apt-get install` runs in a separate, later
`RUN` layer, a rebuild that only invalidates the install layer (a common outcome of Docker's
layer-caching rules — any change earlier in the Dockerfile that doesn't touch the update line
itself) reuses the OLD cached update layer's stale package index. The install layer then
installs whatever package version was available the last time the update layer was actually
rebuilt, which may be missing security patches released since. checkov's own `CKV_DOCKER_5`
check exists specifically for this pattern — it's a well-documented, common real-world
Dockerfile mistake, not a theoretical one.

## Detection scope

- Language: Dockerfile (matched by name via `iter_dockerfiles()`, not a file extension)
- Applies when: `"docker" in profile.features`
- Backslash line continuations (`RUN apt-get update && \` / next line) are joined into one
  logical line before matching, via a local `_join_continuations()` helper — real Dockerfiles
  commonly split a chained `RUN` across several lines for readability
- Fires when a `RUN` instruction's (joined) command matches `_UPDATE_CMD` but not
  `_INSTALL_CMD` anywhere in the same instruction

checkov's own check (`UpdateNotAlone.py`) is looser than this guard: it counts update/install
occurrences across the WHOLE Dockerfile and only fails if the counts don't balance, so an
update in one `RUN` and a matching install in a LATER, separate `RUN` instruction passes
checkov's check even though the layer-caching risk this guard describes is still real for that
exact shape. This guard is intentionally stricter — requiring both in the SAME instruction —
because that's the actual fix (force both to invalidate together), not just a same-file
occurrence count.

## Rules

| Rule ID | Severity | Trigger |
|---|---|---|
| `docker-apt-update-not-alone/update-without-install` | MEDIUM | `RUN` updates the package index without installing in the same instruction |

MEDIUM, not HIGH — this is a supply-chain hygiene issue (stale packages, not a direct
exploitation path), and the actual impact depends on how the image is rebuilt/deployed and
whether a base-image rebuild step (`5-docker-base-rebuild`, already a manual checklist item)
compensates for it.

## Opt-out

`# security: allow-docker-update-not-alone` on the `RUN` line (any physical line of a continued one)
silences that one finding. It is counted only as a real `#` comment (the `hash` comment view, so the phrase inside a quoted string does not count, #1040), read over the joined logical line. A
deliberately separate update-only layer for image-build tooling that never installs anything
in the same Dockerfile is a legitimate (if unusual) pattern.

## Known bypasses / false negatives

| Bypass | Why missed |
|---|---|
| `RUN apt-get update` in one layer, `RUN apt-get install` in a later separate layer | Each `RUN` is checked independently — this guard is intentionally *stricter* than checkov's whole-file count-balance approach, not looser, so this shape is NOT a false negative here (it fires on the bare update line) |
| A package manager not in the recognized set (`pip`, `npm`, `apk` update via a non-standard alias) | Only apt/apt-get/yum/dnf/apk are matched |
| `RUN` content built from a shell script file (`RUN ./update.sh`) that itself does the update/install split | The guard only sees the literal `RUN` command text, not what a called script does |

## False positive scenarios

| Scenario | Why it fires | How to handle |
|---|---|---|
| A deliberate update-only layer in a base image used ONLY to build a later derived image's package cache, never installing anything itself | Same shape as the real risk from the guard's perspective — cannot distinguish intent | Suppress with `# security: allow-docker-update-not-alone` after confirming the layer-caching risk doesn't apply to this build's actual usage pattern |

## Checklist mapping

`5-docker-apt-update-not-alone` (new item, MEDIUM — no prior coverage)

## Standards

- OWASP:A06 (Vulnerable and Outdated Components)
- CIS:Docker (Docker Benchmark, package-management hygiene)

## Related guards

- `hadolint` (external runner): CIS-benchmark Dockerfile linting broadly, but does not carry
  this specific update/install-layer-separation check in its default ruleset.

# Citations

[1] agentsec checklist item `5-docker-apt-update-not-alone` (§5)
[2] CIS:Docker
[3] OWASP:A06
