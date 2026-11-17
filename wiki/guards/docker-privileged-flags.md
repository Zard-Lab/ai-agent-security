---
type: Guard
title: "docker-privileged-flags"
description: "Privileged-container / host-namespace flag enables container escape."
timestamp: "2026-08-19T00:00:00+08:00"
guard_id: "docker-privileged-flags"
checklist_section: ["6c"]
standards: ["CIS:Docker", "CWE-269", "OWASP:A05"]
---

# Privileged-container / host-namespace flag enables container escape

## Threat

**CWE-269 (Improper Privilege Management), OWASP:A05.** `--privileged` (or its docker-compose
equivalent `privileged: true`) disables nearly every container isolation mechanism Docker
provides — cgroup restrictions, seccomp, AppArmor/SELinux, device access controls — making a
container escape trivial for anyone who achieves code execution inside it. Individual
capability grants (`--cap-add=SYS_ADMIN`), host-namespace sharing (`--pid=host`/`--net=host`),
and unconfined security profiles (`--security-opt=...unconfined`) each independently weaken
the same isolation boundary, even without the blanket `--privileged` flag.

```yaml
services:
  app:
    privileged: true
    cap_add:
      - SYS_ADMIN
    network_mode: host
```

Sourced from SkillSpector's `PE5` category ("Privileged Container / Container Escape") — built
for scanning AI agent skill files, where a skill instructing an agent to run a container with
these flags is an especially dangerous combination.

## Detection design

1. **`applies()` gate:** `"docker" in profile.features`.
2. **Files scanned:** `.sh`, `.bash`, `.yml`, `.yaml` via `iter_files()`; test/fixture/vendor
   files are skipped via `is_nonproduct_path` (PR #393 review #2).
3. **CLI-form flat patterns** (checked per line, flat HIGH): `--privileged`,
   `--pid`/`--net`/`--network`/`--ipc` set to `host`, `--security-opt` naming an `unconfined`
   profile. (`--cap-add` is handled separately, graded — see 5.)
4. **YAML-form single-line patterns** (checked per line, flat HIGH): `privileged: true`,
   `network_mode`/`pid` set to `host` (quoted or bare).
5. **`cap_add` — graded severity taxonomy** (`_CAP_SEVERITY`), not one flat bucket. Both the
   CLI form (`--cap-add=<cap>`) and the YAML form (inline `[...]` list or up to 10 following
   `- item` lines under `cap_add:`) extract the actual capability name(s) present and grade
   each independently:
   - **CRITICAL** — `ALL`, `SYS_ADMIN`, `SYS_MODULE`, `SYS_RAWIO` (host code execution, no
     second flaw needed).
   - **HIGH** — `NET_ADMIN`, `BPF`, `SYS_BOOT` (strong, host-adjacent); `PERFMON`, `SYS_TIME`
     (reach the host with no sibling key needed); `SYS_NICE`, `IPC_LOCK`, `LEASE` (host
     availability); `SYSLOG` (host kernel-log disclosure).
   - **MEDIUM** — `SYS_PTRACE`, `DAC_READ_SEARCH` (real but bounded to this container unless
     something else in the file extends its reach).
   - **Not flagged:** `CAP_ALL` (the prefixed spelling) — Docker special-cases `ALL` before
     applying the `CAP_` prefix, so `--cap-add CAP_ALL` fails to start the container outright
     and grants nothing. Flagging it as CRITICAL would describe a container that never runs.
   - Multiple distinct capabilities in one `cap_add:` block each get their own finding.
   - Sourced from compose-lint's `_caps.py`/`CL-0011`/`CL-0024`/`CL-0027`/`CL-0028`/`CL-0029`/
     `CL-0030` rule split (raw source fetched and verified directly — not paraphrased from a
     README), re-derived here as one severity table instead of seven separate rule classes.
6. **`security_opt:` block pattern** (whole-file window, same shape as `cap_add`): matches
   `unconfined` anywhere in the captured window → flat HIGH.
7. **`cap_drop: [ALL]` absence** (new, MEDIUM, mirrors compose-lint `CL-0006`): fires once per
   file when the file contains a `cap_add` (CLI or YAML, any capability — not just a graded
   dangerous one) but no `cap_drop: [ALL]` / `--cap-drop=ALL` anywhere in the same file.
   **Deliberately scoped, not unconditional** — see the dedicated section below.
8. **Skips:** lines starting with `#` or `//`.
9. **Pragma:** `# security: allow-docker-privileged` anywhere in the file skips it entirely
   (all findings, including the cap_drop-absence one).
10. **Rules:** `docker-privileged-flags/privileged-or-host-namespace` (flat findings + all
    graded `cap_add` findings, severity varies per case), `docker-privileged-flags/
    cap-drop-all-missing` (MEDIUM).

Findings are deduplicated per `(line, label)` pair — a flat pattern and a graded `cap_add`
match on the same line each still get their own finding (different labels), but the same
label on the same line is never emitted twice.

## Relationship to checklist item `6c-cap-drop`

That item ("Drop unnecessary Linux capabilities — `--cap-drop ALL`") was previously `partial`,
covered only from the "flag the dangerous grant when present" angle. This guard now also flags
the ABSENCE of `cap_drop: [ALL]` — but only in a file that itself adds a capability, not
unconditionally. An unconditional "no `cap_drop: [ALL]` anywhere" check (compose-lint `CL-0006`'s
actual behavior) was considered and rejected: most compose files never touch capabilities at
all, and requiring a drop-all baseline they never needed would be exactly the
false-positive-prone shape this guard's design has always argued against — and the sibling
`k8s_privileged_capabilities.py` guard makes the identical call for the same reason (see its
own docstring). Scoping to "a file that already adds a capability" keeps the check aligned with
genuine "added privilege with no least-privilege baseline" signal, which is enough to flip the
checklist item to `covered`.

## When NOT to flag

A CI runner or Docker-in-Docker build pipeline stage genuinely needs some of these flags —
this is a real, common exception, not a rare edge case. The pragma exists for exactly this:
isolate the specific job/file that needs it rather than expecting the guard to distinguish
intent from the flag alone.

## Tests

| Test | What it checks |
|---|---|
| `test_docker_privileged_flags_flags_yaml_privileged_true` | `privileged: true` fires HIGH |
| `test_docker_privileged_flags_flags_yaml_cap_add_block_list` | `cap_add:` + `- SYS_ADMIN` fires CRITICAL, plus cap-drop-absent MEDIUM |
| `test_docker_privileged_flags_flags_yaml_cap_add_inline` | `cap_add: [NET_ADMIN]` fires HIGH, plus cap-drop-absent MEDIUM |
| `test_docker_privileged_flags_cap_add_severity_taxonomy` | Every taxonomy capability (`ALL`/`SYS_MODULE`/`SYS_RAWIO`/`BPF`/`SYS_BOOT`/`PERFMON`/`SYS_TIME`/`SYS_NICE`/`IPC_LOCK`/`LEASE`/`SYSLOG`/`SYS_PTRACE`/`DAC_READ_SEARCH`) fires at its documented severity |
| `test_docker_privileged_flags_cap_add_cap_all_prefix_not_flagged` | `cap_add: [CAP_ALL]` (the prefixed spelling) is silent — Docker rejects it outright |
| `test_docker_privileged_flags_flags_yaml_network_mode_host` | `network_mode: host` fires |
| `test_docker_privileged_flags_flags_cli_privileged` | `docker run --privileged` fires |
| `test_docker_privileged_flags_flags_cli_cap_add` | `--cap-add=SYS_ADMIN` fires CRITICAL |
| `test_docker_privileged_flags_silent_safe_compose` | `cap_add: [NET_BIND_SERVICE]` (not in taxonomy) stays silent on the graded check, but cap-drop-absent still fires MEDIUM |
| `test_docker_privileged_flags_cap_drop_present_silences_cap_drop_check` | `cap_add` + `cap_drop: [ALL]` together → cap-drop-absent stays silent |
| `test_docker_privileged_flags_no_cap_add_silences_cap_drop_check` | A file that never touches capabilities at all stays fully silent (FP-bait for the scoped design) |
| `test_docker_privileged_flags_cli_cap_drop_all_silences_cap_drop_check` | `--cap-add=...` + `--cap-drop=ALL` together → cap-drop-absent stays silent |
| `test_docker_privileged_flags_silent_privileged_false` | `privileged: false` stays silent |
| `test_docker_privileged_flags_pragma_silences` | File-level pragma suppresses all findings |
| `test_docker_privileged_flags_skips_nonproduct_path` | Regression (#393 #2): a privileged compose file under `fixtures/` is skipped |
| `test_docker_privileged_flags_applies_gate` | Guard does not apply when `docker` not in features |
| `test_docker_privileged_flags_applies_with_docker` | Guard applies when `docker` in features |

## Known bypasses

- A capability granted via a YAML anchor/alias (`cap_add: *dangerous_caps` referencing a
  definition elsewhere in the file) is not resolved — only a literal inline list or block list
  directly under the key is checked.
- `--cap-add SYS_ADMIN` split across a line continuation in a shell script is not joined —
  only a single physical line is checked per CLI pattern.
- A capability name outside the curated taxonomy (see the detection design's severity table)
  is not flagged, even if genuinely dangerous in context (e.g. `DAC_OVERRIDE`, `MKNOD` — both
  deliberately excluded upstream too, since both are in Docker's own default capability set,
  so flagging them on `cap_add` would score the declaration rather than the runtime state) —
  the list favors precision over exhaustive recall.
- The `cap_drop: [ALL]` absence check is file-scoped, not service-scoped: a multi-service
  compose file where service A adds a capability and unrelated service B drops all
  capabilities reads as "has a drop-all baseline" even though A doesn't. This is a
  false-negative-leaning tradeoff (the guard under-reports rather than over-reports on
  multi-service files), consistent with the guard's existing block-level (not full
  service-tree) parsing elsewhere.

## What this guard does NOT prove

A file with no finding may still run a privileged container via a mechanism this guard doesn't
recognize — a Kubernetes `securityContext.privileged: true` (a different YAML shape entirely,
not covered), a programmatic Docker SDK call setting `privileged=True` (Python's
`docker-py` `containers.run(..., privileged=True)`), or a wrapper script that constructs the
`docker run` command from variables so the literal flag never appears on one line.

# Citations

[1] agentsec checklist item `6c-cap-drop` (§6c)
[2] CIS:Docker
[3] CWE-269
[4] OWASP:A05
[5] compose-lint (tmatens/compose-lint) `src/compose_lint/rules/_caps.py`, `CL-0006`,
    `CL-0011`, `CL-0024`, `CL-0027`, `CL-0028`, `CL-0029`, `CL-0030` — the `cap_add` severity
    taxonomy and `cap_drop: [ALL]`-absence check this batch is derived from
