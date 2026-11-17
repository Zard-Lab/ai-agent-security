---
type: Guard
title: "docker-nonroot-user"
description: "Container does not drop privilege to a non-root user."
timestamp: "2026-07-12T00:44:21+08:00"
guard_id: "docker-nonroot-user"
checklist_section: ["6c"]
standards: ["CIS:Docker", "OWASP:A05"]
---

# Container does not drop privilege to a non-root user

_Author — 2026-07-12_

---

## The threat

A container whose main process runs as root has no privilege boundary between "attacker
achieved code execution inside the container" and "attacker is root inside that
container's namespace." Code execution can arrive through an unrelated bug entirely
outside this guard's scope — a dependency RCE, an unsafe deserialization, a prompt-injected
shell-out from an LLM agent tool call — and once it does, running as root turns any
further container-escape primitive (a misconfigured host volume mount, a Docker-socket
mount, a kernel CVE) from "attacker-controlled unprivileged user" into "attacker-controlled
root," the difference between a contained incident and a host compromise. OWASP:A05
(Security Misconfiguration) / CWE-250 (Execution with Unnecessary Privileges).

Source: `pkg/policies/opa/rego/docker/docker_run/lastUserRoot.rego` in
[tenable/terrascan](https://github.com/tenable/terrascan) — verified by direct fetch. The
real rego body:

```
{{.prefix}}{{.name}}{{.suffix}}[cmd.id]{
    cmd := input.docker_user[count(input.docker_user) - 1]
    cmd.config == "root"
}
```

It only inspects the LAST `USER` instruction's value for the literal string `"root"`.

## Why this guard fits the stack

Almost every FastAPI + React app in agentsec's target shape ships a Dockerfile for the
backend and/or frontend build. Base images (`python:3.12-slim`, `node:20-alpine`) default
to root, and it is extremely common for a Dockerfile to never add a `USER` line at all —
not because root is intentional, but because it's simply the path of least resistance
during initial setup and nobody revisits it.

## Detection design

1. `applies()` — always true (`return True`); a Dockerfile is stack-agnostic.
2. Scans every file returned by `iter_dockerfiles(root)` (`Dockerfile`, `Dockerfile.*`,
   `*.dockerfile`).
3. Two distinct checks, extending the terrascan source concept by one step:
   - **No `USER` instruction anywhere** in the file → `docker-nonroot-user/no-user-instruction`
     (MEDIUM). This is not in the terrascan rule (which requires at least one `USER` entry
     to inspect) but is the more common real-world gap: a Dockerfile that never sets `USER`
     runs as the base image's default, root for almost all public base images.
   - **The LAST `USER` instruction resolves to root** (`_USER_INSTRUCTION` regex captures
     the argument; `_ROOT_TOKEN` matches the literal `root` or `0`, with an optional
     `:group` suffix stripped) → `docker-nonroot-user/last-user-root` (HIGH — higher
     confidence and severity than the missing-instruction case, since it's an explicit,
     unambiguous root assignment).
4. Inline opt-out: `# security: allow-root-container` anywhere in the Dockerfile text
   silences both findings for that file.
5. Severities/rules/standards: see above; both carry `["OWASP:A05", "CWE-250"]`.

## When NOT to flag

- An earlier `USER root` (for setup steps like `apt-get install`) followed by a final
  non-root `USER appuser` is the CORRECT pattern and must stay silent — Docker uses only
  the last `USER` in effect at runtime, and the guard's "last instruction" logic already
  handles this (`test_docker_nonroot_user_switched_to_nonroot_silent`).
- The `# security: allow-root-container` pragma is for a documented, reviewed exception
  (e.g. a local dev-only Dockerfile, or a base image that itself drops privilege via a
  runtime entrypoint the guard cannot see statically).

## Tests

| Test | What it checks |
|---|---|
| `test_docker_nonroot_user_no_user_instruction_fires` | No `USER` line at all → fires `no-user-instruction` |
| `test_docker_nonroot_user_last_user_root_fires` | Non-root `USER` then final `USER root` → fires `last-user-root` (HIGH) |
| `test_docker_nonroot_user_uid_zero_fires` | `USER 0` (numeric root UID) → fires |
| `test_docker_nonroot_user_switched_to_nonroot_silent` | `USER root` (setup) then final `USER appuser` → silent (FP-bait) |
| `test_docker_nonroot_user_group_suffix_root_fires` | `USER root:root` (root user, explicit group) → fires |
| `test_docker_nonroot_user_pragma_silences` | Pragma present → silent |
| `test_docker_nonroot_user_no_dockerfile_silent` | No Dockerfile in repo → silent |
| `test_docker_nonroot_user_applies_always` | `applies()` is `True` for any profile |

## Known bypasses

- **Indirect via build ARG:** `ARG U=root` then `USER $U` is not resolved — the guard
  only recognizes a literal `root`/`0` token, not a variable that expands to it. Adversarially
  tested; confirmed silent. Static analysis of a Dockerfile cannot generically resolve
  build-arg values without executing the build.
- **Multi-stage, final stage has no `USER` but an earlier stage does:** the guard scans
  `USER` instructions across the WHOLE file (mirroring the terrascan source rule's own
  scope), not per build stage. If stage 1 sets `USER appuser` but the final production
  stage never sets `USER` at all, the file's "last USER instruction" is stage 1's
  non-root user, so the guard stays silent even though the actual final image runs as
  root (the default, since the final stage never overrode it). Adversarially tested;
  confirmed this is a real false negative, and it's the same scope limitation the
  terrascan source rule itself has (its rule also just takes `input.docker_user[count-1]`
  over the whole parsed file).
- **A custom base image that already runs non-root by its own `ENTRYPOINT`/exec-user
  switch (e.g. `gosu`/`su-exec` inside the entrypoint script) but has no Dockerfile
  `USER` line:** flagged as `no-user-instruction` even though the running container may
  in practice drop privilege at start-up. This is a deliberate false-positive tradeoff —
  the guard can't see inside an entrypoint script — mitigated by the pragma.

## What this guard does NOT prove

- That the non-root user actually has restricted filesystem/capability access at
  runtime — a non-root user with a writable `/` bind mount or `SYS_ADMIN` capability can
  still cause damage; this guard only proves a `USER` directive exists and isn't root, not
  that the broader container hardening (capabilities, read-only rootfs, seccomp) is sound.
- That `docker run`/orchestrator config doesn't override the image's `USER` at runtime
  (e.g. `docker run --user root`) — that is outside a static Dockerfile scan's reach.
- That the image build itself (steps that ran as root before the final `USER` switch)
  didn't leave behind root-owned files the non-root user can't write to (a common
  operational bug, not itself a security hole) — orthogonal to this check.

# Citations

[1] agentsec checklist item `6c-nonroot-container-user` (§6c)
[2] CIS:Docker
[3] OWASP:A05
