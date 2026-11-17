---
type: Guard
title: "compose-user-directive-missing"
description: "Docker-compose service has no user: directive (image likely runs as root)."
timestamp: "2026-09-05T00:00:00Z"
guard_id: "compose-user-directive-missing"
checklist_section: ["6c"]
standards: ["OWASP:A05", "CWE-250", "CIS:Docker"]
---

# Docker-compose service has no user: directive

_Author — 2026-09-05_

---

## The threat

A container running its main process as root has no privilege boundary between "code execution
inside the container" and "root inside that container's namespace" — materially raising the
blast radius of any container-escape primitive (a misconfigured volume mount, a kernel CVE, a
Docker socket mount) from "attacker-controlled user" to "attacker-controlled root". Compose's
`user:` service field is the run-time lever for this, independent of whatever the image's own
Dockerfile does. Findings carry `OWASP:A05` and `CWE-250` (Execution with Unnecessary Privileges).

## Why it's often introduced / Why this guard fits the stack

`user:` is rarely set in a compose file unless someone deliberately hardens it — most starter
templates and tutorials leave it out entirely, relying on whatever the referenced image already
defaults to. In the 9_Agent_SaaS shape, the compose file is frequently written or edited by a
different person (or at a different time) than the Dockerfile, so a Dockerfile that already drops
privilege can still be silently overridden back to root by a compose file that never says
anything about it — or a compose file that pulls a third-party image (Postgres, Redis, a message
broker) with no visibility into that image's own default user at all.

```yaml
services:
  app:
    image: myapp:1.0
    # no `user:` -> runs as whatever the image defaults to; this file gives no evidence either way
```

## Detection design

1. **applies() gate** — `"docker" in profile.features`.
2. **Files scanned** — `iter_files_named(root, "docker-compose*.yml", "docker-compose*.yaml")`,
   skipping `is_dev_compose_file()` names.
3. **Parse** — `iter_compose_services()` splits the file into per-service blocks. Each service is
   scanned for a `user:` key with a real value, anchored to line-start-plus-whitespace so it can
   never match a differently-named key ending in "user" (`postgres_user:`) or an `environment:`
   list entry (`- USER=root`, which starts with `-`, not `user:`). Comments are stripped first.
4. **Build-context resolution (#804)** — for a service that has no `user:` key but *does* build
   from a local Dockerfile, the guard resolves that Dockerfile before flagging. `build: ./ctx`
   (short form) and a `build:` block with `context:` / `dockerfile:` (long form, defaulting to
   `context: .` and `dockerfile: Dockerfile`) are both parsed; the path is resolved relative to the
   compose file's own directory and only accepted if it exists and lives under the scanned root. The
   Dockerfile's FINAL build stage (from the last `FROM` onward) is then read: if the last `USER`
   there is non-root, the container provably drops privilege and the finding is suppressed. Anything
   short of that positive confirmation keeps firing — `image:`-only services, an unresolvable or
   unreadable Dockerfile, a final stage with no `USER`, or a final-stage `USER root`/`0`.
5. **Pragma opt-out** — `# security: allow-compose-root-user` anywhere in the file.
6. **Severity / rule / standards** — `medium` (lower confidence than an explicit root grant — for an
   `image:`-only service the image may still default to non-root via its own Dockerfile, invisible to
   this guard), rule `compose-user-directive-missing/no-user-directive`, standards
   `["OWASP:A05", "CWE-250", "CIS:Docker"]`.

## When NOT to flag

- A service with any `user:` value set (`user: appuser`, `user: "1000:1000"`) — silent, regardless
  of whether that user happens to be root (an explicit `user: root` is a separate, more confident
  finding this guard deliberately does not attempt — see "What this guard does NOT prove").
- A `build:` service whose resolved Dockerfile's FINAL stage ends on a non-root `USER` (#804) —
  the container provably drops privilege, so silence is correct even with no compose `user:` key.
- An audited exception — suppress with the pragma.

**Not a duplicate of `docker_nonroot_user.py`.** That guard (read in full before writing this one)
parses a Dockerfile's `USER` INSTRUCTION — a build-time directive baked into the image. This guard
parses a compose file's `user:` SERVICE FIELD — a run-time override compose applies on top of
whatever the image already does, governed by an entirely different file, syntax, and often author.
For an `image:`-only service, this guard has no Dockerfile to consult, so it fires at MEDIUM asking
that the run-time identity be set explicitly in compose (or the image's default be confirmed
non-root). For a `build:` service it now resolves that one referenced Dockerfile (#804) and stays
silent when the final stage is non-root — but it still fires when the compose file overrides an
otherwise-non-root image, or when the Dockerfile cannot be confirmed non-root. Conversely a compose
file can set `user: "1000:1000"` on top of a Dockerfile that never dropped privilege. The two guards
cover the two different files that decide "does this container actually run as non-root" end to end.

## Tests

| Test | What it checks |
|---|---|
| `test_no_user_directive_fires` | the common case (no `user:` key) fires; severity/check_id correct |
| `test_commented_out_user_still_fires` | a commented-out `# user: appuser` does not count as present |
| `test_environment_user_var_does_not_suppress` | an `environment:` `USER=root` entry is not mistaken for the field |
| `test_multiple_services_each_evaluated` | each service in a multi-service file is evaluated independently |
| `test_user_directive_present_silent` | `user: "1000:1000"` stays silent |
| `test_user_directive_named_user_silent` | `user: appuser` stays silent |
| `test_similarly_named_key_does_not_suppress_or_falsely_count` | `POSTGRES_USER=admin` neither suppresses nor is required |
| `test_pragma_silences` | the pragma suppresses the finding |
| `test_dev_compose_out_of_scope` | a `*.dev.yml` compose file is skipped |
| `test_applies_gate` / `test_applies_with_docker` | gated on the `docker` feature |
| `test_no_compose_silent` | no compose file -> no findings |
| `test_build_short_form_nonroot_dockerfile_silent` (#804) | `build: ./svc` -> Dockerfile `USER appuser` stays silent |
| `test_build_long_form_custom_dockerfile_nonroot_silent` (#804) | long-form `context:`/`dockerfile:` resolves; non-root stays silent |
| `test_multistage_final_stage_nonroot_silent` (#804) | multi-stage, final stage non-root -> silent (flagship frontend shape) |
| `test_build_context_dockerfile_no_user_still_fires` (#804) | a build Dockerfile with no `USER` still fires |
| `test_build_context_dockerfile_last_user_root_still_fires` (#804) | last-USER-wins: final `USER root` still fires |
| `test_multistage_only_builder_stage_user_still_fires` (#804) | only a non-final stage sets `USER` -> still fires |
| `test_build_context_missing_dockerfile_still_fires` (#804) | unresolvable Dockerfile -> still fires (cannot-confirm) |
| `test_image_only_service_still_fires` (#804) | `image:`-only still fires despite an unrelated non-root Dockerfile |
| `test_pragma_silences_even_a_root_build_service` (#804) | the pragma still suppresses a root build service (Rule 4) |

## Known bypasses

- **Variable indirection** — `user: ${APP_UID}` is treated as "present" even if the interpolated
  value ultimately resolves to `0`/root; the guard does not resolve `.env`/shell interpolation.
- **Swarm/Kubernetes `securityContext`-style fields** outside plain compose `user:` are not parsed.
- A `Dockerfile`-level `USER 0` combined with a compose file that also omits `user:` is only
  caught by `docker_nonroot_user.py`, not this guard.
- **Inline flow-mapping build** — `build: {context: ., dockerfile: X}` is not parsed by the
  indent-based service reader, so such a service is treated as unresolvable and keeps firing (#804,
  the safe direction). The block and short forms are parsed.
- **Named-base-stage USER inheritance (residual FP)** — a final stage `FROM base` that inherits a
  non-root `USER` from an earlier named stage (with no explicit `USER` after the last `FROM`) is not
  recognized as non-root and still fires. This matches `build_secret.py`'s same last-`FROM`
  simplification and errs toward firing (#804).

## What this guard does NOT prove

Silence means one of: a `user:` key with SOME value was found for that service in the committed
compose file, or (for a `build:` service) its resolved Dockerfile's final stage ends on a non-root
`USER` (#804). It does NOT prove a compose `user:` value is actually non-root (`user: root` and
`user: "0"` are known, deliberately out-of-scope non-findings for this guard — see "The threat"
scope note), that the value survives variable interpolation unresolved by this static check, or —
for the build-Dockerfile path — that a final stage inheriting `USER` from a named base stage is
non-root (see Known bypasses).

# Citations

[1] OWASP DockSec `compose_scanner.py::_check_no_non_root_user` (source-verified; see the
    project's private `docksec.md` research digest, candidate #2).
[2] `agentsec/guards/docker_nonroot_user.py` — the Dockerfile-`USER`-instruction sibling this
    guard extends coverage alongside, not duplicates.
[3] OWASP:A05
[4] CWE-250
[5] CIS:Docker
