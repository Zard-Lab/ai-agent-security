---
type: Guard
title: "compose-writable-root-filesystem"
description: "Docker-compose service missing read_only: true (writable container root filesystem)."
timestamp: "2026-09-05T00:00:00Z"
guard_id: "compose-writable-root-filesystem"
checklist_section: ["6c"]
standards: ["OWASP:A05", "CIS:Docker"]
---

# Docker-compose service missing read_only: true

_Author — 2026-09-05_

---

## The threat

By default a container's own root filesystem — the image's layers, mounted at `/` — is writable
at runtime. Any code-execution primitive inside it (a dependency RCE, an unsafe deserialization,
a prompt-injected shell-out) can then drop a webshell, overwrite the app's own binaries, or
persist a backdoor for the container's lifetime, all without needing any host bind mount or
capability grant. Compose's `read_only: true` service field makes the container's root filesystem
immutable at the kernel level, which is a well-known, low-cost hardening step that stops this
whole class of persistence. Findings carry `OWASP:A05` and `CIS:Docker`.

## Why it's often introduced / Why this guard fits the stack

`read_only: true` is opt-in and has zero default; most starter templates and generated compose
files never mention it. In the 9_Agent_SaaS shape, an LLM/agent app often needs to write SOME
runtime state (logs, a cache, a temp upload) — the "solution" that avoids testing scoped `tmpfs:`
mounts is to simply not enable `read_only` at all, leaving the whole filesystem writable when only
one narrow path needed to be.

```yaml
services:
  app:
    image: myapp:1.0
    # no `read_only: true` -> the whole container filesystem is writable at runtime
```

## Detection design

1. **applies() gate** — `"docker" in profile.features`.
2. **Files scanned** — `iter_files_named(root, "docker-compose*.yml", "docker-compose*.yaml")`,
   skipping `is_dev_compose_file()` names.
3. **Parse** — `iter_compose_services()` splits the file into per-service blocks. Each service is
   scanned for a `read_only:` key with a boolean value (bare or quoted, any case). Comments are
   stripped first, so a commented-out `# read_only: true` does not count as present. An explicit
   `read_only: false` is treated the same as absence (both fire).
4. **Pragma opt-out** — `# security: allow-writable-container-rootfs` anywhere in the file.
5. **Severity / rule / standards** — `medium` (a hardening step commonly skipped for legitimate
   write-path reasons, not an active exploit by itself), rule
   `compose-writable-root-filesystem/read-only-missing`, standards
   `["OWASP:A05", "CIS:Docker"]`.

## When NOT to flag

- A service with `read_only: true` (any case, quoted or bare) — silent.
- An audited exception — suppress with the pragma.

**Not a duplicate of `compose_writable_host_root_mount.py`.** That guard (read in full before
writing this one) fires on a `volumes:` bind mount of a specific root-equivalent HOST path
(`/etc`, `/root`, `/var/lib/docker`, …) into the container — a host-escape primitive reached
through a named host directory. This guard has nothing to do with host paths: it fires on the
ABSENCE of the `read_only:` field, which governs whether the CONTAINER'S OWN root filesystem is
writable — independent of whether any host path is bind-mounted anywhere. A compose file can have
zero volume mounts and still leave a fully writable container filesystem; conversely a container
can be `read_only: true` and still separately have a dangerous host bind mount, which is the other
guard's finding, not this one. The two guards' fired lines never overlap by construction.

## Tests

| Test | What it checks |
|---|---|
| `test_no_read_only_at_all_fires` | the common case (no `read_only:` key) fires; severity/check_id correct |
| `test_explicit_read_only_false_fires` | an explicit opt-out fires the same as absence |
| `test_commented_out_read_only_still_fires` | a commented-out `# read_only: true` does not count as present |
| `test_multiple_services_each_evaluated` | each service in a multi-service file is evaluated independently |
| `test_read_only_true_silent` | `read_only: true` stays silent |
| `test_read_only_true_case_insensitive_silent` | `read_only: True` (differently cased) stays silent |
| `test_read_only_true_quoted_silent` | a quoted `"true"` value stays silent |
| `test_pragma_silences` | the pragma suppresses the finding |
| `test_dev_compose_out_of_scope` | a `*.dev.yml` compose file is skipped |
| `test_applies_gate` / `test_applies_with_docker` | gated on the `docker` feature |
| `test_no_compose_silent` | no compose file -> no findings |

## Known bypasses

- **Variable indirection** — `read_only: ${READ_ONLY}` is treated as absent (the value is not a
  literal `true`/`false`), which fires even if the resolved value would be `true` — a conservative
  false-positive-leaning gap rather than a silent miss.
- Swarm/Kubernetes-only equivalents (a Pod's `securityContext.readOnlyRootFilesystem`) are not
  parsed by this guard; that surface is `k8s`-family guards' territory.

## What this guard does NOT prove

Silence means a literal `read_only: true` was found for that service in the committed compose
file. It does NOT prove the running container was actually launched from this compose file, that
any `tmpfs:`/volume carve-outs paired with it are themselves safely scoped, or that no other
persistence path exists (a writable host bind mount is a separate finding from a different guard).

# Citations

[1] OWASP DockSec `compose_scanner.py::_check_writable_root_fs` (source-verified; see the
    project's private `docksec.md` research digest, candidate #3).
[2] `agentsec/guards/compose_writable_host_root_mount.py` — the host-bind-mount sibling this
    guard extends coverage alongside, not duplicates.
[3] OWASP:A05
[4] CIS:Docker
