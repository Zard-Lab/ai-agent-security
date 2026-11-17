---
type: Guard
title: "k8s-docker-sock-mount"
description: "Kubernetes workload mounts the Docker socket."
timestamp: "2026-07-13T14:07:30+08:00"
guard_id: "k8s-docker-sock-mount"
checklist_section: ["6c"]
standards: ["CIS:Kubernetes", "OWASP:A05"]
---

# Kubernetes workload mounts the Docker socket

_Author — 2026-07-13_

---

## The threat

A `hostPath` volume mounting `/var/run/docker.sock` into a container gives that container the same
control as the node's Docker daemon: it can start, stop, and inspect every container on the node,
mount arbitrary host paths into new containers it spawns, and in practice obtain root on the node
itself. This is the classic "Docker socket = root" escalation path, ported here to the Kubernetes
`hostPath` volume shape it takes when a workload is migrated from a plain Docker/Compose deployment
without re-examining the socket mount. Standards: `OWASP:A05`, `CIS:Kubernetes`.

## Why this guard fits the stack

Sourced from kubesec's `DockerSock` rule (`pkg/rules/dockerSock.go`), verified against the real Go
source — it queries every `hostPath.path` under the workload's `volumes` list and checks for the
literal docker.sock path. A workload that genuinely needs to build/manage containers (a CI runner,
a Docker-in-Docker sidecar) should use a scoped alternative (a rootless build tool, a narrowly
RBAC-bound API), not the raw host socket.

## Detection design

1. `applies()` gates on `"k8s" in profile.features`.
2. Scans `.yaml`/`.yml` files, matches Pod-shaped documents via `k8s_manifest_documents()`.
3. Within a matched document (hash-comments stripped), checks for a `path:` value line equal to
   `/var/run/docker.sock` (optionally quoted) — this is the `hostPath.path` value in a real
   manifest's YAML indentation, matched here without full indentation-tree awareness (see "What
   this guard does NOT prove").
4. Inline opt-out: `# security: allow-k8s-docker-sock-mount` anywhere in the document.
5. Severity: `critical`. Rule: `k8s-docker-sock-mount/hostpath-docker-sock`.
   Standards: `["OWASP:A05", "CIS:Kubernetes"]`.

## When NOT to flag

A `hostPath` volume pointing anywhere else (e.g. `/var/lib/app/data`) must stay silent — only the
literal docker.sock path fires.

## Tests

| Test | What it checks |
|---|---|
| `test_k8s_docker_sock_mount_fires` | a `hostPath.path: /var/run/docker.sock` volume fires critical |
| `test_k8s_docker_sock_mount_passes_other_hostpath` | an unrelated hostPath stays silent |
| `test_k8s_docker_sock_mount_pragma_opt_out` | the inline pragma suppresses |
| `test_k8s_docker_sock_mount_not_applicable_without_k8s_feature` | `applies()` gates correctly |

## Known bypasses

A socket path built from a templated/parameterized value, or bind-mounted under a different
in-container path than the conventional `/var/run/docker.sock` while still targeting the same host
inode via a symlink, is invisible to this literal-path match.

## What this guard does NOT prove

A `path:` line match without full indentation-tree parsing means this guard trusts that a `path:`
value equal to the docker.sock literal is genuinely nested under a `hostPath:` key (true in every
real Kubernetes manifest shape — `path:` is not a generic YAML key used elsewhere in a Pod spec),
but it does not verify the containing volume is actually mounted into a container via
`volumeMounts` (an unused, defined-but-unmounted volume would still fire — a deliberately
conservative choice, since an unused-but-present socket volume is still worth a human's attention).

# Citations

[1] agentsec checklist item `6c-k8s-docker-sock-mount` (§6c)
[2] CIS:Kubernetes
[3] OWASP:A05
