---
type: Guard
title: "k8s-privileged-container"
description: "Kubernetes container runs in privileged mode."
timestamp: "2026-07-13T14:07:21+08:00"
guard_id: "k8s-privileged-container"
checklist_section: ["6c"]
standards: ["CIS:Kubernetes", "OWASP:A05"]
---

# Kubernetes container runs in privileged mode

_Author — 2026-07-13_

---

## The threat

A Kubernetes container running `securityContext.privileged: true` gets nearly unrestricted access
to the host: all Linux capabilities, direct access to host devices, and in most configurations the
ability to mount the host filesystem. If that container is ever compromised — a prompt-injected
agent tool executing attacker-controlled code, an app-level RCE, a supply-chain-compromised base
image — privileged mode turns "one container compromised" into "the whole node compromised."
Standards: `OWASP:A05` (Security Misconfiguration), `CIS:Kubernetes`.

## Why this guard fits the stack

`privileged: true` is most often set as a quick unblock during local development ("the container
needs to talk to `/dev/`" or "docker-in-docker isn't working") and never removed before the
manifest ships. Sourced from kubesec's `Privileged` rule (`pkg/rules/privileged.go`), verified
against the real Go source — kubesec's own implementation reads exactly this one boolean field via
a JSONPath query on `securityContext.privileged`.

## Detection design

1. `applies()` gates on `"k8s" in profile.features` — set by `detect.py`/`agentsec/k8s.py` when a
   `*.yaml`/`*.yml` file contains a Pod-shaped workload manifest (`apiVersion` + a recognized
   controller `kind`).
2. Scans every `.yaml`/`.yml` file under the repo (`iter_files`), splitting each into `---`-separated
   documents via `k8s_manifest_documents()` and processing only the ones that match.
3. Within a matched document, hash-comments are stripped (`strip_hash_comments`) and each line is
   checked against `privileged:\s*true\s*$` (case-insensitive). One finding per matching document
   (not per line/container — see "What this guard does NOT prove").
4. Inline opt-out: `# security: allow-k8s-privileged-container` anywhere in the document.
5. Severity: `critical`. Rule: `k8s-privileged-container/securitycontext-privileged-true`.
   Standards: `["OWASP:A05", "CIS:Kubernetes"]`.

## When NOT to flag

`privileged: false` (the safe, explicit default) and a plain `docker-compose.yml`'s own
`privileged: true` key (a different, non-Kubernetes file shape — `k8s_manifest_documents()`
requires both `apiVersion:` and a recognized workload `kind:`, which compose files never have)
must both stay silent. A commented-out example (`# privileged: true`) must not fire either.

## Tests

| Test | What it checks |
|---|---|
| `test_k8s_privileged_container_fires` | `privileged: true` in a Pod manifest fires critical |
| `test_k8s_privileged_container_passes_privileged_false` | explicit `false` stays silent |
| `test_k8s_privileged_container_silent_on_docker_compose` | a compose file's own `privileged: true` is not mistaken for a K8s manifest |
| `test_k8s_privileged_container_silent_on_commented_line` | a `#`-commented mention doesn't fire |
| `test_k8s_privileged_container_pragma_opt_out` | the inline pragma suppresses |
| `test_k8s_privileged_container_not_applicable_without_k8s_feature` | `applies()` gates correctly |

## Known bypasses

A value built via a Helm template expression (`privileged: {{ .Values.privileged }}`) or a
Kustomize patch applied at deploy time is invisible to a static scan of the raw manifest — this
guard only sees literal `true`/`false` in the checked-in YAML. A value set via `kubectl patch` at
runtime, never checked in, is similarly invisible.

## What this guard does NOT prove

Document-scoped, not per-container: a Pod manifest with multiple containers where only ONE sets
`privileged: true` still fires — correctly flags the document, but doesn't localize which
container within it (kubesec's own Go implementation is per-container via a real JSONPath
selector; this guard trades that precision for staying dependency-free, matching the project's
established "no PyYAML" convention for structured-config guards — see `agentsec/k8s.py`'s module
docstring).

# Citations

[1] agentsec checklist item `6c-k8s-privileged-container` (§6c)
[2] CIS:Kubernetes
[3] OWASP:A05
