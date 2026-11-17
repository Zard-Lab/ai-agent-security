---
type: Guard
title: "k8s-host-namespace-sharing"
description: "Kubernetes workload shares a host namespace."
timestamp: "2026-07-13T14:07:29+08:00"
guard_id: "k8s-host-namespace-sharing"
checklist_section: ["6c"]
standards: ["CIS:Kubernetes", "OWASP:A05"]
---

# Kubernetes workload shares a host namespace

_Author — 2026-07-13_

---

## The threat

`hostPID`/`hostNetwork`/`hostIPC: true` share the underlying NODE's process, network, or shared-
memory namespace with the pod, breaking the isolation Kubernetes is supposed to provide.
`hostPID: true` lets a compromised container see and signal every process on the node, including
other pods'. `hostNetwork: true` exposes the node's real network interfaces and bypasses
NetworkPolicy enforcement. `hostIPC: true` gives access to other processes' shared memory segments
and semaphores. Each turns a single-container compromise into node-wide (and often cluster-wide)
visibility or influence. Standards: `OWASP:A05`, `CIS:Kubernetes`.

## Why this guard fits the stack

Sourced from kubesec's `HostPID`/`HostNetwork`/`HostIPC` rules (`pkg/rules/host{PID,Network,IPC}.go`)
— each reads its one boolean field via a JSONPath query resolved through kubesec's own
`getSpecSelector` (Pod → `spec`, everything else → `spec.template.spec`, CronJob →
`spec.jobTemplate.spec.template.spec`), verified against the real Go source. These fields are
occasionally needed by legitimate infra workloads (a CNI plugin, a node-monitoring DaemonSet) but
almost never by an application workload — which is exactly the class of manifest this checklist
targets.

## Detection design

1. `applies()` gates on `"k8s" in profile.features`.
2. Scans `.yaml`/`.yml` files, matches Pod-shaped documents via `k8s_manifest_documents()`.
3. For each of the three fields independently, checks (after `strip_hash_comments`) for a line
   matching `<field>:\s*true\s*$` (case-insensitive) anywhere in the document — one finding per
   field that fires, so a document setting all three produces 3 findings.
4. Inline opt-out: `# security: allow-k8s-host-namespace-sharing` anywhere in the document
   (suppresses all three fields together, not per-field — a document sharing any host namespace is
   already the reviewed exception).
5. Severity: `high` for all three. Rules: `k8s-host-namespace-sharing/hostpid-enabled`,
   `.../hostnetwork-enabled`, `.../hostipc-enabled`. Standards: `["OWASP:A05", "CIS:Kubernetes"]`.

## When NOT to flag

All three fields explicitly `false`, or simply absent (the safe Kubernetes default), must stay
silent — this guard only fires on an explicit `true`.

## Tests

| Test | What it checks |
|---|---|
| `test_k8s_host_namespace_sharing_fires_hostpid` | `hostPID: true` alone fires 1 finding, right rule |
| `test_k8s_host_namespace_sharing_fires_all_three_fields` | all 3 fields `true` fires all 3 rules |
| `test_k8s_host_namespace_sharing_passes_when_false` | explicit `false` on all 3 stays silent |
| `test_k8s_host_namespace_sharing_passes_when_unset` | absent fields stay silent |
| `test_k8s_host_namespace_sharing_pragma_opt_out` | the inline pragma suppresses |
| `test_k8s_host_namespace_sharing_not_applicable_without_k8s_feature` | `applies()` gates correctly |

## Known bypasses

Same as `k8s-privileged-container`: a templated value (Helm/Kustomize) resolved only at deploy
time is invisible to a static scan of the checked-in manifest.

## What this guard does NOT prove

These are genuinely pod-spec-level fields in real Kubernetes (not per-container), so the
document-scoped precision here is not an approximation the way it is for the container-level
guards in this batch — a document-level finding IS the correct precision for these three fields.

# Citations

[1] agentsec checklist item `6c-k8s-host-namespace-sharing` (§6c)
[2] CIS:Kubernetes
[3] OWASP:A05
