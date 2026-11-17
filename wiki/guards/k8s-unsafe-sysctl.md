---
type: Guard
title: "k8s-unsafe-sysctl"
description: "Kubernetes workload sets an unsafe kernel sysctl."
timestamp: "2026-09-05T00:20:00Z"
guard_id: "k8s-unsafe-sysctl"
checklist_section: ["6c"]
standards: ["OWASP:A05", "CIS:Kubernetes"]
---

# Kubernetes workload sets an unsafe kernel sysctl

_Author — 2026-09-05_

---

## The threat

A Pod's `securityContext.sysctls[]` entry sets a kernel parameter on the kernel namespace the Pod
shares with the node. Kubernetes classifies sysctls as "safe" (namespaced per-Pod, cannot affect
other Pods or the node — a small, explicitly documented allowlist, enabled by default) or "unsafe"
(everything else, which the kubelet refuses to apply unless the node operator explicitly opts in via
`--allowed-unsafe-sysctls`). A manifest that sets an unsafe sysctl either fails to schedule (if the
node hasn't opted in — an availability problem) or, if it has, can degrade node stability or affect
sibling workloads sharing the same kernel namespace — a much broader blast radius than the Pod that
set it. Standards: `OWASP:A05`, `CIS:Kubernetes`.

## Why this guard fits the stack

Sourced from kube-linter's `Sysctl` template (`pkg/templates/sysctl/template.go`). The exact default
unsafe-sysctl list kube-linter ships was **not independently re-verified** for this guard (flagged
as an open item in the research this candidate came from) — rather than claim parity with an
unverified upstream list, this guard uses its own curated, documented unsafe-prefix list:

- `kernel.` — kernel-namespace tunables (message queues, shared memory limits, and similar).
- `net.` — network-stack tunables (socket backlogs, TCP/IP behavior, and similar).

Both prefixes are excluded from Kubernetes' own documented "safe sysctls" list by default. To avoid
flagging the small set of genuinely safe, commonly-used sysctls that happen to fall under these two
prefixes, this guard reproduces Kubernetes' own safe-sysctls allowlist as a carve-out:
`kernel.shm_rmid_forced`, `net.ipv4.ip_local_port_range`, `net.ipv4.tcp_syncookies`,
`net.ipv4.ping_group_range`, `net.ipv4.ip_unprivileged_port_start`.

## Detection design

1. `applies()` gates on `"k8s" in profile.features`.
2. Scans `.yaml`/`.yml` files, matches Pod-shaped documents via `k8s_manifest_documents()` — the
   same recognizer `k8s-docker-sock-mount`/`k8s-privileged-capabilities` use. `sysctls` is a
   `PodSecurityContext` field in the real Kubernetes API (Pod-level, not per-container), but this
   guard checks for the pattern's presence anywhere in the matched document, the document-scoped
   precision tradeoff every guard in `agentsec/k8s.py` accepts.
3. Within a matched document (hash-comments stripped), locates a `sysctls:` block-list opener and
   walks its `- name: <sysctl>` items (tolerating each item's `value:` sub-field line, since a
   Kubernetes `Sysctl` object has exactly those two fields). Each name is checked against
   `_UNSAFE_PREFIXES` (`kernel.`, `net.`) and, if it matches, against the `_SAFE_SYSCTLS` allowlist
   above — a name in the allowlist stays silent even though it matches a curated prefix.
4. Inline opt-out: `# security: allow-k8s-unsafe-sysctl` anywhere in the document.
5. Severity: `high`. Rule: `k8s-unsafe-sysctl/<sysctl-name>` (one finding per unsafe sysctl name
   found, e.g. `k8s-unsafe-sysctl/kernel.msgmax`). Standards: `["OWASP:A05", "CIS:Kubernetes"]`.

Like the other `k8s-*` guards, this guard does not consult `is_nonproduct_path()` — see the family
convention noted on `k8s-rbac-cluster-admin-binding`'s design doc.

## When NOT to flag

Any sysctl name outside the `kernel.`/`net.` prefixes (e.g. a hypothetical custom sysctl under a
different namespace) stays silent — this guard is deliberately scoped to the two curated prefixes,
not every possible sysctl. Any of the five documented safe sysctls, even though they carry a
curated-unsafe prefix, must stay silent.

## Tests

| Test | What it checks |
|---|---|
| `test_k8s_unsafe_sysctl_fires_kernel_prefix` | `kernel.msgmax` fires high |
| `test_k8s_unsafe_sysctl_fires_net_prefix_not_on_safe_list` | `net.core.somaxconn` fires |
| `test_k8s_unsafe_sysctl_fires_multiple_entries_independently` | a mixed list fires only the unsafe entries, each its own rule id |
| `test_k8s_unsafe_sysctl_passes_documented_safe_sysctls` | all 5 Kubernetes-documented safe sysctls stay silent |
| `test_k8s_unsafe_sysctl_passes_pod_with_no_sysctls` | a Pod with no `sysctls:` block stays silent |
| `test_k8s_unsafe_sysctl_pragma_opt_out` | the inline pragma suppresses |
| `test_k8s_unsafe_sysctl_not_applicable_without_k8s_feature` | `applies()` gates correctly |

## Known bypasses

A sysctl name built from a templated/parameterized Helm value that renders to an unsafe name at
apply time (but not in the checked-in source) is invisible to this literal-text match. A sysctl
outside the `kernel.`/`net.` prefixes (e.g. under a different tunable family) evades this guard by
design, since it is scoped to a curated subset rather than every unsafe sysctl in existence.

## What this guard does NOT prove

This guard does not attempt to replicate kube-linter's own default unsafe-sysctl list (not
independently verified against the current Go source for this pass) — it is a deliberately narrower,
independently-justified curation (`kernel.`/`net.` prefixes, Kubernetes' own documented safe-sysctls
carve-out). A sysctl under `vm.`, `fs.`, or any other prefix is out of scope even if it would be
"unsafe" by Kubernetes' own classification. A document-scoped match without a real indentation tree
also means it does not verify the `sysctls` block is genuinely nested under a Pod's
`securityContext` rather than some other structure that happens to share the key name (in practice,
`sysctls:` is not a generic YAML key used elsewhere in a Pod spec).

# Citations

[1] agentsec checklist item `6c-k8s-unsafe-sysctl` (§6c)
[2] OWASP:A05
[3] CIS:Kubernetes
[4] kube-linter `Sysctl` template — `pkg/templates/sysctl/template.go`
[5] Kubernetes docs — "safe" vs "unsafe" sysctls and the default safe-sysctls list
