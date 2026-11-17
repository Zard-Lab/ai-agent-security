---
type: Guard
title: "k8s-resource-limits-absent"
description: "Kubernetes container has no CPU or memory resource limit."
timestamp: "2026-08-24T09:00:00Z"
guard_id: "k8s-resource-limits-absent"
checklist_section: ["6c"]
standards: ["OWASP:A05", "CWE-770"]
---

# Kubernetes container has no CPU or memory resource limit

_Author — 2026-08-24_

---

## The threat

A container with no `resources.limits.cpu`/`.memory` has no cap on its CPU or memory use.
Kubernetes imposes none by default, so a single compromised or runaway container (a
prompt-injected agent tool loop, a memory leak, a fork bomb) can consume the whole node,
starving every other pod scheduled there — the same DoS/noisy-neighbor class the existing
`compose-resource-limits-absent` guard already closes for Docker Compose, at cluster scale
instead of single-host scale: an unbounded pod can exhaust resources shared with OTHER
TENANTS' workloads on the same node, not just this app's own containers. CWE-770 (Allocation
of Resources Without Limits or Throttling), OWASP:A05.

## Why this guard fits the stack

This is the Kubernetes-manifest-level sibling of the existing `compose-resource-limits-absent`
check — same finding class, ported to the manifest format a compose-only check can't see. An
LLM/RAG worker or a background job processor is exactly the kind of container that can run
away:

```yaml
containers:
- name: app
  image: myapp
  # no resources.limits.cpu, no resources.limits.memory -> unbounded
```

Sourced from kubesec's `ResourceLimitsCPU`/`ResourceLimitsMemory` rules
(`pkg/rules/resourceLimits{Cpu,Memory}.go`), verified against the real Go source.

## Detection design

1. `applies()` gate — `"k8s" in profile.features`.
2. Scans every `.yaml`/`.yml` file via `iter_files`, splitting each into individual manifest
   documents with `k8s_manifest_documents()` — the same document-scoped helper every sibling
   `k8s-*` guard in this codebase uses (see `agentsec/k8s.py`'s module docstring for the
   document-scoped precision tradeoff: no per-container path precision, no PyYAML).
3. Within each document, comments are blanked (`strip_hash_comments`) before the walk. An
   indentation-scoped walker (mirrors the `add:` list-block walker in
   `k8s_privileged_capabilities.py`, generalized to a plain indented mapping instead of a
   list) looks for a `limits:` key, then checks whether `cpu:`/`memory:` appears as a direct
   child line at greater indentation, anywhere in the document — not scoped to a specific
   container's own `resources:` block (the same document-scoped tradeoff every sibling
   `k8s-*` guard accepts, not per-container precision).
4. Fires once per missing dimension (CPU, memory) per document, when NO `limits:` block
   anywhere in the document declares that key as a direct child.
5. Inline opt-out: `# security: allow-k8s-resource-limits` anywhere in the document.
6. Severity: `medium` for both dimensions — graded higher than compose's `low` because an
   unbounded pod can exhaust node resources shared with OTHER TENANTS' workloads on the same
   cluster, not just a single host's own containers. Rule ids:
   `k8s-resource-limits-absent/cpu-limit-missing`,
   `k8s-resource-limits-absent/memory-limit-missing`. Standards: `["OWASP:A05", "CWE-770"]`.

## When NOT to flag

- A `limits:` block anywhere in the document declares `cpu:`/`memory:` as a direct child —
  each dimension is checked independently, so setting only one still fires for the other.
- `resources.requests` alone (no `limits:`) — a request expresses a scheduling hint, not a
  hard ceiling; it does not count as a limit.
- An audited case, suppressed with `# security: allow-k8s-resource-limits` anywhere in the
  document.

## Tests

| Test | What it checks |
|---|---|
| `test_no_resources_block_fires_both` | Positive: no `resources:` block at all fires both dimensions. |
| `test_cpu_limit_only_fires_memory_missing` | Positive: CPU limit set, memory not → memory fires. |
| `test_memory_limit_only_fires_cpu_missing` | Positive: memory limit set, CPU not → CPU fires. |
| `test_both_limits_set_silent` | FP-bait: both `cpu:`/`memory:` under `limits:` → silent. |
| `test_requests_only_does_not_count_as_limits` | FP-bait direction check: `resources.requests` set, no `limits:` → still fires (a request is not a limit). |
| `test_pragma_opt_out` | Suppress pragma → silent. |
| `test_not_applicable_without_k8s_feature` / `test_applies_with_k8s` | `applies()` gate. |

## Known bypasses

- **Document-scoped, not per-container**: in a multi-container Pod/Deployment spec, a
  `limits:` block anywhere in the document silences BOTH dimensions for every container in
  that document, even one whose own `resources:` block is empty — the same tradeoff every
  sibling `k8s-*` guard in this codebase accepts (no PyYAML, no structural per-container
  path).
- **`limits: cpu: "0"`** or another non-positive value is read as "a limit is present" even
  though a zero limit may not behave as a real cap on some runtimes — presence, not value
  sanity, is what this guard checks.
- **A resource nested inside a Helm template or Kustomize overlay** that only sets limits at
  render/apply time is invisible to a guard that scans the source manifest as committed.

## What this guard does NOT prove

A silent guard does not confirm the limit values are actually sane for the workload (a
1-byte memory limit satisfies this check), or that the applied deployment matches the
source. This is a presence-based, source-only, document-scoped check.

# Citations

[1] agentsec checklist item `6c-k8s-resource-limits` (§6c)
[2] OWASP:A05
[3] CWE-770
[4] kubesec `ResourceLimitsCPU`/`ResourceLimitsMemory` (`pkg/rules/resourceLimits{Cpu,Memory}.go`)
