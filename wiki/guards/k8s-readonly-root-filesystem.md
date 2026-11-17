---
type: Guard
title: "k8s-readonly-root-filesystem"
description: "Kubernetes container doesn't set a read-only root filesystem."
timestamp: "2026-07-13T16:29:55+08:00"
guard_id: "k8s-readonly-root-filesystem"
checklist_section: ["6c"]
standards: ["CIS:Docker", "OWASP-LLM:LLM01", "OWASP-LLM:LLM04", "OWASP:A05"]
---

# Kubernetes container doesn't set a read-only root filesystem

_Author — 2026-07-13_

---

## The threat

A writable container root filesystem gives a compromised process (prompt-injected agent tool
execution, a supply-chain-compromised base image, an app-level RCE) a place to drop and persist a
payload, instead of being confined to volumes the workload explicitly declared as writable.
Standards: `OWASP:A05`, `CIS:Kubernetes`.

## Why this guard fits the stack

This is the Kubernetes-manifest-level sibling of the EXISTING `6c-readonly-container-fs` checklist
item — `ai-docker` already checks this control at the Dockerfile/compose level; a repo that ships
only K8s manifests (no Dockerfile-level signal `ai-docker` can see) was invisible to that item
until now. Sourced from kubesec's `ReadOnlyRootFilesystem` rule (`pkg/rules/readOnlyRootFilesystem.go`),
verified against the real Go source — kubesec's own scoring rewards the explicit `true`, meaning
unset and explicit `false` are equally un-hardened (an absence-of-opt-in check, same direction as
`k8s-automount-serviceaccount-token`).

## Detection design

1. `applies()` gates on `"k8s" in profile.features`.
2. Scans `.yaml`/`.yml` files, matches Pod-shaped documents via `k8s_manifest_documents()`.
3. Within a matched document (hash-comments stripped), fires when NO line matches
   `readOnlyRootFilesystem:\s*true\s*$` (case-insensitive) anywhere in the document.
4. Inline opt-out: `# security: allow-k8s-readonly-root-filesystem` anywhere in the document.
5. Severity: `medium`. Rule: `k8s-readonly-root-filesystem/not-explicitly-enabled`.
   Standards: `["OWASP:A05", "CIS:Kubernetes"]`.

**Checklist mapping:** this guard's `check_id` was added to the EXISTING `6c-readonly-container-fs`
item's `check_ids` array (alongside `ai-docker`), and `"k8s"` was added to that item's
`applies_when` — the same checklist gap, a second detection layer, not a new item.

## When NOT to flag

An explicit `readOnlyRootFilesystem: true` anywhere in the document (pod-spec or container level)
must stay silent.

## Tests

| Test | What it checks |
|---|---|
| `test_k8s_readonly_root_filesystem_fires_when_unset` | no field at all fires medium |
| `test_k8s_readonly_root_filesystem_fires_when_false` | explicit `false` also fires |
| `test_k8s_readonly_root_filesystem_passes_when_true` | explicit `true` stays silent |
| `test_k8s_readonly_root_filesystem_pragma_opt_out` | the inline pragma suppresses |
| `test_k8s_readonly_root_filesystem_not_applicable_without_k8s_feature` | `applies()` gates correctly |

## Known bypasses

Same as the rest of the k8s-* guard family: a templated value (Helm/Kustomize) resolved only at
deploy time is invisible to a static scan of the checked-in manifest. This guard's "absent = bad"
direction actually makes it harder to accidentally bypass than a "present = bad" guard.

## What this guard does NOT prove

Document-scoped: a workload with a genuinely read-only image (no writes attempted anywhere) but no
explicit `readOnlyRootFilesystem: true` still fires — a defense-in-depth control this guard checks
for its explicit presence, not whether the container would actually misbehave without it.

# Citations

[1] agentsec checklist item `6c-readonly-container-fs` (§6c)
[2] CIS:Docker
[3] OWASP-LLM:LLM01
[4] OWASP-LLM:LLM04
[5] OWASP:A05
