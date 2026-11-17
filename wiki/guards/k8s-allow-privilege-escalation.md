---
type: Guard
title: "k8s-allow-privilege-escalation"
description: "Kubernetes workload doesn't explicitly disable privilege escalation."
timestamp: "2026-07-13T16:29:55+08:00"
guard_id: "k8s-allow-privilege-escalation"
checklist_section: ["6c"]
standards: ["CIS:Kubernetes", "OWASP:A05"]
---

# Kubernetes workload doesn't explicitly disable privilege escalation

_Author — 2026-07-13. Reworked to absence-based detection — 2026-07-15._

---

## The threat

`securityContext.allowPrivilegeEscalation` lets a process gain more privileges than its parent —
most commonly via a setuid/setgid binary or a file capability inside the container image. Combined
with a compromised container (prompt-injected agent tool execution, a supply-chain-compromised base
image, an app-level RCE), this turns a limited-privilege foothold into a straightforward local
escalation. Kubernetes defaults this field to *allowed* whenever it is omitted entirely — nobody sets
it to `true` on purpose, they just never think about it, which makes omission the far more common
real-world misconfiguration, not the explicit-`true` case. Standards: `OWASP:A05`, `CIS:Kubernetes`.

## Why this guard fits the stack

Originally sourced from kubesec's `AllowPrivilegeEscalation` rule (`pkg/rules/allowPrivilegeEscalation.go`),
which only flagged the explicit-`true` case. Reworked (2026-07-15) to match checkov's own
`AllowPrivilegeEscalation` check (`CKV_K8S_20`,
`checkov/kubernetes/checks/resource/base_spec/AllowPrivilegeEscalation.py`), which fires unless
`securityContext.allowPrivilegeEscalation` is explicitly `False` — "safe only if explicitly
disabled," the same detection direction `k8s-run-as-non-root` already uses for its own field
(`runAsNonRoot: true` required somewhere in the document, or it fires).

## Detection design

1. `applies()` gates on `"k8s" in profile.features`.
2. Scans `.yaml`/`.yml` files, matches Pod-shaped documents via `k8s_manifest_documents()`.
3. Inline opt-out checked first: `# security: allow-k8s-allow-privilege-escalation` anywhere in the
   document.
4. Within a matched document (hash-comments stripped), checks for a line matching
   `allowPrivilegeEscalation:\s*false\s*$` (case-insensitive) that is scoped to a **container-level**
   `securityContext`. Unlike `runAsNonRoot`, `allowPrivilegeEscalation` is a container-only field
   (`v1.SecurityContext`, NOT `v1.PodSecurityContext`) — the kubelet never inherits it from the pod
   spec, so a `false` on the *pod-spec* `securityContext` is inert and does NOT satisfy the control.
   A lightweight indentation check tells the two apart without PyYAML: a container-level
   `securityContext` is nested deeper than the pod's `containers:`/`initContainers:` key, whereas a
   pod-spec `securityContext` sits at the same indent (a sibling of it). If no container-level `false`
   exists, the document fires — this covers the field being entirely omitted, set to `true`, or set
   to `false` only at the inert pod-spec level.
5. Severity: `high`. Rule: `k8s-allow-privilege-escalation/not-explicitly-disabled`.
   Standards: `["OWASP:A05", "CIS:Kubernetes"]`.

**Rule id changed** from `k8s-allow-privilege-escalation/allowprivilegeescalation-true` to
`k8s-allow-privilege-escalation/not-explicitly-disabled` to reflect the new absence-based trigger
condition (the old id implied "fires because true was found," which no longer describes the omission
case). Anything referencing the old rule string (e.g. `agentsec/canary.py`'s `EXPECTED_RULES` entry
for this guard) needs updating to match.

## When NOT to flag

A **container-level** `allowPrivilegeEscalation: false` present in the document is the only silent
case — the hardened, explicit setting the kubelet actually honors. A `false` at the pod-spec
`securityContext` level is inert and does not silence the finding. An inline
`# security: allow-k8s-allow-privilege-escalation` pragma also suppresses.

## Tests

| Test | What it checks |
|---|---|
| `test_k8s_allow_privilege_escalation_fires_on_explicit_true` | explicit `true` fires high (regression guard — must not stop firing) |
| `test_k8s_allow_privilege_escalation_fires_when_omitted` | field absent entirely fires high (the new case — the common real-world misconfiguration) |
| `test_k8s_allow_privilege_escalation_passes_when_false` | explicit `false` at container level stays silent |
| `test_k8s_allow_privilege_escalation_fires_when_only_pod_spec_level_false` | a `false` at the pod-spec level is inert (container-only field) — still fires |
| `test_k8s_allow_privilege_escalation_document_scoped_across_containers` | one container's `false` silences the whole document (document-scoped tradeoff) |
| `test_k8s_allow_privilege_escalation_fires_when_no_containers_key` | a workload with no `containers:` anchor (a Kustomize patch fragment touching only the pod securityContext) fails OPEN → fires, never accepts an unprovable pod-spec-level `false` |
| `test_k8s_allow_privilege_escalation_passes_when_false_flow_style` | a container-level `false` inside a multi-line flow-style `securityContext: {` block stays silent (no FP) |
| `test_k8s_allow_privilege_escalation_scoping_generalizes_to_deployment_depth` | the relative-indent scoping holds at `template.spec` nesting (Deployment), both the suppress and fire paths |
| `test_k8s_allow_privilege_escalation_silent_on_docker_compose` | a compose file's own key isn't mistaken for a K8s manifest |
| `test_k8s_allow_privilege_escalation_pragma_opt_out` | the inline pragma suppresses |
| `test_k8s_allow_privilege_escalation_not_applicable_without_k8s_feature` | `applies()` gates correctly |

## Known bypasses

Same as the rest of the k8s-* guard family: a templated value (Helm/Kustomize) resolved only at
deploy time is invisible to a static scan of the checked-in manifest.

One known false positive (accepted, low-probability): a container that puts `securityContext:` as its
**first, dash-prefixed** list key —

    containers:
    - securityContext:
        allowPrivilegeEscalation: false
      name: app

— is not recognized as container-scoped, so the guard fires on it despite the valid `false`. The
`- ` list marker makes the `securityContext:` key's raw indentation equal to the `containers:` key's,
which the relative-indent comparison reads as pod-spec level. Fixing it cleanly means measuring the
key's *effective* column past the dash rather than its raw indent — not worth the added indent-fixup
surface for a style real manifests virtually never use (`name:` is near-universally the first key).
Suppress an affected container explicitly with `# security: allow-k8s-allow-privilege-escalation`, or
reorder `name:` first.

## Container scoping — how a container `securityContext` is told from a pod-spec one

`allowPrivilegeEscalation` is a **container-only** field (`v1.SecurityContext`, not
`v1.PodSecurityContext`), so a `false` at pod-spec level is inert and must not suppress the finding.
Distinguishing the two without a YAML parser takes two signals, both required:

1. The `securityContext:` block must be **nested deeper** than a `containers:`-shaped key that
   precedes it.
2. There must be a **list-item dash** between that key and the block.

Signal 2 exists because signal 1 alone is forgeable. Comparing against the *shallowest*
`containers:`-shaped key anywhere in the document let an unrelated key that merely ends in
`containers:` — `metadata.annotations.containers:` is the realistic case — vouch for a pod-spec-level
`false`, re-opening the exact false negative this scoping closes. Anchoring instead to the nearest
preceding such key **and** requiring a dash item between them rejects the decoy, because an
annotation key has no block sequence under it.

Both forms of flow-style mapping are recognised as container-scoped when they pass those tests: the
multi-line opener (`securityContext: {` on its own line) and the single-line
`securityContext: {allowPrivilegeEscalation: false, ...}`, whose field is not alone on a line and so
needs its own matcher.

Falsey values follow the **YAML 1.1** boolean resolver Kubernetes actually uses, so `no`, `off` and
`n` count as explicitly disabled alongside `false`. Matching only the literal `false` fired on
genuinely hardened containers.

When a matched document contains **no** `containers:`/`initContainers:` anchor at all — a Kustomize
strategic-merge patch fragment that touches only the pod `securityContext` — there is no container
scope to compare against, so the guard **fails open toward firing** rather than accept a suppression
it cannot prove.

## What this guard does NOT prove

Document-scoped, not per-container: a Pod manifest with multiple containers where only one omits (or
sets `true` for) `allowPrivilegeEscalation` still fires once for the whole document — correctly flags
the document, doesn't localize which container (see `agentsec/k8s.py`'s module docstring for the
tradeoff). Conversely, a single `allowPrivilegeEscalation: false` anywhere in a multi-container
document silences the whole document even if a different container in the same document never sets
it — same document-scoped tradeoff `k8s-run-as-non-root` already accepts for its own field.

# Citations

[1] agentsec checklist item `6c-k8s-allow-privilege-escalation` (§6c)
[2] CIS:Kubernetes
[3] OWASP:A05
