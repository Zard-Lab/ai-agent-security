---
type: Guard
title: "arm-aks-rbac-disabled"
description: "ARM-templated Azure Kubernetes Service (AKS) cluster does not enable Kubernetes RBAC."
timestamp: "2026-09-12T00:00:00Z"
guard_id: "arm-aks-rbac-disabled"
checklist_section: ["6c"]
standards: ["OWASP:A01", "CWE-284"]
---

# ARM template AKS cluster does not enable Kubernetes RBAC

Flags `Microsoft.ContainerService/managedClusters` resources whose `properties.enableRBAC` is
`false` or entirely absent. agentsec's second ARM-format guard, sitting alongside
`arm-redis-ssl-disabled` on the shared `agentsec.arm` resource parser.

## The threat

`properties.enableRBAC` controls whether Kubernetes role-based access control is enabled for an
AKS cluster at all. When it is disabled, the cluster has no RBAC authorization layer enforcing who
can do what against the Kubernetes API — this is a foundational, cluster-wide absence of access
control, not a specific over-broad grant within an otherwise-governed cluster. Anyone who can
reach the API server (a leaked kubeconfig, a compromised in-cluster identity, a misconfigured
network boundary) inherits whatever access the fallback authorization mode allows, with no RBAC
policy standing in the way. CWE-284 (Improper Access Control), OWASP:A01 (Broken Access Control).

## A different angle from the K8s-manifest RBAC guards

agentsec already has `k8s-rbac-cluster-admin-binding` and `k8s-rbac-wildcard-rule` (plus the
dangerous-verb family), which scan Kubernetes-native RBAC manifests — Role, ClusterRole,
RoleBinding YAML — for grants that are too broad *within* an RBAC-enabled cluster. This guard is
upstream of all of those: it looks at the ARM-level AKS cluster *provisioning* flag that decides
whether Kubernetes RBAC authorization is enabled for the cluster in the first place. A cluster
with `enableRBAC` disabled has no RBAC model for `k8s-rbac-cluster-admin-binding` or
`k8s-rbac-wildcard-rule` findings to even apply to — those guards' entire threat model assumes
RBAC is the enforcement mechanism in play. That is also why this guard uses `critical`, the same
severity class as those two: a disabled RBAC layer is the prerequisite the whole model depends on,
not one misconfigured instance of it, so it is treated as at least as severe as the worst single
RBAC misconfiguration those guards catch.

## Exploitability rationale

CRITICAL. No specific over-broad rule needs to be authored for this to matter — the absence
itself is the vulnerability. Matches the severity of `6c-k8s-rbac-cluster-admin-binding` and
`6c-k8s-rbac-wildcard-rule`, the existing `critical`-rated K8s RBAC checklist items.

## What counts as a hit (and what doesn't)

- `Microsoft.ContainerService/managedClusters` with `enableRBAC: false` → fires.
- `Microsoft.ContainerService/managedClusters` with no `enableRBAC` property at all → fires.
  Azure's own default for this property has shifted across API versions (older API versions
  defaulted to `false`), and the source rule this guard is built from is itself named for
  requiring the property be explicitly turned *on* — so absence is treated as the vulnerable
  case, not silently trusted. This mirrors the "absent attribute is the vulnerable default"
  posture the Terraform guard `kms-key-rotation-not-enabled` already takes for `aws_kms_key`
  blocks with no `enable_key_rotation` attribute.
- `Microsoft.ContainerService/managedClusters` with `enableRBAC: true` (explicit) → silent (the
  fix).
- Any other resource type, including one that happens to carry a similarly-named property →
  silent (the guard only ever looks inside a `Microsoft.ContainerService/managedClusters`
  resource's own `block`).

## When NOT to flag (and the pragma)

- `enableRBAC: true` (explicit) → silent (the fix).
- **No suppression pragma exists for this guard.** ARM templates are pure JSON, which has no
  comment syntax — a known, documented limitation shared by every guard built on `agentsec.arm`
  (see that module's docstring). There is no equivalent to the CFN guards' YAML-only
  `# security: allow-...` pragma here.

## Tests

| Test | What it checks |
|---|---|
| `test_arm_aks_rbac_flags_explicit_false` | `enableRBAC: false` fires `critical`. |
| `test_arm_aks_rbac_flags_absent_property` | Property entirely absent also fires. |
| `test_arm_aks_rbac_silent_when_explicitly_true` | `enableRBAC: true` stays silent. |
| `test_arm_aks_rbac_silent_on_non_aks_resource` | FP bait: unrelated resource type with the same property name. |
| `test_arm_aks_rbac_multiple_resources_only_disabled_flagged` | Only the disabled cluster is flagged among several. |
| `test_arm_aks_rbac_not_applicable_without_arm` | `applies()` is `False` without the `arm` feature. |

## Known bypasses (honest limits)

- **No dataflow, no cross-resource reasoning.** Fires on the property's value directly.
- **File-level location, not line-level** — like every guard built on `agentsec.arm`, the finding
  reports the template file, not a specific line (a `block` is a `json.dumps` reconstruction with
  no original line mapping to report).
- **Template expressions are not evaluated.** If `enableRBAC` is set via
  `"[parameters('enableRbac')]"` rather than a literal `true`/`false`, this guard would not
  recognize it as `true` and would fire on it as if absent — see `agentsec.arm`'s module
  docstring for the same posture on resource `name`. This is a deliberate false-positive-leaning
  choice given the severity of a genuinely disabled RBAC layer.
- **Nested/linked templates** (`Microsoft.Resources/deployments` referencing a separate template
  file or URI) are not followed — each template file is scanned independently.

## What this guard does NOT prove

A clean scan means no `Microsoft.ContainerService/managedClusters` resource in the scanned
templates has `enableRBAC` unset or `false` — it says nothing about a cluster created outside
this template entirely (the Azure Portal, a different IaC tool, a linked template this scan
didn't independently discover), the actual RBAC bindings configured inside a cluster that does
have RBAC enabled (that is what `k8s-rbac-cluster-admin-binding` / `k8s-rbac-wildcard-rule`
cover), or the cluster's actual runtime configuration if it was changed out-of-band after
deployment.

## Canary plant

`arm_aks.json` — a `Microsoft.ContainerService/managedClusters` resource with
`enableRBAC: false`. Expected rule: `arm-aks-rbac-disabled/rbac-disabled`.

# Citations

[1] OWASP:A01 (Broken Access Control)
[2] CWE-284 (Improper Access Control)
[3] Azure/template-analyzer — `AKS.EnableRBAC` (`TA-000024`, provenance only; detection logic
    here is original)
