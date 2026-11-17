---
type: Guard
title: "k8s-default-namespace"
description: "Kubernetes resource has no namespace isolation (uses the default namespace)."
timestamp: "2026-08-24T09:00:00Z"
guard_id: "k8s-default-namespace"
checklist_section: ["6c"]
standards: ["OWASP:A05", "CWE-284"]
---

# Kubernetes resource has no namespace isolation (uses the default namespace)

_Author — 2026-08-24_

---

## The threat

A resource applied with no `metadata.namespace` lands in the `default` namespace; one set to
`namespace: default` lands there explicitly. By convention, most clusters give `default` no
RBAC/NetworkPolicy isolation beyond whatever cluster-wide policy exists — it is the namespace
every `kubectl apply` with no `-n` flag lands in, so it tends to accumulate a mix of
unrelated, ad-hoc workloads with no scoped RBAC `RoleBinding` or `NetworkPolicy` drawing a
boundary around them. CWE-284 (Improper Access Control), OWASP:A05.

**Deliberately the softest signal in this guard family.** Many small clusters and local/dev
setups legitimately run everything in `default` with no ill effect, and a real production
concern (RBAC scoping, network segmentation) is a property of the CLUSTER's namespace
configuration, not something this guard can see from the manifest alone — it can only see
that no namespace boundary was even requested. Graded `low` (deliberately downgraded from
what a stricter read of the source rule would apply) specifically so it reads as a hygiene
nudge, not an alarm competing with a real proven-impact finding for "fix these first"
attention — the same calibration-over-alarm reasoning `compose-resource-limits-absent`
documents for its own severity choice.

## Why this guard fits the stack

A workload manifest with no `namespace:` key is the default shape most `kubectl apply`/CI
pipelines produce unless someone deliberately adds one:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
  # no namespace: key -> the API server places this object in "default"
```

Sourced from `iac-security-scanner`'s `K8S_NET_004` rule.

## Detection design

1. `applies()` gate — `"k8s" in profile.features`.
2. Scans every `.yaml`/`.yml` file via `iter_files`, splitting into individual manifest
   documents with `k8s_manifest_documents()` (the same document-scoped helper every sibling
   `k8s-*` guard uses).
3. Within each document, comments are blanked (`strip_hash_comments`), then a walker looks
   ONLY at the document's own **top-level** `metadata:` block (indent 0) for a `namespace:`
   child. A `spec.template.metadata` (the pod-template metadata nested inside a
   Deployment/StatefulSet/etc) is deliberately never considered — it cannot set its own
   namespace; it always inherits the parent object's, so matching it would double-count or
   misattribute the namespace decision.
4. Two rule shapes, both scoped to Pod/Deployment/StatefulSet/DaemonSet/Job/CronJob/
   ReplicaSet documents:
   - **`namespace-not-set`**: the top-level `metadata:` block has no `namespace:` key at all.
   - **`namespace-explicit-default`**: the top-level `metadata.namespace` value (quotes
     stripped) is literally `default`.
5. Inline opt-out: `# security: allow-k8s-default-namespace` anywhere in the document.
6. Severity: `low` for both rule shapes. Rule ids: `k8s-default-namespace/namespace-not-set`,
   `k8s-default-namespace/namespace-explicit-default`. Standards:
   `["OWASP:A05", "CWE-284"]`.

## When NOT to flag

- The document's own top-level `metadata.namespace` is set to anything other than `default`.
- A nested `spec.template.metadata.namespace` (this guard doesn't look there at all — only
  the document's own top-level metadata governs where the API server actually places the
  object).
- An audited case (e.g. a genuinely single-tenant local/dev cluster), suppressed with
  `# security: allow-k8s-default-namespace`.

## Tests

| Test | What it checks |
|---|---|
| `test_no_namespace_key_fires_not_set` | Positive: no `namespace:` key at all fires `namespace-not-set`. |
| `test_explicit_namespace_default_fires_explicit_default` | Positive: `namespace: default` fires `namespace-explicit-default`. |
| `test_explicit_non_default_namespace_stays_silent` | FP-bait: `namespace: payments` (or any non-default value) → silent. |
| `test_deployment_pod_template_metadata_namespace_ignored` | FP-bait/precision: a nested `spec.template.metadata.namespace` is not mistaken for the document's own top-level namespace. |
| `test_pragma_opt_out` | Suppress pragma → silent. |
| `test_not_applicable_without_k8s_feature` / `test_applies_with_k8s` | `applies()` gate. |

## Known bypasses

- **Variable/templating indirection**: a Helm template or Kustomize overlay that only sets
  the namespace at render/apply time (`namespace: {{ .Values.namespace }}` resolving to a
  real value downstream) is invisible to a guard scanning the source manifest as committed —
  the literal placeholder value, not `default`, is what's actually in the file, so this
  guard correctly stays silent on the templated source (a false negative on the rendered
  form, not a false positive).
- **A namespace set at apply time** via `kubectl apply -n <ns>` or `helm install -n <ns>`,
  overriding whatever (or nothing) the manifest itself declares, is invisible to a
  source-only static check.
- **Whitespace/formatting extremes** beyond what the indent-scoped walker tolerates are not
  expected in practice (K8s YAML is near-universally 2-space indented), but an exotic
  non-standard formatter could theoretically evade the top-level/nested distinction.

## What this guard does NOT prove

A silent guard does not confirm the target cluster actually enforces RBAC/NetworkPolicy
isolation on the namespace named — only that SOME non-default namespace was requested in the
source. It does not confirm the applied deployment matches the source (drift), or that a
namespace override at apply time didn't change the outcome. This is a presence-based,
source-only, document-scoped check, and deliberately the softest-signal guard in its family.

# Citations

[1] agentsec checklist item `6c-k8s-default-namespace` (§6c)
[2] OWASP:A05
[3] CWE-284
[4] iac-security-scanner `K8S_NET_004`
