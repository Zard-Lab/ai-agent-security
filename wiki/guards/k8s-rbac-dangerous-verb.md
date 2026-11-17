---
type: Guard
title: "k8s-rbac-dangerous-verb"
description: "Kubernetes Role/ClusterRole grants a dangerous RBAC verb+resource combo (escalate, bind, impersonate, serviceaccount-token creation, or privileged-namespace pod modification)."
timestamp: "2026-09-05T00:00:00Z"
guard_id: "k8s-rbac-dangerous-verb"
checklist_section: ["6c"]
standards: ["CIS:Kubernetes", "OWASP:A01", "OWASP:A05"]
---

# Kubernetes Role/ClusterRole grants a dangerous RBAC verb+resource combo

_Author — 2026-09-05_

---

## The threat

Five independent RBAC privilege-escalation patterns, all sharing one detection shape (a
`Role`/`ClusterRole` manifest's `rules[]` block granting a specific dangerous verb+resource
combo):

1. **`escalate` (or `*`) on `roles`/`clusterroles`** — a subject with this can grant itself any
   other role's permissions, bypassing Kubernetes' own built-in escalation check (which normally
   blocks a subject from creating a role with more permissions than it already has).
2. **`bind` on `roles`/`clusterroles`** — lets a subject create a binding granting itself the
   rights of any role it can name, sidestepping the normal requirement to already hold those
   rights.
3. **`impersonate` on `users`/`groups`/`serviceaccounts`** — lets a subject act with the full RBAC
   rights of the impersonated identity via the `Impersonate-User`/`Impersonate-Group` headers.
4. **`create` on `serviceaccounts/token`** — lets a subject mint a valid TokenRequest token for any
   service account it can name, equivalent to gaining that account's full rights.
5. **`update`/`patch` on `pods`, scoped to a privileged namespace** (`kube-system` etc.) — lets a
   subject modify pods likely running with powerful service accounts, a path to code execution.

Standards: `OWASP:A01` (1-4), `OWASP:A05` (5), `CIS:Kubernetes` (all).

## Why this guard fits the stack

Sourced from Kubescape's (`kubescape/kubescape`) RBAC "threat matrix" rule set
(`m$K8sThreatMatrix` rule metadata: `escalate-roles-clusterroles-v1`, `bind-roles-clusterroles-v1`,
`impersonate-users-groups-v1`, `create-serviceaccount-token-v1`, `modify-privileged-pods-v1`) —
verified against the real `rule.metadata.json` + `raw.rego` source for each, not descriptions.

**Simplified for static single-file applicability.** Kubescape's real rules correlate a
Role/ClusterRole with its matching Binding AND the bound Subject, via a `subjectVector` structure
it builds by querying a LIVE cluster's API server. That cross-object correlation is dropped here:
each pattern flags a `Role`/`ClusterRole` manifest whose `rules[]` grants the dangerous combo
directly, with no live-cluster dependency and no proof a subject is actually bound to it —
lower-fidelity than Kubescape's own check, the same "scope-narrowing port" pattern used for
`gcp-kms-rotation-period-not-set` (ported from checkov's fuller check, deliberately narrowed).

This guard targets the same `Role`/`ClusterRole` manifest family across all five patterns, a THIRD
distinct document shape from the other `k8s-*` guards (Pod-shaped workloads, and the
`ClusterRoleBinding`/`RoleBinding` shape `k8s-rbac-anonymous-binding` uses) — it required adding a
third recognizer, `k8s_rbac_role_documents()`, to `agentsec/k8s.py`. `is_k8s_manifest_text()` was
updated to recognize all three families, so a repo shipping only Role/ClusterRole manifests still
turns on the `"k8s"` stack feature.

## Detection design

1. `applies()` gates on `"k8s" in profile.features`.
2. Scans `.yaml`/`.yml` files, matches Role/ClusterRole-shaped documents via
   `k8s_rbac_role_documents()` (requires `apiVersion:` + `kind: Role|ClusterRole`).
3. Within a matched document (hash-comments stripped), `_iter_rbac_rule_blocks()` splits the
   `rules:` list into its individual `- ` entries — **rule-scoped, not document-wide**: a dangerous
   verb in one rule is never combined with a resource from a sibling rule in the same manifest
   (the FP a purely document-wide co-occurrence check, the shape `k8s-privileged-capabilities` uses
   for its single `add:` block, would risk here — a Role/ClusterRole routinely carries several
   independent rules).
4. Within each rule block, `_extract_list_field()` reads `verbs:`/`resources:` (inline `[a, b]` or
   block `- item` form) and intersects against each of the 5 lookup-table entries' verb/resource
   sets.
5. Pattern 5 additionally requires the enclosing document to be a `Role` (not `ClusterRole` — no
   namespace of its own) whose `metadata.namespace` is one of the built-in control-plane namespaces:
   `kube-system`, `kube-public`, `kube-node-lease`.
6. Fires once per matched pattern PER DOCUMENT (deduplicated across rule blocks, mirroring
   `k8s-privileged-capabilities`'s per-document dedup) — critical for patterns 1-4, high for
   pattern 5.
7. Inline opt-out: `# security: allow-k8s-rbac-dangerous-verb` anywhere in the document.
8. Rules: `k8s-rbac-dangerous-verb/escalate-verb-on-roles`,
   `k8s-rbac-dangerous-verb/bind-verb-on-roles`, `k8s-rbac-dangerous-verb/impersonate-verb`,
   `k8s-rbac-dangerous-verb/create-serviceaccount-token`,
   `k8s-rbac-dangerous-verb/modify-privileged-namespace-pods`.

## When NOT to flag

- Reading roles/clusterroles (`get`/`list`/`watch`) must stay silent — only `escalate`/`*` fires.
- `bind`/`escalate`/`impersonate` on an unrelated resource (`pods`, `configmaps`) must stay silent
  — the resource match is exact.
- `create` on the bare `serviceaccounts` resource (creating a ServiceAccount object) is a much
  narrower grant than the `/token` subresource and must stay silent.
- `update`/`patch` on `pods` in an ordinary application namespace must stay silent — only a `Role`
  namespaced into `kube-system`/`kube-public`/`kube-node-lease` fires; the identical rule on a
  `ClusterRole` (no namespace of its own) also stays silent.
- Two rules in the same manifest, one with the dangerous verb and one with the dangerous resource
  but never both together, must stay silent (rule-scoped, not document-wide, matching).

## Tests

| Test | What it checks |
|---|---|
| `test_escalate_verb_on_clusterrole_fires` | `escalate` on `clusterroles` fires critical |
| `test_wildcard_verb_on_roles_fires_escalate` | `*` verb is equivalent to `escalate` |
| `test_escalate_verb_among_several_verbs_fires` | indirect form: verb listed among several |
| `test_escalate_on_unrelated_resource_silent` | FP-bait: unrelated resource stays silent |
| `test_get_list_on_roles_silent` | FP-bait: routine read verbs on roles stay silent |
| `test_escalate_and_unrelated_resource_in_different_rules_silent` | rule-scoped, not doc-wide |
| `test_bind_verb_on_roles_fires` / `..._among_several_verbs_fires` / `..._on_unrelated_resource_silent` | review fix |
| `test_impersonate_verb_on_serviceaccounts_fires` / `..._on_users_and_groups_fires` / `..._on_unrelated_resource_silent` | review fix |
| `test_create_serviceaccount_token_fires` / `..._among_verbs_fires` / `test_create_serviceaccounts_without_token_subresource_silent` | review fix |
| `test_patch_pods_in_kube_system_role_fires` / `test_update_pods_among_verbs_in_kube_public_fires` / `test_patch_pods_in_ordinary_namespace_silent` / `test_patch_pods_on_clusterrole_silent` | review fix |
| `test_pragma_opt_out` | inline pragma suppresses |
| `test_not_applicable_without_k8s_feature` | `applies()` gates correctly |
| `test_silent_on_non_rbac_role_manifest` | a ClusterRoleBinding isn't mistaken for a Role |
| `test_multiple_grants_in_one_manifest_all_fire` | independent patterns in one manifest all fire |

Also added `test_detect_k8s_feature_from_rbac_role_only` to `tests/test_detect.py`, confirming the
`"k8s"` stack feature turns on from a Role/ClusterRole-only manifest with no binding and no
workload manifest present.

## Known bypasses

A verb/resource value built via a Helm template expression. `resourceNames` scoping is not
inspected — a rule scoped to one specific, pre-reviewed role/service account/pod via
`resourceNames` still fires identically to an unscoped grant (matching this guard's own stated
remediation advice, which recommends `resourceNames` scoping as the fix rather than treating it as
already-safe). The privileged-namespace list for pattern 5 is intentionally the three built-in
control-plane namespaces only — a repo-specific convention (`prod-*`, a custom operator namespace)
is not recognized.

## What this guard does NOT prove

Does not correlate the Role/ClusterRole with an actual RoleBinding/ClusterRoleBinding or a bound
Subject — a dangerous rule that is never bound to anything is still flagged (lower-fidelity than
Kubescape's live-cluster check, which only fires when a subject is actually granted the rule via a
binding). This is the deliberate scope-narrowing tradeoff documented in the guard's module
docstring.

# Examples

```yaml
# Fires: k8s-rbac-dangerous-verb/escalate-verb-on-roles
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: escalator
rules:
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterroles"]
  verbs: ["escalate"]
```

```yaml
# Fires: k8s-rbac-dangerous-verb/modify-privileged-namespace-pods (severity: high)
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-patcher
  namespace: kube-system
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["patch"]
```

# Citations

[1] agentsec checklist items `6c-k8s-rbac-escalate-verb`, `6c-k8s-rbac-bind-verb`,
    `6c-k8s-rbac-impersonate-verb`, `6c-k8s-rbac-serviceaccount-token-create`,
    `6c-k8s-rbac-privileged-namespace-pod-modify` (§6c)
[2] Kubescape (`kubescape/kubescape`) `rules/escalate-roles-clusterroles-v1`,
    `rules/bind-roles-clusterroles-v1`, `rules/impersonate-users-groups-v1`,
    `rules/create-serviceaccount-token-v1`, `rules/modify-privileged-pods-v1`
[3] CIS:Kubernetes
[4] OWASP:A01
[5] OWASP:A05
