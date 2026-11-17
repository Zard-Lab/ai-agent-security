---
type: Guard
title: "k8s-rbac-cluster-admin-binding"
description: "Kubernetes RBAC binding grants the built-in cluster-admin role to a subject."
timestamp: "2026-09-05T00:00:00Z"
guard_id: "k8s-rbac-cluster-admin-binding"
checklist_section: ["6c"]
standards: ["OWASP:A01", "CIS:Kubernetes"]
---

# Kubernetes RBAC binding grants the built-in cluster-admin role

_Author — 2026-09-05_

---

## The threat

A `ClusterRoleBinding`/`RoleBinding` whose `roleRef` names the built-in `cluster-admin` `ClusterRole`
grants the bound subject every verb on every resource in every API group, cluster-wide (or, for a
namespaced `RoleBinding` referencing the cluster-scoped role, full admin rights within that
namespace). Whoever or whatever holds that subject's credentials — a ServiceAccount token mounted
into a pod, a compromised CI pipeline identity, a user account — can read every Secret, delete any
workload, and grant itself further privileges. Unlike `k8s-rbac-anonymous-binding` (which flags an
unauthenticated *subject*), this guard flags an over-broad *role grant* to an otherwise ordinary,
authenticated subject — the more common real-world shape, since most `cluster-admin` bindings exist
to make an app's own ServiceAccount "just work" rather than to intentionally expose the cluster.
Standards: `OWASP:A01`, `CIS:Kubernetes`.

## Why this guard fits the stack

Sourced from kube-linter's `ClusterAdminRoleBinding` template
(`pkg/templates/clusteradminrolebinding/template.go`), verified against the real Go source — a
direct field-equality check on `roleRef.kind`/`roleRef.name`, no cross-object correlation needed.
`cluster-admin` bindings are routinely introduced during Helm chart installs, quickstart tutorials,
and "just get it working" ServiceAccount wiring, then never revisited once the app is deployed —
the same pattern that produces `k8s-privileged-container` and `k8s-docker-sock-mount` findings on
manifests migrated from a permissive local setup without a security review pass.

## Detection design

1. `applies()` gates on `"k8s" in profile.features`.
2. Scans `.yaml`/`.yml` files, matches RBAC-binding-shaped documents via
   `k8s_rbac_binding_documents()` — the same recognizer `k8s-rbac-anonymous-binding` uses
   (`ClusterRoleBinding`/`RoleBinding` documents with a `subjects`/`roleRef` shape, not the
   Pod-workload shape).
3. Within a matched document (hash-comments stripped), locates the `roleRef:` mapping block by
   indentation and checks it sets `kind: ClusterRole` (optionally quoted) and
   `name: cluster-admin` (optionally quoted) — both fields, in either order, scoped to that one
   block so a `subjects[].name: cluster-admin` (a subject merely *named* "cluster-admin") never
   counts as the granted role. Like the sibling `k8s-*` guards, this is document-scoped rather than
   a full indentation-tree parse — no PyYAML at runtime (see `agentsec/k8s.py`'s module docstring).
4. Inline opt-out: `# security: allow-k8s-rbac-cluster-admin-binding` anywhere in the document.
5. Severity: `critical`. Rule: `k8s-rbac-cluster-admin-binding/role-is-cluster-admin`.
   Standards: `["OWASP:A01", "CIS:Kubernetes"]`.

Like the other `k8s-*` guards, this guard does not consult `is_nonproduct_path()` — the family
convention (see `k8s_docker_sock_mount.py`, `k8s_privileged_capabilities.py`,
`k8s_rbac_anonymous_binding.py`, none of which call it) is to scan every matched manifest document
without a test/example-path carve-out, since a genuinely non-production K8s manifest checked into a
repo is still worth flagging (there is no analogous "fixtures/" convention for cluster manifests the
way there is for application source).

## When NOT to flag

A binding whose `roleRef` names any other role (`view`, `edit`, a custom narrowly-scoped
`ClusterRole`) must stay silent — only the literal built-in `cluster-admin` name fires. A subject
(not the `roleRef`) merely *named* `cluster-admin` must also stay silent (see "When NOT to flag" vs.
`k8s-rbac-anonymous-binding`, which checks the opposite field on the same document family).

## Tests

| Test | What it checks |
|---|---|
| `test_k8s_rbac_cluster_admin_binding_fires_clusterrolebinding` | a `ClusterRoleBinding` to `cluster-admin` fires critical |
| `test_k8s_rbac_cluster_admin_binding_fires_rolebinding` | a namespaced `RoleBinding` referencing the cluster-scoped `cluster-admin` role also fires |
| `test_k8s_rbac_cluster_admin_binding_fires_regardless_of_field_order` | `name:` before `kind:` inside `roleRef`, with an `apiGroup:` line between them, still fires |
| `test_k8s_rbac_cluster_admin_binding_passes_narrow_role` | a binding to `view` stays silent |
| `test_k8s_rbac_cluster_admin_binding_passes_lookalike_subject_name` | a subject merely named `cluster-admin` stays silent |
| `test_k8s_rbac_cluster_admin_binding_passes_role_not_clusterrole` | `roleRef.kind: Role` named `cluster-admin` (a different, user-defined object) stays silent |
| `test_k8s_rbac_cluster_admin_binding_silent_on_non_rbac_manifest` | a `Service` manifest stays silent |
| `test_k8s_rbac_cluster_admin_binding_pragma_opt_out` | the inline pragma suppresses |
| `test_k8s_rbac_cluster_admin_binding_not_applicable_without_k8s_feature` | `applies()` gates correctly |

## Known bypasses

A `roleRef.name` built from a templated/parameterized Helm value that renders to `cluster-admin` at
apply time (but not in the checked-in source) is invisible to this literal-text match, the same
templating blind spot every `k8s-*` guard in this codebase accepts. A custom `ClusterRole` that
merely *duplicates* `cluster-admin`'s full wildcard `rules[]` under a different name also evades
this specific check (though it would separately fire `k8s-rbac-wildcard-rule` on the role
definition itself, once that guard is built).

## What this guard does NOT prove

A document-scoped match without a real indentation tree means this guard trusts that the `kind:`/
`name:` pair it finds nested under `roleRef:` is genuinely that mapping's fields (true in every real
RBAC binding manifest shape), but it does not verify the subject the role is bound to is actually
used anywhere (an unused binding still fires — deliberately conservative, since an unused
`cluster-admin` binding left in a manifest is still worth a human's attention). It also does not
evaluate whether `cluster-admin` is *justified* for a given subject (e.g. a genuine cluster-operator
controller) — that judgment is what the pragma opt-out is for.

# Citations

[1] agentsec checklist item `6c-k8s-rbac-cluster-admin-binding` (§6c)
[2] OWASP:A01
[3] CIS:Kubernetes
[4] kube-linter `ClusterAdminRoleBinding` template — `pkg/templates/clusteradminrolebinding/template.go`
