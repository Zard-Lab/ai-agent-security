---
type: Guard
title: "k8s-rbac-anonymous-binding"
description: "Kubernetes RBAC binding grants a role to the anonymous user."
timestamp: "2026-07-13T16:30:23+08:00"
guard_id: "k8s-rbac-anonymous-binding"
checklist_section: ["6c"]
standards: ["CIS:Kubernetes", "OWASP:A01"]
---

# Kubernetes RBAC binding grants a role to the anonymous user

_Author — 2026-07-13_

---

## The threat

A `ClusterRoleBinding`/`RoleBinding` whose `subjects` list includes `system:anonymous` grants
whatever that role can do to ANYONE who can reach the API server without authenticating at all —
one of the most severe Kubernetes RBAC misconfigurations possible, since it defeats authentication
entirely rather than merely over-authorizing an already-authenticated identity (real-world
incidents involving `system:anonymous` cluster-admin bindings have led to full cluster takeover).
Standards: `OWASP:A01`, `CIS:Kubernetes`.

## Why this guard fits the stack

Sourced from kubesec's `BindingsToSystemAnonymous` rule (`pkg/rules/bindingsToSystemAnonymous.go`),
verified against the real Go source — a plain `subjects[].name` substring check.

This guard targets a DIFFERENT manifest family than every other `k8s-*` guard: `ClusterRoleBinding`/
`RoleBinding` documents, not Pod-shaped workload manifests. It required extending
`agentsec/k8s.py` with a SECOND document recognizer, `k8s_rbac_binding_documents()` — RBAC bindings
carry a `subjects` list, never a pod spec, so they can't reuse `k8s_manifest_documents()`'s
Pod/Deployment/StatefulSet/... `kind:` allowlist. `is_k8s_manifest_text()` (the function `detect.py`
calls to set the `"k8s"` stack feature) was updated to recognize EITHER document family, so a repo
shipping only RBAC manifests (e.g. a Helm chart's `templates/rbac.yaml`, with workloads defined
elsewhere) still turns the feature on.

## Detection design

1. `applies()` gates on `"k8s" in profile.features`.
2. Scans `.yaml`/`.yml` files, matches RBAC-binding-shaped documents via
   `k8s_rbac_binding_documents()` (requires `apiVersion:` + `kind: ClusterRoleBinding|RoleBinding`).
3. Within a matched document (hash-comments stripped), checks for a `name:` value line equal to
   `system:anonymous` (optionally quoted) anywhere in the document — this is the `subjects[].name`
   value in a real manifest's YAML indentation, matched here without full indentation-tree awareness
   (see "What this guard does NOT prove").
4. Inline opt-out: `# security: allow-k8s-rbac-anonymous-binding` anywhere in the document.
5. Severity: `critical`. Rule: `k8s-rbac-anonymous-binding/subject-is-system-anonymous`.
   Standards: `["OWASP:A01", "CIS:Kubernetes"]`.

## When NOT to flag

A `subjects` list naming a `ServiceAccount`/`User`/`Group` other than `system:anonymous` must stay
silent — only that exact literal name fires. A non-RBAC-shaped manifest (Service, ConfigMap, a Pod)
containing the string `system:anonymous` anywhere (e.g. in a comment or unrelated field) must also
stay silent, since `k8s_rbac_binding_documents()` gates on the document's `kind:` first.

## Tests

| Test | What it checks |
|---|---|
| `test_k8s_rbac_anonymous_binding_fires` | `system:anonymous` in a ClusterRoleBinding fires critical |
| `test_k8s_rbac_anonymous_binding_fires_rolebinding` | also fires on a namespaced RoleBinding |
| `test_k8s_rbac_anonymous_binding_passes_service_account_subject` | a normal ServiceAccount subject stays silent |
| `test_k8s_rbac_anonymous_binding_silent_on_non_rbac_manifest` | a Service manifest isn't mistaken for an RBAC binding |
| `test_k8s_rbac_anonymous_binding_pragma_opt_out` | the inline pragma suppresses |
| `test_k8s_rbac_anonymous_binding_not_applicable_without_k8s_feature` | `applies()` gates correctly |

Also added `test_detect_k8s_feature_from_rbac_binding_only` to `tests/test_detect.py`, confirming
the `"k8s"` stack feature turns on from an RBAC-only manifest with no workload manifest present.

## Known bypasses

A `name:` value built via a Helm template expression, or `system:anonymous` referenced indirectly
through a `Group` binding to `system:unauthenticated` (a distinct-but-related built-in group this
guard does NOT check — kubesec's own rule only checks the literal `system:anonymous` string).

## What this guard does NOT prove

Does not check the `roleRef` the binding grants — a `system:anonymous` binding to a narrowly-scoped
role (e.g. read-only access to one ConfigMap) is a much smaller risk than binding it to
`cluster-admin`, but this guard fires at the same severity regardless of what the role itself
grants (matching kubesec's own binary check — it doesn't inspect the referenced Role's rules
either).

# Citations

[1] agentsec checklist item `6c-k8s-rbac-anonymous-binding` (§6c)
[2] CIS:Kubernetes
[3] OWASP:A01
