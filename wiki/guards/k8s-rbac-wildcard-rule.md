---
type: Guard
title: "k8s-rbac-wildcard-rule"
description: "Kubernetes Role/ClusterRole grants a wildcard resources or verbs rule."
timestamp: "2026-09-05T00:10:00Z"
guard_id: "k8s-rbac-wildcard-rule"
checklist_section: ["6c"]
standards: ["OWASP:A01", "CIS:Kubernetes"]
---

# Kubernetes Role/ClusterRole grants a wildcard resources or verbs rule

_Author — 2026-09-05_

---

## The threat

A `Role`/`ClusterRole` `rules[]` entry with a literal `"*"` in `resources` grants every resource
type in the rule's listed API group(s) — Pods, Secrets, ConfigMaps, and any CRD the group carries —
not just the ones the role was meant to manage. A literal `"*"` in `verbs` grants every action
(get/list/watch/create/update/patch/delete/deletecollection) on whatever resources the rule does
name. Either turns an intended narrow, single-purpose role into a near-blanket grant to anything
bound to it — the same over-privilege outcome as `k8s-rbac-cluster-admin-binding`, but reachable
without ever naming the built-in `cluster-admin` role, so a hand-rolled "admin-ish" custom role
evades that guard while still tripping this one. Standards: `OWASP:A01`, `CIS:Kubernetes`.

## Why this guard fits the stack

Sourced from kube-linter's `WildcardInRules` template (`pkg/templates/wildcardinrules/template.go`),
verified against the real Go source — direct iteration over each rule's `resources`/`verbs` fields.
Wildcard RBAC rules show up most often as a shortcut during initial cluster bring-up ("just grant
this operator everything so it works, tighten later") that never gets revisited, the identical
pattern behind most of this repo's other K8s over-privilege guards.

## Detection design

1. `applies()` gates on `"k8s" in profile.features`.
2. Scans `.yaml`/`.yml` files, matches Role/ClusterRole-shaped documents via the new
   `agentsec.k8s.k8s_rbac_role_documents()` — a third document family, distinct from the
   Pod-workload family (`k8s_manifest_documents()`) and the RBAC-BINDING family
   (`k8s_rbac_binding_documents()`, used by `k8s-rbac-anonymous-binding` /
   `k8s-rbac-cluster-admin-binding`): a Role/ClusterRole DEFINES permissions, a binding only GRANTS
   an existing one.
3. Within a matched document (hash-comments stripped), scans for a `resources:`/`verbs:` key whose
   value is `["*"]` inline, or a `resources:`/`verbs:` block-list opener followed by a `- "*"` list
   item — mirroring the `add:`-block scanning `k8s-privileged-capabilities` already uses for the
   same document-scoped, no-PyYAML tradeoff. Only an exact `"*"` entry counts, never a name that
   merely contains an asterisk-adjacent substring.
4. Inline opt-out: `# security: allow-k8s-rbac-wildcard-rule` anywhere in the document.
5. Severity: `critical`. Rules: `k8s-rbac-wildcard-rule/wildcard-resources` and
   `k8s-rbac-wildcard-rule/wildcard-verbs` (a document can trigger either or both independently).
   Standards: `["OWASP:A01", "CIS:Kubernetes"]`.

Scoped to `resources` and `verbs` only — `apiGroups` is out of scope for this guard (see "What this
guard does NOT prove"), matching what this candidate was verified against. Like the other `k8s-*`
guards, this guard does not consult `is_nonproduct_path()` (see the family convention noted on
`k8s-rbac-cluster-admin-binding`'s design doc).

## When NOT to flag

A rule listing specific resource types (`["pods", "configmaps"]`) and specific verbs
(`["get", "list", "watch"]`) must stay silent — only the literal `"*"` entry fires. A
`ClusterRoleBinding`/`RoleBinding` document (a different manifest family with no `rules[]` at all)
must also stay silent even though it is superficially "also an RBAC object".

## Tests

| Test | What it checks |
|---|---|
| `test_k8s_rbac_wildcard_rule_fires_inline_resources` | inline `resources: ["*"]` fires critical |
| `test_k8s_rbac_wildcard_rule_fires_block_list_verbs` | block-list `verbs:` / `- "*"` on a namespaced `Role` fires |
| `test_k8s_rbac_wildcard_rule_fires_both_resources_and_verbs` | a rule wildcarding both emits both rule ids |
| `test_k8s_rbac_wildcard_rule_passes_narrow_rule` | specific resources/verbs stay silent |
| `test_k8s_rbac_wildcard_rule_passes_wildcard_lookalike_value` | an ordinary, non-wildcard rule stays silent |
| `test_k8s_rbac_wildcard_rule_silent_on_rbac_binding_manifest` | a `ClusterRoleBinding` (no `rules[]`) stays silent |
| `test_k8s_rbac_wildcard_rule_pragma_opt_out` | the inline pragma suppresses |
| `test_k8s_rbac_wildcard_rule_not_applicable_without_k8s_feature` | `applies()` gates correctly |

## Known bypasses

A wildcard value built from a templated/parameterized Helm value that renders to `"*"` at apply
time (but not in the checked-in source) is invisible to this literal-text match. A rule that lists
every real resource type/verb individually instead of using `"*"` achieves the identical effective
grant while evading this guard entirely (this guard proves the *shortcut* is absent, not that the
resulting permission set is narrow).

## What this guard does NOT prove

`apiGroups` wildcards (`apiGroups: ["*"]`) are out of scope for this guard even though they are
part of the same over-broad-RBAC family — a rule could wildcard `apiGroups` while still naming
specific `resources`/`verbs`, and this guard stays silent on that shape. A document-scoped match
without a real indentation tree also means a `resources:`/`verbs:` list that happens to span an
unusual multi-line style not covered by the inline-list or simple block-list shapes could be missed
(see `agentsec/k8s.py`'s module docstring for the accepted precision tradeoff).

# Citations

[1] agentsec checklist item `6c-k8s-rbac-wildcard-rule` (§6c)
[2] OWASP:A01
[3] CIS:Kubernetes
[4] kube-linter `WildcardInRules` template — `pkg/templates/wildcardinrules/template.go`
