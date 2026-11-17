"""Shared Kubernetes-manifest helpers for stack detection + the `k8s-*` guards.

No PyYAML at runtime (agentsec is dependency-free) — the house pattern for structured-config
formats without a stdlib parser is document/regex-scoped scanning, not a full YAML parser (see
`guards/compose_dns_bypass.py`'s indentation-aware compose scanner for the same tradeoff one level
shallower). A manifest is recognized by `---`-separated YAML DOCUMENT rather than by precise
container path, so a Pod with several containers where only one sets an unsafe field still fires —
the guards using this module check for the pattern's PRESENCE anywhere in a matched document, not
kubesec's own per-container JSONPath precision. Same FN/FP tradeoff already accepted by several
other document/file-scoped guards in this codebase (no dataflow engine).
"""
from __future__ import annotations

import re

# A recognized Pod-shaped K8s workload controller kind. Deliberately excludes Service/ConfigMap/
# Secret/Ingress/etc — those never carry a pod spec / securityContext, so including them would
# only add non-matching documents to scan, never a real detection surface.
_K8S_KIND = re.compile(
    # Optional quotes around the value: routine Helm/Kustomize/yamllint output emits `kind: "Pod"`.
    # Missing them made `is_k8s_manifest_text` (also used by detect.py for the `k8s` feature) return
    # False on a quote-emitting repo → the whole k8s guard batch silently N/A.
    r"^[^\S\n]*kind:\s*['\"]?(Pod|Deployment|StatefulSet|DaemonSet|Job|CronJob|ReplicaSet)['\"]?\s*(?:#.*)?$",
    re.MULTILINE,
)
_K8S_API_VERSION = re.compile(r"^[^\S\n]*apiVersion:\s*\S+", re.MULTILINE)
# A trailing comment on the separator (`--- # second manifest`) is valid YAML and routine in
# hand-written multi-doc files. Missing it merged the documents either side into one, so a hardened
# manifest silenced a vulnerable one for EVERY k8s-* guard (they all evaluate per document).
_DOC_SEP = re.compile(r"^-{3,}\s*(?:#.*)?$", re.MULTILINE)

# A recognized RBAC binding kind — a second, distinct document recognizer from the Pod-shaped
# workload one above. ClusterRoleBinding/RoleBinding manifests carry a `subjects` list, never a pod
# spec, so they need their own recognizer rather than extending _K8S_KIND (which would make a
# `k8s_manifest_documents()` caller see a shape it doesn't expect — no securityContext, no
# containers — a genuinely different document family, not a variant of the same one).
_K8S_RBAC_KIND = re.compile(
    r"^[^\S\n]*kind:\s*['\"]?(ClusterRoleBinding|RoleBinding)['\"]?\s*(?:#.*)?$", re.MULTILINE,
)

# A recognized RBAC Role/ClusterRole kind — a THIRD, distinct document recognizer. Role/ClusterRole
# manifests carry a `rules[]` block (verb/resource/apiGroup grants), never a `subjects` list (that's
# the binding, matched by `_K8S_RBAC_KIND` above) and never a pod spec. The `$` anchor deliberately
# excludes `RoleBinding`/`ClusterRoleBinding` — trailing "Binding" text after the matched kind name
# fails the end-of-line anchor, so this recognizer and `_K8S_RBAC_KIND` never double-match the same
# document.
_K8S_RBAC_ROLE_KIND = re.compile(
    r"^[^\S\n]*kind:\s*['\"]?(Role|ClusterRole)['\"]?\s*(?:#.*)?$", re.MULTILINE,
)


def k8s_manifest_documents(text: str) -> list[str]:
    """`---`-separated YAML documents in `text` that look like a Pod-shaped K8s workload
    manifest — both `apiVersion:` and a recognized controller `kind:` present. Excludes
    non-matching documents (docker-compose, GitHub Actions, Service/ConfigMap/Ingress and other
    CRDs with no pod spec)."""
    return [d for d in _DOC_SEP.split(text) if _K8S_KIND.search(d) and _K8S_API_VERSION.search(d)]


def k8s_rbac_binding_documents(text: str) -> list[str]:
    """`---`-separated YAML documents in `text` that look like a ClusterRoleBinding/RoleBinding
    manifest — both `apiVersion:` and a recognized RBAC binding `kind:` present. A distinct document
    family from `k8s_manifest_documents()` (no pod spec, no securityContext — a `subjects` list
    instead)."""
    return [d for d in _DOC_SEP.split(text) if _K8S_RBAC_KIND.search(d) and _K8S_API_VERSION.search(d)]


def k8s_rbac_role_documents(text: str) -> list[str]:
    """`---`-separated YAML documents in `text` that look like a Role/ClusterRole manifest — both
    `apiVersion:` and a recognized RBAC role `kind:` present. A third distinct document family from
    `k8s_manifest_documents()` (no pod spec) and `k8s_rbac_binding_documents()` (no `subjects` list)
    — a Role/ClusterRole carries a `rules[]` block of verb/resource/apiGroup grants instead."""
    return [d for d in _DOC_SEP.split(text) if _K8S_RBAC_ROLE_KIND.search(d) and _K8S_API_VERSION.search(d)]


def is_k8s_manifest_text(text: str) -> bool:
    """True if `text` contains at least one Pod-shaped workload, RBAC-binding, or RBAC-role K8s
    manifest document — any is sufficient to turn on the `"k8s"` stack feature (a repo could ship
    only RBAC manifests, e.g. a Helm chart's templates/rbac.yaml, with workloads defined
    elsewhere)."""
    return (
        bool(k8s_manifest_documents(text))
        or bool(k8s_rbac_binding_documents(text))
        or bool(k8s_rbac_role_documents(text))
    )
