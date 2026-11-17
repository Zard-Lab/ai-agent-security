"""Guard: a Kubernetes RBAC binding grants the built-in `cluster-admin` ClusterRole (§6c).

A `ClusterRoleBinding`/`RoleBinding` whose `roleRef` names the built-in `cluster-admin` `ClusterRole`
grants full cluster-administrator rights to whatever subject is listed — every verb on every
resource in every API group, cluster-wide. This checks the GRANTED ROLE, a different angle from
`k8s_rbac_anonymous_binding.py` (which checks the SUBJECT): a binding can grant cluster-admin to a
perfectly ordinary, authenticated ServiceAccount and still be a severe over-grant, no anonymous
access required. Sourced from kube-linter's `ClusterAdminRoleBinding` template
(`pkg/templates/clusteradminrolebinding/template.go`), verified against the real Go source — a
simple field-equality check on `roleRef`, no cross-object correlation needed.

Reuses the same RBAC-binding-document recognizer `k8s_rbac_anonymous_binding.py` uses
(`agentsec.k8s.k8s_rbac_binding_documents()`), since both guards look at fields on a
`ClusterRoleBinding`/`RoleBinding` document — `subjects` for the anonymous check, `roleRef` for this
one.

Fires CRITICAL once per RBAC binding manifest document whose `roleRef` names `kind: ClusterRole`,
`name: cluster-admin`. See `agentsec/k8s.py`'s module docstring for the document-scoped precision
tradeoff (no per-container path precision, no PyYAML).

    roleRef:
      kind: ClusterRole
      name: cluster-admin  # security: allow-k8s-rbac-cluster-admin-binding
      apiGroup: rbac.authorization.k8s.io
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.k8s import k8s_rbac_binding_documents

from .base import CanaryPlant, Guard, iter_files, pragma_present, read, rel, strip_hash_comments

# `roleRef:` is a single mapping block (never a list), so a document has at most one `kind:`/
# `name:` pair inside it. Scoped to lines inside that block (approximated here, document-scoped,
# by indentation rather than a real indentation tree — see module docstring for the tradeoff) so a
# `subjects[].name: cluster-admin` (a subject merely NAMED "cluster-admin") never counts as the
# granted role.
_ROLE_REF_KEY = re.compile(r"^\s*roleRef:\s*$", re.IGNORECASE)
_KIND_LINE = re.compile(r"^\s*kind:\s*['\"]?(\w+)['\"]?\s*(?:#.*)?$", re.IGNORECASE)
_NAME_LINE = re.compile(r"^\s*name:\s*['\"]?([\w:.-]+)['\"]?\s*(?:#.*)?$", re.IGNORECASE)
_PRAGMA = re.compile(r"#\s*security:\s*allow-k8s-rbac-cluster-admin-binding")


def _role_ref_targets_cluster_admin(lines: list[str]) -> bool:
    """True if a `roleRef:` block in `lines` sets `kind: ClusterRole` and `name: cluster-admin`."""
    in_role_ref = False
    role_ref_indent = -1
    kind_val: str | None = None
    name_val: str | None = None
    for line in lines:
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        if _ROLE_REF_KEY.match(line):
            in_role_ref = True
            role_ref_indent = indent
            kind_val = None
            name_val = None
            continue
        if not in_role_ref:
            continue
        if indent <= role_ref_indent:
            in_role_ref = False
            continue
        m = _KIND_LINE.match(line)
        if m:
            kind_val = m.group(1)
            continue
        m = _NAME_LINE.match(line)
        if m:
            name_val = m.group(1)
    return kind_val is not None and kind_val.lower() == "clusterrole" and name_val == "cluster-admin"


class K8sRbacClusterAdminBindingGuard(Guard):
    id = "k8s-rbac-cluster-admin-binding"
    title = "Kubernetes RBAC binding grants the built-in cluster-admin role"
    area = "Kubernetes"

    # k8s-rbac-cluster-admin-binding.yaml: a RoleBinding whose roleRef names the built-in
    # cluster-admin ClusterRole -> k8s-rbac-cluster-admin-binding/role-is-cluster-admin. A
    # namespaced RoleBinding (not just a ClusterRoleBinding) can reference the cluster-scoped
    # cluster-admin ClusterRole too — that still grants full admin rights within the namespace, so
    # the plant deliberately uses a RoleBinding to prove the guard isn't accidentally scoped to
    # ClusterRoleBinding only.
    canary_plant = CanaryPlant(
        files={
            "k8s-rbac-cluster-admin-binding.yaml": (
                "apiVersion: rbac.authorization.k8s.io/v1\n"
                "kind: RoleBinding\n"
                "metadata:\n"
                "  name: canary-admin-binding\n"
                "  namespace: default\n"
                "subjects:\n"
                "- kind: ServiceAccount\n"
                "  name: canary-app-sa\n"
                "  namespace: default\n"
                "roleRef:\n"
                "  kind: ClusterRole\n"
                "  name: cluster-admin\n"
                "  apiGroup: rbac.authorization.k8s.io\n"
            ),
        },
        expects=frozenset({"k8s-rbac-cluster-admin-binding/role-is-cluster-admin"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "k8s" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".yaml", ".yml")):
            for doc in k8s_rbac_binding_documents(read(f)):
                lines = strip_hash_comments(doc).splitlines()
                if not _role_ref_targets_cluster_admin(lines):
                    continue
                if pragma_present(_PRAGMA, doc, dialect="yaml"):
                    continue
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="critical",
                        title="RBAC binding grants the built-in cluster-admin role",
                        location=f"{rel(root, f)}",
                        message=(
                            "This ClusterRoleBinding/RoleBinding's `roleRef` names the built-in "
                            "`cluster-admin` ClusterRole — the bound subject gets every verb on "
                            "every resource in every API group, cluster-wide (or, for a "
                            "namespaced RoleBinding, full admin rights within that namespace)."
                        ),
                        remediation=(
                            "Bind a narrower, purpose-built Role/ClusterRole that grants only the "
                            "verbs/resources the subject actually needs instead of `cluster-admin`. "
                            "Suppress a reviewed, intentional case (e.g. a cluster operator's own "
                            "controller) with `# security: allow-k8s-rbac-cluster-admin-binding`."
                        ),
                        rule="k8s-rbac-cluster-admin-binding/role-is-cluster-admin",
                        standards=["OWASP:A01", "CIS:Kubernetes"],
                    )
                )
        return out
