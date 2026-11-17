"""Guard: a Kubernetes RBAC binding grants a role to the anonymous user (§6c).

A `ClusterRoleBinding`/`RoleBinding` whose `subjects` list includes `system:anonymous` grants
whatever that role can do to ANYONE who can reach the API server without authenticating at all —
one of the most severe Kubernetes RBAC misconfigurations possible, since it defeats authentication
entirely rather than merely over-authorizing an already-authenticated identity. Sourced from
kubesec's `BindingsToSystemAnonymous` rule (`pkg/rules/bindingsToSystemAnonymous.go`), verified
against the real Go source.

This guard targets a DIFFERENT manifest family than the other `k8s-*` guards in this batch —
`ClusterRoleBinding`/`RoleBinding` documents, recognized by `agentsec.k8s.k8s_rbac_binding_documents()`
(a second document recognizer distinct from the Pod-shaped workload one `k8s_manifest_documents()`
provides, since RBAC bindings carry a `subjects` list, never a pod spec).

Fires CRITICAL once per RBAC binding manifest document whose `subjects` block contains
`system:anonymous`. See `agentsec/k8s.py`'s module docstring for the document-scoped precision
tradeoff (no per-container path precision, no PyYAML).

    subjects:
    - kind: User
      name: system:anonymous  # security: allow-k8s-rbac-anonymous-binding
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.k8s import k8s_rbac_binding_documents

from .base import CanaryPlant, Guard, iter_files, pragma_present, read, rel, strip_hash_comments

# Both grant the role to unauthenticated callers: `system:anonymous` is the anonymous *user*;
# `system:unauthenticated` is the *group* every unauthenticated request belongs to — binding to
# either is the identical authentication bypass (kubesec flags both).
_ANONYMOUS_NAME = re.compile(
    r"^\s*name:\s*['\"]?system:(anonymous|unauthenticated)['\"]?\s*$", re.IGNORECASE,
)
_PRAGMA = re.compile(r"#\s*security:\s*allow-k8s-rbac-anonymous-binding")


class K8sRbacAnonymousBindingGuard(Guard):
    id = "k8s-rbac-anonymous-binding"
    title = "Kubernetes RBAC binding grants a role to the anonymous user"
    area = "Kubernetes"

    # k8s-rbac-binding.yaml: a ClusterRoleBinding granting a role to system:anonymous ->
    # k8s-rbac-anonymous-binding/subject-is-system-anonymous. A distinct manifest family (RBAC
    # binding, not a Pod-shaped workload) from the other k8s-* plants.
    canary_plant = CanaryPlant(
        files={
            "k8s-rbac-binding.yaml": (
                "apiVersion: rbac.authorization.k8s.io/v1\n"
                "kind: ClusterRoleBinding\n"
                "metadata:\n"
                "  name: canary-binding\n"
                "subjects:\n"
                "- kind: User\n"
                "  name: system:anonymous\n"
                "  apiGroup: rbac.authorization.k8s.io\n"
                "roleRef:\n"
                "  kind: ClusterRole\n"
                "  name: cluster-admin\n"
                "  apiGroup: rbac.authorization.k8s.io\n"
            ),
        },
        expects=frozenset({"k8s-rbac-anonymous-binding/subject-is-system-anonymous"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "k8s" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".yaml", ".yml")):
            for doc in k8s_rbac_binding_documents(read(f)):
                lines = strip_hash_comments(doc).splitlines()
                if not any(_ANONYMOUS_NAME.match(line) for line in lines):
                    continue
                if pragma_present(_PRAGMA, doc, dialect="yaml"):
                    continue
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="critical",
                        title="RBAC binding grants a role to an anonymous/unauthenticated subject",
                        location=f"{rel(root, f)}",
                        message=(
                            "This ClusterRoleBinding/RoleBinding's `subjects` list includes "
                            "`system:anonymous` or `system:unauthenticated` — the role it binds is "
                            "granted to ANYONE who can reach the API server, authenticated or not. "
                            "This defeats authentication entirely, not just over-authorization."
                        ),
                        remediation=(
                            "Remove the `system:anonymous`/`system:unauthenticated` subject. "
                            "Bind the role to a specific "
                            "ServiceAccount, User, or Group instead. Suppress a reviewed, "
                            "intentional case (e.g. a deliberately public health-check endpoint "
                            "role) with `# security: allow-k8s-rbac-anonymous-binding`."
                        ),
                        rule="k8s-rbac-anonymous-binding/subject-is-system-anonymous",
                        standards=["OWASP:A01", "CIS:Kubernetes"],
                    )
                )
        return out
