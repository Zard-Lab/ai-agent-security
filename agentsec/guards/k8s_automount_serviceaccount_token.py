"""Guard: a Kubernetes workload doesn't disable service-account token automounting (§6c).

Kubernetes automounts the pod's service account token into every container by default
(`/var/run/secrets/kubernetes.io/serviceaccount/token`) unless a manifest explicitly opts out with
`automountServiceAccountToken: false`. A workload that never actually calls the Kubernetes API
still gets a live, exfiltratable credential mounted into every container — if the container is
compromised (prompt-injected agent tool execution, an app-level RCE), that token is immediately
available to the attacker to call the cluster API as that service account. Sourced from kubesec's
`AutomountServiceAccountToken` rule (`pkg/rules/automountServiceAccountToken.go`), verified against
the real Go source — its own comment confirms the default-mount behavior this guard checks for.

Fires MEDIUM once per K8s workload manifest document that does NOT explicitly set
`automountServiceAccountToken: false` at the pod-spec level. See `agentsec/k8s.py`'s module
docstring for the document-scoped precision tradeoff — this is a pod-spec-level field in real K8s,
so document-level (not per-container) precision is actually correct here, not an approximation.

    spec:
      automountServiceAccountToken: false
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.k8s import k8s_manifest_documents

from .base import CanaryPlant, Guard, iter_files, pragma_present, read, rel, strip_hash_comments

_TOKEN_EXPLICITLY_FALSE = re.compile(r"^\s*automountServiceAccountToken:\s*false\s*$", re.IGNORECASE)
_PRAGMA = re.compile(r"#\s*security:\s*allow-k8s-automount-serviceaccount-token")


class K8sAutomountServiceaccountTokenGuard(Guard):
    id = "k8s-automount-serviceaccount-token"
    title = "Kubernetes workload doesn't disable service-account token automount"
    area = "Kubernetes"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `k8s-deployment.yaml`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # k8s-deployment.yaml: no automountServiceAccountToken: false anywhere -> not-explicitly-disabled.
    canary_plant = CanaryPlant(
        expects=frozenset({
            "k8s-automount-serviceaccount-token/not-explicitly-disabled",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "k8s" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".yaml", ".yml")):
            for doc in k8s_manifest_documents(read(f)):
                if pragma_present(_PRAGMA, doc, dialect="yaml"):
                    continue
                lines = strip_hash_comments(doc).splitlines()
                if any(_TOKEN_EXPLICITLY_FALSE.match(line) for line in lines):
                    continue
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="medium",
                        title="Service-account token automount not disabled",
                        location=f"{rel(root, f)}",
                        message=(
                            "Kubernetes automounts the pod's service-account token into every "
                            "container unless `automountServiceAccountToken: false` is set. If this "
                            "workload doesn't call the Kubernetes API, it still carries a live, "
                            "exfiltratable cluster credential — usable by an attacker the moment any "
                            "container in the pod is compromised."
                        ),
                        remediation=(
                            "Set `automountServiceAccountToken: false` on the pod spec (and, if the "
                            "default service account is used, on the ServiceAccount object too) "
                            "unless the workload genuinely needs to call the Kubernetes API. If it "
                            "does, bind a dedicated, narrowly-scoped RBAC service account instead."
                        ),
                        rule="k8s-automount-serviceaccount-token/not-explicitly-disabled",
                        standards=["OWASP:A01", "CIS:Kubernetes"],
                    )
                )
        return out
