"""Guard: a Kubernetes workload manifest runs a container in privileged mode (§6c).

`securityContext.privileged: true` disables nearly all container isolation — the container gets
full access to the host's devices and kernel capabilities, making a container breakout to full
host compromise straightforward if the container is ever compromised (prompt-injected agent tool
execution, a supply-chain-compromised base image, an app-level RCE). Sourced from kubesec's
`Privileged` rule (`pkg/rules/privileged.go`), verified against the real Go source.

Fires CRITICAL once per K8s workload manifest document (Pod/Deployment/StatefulSet/DaemonSet/
Job/CronJob/ReplicaSet) containing `privileged: true`. See `agentsec/k8s.py`'s module docstring
for the document-scoped precision tradeoff (no per-container path precision, no PyYAML).

    securityContext:
      privileged: true  # security: allow-k8s-privileged-container
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.k8s import k8s_manifest_documents

from .base import CanaryPlant, Guard, iter_files, pragma_present, read, rel, strip_hash_comments

_PRIVILEGED_TRUE = re.compile(r"^\s*privileged:\s*true\s*$", re.IGNORECASE)
_PRAGMA = re.compile(r"#\s*security:\s*allow-k8s-privileged-container")


class K8sPrivilegedContainerGuard(Guard):
    id = "k8s-privileged-container"
    title = "Kubernetes container runs in privileged mode"
    area = "Kubernetes"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `k8s-deployment.yaml`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # k8s-deployment.yaml: securityContext.privileged: true -> securitycontext-privileged-true.
    canary_plant = CanaryPlant(
        expects=frozenset({
            "k8s-privileged-container/securitycontext-privileged-true",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "k8s" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".yaml", ".yml")):
            for doc in k8s_manifest_documents(read(f)):
                lines = strip_hash_comments(doc).splitlines()
                if not any(_PRIVILEGED_TRUE.match(line) for line in lines):
                    continue
                if pragma_present(_PRAGMA, doc, dialect="yaml"):
                    continue
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="critical",
                        title="Container runs in privileged mode",
                        location=f"{rel(root, f)}",
                        message=(
                            "`securityContext.privileged: true` disables container isolation — "
                            "the container gets full host device/kernel access, making a container "
                            "breakout to host compromise straightforward if it's ever compromised."
                        ),
                        remediation=(
                            "Remove `privileged: true`. If specific host access is genuinely needed, "
                            "grant only the exact capability via `securityContext.capabilities.add` "
                            "instead of full privileged mode. Suppress an intentional, reviewed case "
                            "with `# security: allow-k8s-privileged-container`."
                        ),
                        rule="k8s-privileged-container/securitycontext-privileged-true",
                        standards=["OWASP:A05", "CIS:Kubernetes"],
                    )
                )
        return out
