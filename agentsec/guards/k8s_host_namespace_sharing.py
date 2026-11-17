"""Guard: a Kubernetes workload manifest shares a host namespace (§6c).

`hostPID`/`hostNetwork`/`hostIPC: true` share the NODE's process/network/IPC namespace with the
container, breaking the isolation a pod is supposed to provide — `hostPID: true` lets a compromised
container see and signal every process on the node (including other pods'), `hostNetwork: true`
exposes the node's real network interfaces and bypasses network policies, `hostIPC: true` lets a
container access other processes' shared memory. Sourced from kubesec's `HostPID`/`HostNetwork`/
`HostIPC` rules (`pkg/rules/host{PID,Network,IPC}.go`), verified against the real Go source.

Fires HIGH once per field, per K8s workload manifest document, when that field is explicitly
`true`. See `agentsec/k8s.py`'s module docstring for the document-scoped precision tradeoff.

    spec:
      hostPID: true  # security: allow-k8s-host-namespace-sharing
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.k8s import k8s_manifest_documents

from .base import CanaryPlant, Guard, iter_files, pragma_present, read, rel, strip_hash_comments

_PRAGMA = re.compile(r"#\s*security:\s*allow-k8s-host-namespace-sharing")

# (yaml field name, rule slug, human name)
_FIELDS: tuple[tuple[str, str, str], ...] = (
    ("hostPID", "hostpid-enabled", "the node's PID (process) namespace"),
    ("hostNetwork", "hostnetwork-enabled", "the node's network namespace"),
    ("hostIPC", "hostipc-enabled", "the node's IPC (shared memory) namespace"),
)


class K8sHostNamespaceSharingGuard(Guard):
    id = "k8s-host-namespace-sharing"
    title = "Kubernetes workload shares a host namespace"
    area = "Kubernetes"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `k8s-deployment.yaml`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # k8s-deployment.yaml: hostPID/hostNetwork/hostIPC: true -> all three sub-rules.
    canary_plant = CanaryPlant(
        expects=frozenset({
            "k8s-host-namespace-sharing/hostpid-enabled",
            "k8s-host-namespace-sharing/hostnetwork-enabled",
            "k8s-host-namespace-sharing/hostipc-enabled",
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
                for field, slug, human in _FIELDS:
                    pattern = re.compile(rf"^\s*{field}:\s*true\s*$", re.IGNORECASE)
                    if not any(pattern.match(line) for line in lines):
                        continue
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="high",
                            title=f"Workload shares {human} with the host",
                            location=f"{rel(root, f)}",
                            message=(
                                f"`{field}: true` shares {human} with the underlying node, "
                                "breaking the isolation a pod is supposed to provide. A "
                                "compromised container gets that much more visibility/influence "
                                "over the rest of the node."
                            ),
                            remediation=(
                                f"Remove `{field}: true` unless the workload genuinely needs "
                                "node-level access (e.g. a CNI/monitoring DaemonSet) — suppress "
                                "that reviewed case with "
                                "`# security: allow-k8s-host-namespace-sharing`."
                            ),
                            rule=f"k8s-host-namespace-sharing/{slug}",
                            standards=["OWASP:A05", "CIS:Kubernetes"],
                        )
                    )
        return out
