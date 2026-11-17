"""Guard: a Kubernetes workload manifest mounts the Docker socket (§6c).

A `hostPath` volume pointing at `/var/run/docker.sock` gives the container the same privileges as
the node's Docker daemon — full control over every container on the node, and typically root on the
node itself (the classic "Docker socket = root" escalation, adapted here to the Kubernetes hostPath
volume shape). Sourced from kubesec's `DockerSock` rule (`pkg/rules/dockerSock.go`), verified
against the real Go source.

Fires CRITICAL once per K8s workload manifest document containing a `hostPath.path` referencing
`/var/run/docker.sock`. See `agentsec/k8s.py`'s module docstring for the document-scoped precision
tradeoff.

    volumes:
    - name: docker-sock
      hostPath:
        path: /var/run/docker.sock  # security: allow-k8s-docker-sock-mount
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.k8s import k8s_manifest_documents

from .base import CanaryPlant, Guard, iter_files, pragma_present, read, rel, strip_hash_comments

_DOCKER_SOCK_PATH = re.compile(r"""^\s*path:\s*['"]?/var/run/docker\.sock['"]?\s*$""", re.IGNORECASE)
_PRAGMA = re.compile(r"#\s*security:\s*allow-k8s-docker-sock-mount")


class K8sDockerSockMountGuard(Guard):
    id = "k8s-docker-sock-mount"
    title = "Kubernetes workload mounts the Docker socket"
    area = "Kubernetes"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `k8s-deployment.yaml`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # k8s-deployment.yaml: hostPath volume path: /var/run/docker.sock -> hostpath-docker-sock.
    canary_plant = CanaryPlant(expects=frozenset({"k8s-docker-sock-mount/hostpath-docker-sock"}))

    def applies(self, profile: StackProfile) -> bool:
        return "k8s" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".yaml", ".yml")):
            for doc in k8s_manifest_documents(read(f)):
                lines = strip_hash_comments(doc).splitlines()
                if not any(_DOCKER_SOCK_PATH.match(line) for line in lines):
                    continue
                if pragma_present(_PRAGMA, doc, dialect="yaml"):
                    continue
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="critical",
                        title="Workload mounts the Docker socket",
                        location=f"{rel(root, f)}",
                        message=(
                            "A `hostPath` volume mounts `/var/run/docker.sock` into the container "
                            "— that gives it the same control as the node's Docker daemon: full "
                            "access to every container on the node and, in practice, root on the "
                            "node itself."
                        ),
                        remediation=(
                            "Remove the docker.sock hostPath mount. If the workload genuinely needs "
                            "to manage containers/images, use a scoped API (e.g. a sidecar with a "
                            "narrow RBAC-bound service account) instead of the raw socket. Suppress "
                            "a reviewed, intentional case with "
                            "`# security: allow-k8s-docker-sock-mount`."
                        ),
                        rule="k8s-docker-sock-mount/hostpath-docker-sock",
                        standards=["OWASP:A05", "CIS:Kubernetes"],
                    )
                )
        return out
