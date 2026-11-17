"""Guard: a Kubernetes workload doesn't require running as a non-root user (§6c).

`securityContext.runAsNonRoot: true` is the Kubernetes-manifest-level sibling of the existing
`6c-nonroot-container-user` checklist item — the same control `hadolint` already checks at the
Dockerfile `USER` level, ported to the K8s workload manifest a Dockerfile-only check can't see.
Without it, a container built from an image that defaults to root (or a base image that later
regresses to root) runs as root at the cluster level regardless of what the Dockerfile says,
handing a compromised process (prompt-injected agent tool execution, an app-level RCE) full root
privileges inside the container. Sourced from kubesec's `RunAsNonRoot` rule
(`pkg/rules/runAsNonRoot.go`), verified against the real Go source — unlike most fields in this
guard family, kubesec checks this one at BOTH the pod-spec and container level, since a
container-level override always wins.

Deliberately does NOT port kubesec's `RunAsUser`/`RunAsGroup` rules (numeric UID/GID > 10000
threshold) — that specific cutoff is somewhat arbitrary and a real manifest commonly runs as UID
1000-9999 (an extremely conventional non-root range, e.g. `USER 1000` in countless base images),
which the >10000 threshold would flag as a false positive. Porting a debatable numeric threshold as
a hard finding needs its own severity/threshold decision, not a silent copy — left as a follow-up.

Fires HIGH once per K8s workload manifest document that does NOT explicitly set
`runAsNonRoot: true` anywhere in the document (pod-spec OR container level — either satisfies the
control). See `agentsec/k8s.py`'s module docstring for the document-scoped precision tradeoff. This
guard EXTENDS the existing `6c-nonroot-container-user` checklist item rather than creating a new
item — same checklist gap, a second detection layer.

    securityContext:
      runAsNonRoot: true
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.k8s import k8s_manifest_documents

from .base import CanaryPlant, Guard, iter_files, pragma_present, read, rel, strip_hash_comments

_RUN_AS_NON_ROOT_TRUE = re.compile(r"^\s*runAsNonRoot:\s*true\s*$", re.IGNORECASE)
_PRAGMA = re.compile(r"#\s*security:\s*allow-k8s-run-as-non-root")


class K8sRunAsNonRootGuard(Guard):
    id = "k8s-run-as-non-root"
    title = "Kubernetes workload doesn't require running as non-root"
    area = "Kubernetes"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `k8s-deployment.yaml`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # k8s-deployment.yaml: no runAsNonRoot: true anywhere -> not-explicitly-enabled.
    canary_plant = CanaryPlant(expects=frozenset({"k8s-run-as-non-root/not-explicitly-enabled"}))

    def applies(self, profile: StackProfile) -> bool:
        return "k8s" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".yaml", ".yml")):
            for doc in k8s_manifest_documents(read(f)):
                if pragma_present(_PRAGMA, doc, dialect="yaml"):
                    continue
                lines = strip_hash_comments(doc).splitlines()
                if any(_RUN_AS_NON_ROOT_TRUE.match(line) for line in lines):
                    continue
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title="Workload doesn't require running as non-root",
                        location=f"{rel(root, f)}",
                        message=(
                            "`securityContext.runAsNonRoot` is not set to `true` anywhere in this "
                            "manifest (pod-spec or container level). A container built from an image "
                            "that defaults to root — or one that later regresses to root — runs as "
                            "root at the cluster level regardless of the Dockerfile's own `USER` "
                            "directive."
                        ),
                        remediation=(
                            "Set `runAsNonRoot: true` on the pod spec (or per-container if different "
                            "containers need different users). Kubernetes will then refuse to start "
                            "any container whose effective user is root, closing the gap even if a "
                            "future image change regresses to root. Suppress a reviewed, intentional "
                            "case with `# security: allow-k8s-run-as-non-root`."
                        ),
                        rule="k8s-run-as-non-root/not-explicitly-enabled",
                        standards=["OWASP:A05", "CIS:Kubernetes"],
                    )
                )
        return out
