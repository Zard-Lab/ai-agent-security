"""Guard: a Kubernetes container doesn't set a read-only root filesystem (§6c).

`securityContext.readOnlyRootFilesystem: true` is the Kubernetes-manifest-level sibling of the
existing `6c-readonly-container-fs` checklist item — the same control `ai-docker` already checks
at the Dockerfile/compose level, ported to the K8s workload manifest a Dockerfile-only check can't
see. Without it, a container's own image filesystem stays writable, giving a compromised process a
place to drop and persist a payload (prompt-injected agent tool execution, a supply-chain-
compromised base image, an app-level RCE) instead of being confined to the volumes the workload
actually declared as writable. Sourced from kubesec's `ReadOnlyRootFilesystem` rule
(`pkg/rules/readOnlyRootFilesystem.go`), verified against the real Go source — kubesec's own scoring
rewards the explicit `true`, meaning unset and explicit `false` are equally un-hardened.

Fires MEDIUM once per K8s workload manifest document that does NOT explicitly set
`readOnlyRootFilesystem: true`. See `agentsec/k8s.py`'s module docstring for the document-scoped
precision tradeoff. This guard EXTENDS the existing `6c-readonly-container-fs` checklist item
(mapped there alongside `ai-docker`) rather than creating a new item — same checklist gap, a second
detection layer.

    securityContext:
      readOnlyRootFilesystem: true
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.k8s import k8s_manifest_documents

from .base import CanaryPlant, Guard, iter_files, pragma_present, read, rel, strip_hash_comments

_READONLY_TRUE = re.compile(r"^\s*readOnlyRootFilesystem:\s*true\s*$", re.IGNORECASE)
_PRAGMA = re.compile(r"#\s*security:\s*allow-k8s-readonly-root-filesystem")


class K8sReadonlyRootFilesystemGuard(Guard):
    id = "k8s-readonly-root-filesystem"
    title = "Kubernetes container doesn't set a read-only root filesystem"
    area = "Kubernetes"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `k8s-deployment.yaml`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # k8s-deployment.yaml: no readOnlyRootFilesystem: true anywhere -> not-explicitly-enabled.
    canary_plant = CanaryPlant(expects=frozenset({"k8s-readonly-root-filesystem/not-explicitly-enabled"}))

    def applies(self, profile: StackProfile) -> bool:
        return "k8s" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".yaml", ".yml")):
            for doc in k8s_manifest_documents(read(f)):
                if pragma_present(_PRAGMA, doc, dialect="yaml"):
                    continue
                lines = strip_hash_comments(doc).splitlines()
                if any(_READONLY_TRUE.match(line) for line in lines):
                    continue
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="medium",
                        title="Container root filesystem is not read-only",
                        location=f"{rel(root, f)}",
                        message=(
                            "`securityContext.readOnlyRootFilesystem` is not set to `true`. A "
                            "writable root filesystem gives a compromised container a place to drop "
                            "and persist a payload, instead of being confined to volumes the "
                            "workload explicitly declared as writable."
                        ),
                        remediation=(
                            "Set `readOnlyRootFilesystem: true` and mount an explicit `emptyDir` "
                            "volume for any path the container genuinely needs to write to (e.g. "
                            "`/tmp`, a cache dir). Suppress a reviewed, intentional case with "
                            "`# security: allow-k8s-readonly-root-filesystem`."
                        ),
                        rule="k8s-readonly-root-filesystem/not-explicitly-enabled",
                        standards=["OWASP:A05", "CIS:Kubernetes"],
                    )
                )
        return out
