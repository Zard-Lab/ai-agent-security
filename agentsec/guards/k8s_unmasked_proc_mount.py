"""Guard: a Kubernetes container disables the default masked /proc mount (§6c).

`securityContext.procMount: Unmasked` disables the kernel's default masking of `/proc` paths that
can leak host/kernel information or be used to probe kernel internals from inside a container —
Kubernetes' default (`Default`, effectively equivalent to Docker's `MaskedPaths`/`ReadonlyPaths`)
hides those paths specifically to weaken this kind of container-to-host information exposure and
escape surface. Setting `Unmasked` opts back into the pre-masking behavior. Sourced from
kube-linter's `UnsafeProcMount` template (`pkg/templates/unsafeprocmount/template.go`), verified
against the real Go source.

Targets the Pod-workload document family (`agentsec.k8s.k8s_manifest_documents()`), the same
recognizer `k8s_docker_sock_mount.py`/`k8s_privileged_capabilities.py` use — `procMount` is a
container `securityContext` field.

Fires CRITICAL once per K8s workload manifest document containing `procMount: Unmasked`. See
`agentsec/k8s.py`'s module docstring for the document-scoped precision tradeoff.

    securityContext:
      procMount: Unmasked  # security: allow-k8s-unmasked-proc-mount
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.k8s import k8s_manifest_documents

from .base import CanaryPlant, Guard, iter_files, pragma_present, read, rel, strip_hash_comments

_UNMASKED_PROC_MOUNT = re.compile(
    r"""^\s*procMount:\s*['"]?Unmasked['"]?\s*(?:#.*)?$""", re.IGNORECASE,
)
_PRAGMA = re.compile(r"#\s*security:\s*allow-k8s-unmasked-proc-mount")


class K8sUnmaskedProcMountGuard(Guard):
    id = "k8s-unmasked-proc-mount"
    title = "Kubernetes container disables the default masked /proc mount"
    area = "Kubernetes"

    # k8s-unmasked-proc-mount.yaml: a container securityContext.procMount: Unmasked -> fires.
    canary_plant = CanaryPlant(
        files={
            "k8s-unmasked-proc-mount.yaml": (
                "apiVersion: v1\n"
                "kind: Pod\n"
                "metadata:\n"
                "  name: canary-proc-mount\n"
                "spec:\n"
                "  containers:\n"
                "  - name: app\n"
                "    image: canary-app:latest\n"
                "    securityContext:\n"
                "      procMount: Unmasked\n"
            ),
        },
        expects=frozenset({"k8s-unmasked-proc-mount/proc-mount-unmasked"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "k8s" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".yaml", ".yml")):
            for doc in k8s_manifest_documents(read(f)):
                lines = strip_hash_comments(doc).splitlines()
                if not any(_UNMASKED_PROC_MOUNT.match(line) for line in lines):
                    continue
                if pragma_present(_PRAGMA, doc, dialect="yaml"):
                    continue
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="critical",
                        title="Container disables the default masked /proc mount",
                        location=f"{rel(root, f)}",
                        message=(
                            "`securityContext.procMount: Unmasked` disables Kubernetes' default "
                            "masking of `/proc` paths that can leak host/kernel information or "
                            "expose kernel internals the container should not be able to probe."
                        ),
                        remediation=(
                            "Remove `procMount: Unmasked` (or set it to `Default`) unless the "
                            "workload has a specific, reviewed need to access unmasked `/proc` "
                            "paths (e.g. certain container-runtime/debugging tooling). Suppress a "
                            "reviewed, intentional case with "
                            "`# security: allow-k8s-unmasked-proc-mount`."
                        ),
                        rule="k8s-unmasked-proc-mount/proc-mount-unmasked",
                        standards=["OWASP:A05", "CIS:Kubernetes"],
                    )
                )
        return out
