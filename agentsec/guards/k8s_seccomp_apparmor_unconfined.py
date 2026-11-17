"""Guard: a Kubernetes workload explicitly opts out of seccomp/AppArmor confinement (§6c).

`seccompProfile.type: Unconfined` and `appArmorProfile.type: Unconfined` each explicitly disable a
kernel-level syscall/capability confinement layer that's on by default in modern Kubernetes
(`RuntimeDefault` is the safe default seccomp profile since v1.27). An `Unconfined` profile removes
that whole layer of defense for the container, widening the blast radius if the container is ever
compromised (prompt-injected agent tool execution, a supply-chain-compromised base image, an
app-level RCE) — the same class of risk `k8s-privileged-container` and `k8s-privileged-capabilities`
address, from the syscall-filtering angle instead of the capability/mode angle. Sourced from
kubesec's `SeccompUnconfined`/`ApparmorUnconfined` rules (`pkg/rules/seccompUnconfined.go`,
`pkg/rules/apparmorUnconfined.go`), verified against the real Go source — both check for the exact
literal string `"Unconfined"`, not "any non-default value" (a named custom profile is not flagged).

Fires HIGH once per profile type per K8s workload manifest document containing an explicit
`Unconfined` value. See `agentsec/k8s.py`'s module docstring for the document-scoped precision
tradeoff (no per-container path precision, no PyYAML).

    securityContext:
      seccompProfile:
        type: Unconfined  # security: allow-k8s-seccomp-apparmor-unconfined
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.k8s import k8s_manifest_documents

from .base import CanaryPlant, Guard, iter_files, pragma_present, read, rel, strip_hash_comments

_PRAGMA = re.compile(r"#\s*security:\s*allow-k8s-seccomp-apparmor-unconfined")

# (yaml field name, rule slug, human profile name)
_PROFILES: tuple[tuple[str, str, str], ...] = (
    ("seccompProfile", "seccomp-unconfined", "seccomp"),
    ("appArmorProfile", "apparmor-unconfined", "AppArmor"),
)


class K8sSeccompApparmorUnconfinedGuard(Guard):
    id = "k8s-seccomp-apparmor-unconfined"
    title = "Kubernetes workload opts out of seccomp/AppArmor confinement"
    area = "Kubernetes"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `k8s-deployment.yaml`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # k8s-deployment.yaml: seccompProfile.type + appArmorProfile.type both Unconfined ->
    # both sub-rules.
    canary_plant = CanaryPlant(
        expects=frozenset({
            "k8s-seccomp-apparmor-unconfined/seccomp-unconfined",
            "k8s-seccomp-apparmor-unconfined/apparmor-unconfined",
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
                for field, slug, human in _PROFILES:
                    pattern = re.compile(rf"^\s*{field}:\s*$")
                    type_pattern = re.compile(r"^\s*type:\s*Unconfined\s*$", re.IGNORECASE)
                    fired = False
                    for i, line in enumerate(lines):
                        if pattern.match(line):
                            # scan the immediately following indented block for `type: Unconfined`
                            block_indent = len(line) - len(line.lstrip())
                            for follow in lines[i + 1:]:
                                if not follow.strip():
                                    continue
                                indent = len(follow) - len(follow.lstrip())
                                if indent <= block_indent:
                                    break
                                if type_pattern.match(follow):
                                    fired = True
                                    break
                        if fired:
                            break
                    if not fired:
                        continue
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="high",
                            title=f"Workload opts out of {human} confinement",
                            location=f"{rel(root, f)}",
                            message=(
                                f"`{field}.type: Unconfined` explicitly disables {human} "
                                "confinement — a kernel-level defense layer that's on by default in "
                                "modern Kubernetes. Removing it widens the blast radius of a "
                                "compromised container."
                            ),
                            remediation=(
                                f"Remove the explicit `{field}.type: Unconfined` override (letting "
                                "the cluster's `RuntimeDefault` apply) or set a specific named "
                                "profile tailored to the workload. Suppress a reviewed, intentional "
                                "case with `# security: allow-k8s-seccomp-apparmor-unconfined`."
                            ),
                            rule=f"k8s-seccomp-apparmor-unconfined/{slug}",
                            standards=["OWASP:A05", "CIS:Kubernetes"],
                        )
                    )
        return out
