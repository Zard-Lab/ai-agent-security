"""Guard: a Kubernetes workload manifest sets no CPU or memory resource limit (§6c).

    containers:
    - name: app
      image: myapp
      # no resources.limits.cpu, no resources.limits.memory -> unbounded

The Kubernetes-manifest-level sibling of the existing docker-compose check
(`compose_resource_limits_absent.py`) — the same finding class (unbounded resource consumption),
ported to the manifest format a compose-only check can't see. Without `resources.limits.cpu`/
`.memory`, Kubernetes imposes no cap on the container's CPU or memory use: a single compromised or
runaway container (a prompt-injected agent tool loop, a memory leak, a fork bomb) can consume the
whole node, starving every other pod scheduled on it — the same DoS/noisy-neighbor class, at cluster
scale instead of single-host scale. CWE-770 (Allocation of Resources Without Limits or Throttling),
OWASP:A05.

Sourced from kubesec's `ResourceLimitsCPU`/`ResourceLimitsMemory` rules
(`pkg/rules/resourceLimits{Cpu,Memory}.go`), verified against the real Go source.

Fires MEDIUM once per missing dimension (CPU, memory), per K8s workload manifest document, when NO
`limits:` block anywhere in the document declares that key as a direct child. See
`agentsec/k8s.py`'s module docstring for the document-scoped precision tradeoff (no per-container
path precision, no PyYAML) — the same tradeoff every sibling `k8s-*` guard in this codebase accepts.
Graded MEDIUM rather than compose's LOW: unlike a single Docker host, an unbounded pod can exhaust
node resources shared with OTHER TENANTS' workloads on the same cluster, not just this app's own
containers.

    resources:
      limits:
        cpu: "500m"       # security: allow-k8s-resource-limits
        memory: "256Mi"
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.k8s import k8s_manifest_documents

from .base import CanaryPlant, Guard, iter_files, pragma_present, read, rel, strip_hash_comments

_PRAGMA = re.compile(r"#\s*security:\s*allow-k8s-resource-limits")

_LIMITS_KEY = re.compile(r"^(?P<indent>[ \t]*)limits:\s*$")
_CPU_KEY = re.compile(r"^\s*cpu:\s*\S")
_MEMORY_KEY = re.compile(r"^\s*memory:\s*\S")

# (yaml key under limits:, rule slug, human name)
_DIMENSIONS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (_CPU_KEY, "cpu-limit-missing", "a CPU limit"),
    (_MEMORY_KEY, "memory-limit-missing", "a memory limit"),
)


def _limits_declares(lines: list[str], key: re.Pattern[str]) -> bool:
    """True if some `limits:` block in the document declares `key` as a direct child line —
    an indentation-scoped walk (mirrors the `add:` list-block walker in
    `k8s_privileged_capabilities.py`, generalized to a plain indented mapping instead of a list)."""
    limits_indent: int | None = None
    for line in lines:
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" \t"))
        if limits_indent is not None and indent <= limits_indent:
            limits_indent = None  # dedented past this limits: block
        m = _LIMITS_KEY.match(line)
        if m:
            limits_indent = len(m.group("indent"))
            continue
        if limits_indent is not None and key.match(line):
            return True
    return False


class K8sResourceLimitsAbsentGuard(Guard):
    id = "k8s-resource-limits-absent"
    title = "Kubernetes container has no CPU or memory resource limit"
    area = "Kubernetes"

    # Canary plant: EXPECTS-ONLY -- no `files`. The shared `k8s-deployment.yaml` base plant (see
    # canary.py) has a `containers:` entry with no `resources:` block at all, so both dimensions
    # fire against it already; the file stays in canary.py's base owned by no single guard (the
    # ownership rule documented on `xxe_safe.py`).
    canary_plant = CanaryPlant(
        expects=frozenset({
            "k8s-resource-limits-absent/cpu-limit-missing",
            "k8s-resource-limits-absent/memory-limit-missing",
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
                for key, slug, human in _DIMENSIONS:
                    if _limits_declares(lines, key):
                        continue
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="medium",
                            title=self.title,
                            location=f"{rel(root, f)}",
                            message=(
                                f"No `resources.limits` block in this manifest declares {human}. "
                                "Kubernetes imposes no cap by default, so a compromised or runaway "
                                "container can consume the whole node's CPU or memory, starving "
                                "every other pod scheduled there."
                            ),
                            remediation=(
                                "Set `resources.limits.cpu` and `resources.limits.memory` on every "
                                "container, sized from the workload's observed steady state. "
                                "Suppress an audited exception with "
                                "`# security: allow-k8s-resource-limits` anywhere in the document."
                            ),
                            rule=f"k8s-resource-limits-absent/{slug}",
                            standards=["OWASP:A05", "CWE-770"],
                        )
                    )
        return out
