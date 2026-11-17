"""Guard: a Kubernetes resource has no explicit non-default namespace (§6c).

    metadata:
      name: app
      # no namespace: key -> the API server places this object in "default"

A resource applied with no `metadata.namespace` lands in the `default` namespace; one set to
`namespace: default` lands there explicitly. By convention, most clusters give `default` no
RBAC/NetworkPolicy isolation beyond whatever cluster-wide policy exists — it is the namespace every
`kubectl apply` with no `-n` flag lands in, so it tends to accumulate a mix of unrelated, ad-hoc
workloads with no scoped RBAC `RoleBinding` or `NetworkPolicy` drawing a boundary around them.
CWE-284 (Improper Access Control), OWASP:A05.

**Deliberately the softest signal in this guard family.** Many small clusters and local/dev setups
legitimately run everything in `default` with no ill effect, and a real production concern (RBAC
scoping, network segmentation) is a property of the CLUSTER's namespace configuration, not something
this guard can see from the manifest alone — it can only see that no namespace boundary was even
requested. Graded LOW (not the unscored default a stricter read of the source material would apply)
specifically so it reads as a hygiene nudge, not an alarm competing with a real proven-impact finding
for "fix these first" attention.

Fires LOW once per K8s workload manifest document (Pod/Deployment/StatefulSet/DaemonSet/Job/CronJob/
ReplicaSet) whose OWN top-level `metadata` has no `namespace:` key (implicit `default`), or an
explicit `namespace: default`. A `spec.template.metadata` (the pod-template metadata nested inside a
Deployment/StatefulSet/etc — which cannot set its own namespace; it always inherits the parent
object's) is not considered — only the document's own top-level metadata block. See
`agentsec/k8s.py`'s module docstring for the document-scoped precision tradeoff.

    metadata:
      name: app
      namespace: payments  # security: allow-k8s-default-namespace
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.k8s import k8s_manifest_documents

from .base import CanaryPlant, Guard, iter_files, pragma_present, read, rel, strip_hash_comments

_PRAGMA = re.compile(r"#\s*security:\s*allow-k8s-default-namespace")

_TOP_LEVEL_METADATA = re.compile(r"^metadata:\s*$")
_NAMESPACE_ATTR = re.compile(r"^\s*namespace:\s*(?P<val>\S.*)$")

_STANDARDS = ["OWASP:A05", "CWE-284"]


def _top_level_namespace(lines: list[str]) -> str | None:
    """The document's OWN top-level `metadata.namespace` value (quotes stripped), or `None` if
    `metadata:` (indent 0) has no `namespace:` child. A nested `spec.template.metadata` is never
    considered -- only a line with ZERO leading whitespace can open the document's own metadata
    block, since `apiVersion`/`kind`/`metadata`/`spec` are always top-level keys."""
    in_metadata = False
    for line in lines:
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" \t"))
        if in_metadata and indent == 0:
            in_metadata = False
        if indent == 0 and _TOP_LEVEL_METADATA.match(line):
            in_metadata = True
            continue
        if in_metadata:
            m = _NAMESPACE_ATTR.match(line)
            if m:
                return m.group("val").strip().strip("'\"")
    return None


class K8sDefaultNamespaceGuard(Guard):
    id = "k8s-default-namespace"
    title = "Kubernetes resource has no namespace isolation (uses the default namespace)"
    area = "Kubernetes"

    # Canary plant: EXPECTS-ONLY -- no `files`. The shared `k8s-deployment.yaml` base plant (see
    # canary.py) has a top-level `metadata:` block with no `namespace:` key at all, so this fires
    # already; the file stays in canary.py's base owned by no single guard (the ownership rule
    # documented on `xxe_safe.py`).
    canary_plant = CanaryPlant(
        expects=frozenset({"k8s-default-namespace/namespace-not-set"}),
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
                namespace = _top_level_namespace(lines)
                if namespace is None:
                    out.append(self._finding(root, f, kind="namespace-not-set"))
                elif namespace == "default":
                    out.append(self._finding(root, f, kind="namespace-explicit-default"))
        return out

    def _finding(self, root: Path, f: Path, *, kind: str) -> Finding:
        if kind == "namespace-not-set":
            message = (
                "This manifest sets no `metadata.namespace` — the object lands in the `default` "
                "namespace, which by convention carries no RBAC/NetworkPolicy isolation beyond "
                "whatever cluster-wide policy exists."
            )
        else:
            message = (
                "This manifest explicitly sets `namespace: default` — the `default` namespace "
                "carries no RBAC/NetworkPolicy isolation by convention beyond whatever cluster-"
                "wide policy exists."
            )
        return Finding(
            check_id=self.id,
            severity="low",
            title=self.title,
            location=f"{rel(root, f)}",
            message=message,
            remediation=(
                "Set `metadata.namespace` to a dedicated, purpose-named namespace (e.g. `payments`, "
                "`agent-runtime`) and scope RBAC `RoleBinding`s / `NetworkPolicy` to it. Suppress a "
                "reviewed, intentional case (e.g. a genuinely single-tenant local/dev cluster) with "
                "`# security: allow-k8s-default-namespace`."
            ),
            rule=f"k8s-default-namespace/{kind}",
            standards=list(_STANDARDS),
        )
