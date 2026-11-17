"""Guard: a Kubernetes workload doesn't explicitly disable privilege escalation (§6c).

`securityContext.allowPrivilegeEscalation` lets a process gain more privileges than its parent —
most commonly via a setuid/setgid binary or a file capability inside the container image. Combined
with a compromised container (prompt-injected agent tool execution, a supply-chain-compromised base
image, an app-level RCE), this turns a limited-privilege foothold into a straightforward local
escalation, undermining the same isolation boundary `k8s-privileged-container` protects — just via a
narrower, single-process path instead of full privileged mode. Kubernetes defaults this field to
*allowed* whenever it is omitted entirely — nobody sets it to `true` on purpose, they just never
think about it, which makes omission the far more common real-world misconfiguration, not the
explicit-`true` case. Sourced from checkov's `AllowPrivilegeEscalation` check (`CKV_K8S_20`,
`checkov/kubernetes/checks/resource/base_spec/AllowPrivilegeEscalation.py`), which fires unless
`securityContext.allowPrivilegeEscalation` is explicitly `False` — the same "safe only if explicitly
disabled" direction `k8s-run-as-non-root` already uses for its own field.

Unlike `runAsNonRoot` (which kubesec checks at BOTH the pod-spec and container level, because a
container-level override always wins), `allowPrivilegeEscalation` is a **container-level-only** field
(`v1.SecurityContext`, NOT `v1.PodSecurityContext`) — the kubelet does not inherit it from the pod's
security context. A `securityContext.allowPrivilegeEscalation: false` sitting at the *pod-spec* level
is inert: it silences nothing and every container still defaults to escalation-allowed. So only a
**container-level** `false` counts as a valid suppression here — a pod-spec-level one is ignored
(else an inert field would create a false negative for exactly the risk this guard exists to catch).

Fires HIGH once per K8s workload manifest document (Pod/Deployment/StatefulSet/DaemonSet/Job/
CronJob/ReplicaSet) that does NOT contain a **container-level** `allowPrivilegeEscalation: false`. A
container-level `securityContext` is nested deeper than the pod's `containers:` key (it lives inside
a container list item); the pod-spec `securityContext` sits at the same indent as `containers:` — a
lightweight indentation check (no PyYAML) that distinguishes the two. See `agentsec/k8s.py`'s module
docstring for the remaining document-scoped precision tradeoff (a single container-level `false`
suppresses the whole document, even a sibling container that omits the field — no per-container path).

    securityContext:
      allowPrivilegeEscalation: false
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.k8s import k8s_manifest_documents

from .base import CanaryPlant, Guard, iter_files, pragma_present, read, rel, strip_hash_comments

# Kubernetes parses manifests with a YAML 1.1 boolean resolver, so `no`/`off`/`n` are all false and
# a container hardened that way is genuinely hardened — matching only the literal `false` fired on
# correct config.
_FALSEY = r"(?:false|no|off|n)"
_ALLOW_ESCALATION_FALSE = re.compile(
    rf"^(\s*)allowPrivilegeEscalation:\s*{_FALSEY}\s*$", re.IGNORECASE
)
# The single-line flow-style form: `securityContext: {allowPrivilegeEscalation: false, ...}`. The
# field is not alone on its own line, so `_ALLOW_ESCALATION_FALSE` can't see it and a correctly
# hardened container fired. Captured indent is the `securityContext:` key's own, which is what the
# container-scope test needs.
_SECURITY_CONTEXT_INLINE_FALSE = re.compile(
    rf"^(\s*)securityContext:\s*\{{[^}}]*\ballowPrivilegeEscalation:\s*{_FALSEY}\s*[,}}]",
    re.IGNORECASE,
)
# The trailing `\{?` accepts a multi-line flow-style block opener (`securityContext: {`) so a
# container-level `false` nested inside one is still recognized as container-scoped, not a false
# positive.
_SECURITY_CONTEXT = re.compile(r"^(\s*)securityContext:\s*\{?\s*$", re.IGNORECASE)
# A list item under `containers:`. A real container-level `securityContext` sits inside one of
# these; a decoy key that merely *looks* like a container list (`metadata.annotations.containers:`)
# has no dash item between it and the field, which is what tells the two apart.
_LIST_ITEM = re.compile(r"^(\s*)-\s")
# The pod's container list. `initContainers`/`ephemeralContainers` also carry a per-container
# `securityContext`, so they anchor the container-level scope just like `containers` does.
_CONTAINERS_KEY = re.compile(r"^(\s*)(?:init|ephemeral)?[cC]ontainers:\s*$")
_PRAGMA = re.compile(r"#\s*security:\s*allow-k8s-allow-privilege-escalation")


def _enclosing_block_indent(lines: list[str], idx: int, field_indent: int) -> int | None:
    """Indent of the block key that directly encloses `lines[idx]` (the nearest preceding non-blank
    line indented less than the field), or None if it isn't a `securityContext:` block. Used to tell
    a container-level `securityContext` from a pod-spec one without a full YAML parser."""
    for j in range(idx - 1, -1, -1):
        prev = lines[j]
        if not prev.strip():
            continue
        indent = len(prev) - len(prev.lstrip())
        if indent < field_indent:
            return indent if _SECURITY_CONTEXT.match(prev) else None
    return None


def _has_container_level_false(lines: list[str]) -> bool:
    """True if a `allowPrivilegeEscalation: false` is scoped to a *container* securityContext (the
    only place the kubelet honors it). A container-level `securityContext` is nested deeper than the
    pod's `containers:` key; a pod-spec-level one sits at the same indent (a sibling of it)."""
    if not any(_CONTAINERS_KEY.match(line) for line in lines):
        # No `containers:`/`initContainers:` anchor in this document (e.g. a Kustomize strategic-
        # merge patch fragment that touches only the pod `securityContext`). Without a container
        # scope to compare against we can't confirm a `false` is container-level — and this field is
        # inert at pod-spec level — so fail OPEN toward firing rather than accept an unprovable
        # suppression. (A pod-spec-only `false` here would otherwise be waved through as the exact
        # false negative this guard exists to catch.)
        return False
    for i, line in enumerate(lines):
        inline = _SECURITY_CONTEXT_INLINE_FALSE.match(line)
        if inline:
            # The flow-style form carries its own `securityContext:` key, so that line IS the block.
            if _is_container_scoped(lines, i, len(inline.group(1))):
                return True
            continue
        fm = _ALLOW_ESCALATION_FALSE.match(line)
        if not fm:
            continue
        sc_indent = _enclosing_block_indent(lines, i, len(fm.group(1)))
        if sc_indent is not None and _is_container_scoped(lines, i, sc_indent):
            return True
    return False


def _is_container_scoped(lines: list[str], idx: int, sc_indent: int) -> bool:
    """True if the `securityContext` block at `sc_indent` (enclosing `lines[idx]`) belongs to a
    *container* rather than the pod spec.

    Walks back to the nearest `containers:`-shaped key shallower than the block, then requires a
    list-item dash between that key and the block. Comparing against the shallowest such key in the
    document instead would let an unrelated key that merely ends in `containers:` — e.g.
    `metadata.annotations.containers:` — vouch for a pod-spec-level `false` that the kubelet ignores,
    re-opening the false negative this scoping exists to close."""
    for j in range(idx - 1, -1, -1):
        cm = _CONTAINERS_KEY.match(lines[j])
        if not cm or len(cm.group(1)) >= sc_indent:
            continue
        containers_indent = len(cm.group(1))
        # A block-sequence dash is conventionally written at the SAME indent as its key
        # (`containers:` then `- name: app`), so this is `>=`, not `>`.
        return any(
            (lm := _LIST_ITEM.match(lines[k])) is not None
            and len(lm.group(1)) >= containers_indent
            for k in range(j + 1, idx + 1)
        )
    return False


class K8sAllowPrivilegeEscalationGuard(Guard):
    id = "k8s-allow-privilege-escalation"
    title = "Kubernetes workload doesn't explicitly disable privilege escalation"
    area = "Kubernetes"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `k8s-deployment.yaml`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # k8s-deployment.yaml: securityContext.allowPrivilegeEscalation: true ->
    # not-explicitly-disabled (now fires on omission too, not just explicit true).
    canary_plant = CanaryPlant(expects=frozenset({"k8s-allow-privilege-escalation/not-explicitly-disabled"}))

    def applies(self, profile: StackProfile) -> bool:
        return "k8s" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".yaml", ".yml")):
            for doc in k8s_manifest_documents(read(f)):
                if pragma_present(_PRAGMA, doc, dialect="yaml"):
                    continue
                lines = strip_hash_comments(doc).splitlines()
                if _has_container_level_false(lines):
                    continue
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title="Workload doesn't explicitly disable privilege escalation",
                        location=f"{rel(root, f)}",
                        message=(
                            "No container in this manifest sets `securityContext."
                            "allowPrivilegeEscalation: false`. Kubernetes defaults this field to "
                            "allowed when it's omitted, letting a process gain more privileges than "
                            "its parent (e.g. via a setuid binary in the image) — a narrower path to "
                            "the same host-compromise risk as full privileged mode if the container "
                            "is ever compromised. Note it is a container-level field: a `false` on "
                            "the pod-spec `securityContext` is inert and does not count."
                        ),
                        remediation=(
                            "Set `allowPrivilegeEscalation: false` on each container's "
                            "`securityContext` unless a specific process genuinely needs to escalate. "
                            "Suppress an intentional, reviewed case with "
                            "`# security: allow-k8s-allow-privilege-escalation`."
                        ),
                        rule="k8s-allow-privilege-escalation/not-explicitly-disabled",
                        standards=["OWASP:A05", "CIS:Kubernetes"],
                    )
                )
        return out
