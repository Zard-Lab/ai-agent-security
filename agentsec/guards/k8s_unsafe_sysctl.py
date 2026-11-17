"""Guard: a Kubernetes workload sets an unsafe kernel sysctl (§6c).

A Pod's `securityContext.sysctls[]` entry sets a kernel parameter on the node's kernel namespace the
Pod shares. Kubernetes itself splits sysctls into "safe" (namespaced per-Pod, cannot affect other
Pods or the node — a small, explicitly documented allowlist) and "unsafe" (everything else, which is
why the kubelet requires an explicit `--allowed-unsafe-sysctls` opt-in to run them at all). Setting
an unsafe sysctl from application manifests bypasses that node-operator gate's intent and can affect
node stability or other workloads sharing the kernel namespace. Sourced from kube-linter's `Sysctl`
template (`pkg/templates/sysctl/template.go`); the exact default unsafe-list kube-linter ships was
not independently re-verified this pass (flagged as such in the research this guard was built from),
so this guard uses its OWN curated, defensible unsafe-prefix list documented below rather than
claiming parity with kube-linter's defaults.

Curated unsafe-prefix list: `kernel.` and `net.` — the two prefixes this candidate was scoped to.
Both are excluded from Kubernetes' own "safe sysctls" allowlist by default; this guard reproduces
that allowlist as `_SAFE_SYSCTLS` so the small set of genuinely safe, commonly-used `net.*`/`kernel.*`
sysctls (`net.ipv4.tcp_syncookies`, `kernel.shm_rmid_forced`, etc.) does not fire. See "Detection
design" for the full allowlist and "What this guard does NOT prove" for what's deliberately left out
(`vm.*`, `fs.*`, and any sysctl outside these two prefixes).

Targets the Pod-workload document family (`agentsec.k8s.k8s_manifest_documents()`), the same
recognizer `k8s_docker_sock_mount.py`/`k8s_privileged_capabilities.py` use — `sysctls` is a
`PodSecurityContext` field in the real Kubernetes API (pod-level, not per-container), but this guard
scans for the pattern's presence anywhere in the matched document, the same document-scoped
precision tradeoff every guard in this module accepts (see `agentsec/k8s.py`'s module docstring).

Fires HIGH once per unsafe sysctl name found. See the module docstring above for the tradeoff.

    securityContext:
      sysctls:
      - name: kernel.msgmax   # security: allow-k8s-unsafe-sysctl
        value: "65536"
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.k8s import k8s_manifest_documents

from .base import CanaryPlant, Guard, iter_files, pragma_present, read, rel, strip_hash_comments

_SYSCTLS_KEY = re.compile(r"^\s*sysctls:\s*$", re.IGNORECASE)
_LIST_ITEM_NAME = re.compile(r"^\s*-\s*name:\s*['\"]?([\w.-]+)['\"]?\s*(?:#.*)?$", re.IGNORECASE)
# A Kubernetes `Sysctl` object has exactly two fields (`name`, `value`) — a `value:` line
# immediately following a `- name:` list item is that same item's other field, not a new item or a
# dedent, so it must not end the `sysctls:` block.
_VALUE_LINE = re.compile(r"^\s*value:\s*.*$", re.IGNORECASE)
_PRAGMA = re.compile(r"#\s*security:\s*allow-k8s-unsafe-sysctl")

# Curated, not exhaustive -- see module docstring.
_UNSAFE_PREFIXES = ("kernel.", "net.")

# Kubernetes' own documented "safe" sysctls (namespaced per-Pod; enabled by default with no
# kubelet flag). These fall under the `_UNSAFE_PREFIXES` above by string prefix alone, so they are
# carved out explicitly to avoid flagging the most common legitimate sysctl usage.
_SAFE_SYSCTLS = frozenset(
    {
        "kernel.shm_rmid_forced",
        "net.ipv4.ip_local_port_range",
        "net.ipv4.tcp_syncookies",
        "net.ipv4.ping_group_range",
        "net.ipv4.ip_unprivileged_port_start",
    }
)


def _unsafe_sysctl_names(lines: list[str]) -> list[str]:
    """Sysctl names set under a `sysctls:` list in `lines` that match an unsafe prefix and are not
    in the Kubernetes-documented safe-sysctls allowlist."""
    found: list[str] = []
    in_sysctls = False
    for line in lines:
        if _SYSCTLS_KEY.match(line):
            in_sysctls = True
            continue
        if not in_sysctls:
            continue
        if not line.strip():
            continue
        item = _LIST_ITEM_NAME.match(line)
        if item:
            name = item.group(1)
            if name not in _SAFE_SYSCTLS and any(name.startswith(p) for p in _UNSAFE_PREFIXES):
                found.append(name)
            continue
        if _VALUE_LINE.match(line):
            continue
        in_sysctls = False  # dedented past the list (or an unrelated key) -- block ends
    return found


class K8sUnsafeSysctlGuard(Guard):
    id = "k8s-unsafe-sysctl"
    title = "Kubernetes workload sets an unsafe kernel sysctl"
    area = "Kubernetes"

    # k8s-unsafe-sysctl.yaml: a Pod setting sysctls kernel.msgmax (unsafe) and the documented-safe
    # net.ipv4.tcp_syncookies (must stay silent, proving the allowlist carve-out works even inside
    # the guard's OWN canary plant, not just its unit tests) -> one finding, kernel.msgmax only.
    canary_plant = CanaryPlant(
        files={
            "k8s-unsafe-sysctl.yaml": (
                "apiVersion: v1\n"
                "kind: Pod\n"
                "metadata:\n"
                "  name: canary-sysctl\n"
                "spec:\n"
                "  securityContext:\n"
                "    sysctls:\n"
                "    - name: kernel.msgmax\n"
                '      value: "65536"\n'
                "    - name: net.ipv4.tcp_syncookies\n"
                '      value: "1"\n'
                "  containers:\n"
                "  - name: app\n"
                "    image: canary-app:latest\n"
            ),
        },
        expects=frozenset({"k8s-unsafe-sysctl/kernel.msgmax"}),
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
                for name in _unsafe_sysctl_names(lines):
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="high",
                            title=f"Workload sets the unsafe sysctl `{name}`",
                            location=f"{rel(root, f)}",
                            message=(
                                f"`securityContext.sysctls` sets `{name}` — this is not one of "
                                "Kubernetes' documented namespaced-safe sysctls, so applying it "
                                "requires the node's kubelet to opt in via "
                                "`--allowed-unsafe-sysctls` and can affect node stability or other "
                                "workloads sharing the same kernel namespace."
                            ),
                            remediation=(
                                "Remove the sysctl unless the node operator has deliberately "
                                "allow-listed it, or replace it with one of Kubernetes' documented "
                                "safe sysctls if the goal can be met that way. Suppress a reviewed, "
                                "intentional case with `# security: allow-k8s-unsafe-sysctl`."
                            ),
                            rule=f"k8s-unsafe-sysctl/{name}",
                            standards=["OWASP:A05", "CIS:Kubernetes"],
                        )
                    )
        return out
