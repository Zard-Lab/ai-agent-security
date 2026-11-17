"""Guard: a Kubernetes hostPath volume is mounted into a container without `readOnly: true` (§6c).

A `hostPath` volume gives a container direct access to a path on the NODE's filesystem, not an
isolated, container-scoped filesystem — mounting it without `readOnly: true` means the container can
WRITE to that host path, which a compromised container can use to plant files the node (or another
workload sharing the node) will later read/execute, escape the container's filesystem isolation, or
tamper with node state. This is the GENERAL case; `k8s_docker_sock_mount.py` is a NARROWER, existing
sibling guard scoped ONLY to the specific `/var/run/docker.sock` path (a docker-socket-specific
privilege-escalation vector). This guard is intentionally broader and complements that one rather
than duplicating it: a hostPath mount to `/var/run/docker.sock` without `readOnly: true` legitimately
fires BOTH guards at once — one flags the specific docker-socket escalation, this one flags the
general writable-host-mount hygiene issue. Sourced from kube-linter's `WritableHostMount` template
(`pkg/templates/writablehostmount/template.go`), verified against the real Go source.

Targets the Pod-workload document family (`agentsec.k8s.k8s_manifest_documents()`). Correlates a
`hostPath` volume's `name` (under `spec.volumes[]`) with any `volumeMounts[].name` referencing it, and
fires when a matching mount does not set `readOnly: true` — document-scoped name correlation, not a
full indentation-tree parse (see `agentsec/k8s.py`'s module docstring for the accepted tradeoff).
Deliberately does NOT fire for a `hostPath` volume that is defined but never referenced by any
`volumeMounts[]` (no actual writable exposure without a mount) — a narrower, more precise contract
than `k8s-docker-sock-mount`'s own deliberately conservative "fires even if unused" choice, made
possible here because this guard already has to parse `volumeMounts[]` to check `readOnly` at all.

Fires HIGH once per hostPath volume name found mounted without `readOnly: true` anywhere in the
document. See the module docstring above and `agentsec/k8s.py`'s module docstring for the tradeoffs.

    volumes:
    - name: data
      hostPath:
        path: /var/lib/app/data
    containers:
    - name: app
      volumeMounts:
      - name: data
        mountPath: /data  # security: allow-k8s-hostpath-writable-mount
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.k8s import k8s_manifest_documents

from .base import CanaryPlant, Guard, iter_files, pragma_present, read, rel, strip_hash_comments

_VOLUMES_KEY = re.compile(r"^\s*volumes:\s*$", re.IGNORECASE)
_VOLUME_MOUNTS_KEY = re.compile(r"^\s*volumeMounts:\s*$", re.IGNORECASE)
_LIST_ITEM_NAME = re.compile(r"^\s*-\s*name:\s*['\"]?([\w.-]+)['\"]?\s*(?:#.*)?$", re.IGNORECASE)
_HOSTPATH_KEY = re.compile(r"^\s*hostPath:\s*$", re.IGNORECASE)
_READONLY_TRUE = re.compile(r"^\s*readOnly:\s*true\s*(?:#.*)?$", re.IGNORECASE)
_PRAGMA = re.compile(r"#\s*security:\s*allow-k8s-hostpath-writable-mount")


def _block_ended(line: str, indent: int, block_indent: int) -> bool:
    """True if `line` (at `indent`) dedents out of, or is a sibling key of, a list block opened at
    `block_indent` — the shared end-of-block test both list scanners below use. A block continues
    on any line indented past `block_indent`, or exactly at it if it starts a new `- ` list item."""
    return indent < block_indent or (indent == block_indent and not line.lstrip().startswith("-"))


def _hostpath_volume_names(lines: list[str]) -> set[str]:
    """Names of `spec.volumes[]` entries that carry a nested `hostPath:` key."""
    names: set[str] = set()
    in_block = False
    block_indent = -1
    current_name: str | None = None
    current_is_hostpath = False
    for line in lines:
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        if _VOLUMES_KEY.match(line):
            in_block, block_indent = True, indent
            current_name, current_is_hostpath = None, False
            continue
        if not in_block:
            continue
        if _block_ended(line, indent, block_indent):
            if current_name and current_is_hostpath:
                names.add(current_name)
            in_block = False
            continue
        item = _LIST_ITEM_NAME.match(line)
        if item:
            if current_name and current_is_hostpath:
                names.add(current_name)
            current_name, current_is_hostpath = item.group(1), False
            continue
        if _HOSTPATH_KEY.match(line):
            current_is_hostpath = True
    if in_block and current_name and current_is_hostpath:
        names.add(current_name)
    return names


def _volume_mounts(lines: list[str]) -> list[tuple[str, bool]]:
    """`(mount_name, is_read_only)` for every `volumeMounts[]` item across the document (there can
    be one `volumeMounts:` block per container)."""
    mounts: list[tuple[str, bool]] = []
    in_block = False
    block_indent = -1
    current_name: str | None = None
    current_readonly = False
    for line in lines:
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        if _VOLUME_MOUNTS_KEY.match(line):
            if current_name is not None:
                mounts.append((current_name, current_readonly))
            in_block, block_indent = True, indent
            current_name, current_readonly = None, False
            continue
        if not in_block:
            continue
        if _block_ended(line, indent, block_indent):
            if current_name is not None:
                mounts.append((current_name, current_readonly))
            in_block, current_name = False, None
            continue
        item = _LIST_ITEM_NAME.match(line)
        if item:
            if current_name is not None:
                mounts.append((current_name, current_readonly))
            current_name, current_readonly = item.group(1), False
            continue
        if _READONLY_TRUE.match(line):
            current_readonly = True
    if current_name is not None:
        mounts.append((current_name, current_readonly))
    return mounts


class K8sHostpathWritableMountGuard(Guard):
    id = "k8s-hostpath-writable-mount"
    title = "Kubernetes hostPath volume is mounted without readOnly"
    area = "Kubernetes"

    # k8s-hostpath-writable-mount.yaml: a hostPath volume "data" mounted into a container WITHOUT
    # readOnly: true -> fires. A second hostPath volume "config" mounted WITH readOnly: true must
    # stay silent (proves the readOnly carve-out inside the guard's own plant, not just unit tests).
    canary_plant = CanaryPlant(
        files={
            "k8s-hostpath-writable-mount.yaml": (
                "apiVersion: v1\n"
                "kind: Pod\n"
                "metadata:\n"
                "  name: canary-hostpath-writable\n"
                "spec:\n"
                "  containers:\n"
                "  - name: app\n"
                "    image: canary-app:latest\n"
                "    volumeMounts:\n"
                "    - name: data\n"
                "      mountPath: /data\n"
                "    - name: config\n"
                "      mountPath: /config\n"
                "      readOnly: true\n"
                "  volumes:\n"
                "  - name: data\n"
                "    hostPath:\n"
                "      path: /var/lib/app/data\n"
                "  - name: config\n"
                "    hostPath:\n"
                "      path: /var/lib/app/config\n"
            ),
        },
        expects=frozenset({"k8s-hostpath-writable-mount/data-not-readonly"}),
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
                hostpath_names = _hostpath_volume_names(lines)
                if not hostpath_names:
                    continue
                mounts = _volume_mounts(lines)
                unsafe = {
                    name for name, readonly in mounts if not readonly and name in hostpath_names
                }
                for name in sorted(unsafe):
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="high",
                            title="hostPath volume mounted without readOnly",
                            location=f"{rel(root, f)}",
                            message=(
                                f"The `hostPath` volume `{name}` is mounted into a container "
                                "without `readOnly: true` — the container can WRITE to that path "
                                "on the node's filesystem, not just read it."
                            ),
                            remediation=(
                                "Set `readOnly: true` on the volumeMount unless the workload "
                                "genuinely needs to write to the host path, or replace the "
                                "`hostPath` volume with a workload-scoped alternative (a "
                                "PersistentVolumeClaim, an emptyDir, a ConfigMap/Secret) if write "
                                "access to the node's filesystem isn't actually required. Suppress "
                                "a reviewed, intentional case with "
                                "`# security: allow-k8s-hostpath-writable-mount`."
                            ),
                            rule=f"k8s-hostpath-writable-mount/{name}-not-readonly",
                            standards=["OWASP:A05", "CIS:Kubernetes"],
                        )
                    )
        return out
