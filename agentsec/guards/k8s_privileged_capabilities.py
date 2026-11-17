"""Guard: a Kubernetes container adds a dangerous Linux capability (§6c).

`securityContext.capabilities.add` granting `SYS_ADMIN` or `ALL` hands the container root-equivalent
kernel privileges — `SYS_ADMIN` alone is described by the kernel docs as "a huge hammer" covering
dozens of privileged operations (mount, ptrace-adjacent syscalls, kernel keyring, more), and `ALL`
is every capability at once. Either turns a container compromise into a straightforward host
escape. Sourced from kubesec's `CapSysAdmin` rule (`pkg/rules/capSysAdmin.go`), verified against the
real Go source; the `ALL` case is the same shape applied to the broader keyword (kubesec's own
`CapDropAll` rule confirms `ALL` is a recognized capabilities-list keyword, just checked on the
`drop` side there — this guard checks the more direct violation of the same keyword on `add`).

Deliberately does NOT flag a missing `capabilities.drop: [ALL]` (kubesec's `CapDropAll`/`CapDropAny`
checks) — most real manifests simply don't set a `capabilities` block at all, and requiring one
would be a "must configure this every time" precision that generates significant noise on ordinary,
non-dangerous manifests. This guard only fires on the unambiguous case: a capability explicitly
*added*.

Fires CRITICAL once per K8s workload manifest document containing `capabilities.add` with `SYS_ADMIN`
or `ALL`. See `agentsec/k8s.py`'s module docstring for the document-scoped precision tradeoff.

    securityContext:
      capabilities:
        add: ["SYS_ADMIN"]  # security: allow-k8s-privileged-capabilities
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.k8s import k8s_manifest_documents

from .base import CanaryPlant, Guard, iter_files, pragma_present, read, rel, strip_hash_comments

# A `add:` block/inline-list value containing the keyword, e.g. `add: ["SYS_ADMIN"]` or
# `add:\n  - SYS_ADMIN`. Scoped to lines that are plausibly inside a capabilities `add` context
# by requiring the keyword to appear on the `add:` line itself or a following list-item line —
# approximated here (document-scoped, no indentation tree) by just requiring both the `add:`
# key and the keyword to co-occur in the document; see module docstring for the tradeoff.
_ADD_KEY = re.compile(r"^\s*add:\s*(.*)$", re.IGNORECASE)
_LIST_ITEM = re.compile(r"^\s*-\s*['\"]?(\w+)['\"]?\s*$")
_PRAGMA = re.compile(r"#\s*security:\s*allow-k8s-privileged-capabilities")

_DANGEROUS = ("SYS_ADMIN", "ALL")


def _added_dangerous_caps(lines: list[str]) -> set[str]:
    """Capabilities in `_DANGEROUS` found on an `add:` line (inline list) or a `- NAME` list-item
    line immediately following an `add:` block opener."""
    found: set[str] = set()
    in_add_block = False
    for line in lines:
        m = _ADD_KEY.match(line)
        if m:
            inline = m.group(1)
            # Split the inline list on commas and whole-match each stripped entry (mirrors the
            # `- NAME` list-item branch's `\w+` anchoring), so a capability name that merely
            # *contains* a dangerous keyword — `metrics-wallboard`, `install-all` — is never a
            # dangerous cap. Only an exact `SYS_ADMIN`/`ALL` entry fires. (Comments are already
            # stripped by the caller, so `inline` is a clean list literal.)
            for raw in inline.strip().strip("[]").split(","):
                entry = raw.strip().strip("\"'").upper()
                if entry in _DANGEROUS:
                    found.add(entry)
            in_add_block = not inline.strip()  # `add:` with nothing after -> block list follows
            continue
        if in_add_block:
            if not line.strip():
                # A blank line, or a comment-only line (already blanked to whitespace by
                # strip_hash_comments), does not end the list block (#422 S10); the seccomp
                # sibling guard skips these the same way.
                continue
            item = _LIST_ITEM.match(line)
            if item:
                name = item.group(1).upper()
                if name in _DANGEROUS:
                    found.add(name)
                continue
            in_add_block = False  # dedented past the list
    return found


class K8sPrivilegedCapabilitiesGuard(Guard):
    id = "k8s-privileged-capabilities"
    title = "Kubernetes container adds a dangerous Linux capability"
    area = "Kubernetes"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `k8s-deployment.yaml`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # k8s-deployment.yaml: securityContext.capabilities.add: [SYS_ADMIN] -> sys-admin-added.
    canary_plant = CanaryPlant(expects=frozenset({"k8s-privileged-capabilities/sys-admin-added"}))

    def applies(self, profile: StackProfile) -> bool:
        return "k8s" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".yaml", ".yml")):
            for doc in k8s_manifest_documents(read(f)):
                if pragma_present(_PRAGMA, doc, dialect="yaml"):
                    continue
                lines = strip_hash_comments(doc).splitlines()
                for cap in sorted(_added_dangerous_caps(lines)):
                    slug = "sys-admin-added" if cap == "SYS_ADMIN" else "all-capabilities-added"
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="critical",
                            title=f"Container adds the {cap} capability",
                            location=f"{rel(root, f)}",
                            message=(
                                f"`securityContext.capabilities.add` grants `{cap}` — "
                                + (
                                    "a root-equivalent capability covering mount, ptrace-adjacent "
                                    "syscalls, kernel keyring, and dozens of other privileged "
                                    "operations."
                                    if cap == "SYS_ADMIN"
                                    else "every Linux capability at once, equivalent to running "
                                    "the container as root with no capability restriction."
                                )
                            ),
                            remediation=(
                                f"Remove `{cap}` from `capabilities.add`. Grant only the specific, "
                                "narrow capability the workload actually needs (e.g. "
                                "`NET_BIND_SERVICE` to bind a low port), and pair it with "
                                "`capabilities.drop: [ALL]` as the baseline. Suppress a reviewed, "
                                "intentional case with "
                                "`# security: allow-k8s-privileged-capabilities`."
                            ),
                            rule=f"k8s-privileged-capabilities/{slug}",
                            standards=["OWASP:A05", "CIS:Kubernetes"],
                        )
                    )
        return out
