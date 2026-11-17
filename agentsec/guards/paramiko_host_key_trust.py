"""Guard: paramiko SSH client implicitly trusts the server's host key (checklist §2a, new item).

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname, username=user, password=pw)

`AutoAddPolicy` (and its noisier sibling `WarningPolicy`) accepts and stores ANY
server's host key on first connect, with no verification against a known-hosts list.
An attacker who can intercept the connection (DNS spoofing, ARP poisoning, a
compromised network path) can MITM the SSH session entirely undetected. CWE-322
(Key Exchange without Entity Authentication), OWASP:A02 (Cryptographic Failures).

Fires HIGH when `set_missing_host_key_policy(` is called with `AutoAddPolicy` or
`WarningPolicy` as the argument (module-qualified or bare, e.g.
`paramiko.AutoAddPolicy()`, `paramiko.client.AutoAddPolicy()`, or a bare
`AutoAddPolicy()` after `from paramiko import AutoAddPolicy`).

Suppress an audited case (e.g. a known-closed lab network) with:

    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # security: allow-paramiko-auto-add
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    pragma_line_set,
    python_scan_dirs,
    read,
    rel,
    strip_python_strings,
)

_HOST_KEY_POLICY_CALL = re.compile(r"\bset_missing_host_key_policy\s*\(")
_INSECURE_POLICY = re.compile(r"\b(?:AutoAddPolicy|WarningPolicy)\b")
_PRAGMA = re.compile(r"#\s*security:\s*allow-paramiko-auto-add")

_STANDARDS = ["OWASP:A02", "CWE-322"]


class ParamikoHostKeyTrustGuard(Guard):
    id = "paramiko-host-key-trust"
    title = "Paramiko SSH client implicitly trusts the server's host key"
    area = "Server hardening"

    # set_missing_host_key_policy(paramiko.AutoAddPolicy()) -> fires
    # paramiko-host-key-trust/implicit-trust-policy (HIGH).
    canary_plant = CanaryPlant(
        files={
            "ssh_client.py": (
                "import paramiko\n"
                "\n"
                "\n"
                "def connect_remote(hostname: str) -> paramiko.SSHClient:\n"
                "    client = paramiko.SSHClient()\n"
                "    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"
                "    return client\n"
            ),
        },
        expects=frozenset({
            "paramiko-host-key-trust/implicit-trust-policy",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = strip_python_strings(read(f), filename=f)
        # The pragma counts only as a real comment on the line, never quoted in a string there (#1040),
        # numbered on the text walked below (a form feed in a docstring shifts the raw count, #1132).
        pragmas = pragma_line_set(_PRAGMA, text, dialect="python")
        for i, line in enumerate(text.splitlines(), start=1):
            if i in pragmas:
                continue
            if _HOST_KEY_POLICY_CALL.search(line) and _INSECURE_POLICY.search(line):
                out.append(self._finding(root, f, i))
        return out

    def _finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=(
                "set_missing_host_key_policy() is set to AutoAddPolicy/WarningPolicy, "
                "which accepts and stores ANY server's host key with no verification. "
                "An attacker who intercepts the connection can MITM the SSH session "
                "undetected."
            ),
            remediation=(
                "Use paramiko.RejectPolicy() (the default) or load and verify a "
                "known-hosts file with client.load_system_host_keys() / "
                "load_host_keys() instead of auto-trusting unknown hosts."
            ),
            rule="paramiko-host-key-trust/implicit-trust-policy",
            standards=list(_STANDARDS),
        )
