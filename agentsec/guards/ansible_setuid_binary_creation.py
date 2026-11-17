"""Guard: Ansible task creates a setuid binary (checklist §2b).

A task that runs `chmod 4755` (or any octal mode with the setuid bit set — a leading
4/5/6/7 in a 4-digit octal — or the symbolic `u+s`) on a binary creates an enduring
local-privilege-escalation surface: any local user who can execute that binary runs
it with the file owner's (often root's) privileges. CWE-250 (Execution with
Unnecessary Privileges), CWE-732 (Incorrect Permission Assignment for Critical
Resource).

Sourced from `cpeoples/ansible-security-scanner`'s `privilege_escalation.yml` rule
`setuid_binary_creation`, verified against real fetched source. The regex requires
an actual setuid octal digit or the symbolic form — a benign `chmod 0640` (no `4`
leading digit) does not match.

Fires CRITICAL per match:

    - name: install helper with setuid
      ansible.builtin.file:
        path: /usr/local/bin/helper
        mode: '4755'  # security: allow-ansible-setuid-binary-creation
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
    pragma_present,
    read,
    rel,
    strip_hash_comments,
)

_SUFFIXES = (".yml", ".yaml")
_PRAGMA = "security: allow-ansible-setuid-binary-creation"
_PATTERN = re.compile(r"chmod\s+(?:0?[4567][0-7]{3}|u\+s)\b|mode\s*:\s*['\"]?0?[4567][0-7]{3}['\"]?")


class AnsibleSetuidBinaryCreationGuard(Guard):
    id = "ansible-setuid-binary-creation"
    title = "Ansible task creates a setuid binary"
    area = "Server hardening"

    # playbook_setuid.yml: chmod 4755 -> fires ansible-setuid-binary-creation.
    canary_plant = CanaryPlant(
        files={
            "playbook_setuid.yml": (
                "- hosts: all\n"
                "  tasks:\n"
                "    - name: install helper with setuid\n"
                "      shell: chmod 4755 /usr/local/bin/helper\n"
            ),
        },
        expects=frozenset({"ansible-setuid-binary-creation/setuid-bit-set"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "ansible" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect="yaml"):
                continue
            code = strip_hash_comments(text)
            m = _PATTERN.search(code)
            if not m:
                continue
            line = code.count("\n", 0, m.start()) + 1
            out.append(
                Finding(
                    check_id=self.id,
                    severity="critical",
                    title=self.title,
                    location=f"{rel(root, f)}:{line}",
                    message=(
                        "This task sets the setuid bit on a file (a leading 4/5/6/7 octal "
                        "digit or `u+s`). Any local user who can execute this binary runs "
                        "it with the file owner's privileges — an enduring "
                        "privilege-escalation surface."
                    ),
                    remediation=(
                        "Prefer filesystem capabilities (`setcap cap_net_bind_service+ep`) "
                        "or a systemd unit with `User=`/`AmbientCapabilities=` instead of "
                        "the setuid bit."
                    ),
                    rule="ansible-setuid-binary-creation/setuid-bit-set",
                    standards=["CWE-250", "CWE-732"],
                )
            )
        return out
