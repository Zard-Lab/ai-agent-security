"""Guard: Ansible task grants blanket sudo NOPASSWD:ALL (checklist §2b).

A task that writes `NOPASSWD: ALL` (or the sudoers line-form `%group ALL=(ALL)
NOPASSWD:ALL`) into `/etc/sudoers` or a `sudoers.d/` drop-in grants a user/group
passwordless root access to EVERY command — no scoping to the specific binaries the
automation actually needs. CWE-250 (Execution with Unnecessary Privileges), CWE-269
(Improper Privilege Management), OWASP:A04.

Sourced from `cpeoples/ansible-security-scanner`'s `privilege_escalation.yml` rule
`sudo_nopasswd`, verified against real fetched source.

Fires HIGH per match:

    - name: allow bitcoin group passwordless sudo
      lineinfile:
        dest: /etc/sudoers
        line: '%bitcoin ALL=(ALL) NOPASSWD:ALL'  # security: allow-ansible-sudo-nopasswd
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
_PRAGMA = "security: allow-ansible-sudo-nopasswd"
# Only BLANKET `NOPASSWD: ALL` fires. The dropped `sudoers.*NOPASSWD` branch required no `ALL`, so
# it flagged ANY line where "sudoers" preceded "NOPASSWD" -- including a properly SCOPED
# `/etc/sudoers.d/` drop-in (`deploy ALL=(root) NOPASSWD: /usr/bin/systemctl ...`), which is the
# exact remediation this guard recommends. A scoped NOPASSWD is the fix, not the finding (#408 #7).
_PATTERN = re.compile(r"NOPASSWD:\s*ALL")


class AnsibleSudoNopasswdGuard(Guard):
    id = "ansible-sudo-nopasswd"
    title = "Ansible task grants blanket sudo NOPASSWD:ALL"
    area = "Server hardening"

    # playbook_sudoers.yml: NOPASSWD:ALL -> fires ansible-sudo-nopasswd.
    canary_plant = CanaryPlant(
        files={
            "playbook_sudoers.yml": (
                "- hosts: all\n"
                "  tasks:\n"
                "    - name: allow bitcoin group passwordless sudo\n"
                "      lineinfile:\n"
                "        dest: /etc/sudoers\n"
                "        line: '%bitcoin ALL=(ALL) NOPASSWD:ALL'\n"
            ),
        },
        expects=frozenset({"ansible-sudo-nopasswd/blanket-nopasswd-all"}),
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
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}:{line}",
                    message=(
                        "This task grants blanket passwordless sudo (NOPASSWD:ALL) — the "
                        "user or group gets root access to every command, not just the "
                        "ones the automation actually needs."
                    ),
                    remediation=(
                        "Grant NOPASSWD only on the specific command(s) the automation "
                        "needs (e.g. `/usr/sbin/systemctl restart nginx`) via a scoped "
                        "drop-in under /etc/sudoers.d/, validated with `visudo -cf`."
                    ),
                    rule="ansible-sudo-nopasswd/blanket-nopasswd-all",
                    standards=["OWASP:A04", "CWE-250", "CWE-269"],
                )
            )
        return out
