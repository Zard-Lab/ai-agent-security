"""Guard: ANSIBLE_HOST_KEY_CHECKING disabled — SSH MitM enabler (checklist §8).

Setting `ANSIBLE_HOST_KEY_CHECKING=False` (or `=0`/`=no`) — in an `environment:`
block, `group_vars/all.yml`, a Dockerfile `ENV`, or a CI pipeline env map — disables
SSH host-key verification for the ENTIRE Ansible control path. Every connection from
the controller to a managed node becomes MitM-vulnerable: an attacker on-path (rogue
Wi-Fi, a compromised jump host, a TLS-intercepting proxy) can intercept the
`ansible` -> managed-node connection and steal root credentials or inject commands.
CWE-295 (Improper Certificate Validation), CWE-300 (Channel Accessible by
Non-Endpoint), CWE-322 (Key Exchange without Entity Authentication), OWASP:A02/A07.

Sourced from `cpeoples/ansible-security-scanner`'s `ansible_hygiene.yml` rule
`ansible_host_key_checking_false_in_env_or_config`, verified against real fetched
source.

Fires HIGH per match:

    environment:
      ANSIBLE_HOST_KEY_CHECKING: False  # security: allow-ansible-host-key-checking-disabled

This is distinct from `ansible.cfg [defaults] host_key_checking = False` (an
INI-format config file this guard does not scan) — this rule catches the
env-var-level override, which re-enables the weakness even when `ansible.cfg` itself
is correctly configured.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    is_nonproduct_path,
    iter_dockerfiles,
    iter_files,
    pragma_present,
    read,
    rel,
    strip_hash_comments,
)

_SUFFIXES = (".yml", ".yaml")
_PRAGMA = "security: allow-ansible-host-key-checking-disabled"
# Left-boundaried so a CUSTOM env var that merely ends in the Ansible name (`MY_ANSIBLE_HOST_KEY_
# CHECKING`, which has zero effect on Ansible) doesn't false-fire -- only the real, unprefixed
# `ANSIBLE_HOST_KEY_CHECKING` variable does (#408 Minor #8).
_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_])ANSIBLE_HOST_KEY_CHECKING\s*[:=]\s*['\"]?(?:False|false|0|no|No)['\"]?"
)


class AnsibleHostKeyCheckingDisabledGuard(Guard):
    id = "ansible-host-key-checking-disabled"
    title = "ANSIBLE_HOST_KEY_CHECKING disabled — SSH MitM enabler"
    area = "Server hardening"

    # playbook_hostkey.yml: ANSIBLE_HOST_KEY_CHECKING: False -> fires ansible-host-key-checking-disabled.
    canary_plant = CanaryPlant(
        files={
            "playbook_hostkey.yml": (
                "- hosts: all\n"
                "  environment:\n"
                "    ANSIBLE_HOST_KEY_CHECKING: False\n"
                "  tasks:\n"
                "    - name: connect\n"
                "      debug: msg=hi\n"
            ),
        },
        expects=frozenset({"ansible-host-key-checking-disabled/env-override"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "ansible" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in [*iter_files(root, _SUFFIXES), *iter_dockerfiles(root)]:
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
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
                        "ANSIBLE_HOST_KEY_CHECKING is disabled here, turning off SSH "
                        "host-key verification for the whole Ansible control path. Every "
                        "controller-to-managed-node connection becomes MitM-vulnerable."
                    ),
                    remediation=(
                        "Remove the env override. For a genuine first-connect bootstrap "
                        "case, use `--ssh-extra-args='-o StrictHostKeyChecking=accept-new'` "
                        "(adds the key on first contact, fails on later mismatches) instead "
                        "of disabling checking permanently."
                    ),
                    rule="ansible-host-key-checking-disabled/env-override",
                    standards=["OWASP:A02", "CWE-295", "CWE-322"],
                )
            )
        return out
