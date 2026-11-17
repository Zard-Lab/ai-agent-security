"""Guard: ignore_errors: true on a security-critical Ansible task (checklist §8).

`ignore_errors: true` (or `yes`) on a task whose name/path/args reference a
security-critical concern (firewall, selinux, sudoers, pam, auth, tls/ssl,
certificate, vault, iptables, ufw, nftables, kerberos, audit) leaves the system in a
half-hardened state on failure — often worse than no hardening at all, because the
surrounding playbook still reports SUCCESS. A hidden firewall-rule failure, for
example, is silently swallowed and the run is reported green. CWE-754 (Improper
Check for Unusual or Exceptional Conditions), CWE-755 (Improper Handling of
Exceptional Conditions).

Sourced from `cpeoples/ansible-security-scanner`'s `ansible_hygiene.yml` rule
`ignore_errors_security`, verified against real fetched source.

Fires HIGH per match:

    - name: ensure SSL certificate is checked
      ansible.builtin.command: openssl verify {{ cert_path }}
      ignore_errors: true  # security: allow-ansible-ignore-errors-on-security-task
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
_PRAGMA = "security: allow-ansible-ignore-errors-on-security-task"
# Each security keyword is LEFT-boundaried (`\b`) so a stem can't bleed in from an ordinary word:
# `pam_`⊄`spam_filter`, `cert`⊄`concert` (and `certain` is excluded by the right `\b`), `auth_`
# only as a real prefix. Without these the guard fired HIGH on e.g. `name: import concert tickets`.
_SECURITY_KEYWORD_LINE = (
    r"(?:name|path|dest|src|regexp|line|content)\s*:\s*['\"]?[^'\"\n]*"
    r"(?:\bfirewall|\bselinux|\bsudoers|\bpam[._]|\bauth_|\btls\b|\bssl\b|\bcertificate|\bcert\b|"
    r"\bvault|\biptables|\bufw\b|\bnftables|\bpasswordless|\bkerberos|\bkrb5|\baudit)"
)
_IGNORE = r"^\s*ignore_errors\s*:\s*(?:true|yes|True|Yes)\b"
# The proximity window must stay INSIDE one task: it may not cross a task boundary, or an unrelated
# task's `ignore_errors`/keyword would be misattributed to a different (security) task purely by char
# distance. A task boundary is a new sequence-item mapping (`\n- <key>:`) — matched by name OR module
# key (`- name:`, `- command:`, `- ansible.builtin.copy:`), so NAMELESS tasks are scoped too (a bare
# `- name:`-only temper missed them). A `- scalar` loop value has no `:` and is not a boundary.
_SAME_TASK = r"(?:(?!\n\s*-\s+[\w.]+\s*:)[\s\S])"
# Symmetric on key order (like the sibling no_log guard): the keyword may precede OR follow the
# `ignore_errors` key within the same task — playbooks legitimately write the flag either side.
_PATTERN = re.compile(
    rf"(?i)(?:{_SECURITY_KEYWORD_LINE}[^\n]{{0,200}}\n{_SAME_TASK}{{0,300}}?{_IGNORE}"
    rf"|{_IGNORE}{_SAME_TASK}{{0,300}}?{_SECURITY_KEYWORD_LINE})",
    re.MULTILINE,
)


class AnsibleIgnoreErrorsOnSecurityTaskGuard(Guard):
    id = "ansible-ignore-errors-on-security-task"
    title = "ignore_errors: true on a security-critical Ansible task"
    area = "Server hardening"

    # playbook_ignore_errors.yml: ignore_errors: true on an SSL-cert task -> fires
    # ansible-ignore-errors-on-security-task.
    canary_plant = CanaryPlant(
        files={
            "playbook_ignore_errors.yml": (
                "- hosts: all\n"
                "  tasks:\n"
                "    - name: ensure SSL certificate is checked\n"
                "      ansible.builtin.command: openssl verify {{ cert_path }}\n"
                "      ignore_errors: true\n"
            ),
        },
        expects=frozenset({"ansible-ignore-errors-on-security-task/silent-failure"}),
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
                        "This task references a security-critical concern (firewall, "
                        "SELinux, sudoers, PAM, TLS/SSL, vault, iptables, ...) AND sets "
                        "ignore_errors: true. A hidden failure here leaves the system "
                        "half-hardened while the playbook still reports success."
                    ),
                    remediation=(
                        "Remove ignore_errors: true from security-hardening tasks. If the "
                        "task legitimately may not apply to every host, use failed_when: "
                        "with an explicit condition, or when: to skip where the "
                        "prerequisite is absent."
                    ),
                    rule="ansible-ignore-errors-on-security-task/silent-failure",
                    standards=["CWE-754", "CWE-755"],
                )
            )
        return out
