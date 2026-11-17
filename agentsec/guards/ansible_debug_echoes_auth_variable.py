"""Guard: Ansible debug task echoes a live authentication variable (checklist §10).

Ansible's reserved "magic" authentication variables (`ansible_password`,
`ansible_ssh_pass`, `ansible_become_password`, `ansible_become_pass`,
`ansible_sudo_pass`, `ansible_su_pass`, `ansible_httpapi_pass`,
`ansible_netconf_pass`) hold the LIVE SSH/become/API password the controller is
currently using against managed nodes. Ansible does NOT auto-scrub these from
`debug:` output — a `debug: var: ansible_become_password` (or the same variable
interpolated into a `msg:`) leaks the credential to stdout, ansible-runner job
artifacts, the AWX/AAP job-output database, CI log archives, and any callback
plugin attached to the run. This is a common "let me just check what I'm using"
developer pattern that survives code review because the debug task itself looks
harmless. CWE-200/CWE-312/CWE-532, OWASP:A09.

Sourced from `cpeoples/ansible-security-scanner`'s `ansible_hygiene.yml` rule
`debug_of_ansible_magic_auth_variable`, verified against real fetched source.

Fires CRITICAL per match:

    - name: show become password in message
      ansible.builtin.debug:
        msg: "Using {{ ansible_become_password }} for {{ inventory_hostname }}"

Debugging a non-auth variable (`ansible_user`, `ansible_host`, a custom
`ansible_passthrough_config`) does NOT fire — only the specific reserved
auth-magic variable names above do. Suppress an audited, intentional case with
`# security: allow-ansible-debug-echoes-auth-variable` anywhere in the file.
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
_PRAGMA = "security: allow-ansible-debug-echoes-auth-variable"

# Strip `#` comments before matching: a commented-out debug task must not fire. The shared
# `strip_hash_comments` is now quote-aware (issue #418), so a `#` INSIDE a quoted `msg:`
# (`msg: "Info #1: password is {{ ansible_password }}"`) is preserved and this credential-echo
# guard still sees the leak — while a genuine trailing/whole-line comment is stripped. It strips
# one line at a time, so line count is preserved and a match position still maps to the right line.
# (Previously a local whole-line-only stripper, kept while the shared helper was quote-unaware.)

_AUTH_VAR = (
    r"ansible_(?:ssh_pass|password|become_pass(?:word)?|sudo_pass|su_pass|httpapi_pass|netconf_pass)"
)
# Both spans are tempered so the match stays INSIDE one debug task: because the `msg:` branch now
# spans lines (to catch a block scalar), an un-tempered span would reach a LATER task's `{{ auth }}`
# and fire CRITICAL against an innocent debug task. A task boundary is a new sequence-item mapping
# (`\n- <key>:`, named or nameless); a `- scalar` loop value is not.
_SAME_TASK = r"(?:(?!\n\s*-\s+[\w.]+\s*:)[\s\S])"
# `msg:` branch spans lines up to the auth var so a YAML block scalar (`msg: >` / `msg: |` with the
# `{{ ansible_* }}` interpolation on a following line) is caught, not just a same-line `msg:`.
_PATTERN = re.compile(
    rf"(?:ansible\.builtin\.)?debug\s*:{_SAME_TASK}{{0,200}}?"
    rf"(?:var\s*:\s*['\"]?{_AUTH_VAR}['\"]?\s*$|msg\s*:{_SAME_TASK}{{0,200}}?\{{\{{\s*{_AUTH_VAR}\b)",
    re.MULTILINE,
)


class AnsibleDebugEchoesAuthVariableGuard(Guard):
    id = "ansible-debug-echoes-auth-variable"
    title = "Ansible debug task echoes a live authentication variable"
    area = "Logging"

    # playbook_debug.yml: debug: var: ansible_become_password -> fires ansible-debug-echoes-auth-variable.
    canary_plant = CanaryPlant(
        files={
            "playbook_debug.yml": (
                "- hosts: all\n"
                "  tasks:\n"
                "    - name: show become password\n"
                "      debug:\n"
                "        var: ansible_become_password\n"
            ),
        },
        expects=frozenset({"ansible-debug-echoes-auth-variable/debug-prints-auth-magic-var"}),
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
                        "This debug task prints one of Ansible's reserved authentication "
                        "magic variables (ansible_password, ansible_become_password, "
                        "ansible_sudo_pass, ...). These hold the LIVE credential the "
                        "controller is using and are not auto-scrubbed from debug output — "
                        "the value leaks to stdout, job artifacts, and any attached "
                        "callback plugin."
                    ),
                    remediation=(
                        "Delete the debug task. To verify auth without printing the "
                        "credential, run `ansible -m ping` against a single host and check "
                        "the return code, or debug a derived non-sensitive value such as "
                        "`{{ ansible_user }}@{{ inventory_hostname }}`."
                    ),
                    rule="ansible-debug-echoes-auth-variable/debug-prints-auth-magic-var",
                    standards=["OWASP:A09", "CWE-200", "CWE-312"],
                )
            )
        return out
