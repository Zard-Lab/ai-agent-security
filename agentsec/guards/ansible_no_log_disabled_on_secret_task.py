"""Guard: Ansible task explicitly disables no_log while handling a secret (checklist §10).

Ansible's `no_log: true` suppresses a task's arguments/results from every log line,
callback plugin, and CI artifact. Explicitly setting `no_log: false` (or `no`) near a
secret-shaped value is strictly worse than never setting `no_log` at all: the author
made an active decision to defeat the suppression, dumping the resolved secret into
plaintext logs (the 2024 TeamCity-Ansible-plugin incident: build logs contained every
customer's SSH private key after exactly this override).

Sourced from njsscan-scanner's sibling project `ansible-security-scanner`'s
`ansible_hygiene.yml` rule pack (rules `no_log_explicitly_false_on_credential_task` and
`no_log_false_on_secret_handling_task`, verified against real fetched source), combined
into one guard/rule slug — both check the same underlying anti-pattern (`no_log: false`
near a secret signal), just via two different secret-signal shapes: a Jinja variable
reference (`{{ vault_db_password }}`) or a literal module-arg key (`password:`).

Fires HIGH when `no_log: false`/`no_log: no` appears within ~400 characters of either
shape, in either order (the secret signal may appear before or after the `no_log` key).
CWE-200/CWE-532/CWE-778, OWASP:A09.

    - name: fetch db credentials
      no_log: false
      uri:
        url: "https://vault.internal/v1/db"
        headers:
          Authorization: "Bearer {{ vault_db_token }}"  # security: allow-ansible-no-log-disabled-on-secret-task

Suppress an audited, intentional case with the pragma above anywhere in the file.
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
_PRAGMA = "security: allow-ansible-no-log-disabled-on-secret-task"

_NO_LOG_FALSE = r"no_log\s*:\s*(?:false|no|False|No)\b"
_SECRET_SIGNAL = (
    r"(?:\{\{\s*(?:vault_[A-Za-z0-9_]+|[A-Za-z0-9_]+"  # nosec B105 (detection pattern, not a credential)
    r"(?:_password|_passwd|_token|_secret|_api_key|_apikey|_private_key))\s*\}\}"
    r"|(?:password|token|secret|api_key|authorization|bearer|access_key|private_key)\s*:)"
)
# The proximity window must stay INSIDE one task: it may not cross a task boundary, or an unrelated
# `no_log: false` on a DIFFERENT task would be misattributed to this secret-handling task purely by
# char distance. A task boundary is a new sequence-item mapping (`\n- <key>:`) — matched by name OR
# module key (`- name:`, `- command:`, `- ansible.builtin.copy:`), so NAMELESS tasks are scoped too
# (a bare `- name:`-only temper missed them). A `- scalar` loop value has no `:` and is not a boundary.
_SAME_TASK = r"(?:(?!\n\s*-\s+[\w.]+\s*:)[\s\S])"
_PATTERN = re.compile(
    rf"{_NO_LOG_FALSE}{_SAME_TASK}{{0,400}}?{_SECRET_SIGNAL}"
    rf"|{_SECRET_SIGNAL}{_SAME_TASK}{{0,400}}?{_NO_LOG_FALSE}"
)


class AnsibleNoLogDisabledOnSecretTaskGuard(Guard):
    id = "ansible-no-log-disabled-on-secret-task"
    title = "Ansible task explicitly disables no_log while handling a secret"
    area = "Logging"

    # site.yml: no_log: false near {{ vault_db_token }} -> fires ansible-no-log-disabled-on-secret-task.
    # Gated broadly on Ansible playbook-shape presence (the "hosts:"+"tasks:" content scan already
    # detects this file itself, so no separate marker is needed).
    canary_plant = CanaryPlant(
        files={
            "site.yml": (
                "- hosts: all\n"
                "  tasks:\n"
                "    - name: fetch db credentials\n"
                "      no_log: false\n"
                "      uri:\n"
                "        url: https://vault.internal/v1/db\n"
                "        headers:\n"
                '          Authorization: "Bearer {{ vault_db_token }}"\n'
            ),
        },
        expects=frozenset({"ansible-no-log-disabled-on-secret-task/no-log-false-near-secret"}),
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
            # Strip whole-line/trailing `#` comments before matching — a doc comment merely
            # mentioning "no_log: false" and "password:" must not fire (same false-positive
            # class this session's invisible-unicode and js-buffer-noassert fixes hit). Line
            # count is preserved, so a match position in the stripped text still maps to the
            # correct line number in the original file.
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
                        "This task explicitly sets `no_log: false` near a secret-shaped value "
                        "(a vault/password/token Jinja variable or a password/token/secret/"
                        "api_key module argument). This defeats Ansible's log suppression and "
                        "dumps the resolved secret into every task-result log line, callback "
                        "plugin, and CI artifact."
                    ),
                    remediation=(
                        "Remove `no_log: false` (or change it to `no_log: true`). If you need "
                        "to confirm the task succeeded, register the result and debug only a "
                        "non-sensitive derived field (e.g. `{{ result.status }}`), never the "
                        "raw secret value."
                    ),
                    rule="ansible-no-log-disabled-on-secret-task/no-log-false-near-secret",
                    standards=["OWASP:A09", "CWE-200", "CWE-532"],
                )
            )
        return out
