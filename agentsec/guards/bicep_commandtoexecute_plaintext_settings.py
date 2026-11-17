"""Guard: Bicep VM `CustomScriptExtension`/`CustomScript` resource puts a secret-bearing
`commandToExecute` value under the PLAINTEXT `settings` object instead of the encrypted
`protectedSettings` object (checklist §6c). One of the batch of Bicep-SYNTAX guards built on the
shared `agentsec.bicep` resource/param/output parser landed with `bicep-admin-username-literal`
 — this guard is the same shape, reasoning about the same `bicep_resources()` blocks.

    resource vmExt 'Microsoft.Compute/virtualMachines/extensions@2023-03-01' = {
      parent: vm
      name: 'CustomScript'
      properties: {
        publisher: 'Microsoft.Azure.Extensions'
        type: 'CustomScript'
        settings: {
          commandToExecute: 'echo ${dbPassword} > /tmp/config'   // <- plaintext, fires
        }
      }
    }

vs. the safe form (the secret-bearing command moved to `protectedSettings`):

    settings: {}
    protectedSettings: {
      commandToExecute: 'echo ${dbPassword} > /tmp/config'
    }

`settings` is stored and returned in cleartext (`az vm extension show`, the Azure Portal,
deployment history) to anyone with read access to the VM resource; `protectedSettings` is
encrypted at rest and never returned by a read. A `commandToExecute` that carries a password,
token, or other secret belongs in `protectedSettings` — putting it in `settings` is a real,
not hypothetical, credential exposure. Sourced from Bicep's own compiler-embedded linter,
`UseProtectedSettingsForCommandToExecuteSecretsRule.cs` (`protect-commandtoexecute-secrets`),
verified against the real fetched source.

## Detection design (the nearest-preceding-keyword heuristic)

A full nested-object-path parser (walking `properties.settings.commandToExecute` vs.
`properties.protectedSettings.commandToExecute` as distinct JSON-like paths) is out of scope for a
regex-based guard, so this guard uses a deliberately simple, documented heuristic instead:

1. The resource's `resource_type` must be `Microsoft.Compute/virtualMachines/extensions`
   (**exact match, not substring** — mirrors the exact-match discipline other ARM/CFN guards in
   this codebase use for resource-type gating, e.g. `resource_type == "..."` comparisons in
   `aws_observability_hygiene.py`/`iam_policy_attached_to_user_directly.py`).
2. Within the resource's `block` text, find every `commandToExecute:` occurrence. For each one,
   walk BACKWARD through the block text and find whichever of the literal substrings `settings:`
   or `protectedSettings:` has its LAST (nearest-preceding) occurrence closest to that
   `commandToExecute:` — a plain `str.rfind()` on the text before the match, no brace-scope
   tracking. If the nearer keyword is `settings:` (not `protectedSettings:`), the command is
   sitting in the plaintext block.
3. The `commandToExecute` value only fires if it also "looks secret-bearing" (see below) — an
   ordinary `echo hello`-type command in `settings` is completely fine and must stay silent; this
   is the guard's core false-positive-avoidance mechanism.

**Known heuristic limitation, disclosed honestly:** `str.rfind()` on literal text has no concept
of brace scope or string-literal boundaries. A command string that happens to contain the literal
substring `"settings:"` or `"protectedSettings:"` INSIDE a quoted value elsewhere in the block
(not as the actual property key) could in principle confuse which keyword is "nearest" and flip
the classification. This is not expected in practice for the `commandToExecute` property (its
value is a shell command string, not JSON-with-those-key-names embedded in it), but it is not
proven impossible, and it is why this is the most heuristic guard in this batch. Case matters too:
`settings:` (lowercase `s`) is not a substring of `protectedSettings:` (capital `S` in
`...edSettings:`), which is what keeps the two keywords from colliding on ordinary
correctly-cased Bicep source — a `str.find`/`rfind`, not a regex, so it is case-sensitive by
construction.

**"Looks secret-bearing"**: the `commandToExecute` value (the quoted string after the colon),
lower-cased, contains one of: `password`, `secret`, `token`, `apikey`, or `-p ` (a common CLI
secret-flag pattern, e.g. `mysql -u root -p hunter2`). A Bicep string-interpolation reference to a
parameter/variable whose own name matches one of those terms (e.g. `${dbPassword}`) is caught by
the SAME substring check for free — the interpolation text is part of the value's literal source,
so `${dbPassword}`.lower() already contains `password`. No separate interpolation-parsing logic is
needed or implemented.

Fires HIGH when a `Microsoft.Compute/virtualMachines/extensions` resource's `commandToExecute` is
nearest-preceded by `settings:` (not `protectedSettings:`) AND the command value looks
secret-bearing. Silent when the same command sits under `protectedSettings`, when the command has
no secret signal at all, or on any other resource type.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.bicep import bicep_resources
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, read, rel

_EXTENSION_TYPE = "Microsoft.Compute/virtualMachines/extensions"

_COMMAND_TO_EXECUTE = re.compile(r"commandToExecute\s*:\s*(?P<value>'(?:\\.|[^'\\])*')")

_SECRET_TERMS = ("password", "secret", "token", "apikey", "-p ")

_STANDARDS = ["OWASP:A02", "CWE-522"]

_RULE = "bicep-commandtoexecute-plaintext-settings/secret-in-plaintext-settings"


def _looks_secret_bearing(value: str) -> bool:
    """True if the (quoted) `commandToExecute` value text, case-insensitively, carries one of the
    secret-name signals in `_SECRET_TERMS`. A Bicep `${paramName}` interpolation of a
    secret-shaped name (e.g. `${dbPassword}`) is caught by the same substring check for free,
    since the interpolated text is part of the value's literal source."""
    lower = value.lower()
    return any(term in lower for term in _SECRET_TERMS)


class BicepCommandtoexecutePlaintextSettingsGuard(Guard):
    id = "bicep-commandtoexecute-plaintext-settings"
    title = "Bicep CustomScript commandToExecute carries a secret under plaintext settings, not protectedSettings"
    area = "Cloud & IaC"

    # bicep_cmdexec.bicep: a Microsoft.Compute/virtualMachines/extensions resource with a
    # secret-bearing commandToExecute ('echo ${dbPassword}') nested under the plaintext `settings`
    # object (not `protectedSettings`) -> fires
    # bicep-commandtoexecute-plaintext-settings/secret-in-plaintext-settings.
    canary_plant = CanaryPlant(
        files={
            "bicep_cmdexec.bicep": (
                "resource canaryVmExt 'Microsoft.Compute/virtualMachines/extensions@2023-03-01' = {\n"
                "  parent: canaryVm\n"
                "  name: 'CustomScript'\n"
                "  properties: {\n"
                "    publisher: 'Microsoft.Azure.Extensions'\n"
                "    type: 'CustomScript'\n"
                "    settings: {\n"
                "      commandToExecute: 'echo ${dbPassword}'\n"
                "    }\n"
                "  }\n"
                "}\n"
            ),
        },
        expects=frozenset({_RULE}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "bicep" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".bicep",)):
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        for resource in bicep_resources(read(f)):
            if resource.resource_type != _EXTENSION_TYPE:
                continue
            block = resource.block
            for m in _COMMAND_TO_EXECUTE.finditer(block):
                value = m.group("value")
                if not _looks_secret_bearing(value):
                    continue
                before = block[: m.start()]
                settings_pos = before.rfind("settings:")
                protected_pos = before.rfind("protectedSettings:")
                if settings_pos == -1 and protected_pos == -1:
                    # Neither keyword found before this occurrence — can't classify, skip rather
                    # than guess.
                    continue
                if settings_pos <= protected_pos:
                    # protectedSettings: is the nearer (or equally-absent) keyword -> safe.
                    continue
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title=self.title,
                        location=f"{rel(root, f)}:{resource.start_line}",
                        message=(
                            f"`{resource.name}` ({resource.resource_type}) puts a secret-bearing "
                            f"`commandToExecute` ({value}) under the PLAINTEXT `settings` object "
                            "instead of `protectedSettings`. `settings` is readable in cleartext "
                            "via `az vm extension show`, the Azure Portal, and deployment history "
                            "by anyone with read access to the VM resource."
                        ),
                        remediation=(
                            "Move `commandToExecute` (and any other secret-bearing extension "
                            "settings) into `protectedSettings`, which is encrypted at rest and "
                            "never returned by a read. Leave `settings` with only non-secret "
                            "configuration."
                        ),
                        rule=_RULE,
                        standards=list(_STANDARDS),
                    )
                )
        return out
