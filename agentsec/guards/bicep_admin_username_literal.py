"""Guard: Bicep resource `adminUsername` property set to a hardcoded string literal instead of a
parameter reference (checklist §6c). agentsec's first Bicep-SYNTAX guard — Bicep
detection and the shared `agentsec.bicep` resource/param/output parser landed in this same PR to
support it. Bicep compiles to ARM JSON, which `agentsec.arm`'s guards already scan for
property-level misconfiguration; this guard (and its siblings in the same batch) instead reasons
about Bicep SOURCE SYNTAX that the compiler erases — a `@secure()` decorator, or here, whether a
value is a literal versus a parameter reference — which is only visible before compilation.

    resource vm 'Microsoft.Compute/virtualMachines@2023-03-01' = {
      name: 'myVm'
      properties: {
        osProfile: {
          adminUsername: 'admin'   // <- hardcoded, fires
        }
      }
    }

A hardcoded `adminUsername` narrows a brute-force attacker's search space: they no longer need to
guess the login name, only the password/key, for every VM deployed from this template. Sourced
from Bicep's own compiler-embedded linter, `AdminUsernameShouldNotBeLiteralRule.cs`
(`adminusername-should-not-be-literal`), verified against the real fetched source.

Fires MEDIUM when a `resource` block's `adminUsername` property is set to a quoted string literal.
Silent when the value is a bare identifier (a parameter/variable reference — Bicep references are
never quoted) or a property-access expression on one (e.g. `adminUsername: adminUser` or
`adminUsername: vmConfig.adminUsername`).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.bicep import bicep_resources
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, read, rel

_ADMIN_USERNAME_LITERAL = re.compile(r"adminUsername\s*:\s*'[^']*'")

_STANDARDS = ["OWASP:A07", "CWE-798"]


class BicepAdminUsernameLiteralGuard(Guard):
    id = "bicep-admin-username-literal"
    title = "Bicep resource adminUsername is a hardcoded string literal, not a parameter reference"
    area = "Cloud & IaC"

    # bicep_vm.bicep: a VM resource with adminUsername: 'admin' (a quoted literal) -> fires
    # bicep-admin-username-literal/hardcoded-literal.
    canary_plant = CanaryPlant(
        files={
            "bicep_vm.bicep": (
                "resource canaryVm 'Microsoft.Compute/virtualMachines@2023-03-01' = {\n"
                "  name: 'canaryVm'\n"
                "  properties: {\n"
                "    osProfile: {\n"
                "      adminUsername: 'admin'\n"
                "    }\n"
                "  }\n"
                "}\n"
            ),
        },
        expects=frozenset({"bicep-admin-username-literal/hardcoded-literal"}),
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
            if not _ADMIN_USERNAME_LITERAL.search(resource.block):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=f"{rel(root, f)}:{resource.start_line}",
                    message=(
                        f"`{resource.name}` ({resource.resource_type}) sets `adminUsername` "
                        "to a hardcoded string literal instead of a parameter reference. "
                        "Every VM deployed from this template gets the same predictable "
                        "login name, narrowing a brute-force attacker's search space to "
                        "just the password/key."
                    ),
                    remediation=(
                        "Replace the literal with a `param` (or `secure()`-decorated param) "
                        "reference, e.g. `adminUsername: adminUsernameParam`, so each "
                        "deployment can supply its own value."
                    ),
                    rule="bicep-admin-username-literal/hardcoded-literal",
                    standards=list(_STANDARDS),
                )
            )
        return out
