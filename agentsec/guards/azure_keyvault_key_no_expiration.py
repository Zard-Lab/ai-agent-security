"""Guard: Terraform Azure Key Vault key with no expiration date (checklist §7).

    resource "azurerm_key_vault_key" "app" {
      name         = "app-key"
      key_vault_id = azurerm_key_vault.main.id
      key_type     = "RSA"
      key_size     = 2048
      key_opts     = ["decrypt", "encrypt", "sign", "unwrapKey", "verify", "wrapKey"]
      # no expiration_date attribute at all -> the key never expires
    }

An `azurerm_key_vault_key` resource with no `expiration_date` set never expires. Without a
forced rotation cadence, a compromised or leaked key stays valid indefinitely — the blast
radius of the compromise grows the longer the key lives, and there is no automatic point at
which an operator is forced to notice and rotate it. CWE-320 (Key Management Errors), OWASP:A04.

Sourced from checkov's `CKV_AZURE_40` (`KeyExpirationDate.py`), which requires the attribute to
be present with ANY value at all (checkov's own `ANY_VALUE` sentinel) — it does not validate the
date itself, only that the key has *some* expiration configured. This guard mirrors that scope
exactly: it does not parse or validate the date value, only checks whether `expiration_date`
appears anywhere in the resource block.

Fires LOW when an `azurerm_key_vault_key` resource block does NOT contain an `expiration_date`
attribute anywhere in its (non-comment) body — a real, uncommented occurrence of the attribute
name, with any value, is sufficient to silence it.

Suppress an audited case (e.g. a short-lived key already covered by an external rotation
process) with `# security: allow-azure-keyvault-key-expiration` anywhere in the resource block.

Deliberately scoped to `azurerm_key_vault_key` only — a sibling `azurerm_key_vault` resource (the
vault itself, holding the key) is a different resource type and is never scanned by this guard.
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
    iter_terraform_resources,
    pragma_present,
    read,
    rel,
)

_EXPIRATION_DATE = re.compile(r"\bexpiration_date\s*=")
_PRAGMA = re.compile(r"#\s*security:\s*allow-azure-keyvault-key-expiration")

_STANDARDS = ["OWASP:A02", "CWE-320"]


class AzureKeyvaultKeyNoExpirationGuard(Guard):
    id = "azure-keyvault-key-no-expiration"
    title = "Azure Key Vault key with no expiration date"
    area = "Cloud & IaC"

    # azure_keyvault_key.tf: azurerm_key_vault_key with no expiration_date attribute ->
    # fires azure-keyvault-key-no-expiration. Must NOT contain:
    # allow-azure-keyvault-key-expiration pragma.
    canary_plant = CanaryPlant(
        files={
            "azure_keyvault_key.tf": (
                'resource "azurerm_key_vault_key" "canary" {\n'
                '  name         = "canary-key"\n'
                "  key_vault_id = azurerm_key_vault.canary.id\n"
                '  key_type     = "RSA"\n'
                "  key_size     = 2048\n"
                "}\n"
            ),
        },
        expects=frozenset({"azure-keyvault-key-no-expiration/missing-expiration-date"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "terraform" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".tf",)):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        for resource_type, resource_name, start_line, body in iter_terraform_resources(text):
            if resource_type != "azurerm_key_vault_key":
                continue
            body_text = "\n".join(line for _, line in body)
            if pragma_present(_PRAGMA, body_text, dialect="hcl"):
                continue
            # Search a comment-blanked view (pragma already handled on the comment-only view above, #424) so a
            # commented `# expiration_date = "..."` can't silence a key that genuinely never
            # expires. Blank, don't drop, so nothing downstream shifts.
            code_body = "\n".join(
                "" if line.lstrip().startswith(("#", "//")) else line for _, line in body
            )
            if _EXPIRATION_DATE.search(code_body):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=f"{rel(root, f)}:{start_line}",
                    message=(
                        f"`azurerm_key_vault_key.{resource_name}` does not set "
                        "`expiration_date`. A Key Vault key with no expiration never forces "
                        "rotation — a compromised or leaked key stays valid indefinitely, "
                        "growing the blast radius of the compromise the longer it goes "
                        "unnoticed."
                    ),
                    remediation=(
                        "Add `expiration_date = \"<RFC3339 timestamp>\"` to the resource so the "
                        "key has a forced rotation cadence. Suppress an audited exception (e.g. "
                        "a key already covered by an external rotation process) with "
                        "`# security: allow-azure-keyvault-key-expiration` anywhere in the block."
                    ),
                    rule="azure-keyvault-key-no-expiration/missing-expiration-date",
                    standards=list(_STANDARDS),
                )
            )
        return out
