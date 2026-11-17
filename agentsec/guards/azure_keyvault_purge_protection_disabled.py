"""Guard: Terraform Azure Key Vault without purge protection (checklist §7).

    resource "azurerm_key_vault" "app" {
      name = "app-kv"
      sku_name = "standard"
      # no purge_protection_enabled attribute at all -> defaults to false
    }

Azure Key Vault's soft-delete feature (on by default since 2020) gives a deleted vault a
recovery window, but soft-delete alone does not stop someone with `purge` permission from
permanently, irrecoverably destroying the vault (and every secret/key/certificate inside it)
during that window. `purge_protection_enabled` is the attribute that closes that gap — it is
opt-in and defaults to `false` if never set. Without it, a compromised or over-privileged
identity (or an operator fat-fingering a Terraform apply/CLI command) can purge the vault with
no recovery path: every secret, signing key, and certificate it held is gone for good.
CWE-320 (Key Management Errors), OWASP:A04 (Insecure Design).

Sourced from checkov's `KeyVaultEnablesPurgeProtection` (`CKV_AZURE_110`), which has no
override on `missing_block_result` — the default `FAILED` applies, so an omitted attribute
fires exactly like an explicit `false`. This guard mirrors that: it is agentsec's first
Azure-specific Terraform guard (every prior Terraform guard targets `aws_*` resource types),
but reuses the same resource-type-agnostic `iter_terraform_resources()` helper and the
established "omitted OR explicit-false, both fire" shape (see `rds_storage_not_encrypted.py`).

Fires MEDIUM when an `azurerm_key_vault` resource block does NOT contain
`purge_protection_enabled = true` anywhere in its body — whether the attribute is missing
entirely (the common case) or explicitly set to `false`.

Suppress an audited case (e.g. a genuinely disposable dev/scratch vault) with
`# security: allow-azure-keyvault-purge-protection` anywhere in the resource block.
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

_PURGE_PROTECTION_TRUE = re.compile(r"\bpurge_protection_enabled\s*=\s*true\b")
_PRAGMA = re.compile(r"#\s*security:\s*allow-azure-keyvault-purge-protection")

_STANDARDS = ["OWASP:A05", "CWE-320"]


class AzureKeyvaultPurgeProtectionDisabledGuard(Guard):
    id = "azure-keyvault-purge-protection-disabled"
    title = "Azure Key Vault without purge protection"
    area = "Cloud & IaC"

    # azure_keyvault.tf: azurerm_key_vault with no purge_protection_enabled attribute ->
    # fires azure-keyvault-purge-protection-disabled. Must NOT contain:
    # allow-azure-keyvault-purge-protection pragma.
    canary_plant = CanaryPlant(
        files={
            "azure_keyvault.tf": (
                'resource "azurerm_key_vault" "canary" {\n'
                '  name     = "canary-kv"\n'
                '  sku_name = "standard"\n'
                "}\n"
            ),
        },
        expects=frozenset({"azure-keyvault-purge-protection-disabled/missing-purge-protection"}),
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
            if resource_type != "azurerm_key_vault":
                continue
            body_text = "\n".join(line for _, line in body)
            if pragma_present(_PRAGMA, body_text, dialect="hcl"):
                continue
            # Search a comment-blanked view (pragma already handled on the comment-only view above, #424) so a
            # commented `# purge_protection_enabled = true` can't suppress a finding on a
            # genuinely unprotected vault. Blank, don't drop, so nothing downstream shifts.
            code_body = "\n".join(
                "" if line.lstrip().startswith(("#", "//")) else line for _, line in body
            )
            if _PURGE_PROTECTION_TRUE.search(code_body):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=f"{rel(root, f)}:{start_line}",
                    message=(
                        f"`azurerm_key_vault.{resource_name}` does not set "
                        "`purge_protection_enabled = true`. Purge protection is opt-in and "
                        "defaults to false — soft-delete alone still lets anyone with purge "
                        "permission permanently destroy the vault and every secret, key, and "
                        "certificate it holds, with no recovery window."
                    ),
                    remediation=(
                        "Add `purge_protection_enabled = true` to the resource. Note this "
                        "cannot be reverted once set — Azure does not allow disabling purge "
                        "protection on a vault after it's enabled. Suppress an audited "
                        "exception (e.g. a genuinely disposable dev/scratch vault) with "
                        "`# security: allow-azure-keyvault-purge-protection` anywhere in the "
                        "block."
                    ),
                    rule="azure-keyvault-purge-protection-disabled/missing-purge-protection",
                    standards=list(_STANDARDS),
                )
            )
        return out
