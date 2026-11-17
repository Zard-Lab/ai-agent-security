"""Guard: Terraform Azure Storage Account does not enforce HTTPS-only traffic (checklist §6a).

    resource "azurerm_storage_account" "app" {
      name                     = "appstorage"
      account_tier             = "Standard"
      account_replication_type = "LRS"
      # no enable_https_traffic_only / https_traffic_only_enabled attribute at all
    }

An Azure Storage Account can be reached over plain HTTP unless it is explicitly told to
require HTTPS for every request. Traffic to a storage account routinely carries
authentication (SAS tokens, storage account keys in the query string or headers) and
application data (uploads, generated documents) — allowing it over cleartext HTTP means
any network position between the client and Azure (a shared Wi-Fi, a compromised
router, a misconfigured proxy) can read or tamper with that traffic, including the
credentials used to authenticate to the account itself. CWE-319 (Cleartext Transmission
of Sensitive Information), OWASP:A02 (Cryptographic Failures).

Sourced from KICS's `storage_account_not_forcing_https` query, verified against the
real fetched `query.rego`: the query explicitly handles BOTH the pre-v4 attribute name
`enable_https_traffic_only` and its Terraform AzureRM provider v4 rename
`https_traffic_only_enabled` — a provider migration that would otherwise silently defeat
a guard hard-coded to only one of the two names.

Fires MEDIUM when an `azurerm_storage_account` resource block does NOT contain either
`enable_https_traffic_only = true` or `https_traffic_only_enabled = true` anywhere in
its body — whether both attributes are missing entirely (the common case), or the one
attribute that IS present is set to `false`.

Suppress an audited case (e.g. a legacy client that cannot be migrated off plain HTTP)
with `# security: allow-azure-storage-https-only` anywhere in the resource block.
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

# Both the pre-v4 attribute name and its v4 rename count as "HTTPS enforced" when true — a
# provider migration must not silently defeat this guard (KICS's own query handles both too).
_HTTPS_ONLY_TRUE = re.compile(
    r"\b(?:enable_https_traffic_only|https_traffic_only_enabled)\s*=\s*true\b"
)
_PRAGMA = re.compile(r"#\s*security:\s*allow-azure-storage-https-only")

_STANDARDS = ["OWASP:A02", "CWE-319"]


class AzureStorageAccountHttpsOnlyGuard(Guard):
    id = "azure-storage-account-https-only"
    title = "Azure Storage Account does not enforce HTTPS-only traffic"
    area = "Cloud & IaC"

    # azure_storage_https.tf: azurerm_storage_account with neither https-only attribute set ->
    # fires azure-storage-account-https-only. Must NOT contain:
    # allow-azure-storage-https-only pragma.
    canary_plant = CanaryPlant(
        files={
            "azure_storage_https.tf": (
                'resource "azurerm_storage_account" "canary" {\n'
                '  name                     = "canaryhttps"\n'
                '  account_tier             = "Standard"\n'
                '  account_replication_type = "LRS"\n'
                "}\n"
            ),
        },
        expects=frozenset({"azure-storage-account-https-only/missing-or-disabled"}),
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
            if resource_type != "azurerm_storage_account":
                continue
            body_text = "\n".join(line for _, line in body)
            if pragma_present(_PRAGMA, body_text, dialect="hcl"):
                continue
            # Search a comment-blanked view (pragma already handled on the comment-only view above, #424) so a
            # commented `# https_traffic_only_enabled = true` can't suppress a finding on a
            # genuinely unenforced account. Blank, don't drop, so nothing downstream shifts.
            code_body = "\n".join(
                "" if line.lstrip().startswith(("#", "//")) else line for _, line in body
            )
            if _HTTPS_ONLY_TRUE.search(code_body):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=f"{rel(root, f)}:{start_line}",
                    message=(
                        f"`azurerm_storage_account.{resource_name}` does not set "
                        "`enable_https_traffic_only = true` (or its v4 rename "
                        "`https_traffic_only_enabled = true`). Requests to this account "
                        "— including SAS tokens and storage account keys carried in the "
                        "request — can be sent over plain HTTP, readable and "
                        "tamperable by anyone on the network path."
                    ),
                    remediation=(
                        "Add `https_traffic_only_enabled = true` (AzureRM provider v4+; "
                        "use `enable_https_traffic_only = true` on v3 and earlier) to the "
                        "resource. Suppress an audited exception (e.g. an unmigrated "
                        "legacy client) with "
                        "`# security: allow-azure-storage-https-only` anywhere in the "
                        "block."
                    ),
                    rule="azure-storage-account-https-only/missing-or-disabled",
                    standards=list(_STANDARDS),
                )
            )
        return out
