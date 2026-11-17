"""Guard: Terraform Azure Storage Account allows public blob access (checklist §6a).

    resource "azurerm_storage_account" "app" {
      name                     = "appstorage"
      account_tier             = "Standard"
      account_replication_type = "LRS"
      # no allow_blob_public_access attribute at all -> not explicitly disabled
    }

`allow_blob_public_access` controls whether an individual container or blob inside the
storage account may be configured for anonymous (unauthenticated) public read access.
Leaving it unset, or setting it to `true`, does not itself make every blob public — but
it means nothing at the storage-account level stops a container's own ACL from being
flipped to public, whether by a misconfigured Terraform elsewhere in the same plan, a
manual Azure Portal/CLI change, or an application bug. Explicitly setting the attribute
to `false` is a account-wide guardrail: no container in the account can be made
anonymously public no matter what its own ACL says. This is the direct Azure analog of
an S3 bucket's Block Public Access controls (checklist `6a-s3-public-access-block-disabled`).
CWE-284 (Improper Access Control), OWASP:A05.

Sourced from KICS's `public_storage_account` query (`query.rego`), verified against the
real source: `storage.allow_blob_public_access != false` is one of several sub-checks in
that query. This guard scopes to just that boolean-flag sub-case — the `network_rules`/
`ip_rules` 0.0.0.0/0 sub-cases in the same KICS query are a materially different check
(a firewall allowlist, not an ACL guardrail) and are not covered here.

Fires HIGH when an `azurerm_storage_account` resource block does NOT contain
`allow_blob_public_access = false` anywhere in its body — whether the attribute is
missing entirely (the common case) or explicitly set to `true`.

Suppress an audited case (e.g. a deliberately public static-asset storage account) with
`# security: allow-azure-storage-public-blob-access` anywhere in the resource block.
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

_ALLOW_BLOB_PUBLIC_ACCESS_FALSE = re.compile(r"\ballow_blob_public_access\s*=\s*false\b")
_PRAGMA = re.compile(r"#\s*security:\s*allow-azure-storage-public-blob-access")

_STANDARDS = ["OWASP:A05", "CWE-284"]


class AzureStorageAccountPublicBlobAccessGuard(Guard):
    id = "azure-storage-account-public-blob-access"
    title = "Azure Storage Account allows public blob access"
    area = "Cloud & IaC"

    # azure_storage_public.tf: azurerm_storage_account with no allow_blob_public_access
    # attribute -> fires azure-storage-account-public-blob-access. Must NOT contain:
    # allow-azure-storage-public-blob-access pragma.
    canary_plant = CanaryPlant(
        files={
            "azure_storage_public.tf": (
                'resource "azurerm_storage_account" "canary" {\n'
                '  name                     = "canarystorage"\n'
                '  account_tier             = "Standard"\n'
                '  account_replication_type = "LRS"\n'
                "}\n"
            ),
        },
        expects=frozenset(
            {"azure-storage-account-public-blob-access/missing-or-enabled"}
        ),
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
            # commented `# allow_blob_public_access = false` can't suppress a finding on a
            # genuinely unguarded account. Blank, don't drop, so nothing downstream shifts.
            code_body = "\n".join(
                "" if line.lstrip().startswith(("#", "//")) else line for _, line in body
            )
            if _ALLOW_BLOB_PUBLIC_ACCESS_FALSE.search(code_body):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}:{start_line}",
                    message=(
                        f"`azurerm_storage_account.{resource_name}` does not set "
                        "`allow_blob_public_access = false`. Without this account-wide "
                        "guardrail, any container in the account can be flipped to "
                        "anonymous public read access — by a later Terraform change, a "
                        "manual Portal/CLI edit, or an application bug — with nothing at "
                        "the storage-account level to stop it."
                    ),
                    remediation=(
                        "Add `allow_blob_public_access = false` to the resource. Suppress "
                        "an audited exception (e.g. a deliberately public static-asset "
                        "storage account) with "
                        "`# security: allow-azure-storage-public-blob-access` anywhere in "
                        "the block."
                    ),
                    rule="azure-storage-account-public-blob-access/missing-or-enabled",
                    standards=list(_STANDARDS),
                )
            )
        return out
