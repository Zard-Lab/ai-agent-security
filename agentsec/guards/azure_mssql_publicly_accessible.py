"""Guard: Terraform Azure SQL Server directly reachable from the internet (checklist §7).

    resource "azurerm_mssql_server" "app" {
      name                         = "app-sql-server"
      administrator_login          = "sqladmin"
      administrator_login_password = var.sql_admin_password
      version                      = "12.0"
      # no public_network_access_enabled attribute at all -> defaults to true
    }

`public_network_access_enabled` controls whether an `azurerm_mssql_server` accepts
connections from the public internet at all, before any firewall rule is even
evaluated. Unlike AWS RDS's `publicly_accessible` (which defaults to `false`), the
Azure provider's default for this attribute is `true` — so a server that never sets it
is reachable from any IP address that also passes the server's firewall rules, and a
single overly-broad firewall rule (or none at all, which some Terraform modules
provision fine without) leaves the whole SQL server exposed to brute-force and
credential-stuffing attempts directly from the internet. CWE-284 (Improper Access
Control), OWASP:A05.

Sourced from KICS's `mssql_server_public_network_access_enabled` query, verified
against the real fetched `query.rego`: two separate CxPolicy rules cover the
missing-attribute case and the explicit `== true` case respectively — this guard
mirrors both in one check.

Fires HIGH when an `azurerm_mssql_server` resource block does NOT contain
`public_network_access_enabled = false` anywhere in its body — whether the attribute
is missing entirely (the common case, and the more dangerous one since the Azure
default is permissive) or explicitly set to `true`.

Suppress an audited case (e.g. a server intentionally reachable via Azure AD-only auth
plus IP allowlisting) with `# security: allow-azure-mssql-public` anywhere in the
resource block.
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

_PUBLIC_NETWORK_ACCESS_FALSE = re.compile(r"\bpublic_network_access_enabled\s*=\s*false\b")
_PRAGMA = re.compile(r"#\s*security:\s*allow-azure-mssql-public")

_STANDARDS = ["OWASP:A05", "CWE-284"]


class AzureMssqlPubliclyAccessibleGuard(Guard):
    id = "azure-mssql-publicly-accessible"
    title = "Azure SQL Server directly reachable from the internet"
    area = "Cloud & IaC"

    # azure_mssql.tf: azurerm_mssql_server with no public_network_access_enabled
    # attribute -> fires azure-mssql-publicly-accessible. Must NOT contain:
    # allow-azure-mssql-public pragma.
    canary_plant = CanaryPlant(
        files={
            "azure_mssql.tf": (
                'resource "azurerm_mssql_server" "canary" {\n'
                '  name                         = "canary-sql-server"\n'
                '  administrator_login          = "sqladmin"\n'
                '  administrator_login_password = "not-a-real-secret"\n'
                '  version                      = "12.0"\n'
                "}\n"
            ),
        },
        expects=frozenset({"azure-mssql-publicly-accessible/missing-or-enabled"}),
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
            if resource_type != "azurerm_mssql_server":
                continue
            body_text = "\n".join(line for _, line in body)
            if pragma_present(_PRAGMA, body_text, dialect="hcl"):
                continue
            # Search a comment-blanked view (pragma already handled on the comment-only view above, #424) so a
            # commented `# public_network_access_enabled = false` can't suppress a finding on a
            # genuinely public server. Blank, don't drop, so nothing downstream shifts.
            code_body = "\n".join(
                "" if line.lstrip().startswith(("#", "//")) else line for _, line in body
            )
            if _PUBLIC_NETWORK_ACCESS_FALSE.search(code_body):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}:{start_line}",
                    message=(
                        f"`azurerm_mssql_server.{resource_name}` does not set "
                        "`public_network_access_enabled = false`. The Azure provider "
                        "defaults this attribute to `true`, so an omitted setting is the "
                        "more dangerous case: the server accepts connections from the "
                        "public internet, subject only to its firewall rules, and is a "
                        "direct target for brute-force and credential-stuffing attempts."
                    ),
                    remediation=(
                        "Add `public_network_access_enabled = false` and connect via a "
                        "private endpoint or VNet integration instead. Suppress an "
                        "audited exception (e.g. Azure AD-only auth plus a tight IP "
                        "allowlist) with `# security: allow-azure-mssql-public` anywhere "
                        "in the block."
                    ),
                    rule="azure-mssql-publicly-accessible/missing-or-enabled",
                    standards=list(_STANDARDS),
                )
            )
        return out
