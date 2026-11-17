---
type: Guard
title: "azure-mssql-publicly-accessible"
description: "Azure SQL Server directly reachable from the internet (public_network_access_enabled not false)."
timestamp: "2026-09-05T00:00:00Z"
guard_id: "azure-mssql-publicly-accessible"
checklist_section: ["7"]
standards: ["OWASP:A05", "CWE-284", "SOC2:CC6.6"]
---

# Azure SQL Server directly reachable from the internet

_Author — 2026-09-05_

---

## The threat

`public_network_access_enabled` gates whether an `azurerm_mssql_server` accepts connections
from the public internet at all — before any firewall rule on the server is even evaluated.
Unlike AWS RDS's `publicly_accessible` (which defaults to `false`), the Azure Terraform
provider's default for this attribute is `true`. A server that never sets it is therefore
reachable from any IP address that also clears the server's firewall rules — and plenty of
real-world Terraform never configures any firewall rule at all, leaving the whole SQL Server
exposed directly to the internet for brute-force and credential-stuffing attempts against its
admin login. CWE-284 (Improper Access Control), OWASP:A05 (Security Misconfiguration).

## Why this guard fits the stack

A FastAPI + React app deployed on Azure with an Azure SQL backend provisions its server via
`azurerm_mssql_server`, and this is exactly the kind of "opposite-of-AWS default" mistake this
class of guard exists to catch — someone porting an RDS Terraform module to Azure and assuming
the same safe-by-default behavior gets a publicly reachable database instead:

```hcl
resource "azurerm_mssql_server" "app" {
  name                         = "app-sql-server"
  administrator_login          = "sqladmin"
  administrator_login_password = var.sql_admin_password
  version                      = "12.0"
  # no public_network_access_enabled attribute at all -> defaults to true
}
```

Sourced from KICS's `mssql_server_public_network_access_enabled` query, verified against the
real fetched `query.rego`: two separate CxPolicy rules cover the missing-attribute case and the
explicit `== true` case respectively. This guard mirrors both in one check, the same "omitted OR
explicit-unsafe-value, both fire" shape as `rds-publicly-accessible`.

## Detection design

1. `applies()` gate: `"terraform" in profile.features`.
2. Scanned files: every `.tf` file under the repo root (via `iter_files(root, (".tf",))`),
   skipping non-product paths (`is_nonproduct_path`).
3. Uses `iter_terraform_resources()` to isolate `azurerm_mssql_server` blocks. Within each such
   block, a comment-blanked view of the body is searched for
   `public_network_access_enabled = false` (regex
   `\bpublic_network_access_enabled\s*=\s*false\b`); if not found — whether because the
   attribute is missing entirely, or present as `true` — the resource fires.
4. Inline opt-out pragma: `# security: allow-azure-mssql-public` anywhere in the resource block.
5. Severity: HIGH. Rule id: `azure-mssql-publicly-accessible/missing-or-enabled`. Standards:
   `["OWASP:A05", "CWE-284"]`.

## When NOT to flag

A resource that explicitly sets `public_network_access_enabled = false` does not fire — the
server only accepts connections via a private endpoint or VNet integration. The pragma exists
for a genuinely-audited exception, e.g. a server intentionally reachable from the internet but
locked to Azure AD-only authentication plus a tight IP allowlist on the firewall rules — narrow
and rare, but real.

## Tests

| Test | What it checks |
|---|---|
| `test_azure_mssql_publicly_accessible_flags_missing_attribute` | no `public_network_access_enabled` attribute at all fires |
| `test_azure_mssql_publicly_accessible_flags_explicit_true` | `public_network_access_enabled = true` fires |
| `test_azure_mssql_publicly_accessible_silent_when_explicitly_false` | `public_network_access_enabled = false` stays silent |
| `test_azure_mssql_publicly_accessible_silent_other_resource` | a non-`azurerm_mssql_server` resource carrying the same attribute name is not scoped in |
| `test_azure_mssql_publicly_accessible_silent_comment_mention` | a commented-out `# public_network_access_enabled = false` does NOT suppress a real missing-attribute finding |
| `test_azure_mssql_publicly_accessible_pragma_silences` | `# security: allow-azure-mssql-public` in the block suppresses an otherwise-firing violation |
| `test_azure_mssql_publicly_accessible_applies_gate` | `applies()` is `False` without `"terraform"` in `profile.features` |
| `test_azure_mssql_publicly_accessible_applies_with_terraform` | `applies()` is `True` with `"terraform"` in `profile.features` |

## Known bypasses

- **Indirection via a variable/local**: `public_network_access_enabled = var.public_ok` — the
  literal `false` never appears in the resource block itself, so the scan misses it.
- A **firewall rule that in practice restricts access to nothing** (e.g. a deliberately
  unsatisfiable `azurerm_mssql_firewall_rule`) is not evaluated by this guard — it only inspects
  the server resource's own attribute, not the firewall rules attached to it.

## What this guard does NOT prove

A silent guard proves only that the scanned `.tf` files contain
`public_network_access_enabled = false` on this resource. It does not evaluate the server's
firewall rules, private endpoint configuration, or VNet integration, does not resolve
variable/local indirection, and does not inspect the *effective* setting in the live Azure
subscription (drift between Terraform state and reality is out of scope for any static guard in
this codebase).

## Checklist mapping

`7-azure-mssql-publicly-accessible` (§7).

## Standards

- OWASP:A05 (Security Misconfiguration)
- CWE-284 (Improper Access Control)

## Related guards

- `rds-publicly-accessible`: the AWS analog — `publicly_accessible = true` on an
  `aws_db_instance`, but with the OPPOSITE safe default (AWS defaults to `false`, Azure to
  `true`), which is exactly why this guard could not simply reuse that one's logic.
- `gcp-sql-publicly-accessible`: the GCP analog for `google_sql_database_instance`, from the
  same KICS batch.

# Citations

[1] agentsec checklist item `7-azure-mssql-publicly-accessible` (§7)
[2] OWASP:A05
[3] CWE-284
