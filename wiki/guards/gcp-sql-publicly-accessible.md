---
type: Guard
title: "gcp-sql-publicly-accessible"
description: "GCP Cloud SQL instance reachable from the internet (public IP with no restriction, or a 0.0.0.0 authorized network)."
timestamp: "2026-09-05T00:00:00Z"
guard_id: "gcp-sql-publicly-accessible"
checklist_section: ["7"]
standards: ["OWASP:A05", "CWE-284", "SOC2:CC6.6"]
---

# GCP Cloud SQL instance reachable from the internet

_Author — 2026-09-05_

---

## The threat

A `google_sql_database_instance`'s `settings.ip_configuration` block controls whether the
instance has a public IP at all, and — if it does — what may reach it. `ipv4_enabled` defaults
to `true` when the block or the attribute is omitted, meaning an instance provisioned without
ever touching `ip_configuration` gets a public IP by default. An `authorized_networks` entry of
`0.0.0.0/0` (or any range that includes it) then allowlists every IPv4 address on the internet
to attempt a connection, subject only to database-level authentication — a direct target for
credential-stuffing and brute-force attacks against the database. CWE-284 (Improper Access
Control), OWASP:A05 (Security Misconfiguration).

## Why this guard fits the stack

A GCP-hosted Postgres/MySQL backend for a FastAPI + React app provisioned via
`google_sql_database_instance` needs this locked down the same way an AWS RDS instance does —
but the GCP shape is nested (`settings.ip_configuration`) rather than a single top-level
attribute, and the safe-by-default assumption fails the same way it does for Azure SQL: the
permissive value is the DEFAULT, not something a developer has to opt into.

```hcl
resource "google_sql_database_instance" "app" {
  name             = "app-db"
  database_version = "POSTGRES_15"
  settings {
    tier = "db-f1-micro"
    # no ip_configuration block at all -> ipv4_enabled defaults to true, unrestricted
  }
}
```

Sourced from KICS's `sql_db_instance_is_publicly_accessible` query, verified against the real
fetched `query.rego`: four separate CxPolicy rules cover the sub-cases below. This guard
implements three of them — the fourth (a data-source-driven or otherwise dynamically generated
`authorized_networks` value) is not resolvable statically and is a documented bypass, the same
class of limitation as every other literal-Terraform-text guard in this codebase.

## Detection design

1. `applies()` gate: `"terraform" in profile.features`.
2. Scanned files: every `.tf` file under the repo root (via `iter_files(root, (".tf",))`),
   skipping non-product paths (`is_nonproduct_path`).
3. Uses `iter_terraform_resources()` to isolate `google_sql_database_instance` blocks. A local
   helper, `_nested_block_bodies()`, extracts the balanced-brace body text of a named nested
   block (`settings`, then `ip_configuration` within it, then `authorized_networks` within
   that) — a plain depth counter, not string-aware, sufficient because none of the attribute
   values this guard inspects legitimately contain a brace character. Three rules are checked
   in order, each returning its own rule id (a multi-rule guard, same shape as `ai-docker`):
   - `authorized-network-wildcard`: any `authorized_networks { ... }` block whose body contains
     the literal substring `0.0.0.0` fires — checked FIRST, independent of `ipv4_enabled`, since
     an internet-wide allowlist is dangerous regardless of what else is configured.
   - `public-ip-no-restriction`: `ipv4_enabled = true` is explicitly set, AND no
     `private_network` attribute is present, AND no `authorized_networks` block exists at all.
   - `missing-ip-configuration`: the `ip_configuration` block (or its enclosing `settings`
     block) is missing entirely from the resource — the GCP default applies with no
     restriction configured.
4. Inline opt-out pragma: `# security: allow-gcp-sql-public` anywhere in the resource block.
5. Severity: HIGH (all three rules). Rule ids:
   `gcp-sql-publicly-accessible/authorized-network-wildcard`,
   `gcp-sql-publicly-accessible/public-ip-no-restriction`,
   `gcp-sql-publicly-accessible/missing-ip-configuration`. Standards:
   `["OWASP:A05", "CWE-284"]`.

## When NOT to flag

An instance with `private_network` set (VPC peering, whether or not `ipv4_enabled` is also
true) does not fire — that is the deliberate, safe pattern for exposing a Cloud SQL instance
only inside a private network. An instance with a narrow, specific `authorized_networks` entry
(a single office IP, `/32`) and no `0.0.0.0` anywhere also stays silent — that is the intended
use of the allowlist. The pragma exists for a genuinely-audited exception, e.g. a deliberately
public read-replica with its own compensating controls (strict auth, network-layer WAF) —
narrow and rare, but real.

## Tests

| Test | What it checks |
|---|---|
| `test_gcp_sql_publicly_accessible_flags_authorized_network_wildcard` | an `authorized_networks` entry with `value = "0.0.0.0/0"` fires |
| `test_gcp_sql_publicly_accessible_flags_authorized_network_wildcard_among_many` | a `0.0.0.0/0` entry mixed among other, narrower `authorized_networks` blocks still fires |
| `test_gcp_sql_publicly_accessible_flags_public_ip_no_restriction` | `ipv4_enabled = true` alone, no `private_network`/`authorized_networks`, fires |
| `test_gcp_sql_publicly_accessible_flags_missing_ip_configuration` | a `settings` block with no `ip_configuration` sub-block fires |
| `test_gcp_sql_publicly_accessible_flags_missing_settings_block` | no `settings` block at all fires the same missing-ip-configuration rule |
| `test_gcp_sql_publicly_accessible_silent_with_private_network` | `ipv4_enabled = true` with `private_network` set stays silent |
| `test_gcp_sql_publicly_accessible_silent_with_narrow_authorized_network` | a narrow, specific `authorized_networks` entry with no `0.0.0.0` stays silent |
| `test_gcp_sql_publicly_accessible_silent_ipv4_disabled` | `ipv4_enabled = false` with `private_network` set stays silent |
| `test_gcp_sql_publicly_accessible_silent_other_resource` | a non-`google_sql_database_instance` resource is not scoped in |
| `test_gcp_sql_publicly_accessible_silent_comment_mention` | a commented-out `0.0.0.0/0` `authorized_networks` block does NOT fire |
| `test_gcp_sql_publicly_accessible_pragma_silences` | `# security: allow-gcp-sql-public` in the block suppresses an otherwise-firing violation |
| `test_gcp_sql_publicly_accessible_applies_gate` | `applies()` is `False` without `"terraform"` in `profile.features` |
| `test_gcp_sql_publicly_accessible_applies_with_terraform` | `applies()` is `True` with `"terraform"` in `profile.features` |

## Known bypasses

- **`ipv4_enabled` omitted (not explicitly `true`) with a present `ip_configuration` block and
  no `private_network`/`authorized_networks`**: GCP's own default still assigns a public IP
  here, but rule 2 requires the literal token `true` (matching KICS's own rego rule shape) —
  an instance that omits `ipv4_enabled` entirely inside an otherwise-empty `ip_configuration`
  block is a documented false negative.
- **Indirection via a variable/local/data source**: `authorized_networks { value =
  var.allowed_cidr }`, or a `dynamic "authorized_networks"` block built from a `for_each` over
  an external list — the literal `0.0.0.0` never appears as static text, so the scan misses it.
  This is the fourth KICS CxPolicy rule (a data-source-driven check) that this guard does not
  implement, since it requires resolving values outside the Terraform source text.
- **`private_network` referencing a network that itself allows 0.0.0.0/0 ingress** (a VPC
  firewall misconfiguration) is out of scope — this guard only inspects the SQL instance
  resource's own attributes, not the referenced network's firewall rules.

## What this guard does NOT prove

A silent guard proves only that the scanned `.tf` files do not contain the three static
patterns above on this resource. It does not evaluate VPC firewall rules on a referenced
`private_network`, does not resolve variable/local/data-source indirection, and does not
inspect the *effective* configuration of the live GCP Cloud SQL instance (drift between
Terraform state and reality is out of scope for any static guard in this codebase).

## Checklist mapping

`7-gcp-sql-publicly-accessible` (§7).

## Standards

- OWASP:A05 (Security Misconfiguration)
- CWE-284 (Improper Access Control)

## Related guards

- `rds-publicly-accessible`: the AWS analog — a single top-level `publicly_accessible`
  attribute rather than a nested `settings.ip_configuration` block.
- `azure-mssql-publicly-accessible`: the Azure analog, from the same KICS batch.
- `gcp-kms-key-public`: the same "GCP resource left reachable by an over-broad grant" shape,
  applied to a KMS key's/Storage bucket's IAM policy instead of a Cloud SQL instance's network
  configuration.

# Citations

[1] agentsec checklist item `7-gcp-sql-publicly-accessible` (§7)
[2] OWASP:A05
[3] CWE-284
