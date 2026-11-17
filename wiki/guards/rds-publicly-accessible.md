---
type: Guard
title: "rds-publicly-accessible"
description: "RDS instance directly reachable from the internet."
timestamp: "2026-07-12T17:06:23+08:00"
guard_id: "rds-publicly-accessible"
checklist_section: ["7"]
standards: ["CWE-284", "OWASP:A05", "SOC2:CC6.6"]
---

# RDS instance directly reachable from the internet

## What it detects

A Terraform `aws_db_instance`, `aws_rds_cluster_instance`, or `aws_redshift_cluster` resource
block setting `publicly_accessible = true`.

**2026-10-25 (this session's extension):** added `aws_redshift_cluster` to the covered resource
types. Redshift uses the exact same `publicly_accessible` attribute name and the exact same
"fires when true" trigger logic as the RDS resource types above, so this was a one-line addition
to the resource-type set (`_RDS_RESOURCE_TYPES`) with no other detection-logic changes.

## Why it matters

`publicly_accessible = true` assigns the database a public IP reachable from the internet.
Combined with any permissive security-group rule (or simply the port being reachable once the
instance itself is public), this is one of the most common real-world causes of an exposed
production database — a class of misconfiguration checkov's own `CKV_AWS_17` check exists
specifically to catch. The Terraform AWS provider defaults this attribute to `false`, so an
explicit `true` is always a deliberate choice, not an accident of an unset default.

## Detection scope

- Language: Terraform (`.tf`)
- Applies when: `"terraform" in profile.features`
- Scanned files: every `.tf` file under the repo root
- Uses the shared `iter_terraform_resources()` helper (`agentsec/guards/base.py`) to isolate
  each `resource "type" "name" { ... }` block by brace-depth tracking from the resource's own
  opening line, then regex-searches only the lines inside a matching resource type
- Fires when a `resource "aws_db_instance" "..."`, `resource "aws_rds_cluster_instance" "..."`,
  or `resource "aws_redshift_cluster" "..."` block contains a line matching
  `publicly_accessible\s*=\s*true`

## Rules

| Rule ID | Severity | Trigger |
|---|---|---|
| `rds-publicly-accessible/public-instance` | HIGH | `aws_db_instance`/`aws_rds_cluster_instance`/`aws_redshift_cluster` block sets `publicly_accessible = true` |

## Opt-out

`# security: allow-rds-public` on the `publicly_accessible` line silences that one finding —
line-level, not file-level, since a file may legitimately contain both a public read-replica
and a private primary instance.

## Known bypasses / false negatives

| Bypass | Why missed |
|---|---|
| `publicly_accessible = var.is_public` where the variable defaults to `true` elsewhere | Only a literal `true` on the attribute line is matched; variable-indirection requires resolving `variables.tf`, out of scope for a single-file regex |
| A resource nested inside a `module` block that itself sets `publicly_accessible` via a passed-through variable at the call site, not inside the resource body | The helper only sees the resource's own literal body |
| `aws_rds_cluster` (the cluster resource itself, distinct from `aws_rds_cluster_instance`) does not carry `publicly_accessible` in the AWS provider schema — not a gap, just not applicable to that resource type |
| `aws_redshift_cluster` that omits `publicly_accessible` on AWS provider **v5 or earlier** | The default was `true` before v6 [5] and is `false` from v6 [6]. The guard assumes v6 and does not read the repo's `required_providers` pin, so an omitted attribute on a v5 pin is a public cluster it does not report. Firing on absence instead would be a mass false positive on v6 |

## False positive scenarios

| Scenario | Why it fires | How to handle |
|---|---|---|
| A deliberately public read-replica behind its own separate firewalling (a Lambda-only ingress rule, for example) | The guard cannot see cross-resource security-group scoping | Suppress with `# security: allow-rds-public` after confirming the network boundary |

## Checklist mapping

`7-rds-not-publicly-accessible` (new item, HIGH — no prior coverage; agentsec's Terraform
coverage before this guard was a single item, `6c-iac-open-ingress`, covering security-group
CIDR ranges only, not the database resource's own `publicly_accessible` flag)

## Standards

- OWASP:A05 (Security Misconfiguration)
- CWE-284 (Improper Access Control)

## Related guards

- `iac-open-ingress`: security-group `cidr_blocks` open to `0.0.0.0/0` — a different Terraform
  resource type (`aws_security_group`) and a different specific attribute; both close the same
  broad "internet-exposed cloud resource" family from different angles.

# Citations

[1] agentsec checklist item `7-rds-not-publicly-accessible` (§7)
[2] CWE-284
[3] OWASP:A05
[4] SOC2:CC6.6
[5] hashicorp/terraform-provider-aws v5.100.0, `aws_redshift_cluster` resource doc: "If true, the
cluster can be accessed from a public network. Default is `true`."
https://github.com/hashicorp/terraform-provider-aws/blob/v5.100.0/website/docs/r/redshift_cluster.html.markdown
[6] hashicorp/terraform-provider-aws, version 6 upgrade guide, `aws_redshift_cluster`:
"`publicly_accessible` now defaults to `false`."
https://github.com/hashicorp/terraform-provider-aws/blob/main/website/docs/guides/version-6-upgrade.html.markdown
