---
type: Guard
title: "rds-storage-not-encrypted"
description: "RDS instance without encryption at rest."
timestamp: "2026-07-12T17:10:08+08:00"
guard_id: "rds-storage-not-encrypted"
checklist_section: ["7"]
standards: ["OWASP:A02", "SOC2:CC6.1"]
---

# RDS instance without encryption at rest

## What it detects

A Terraform `aws_db_instance` resource block that does not set `storage_encrypted = true`
anywhere in its body — whether the attribute is missing entirely or explicitly `false`.

## Why it matters

RDS storage encryption is opt-in, unlike most AWS resource encryption settings — the
`storage_encrypted` attribute defaults to `false` if never set at all. A database holding
customer data with disk-level encryption disabled means anyone with access to the underlying
storage layer (a snapshot, a volume backup, a misconfigured storage-layer IAM grant) reads the
raw data directly, no application-level bug required. checkov's own `CKV_AWS_16` check exists
specifically to catch this — and unlike a check that only flags an explicit `false`, missing
the attribute entirely is the more common real-world case (a developer who never thought about
it, not one who deliberately disabled it), which is why this guard treats "absent" and
"explicit false" identically.

## Detection scope

- Language: Terraform (`.tf`)
- Applies when: `"terraform" in profile.features`
- Scanned files: every `.tf` file under the repo root
- Uses the shared `iter_terraform_resources()` helper (`agentsec/guards/base.py`, added
  alongside `rds-publicly-accessible` in the same batch)
- Fires when an `aws_db_instance` resource block's full body text does NOT contain a match for
  `storage_encrypted\s*=\s*true` — an absence check across the whole block, not a per-line
  presence check, since the finding is "this attribute was never correctly set," not "this
  specific line is dangerous"

`aws_rds_cluster_instance` is deliberately NOT covered — checkov's own `CKV_AWS_16` scopes to
`aws_db_instance` only (Aurora cluster encryption is configured on the parent `aws_rds_cluster`
resource, a different attribute shape, out of scope for this first pass).

## Rules

| Rule ID | Severity | Trigger |
|---|---|---|
| `rds-storage-not-encrypted/missing-encryption` | HIGH | `aws_db_instance` block has no `storage_encrypted = true` anywhere in its body (excludes Aurora-engine instances, see below) |
| `rds-storage-not-encrypted/cluster-missing-encryption` | HIGH | `aws_rds_cluster` block has no `storage_encrypted = true` anywhere in its body (excludes `engine_mode = "serverless"` clusters and clusters created from a source, see below) |

**2026-10-25 (this session's extension):** two additions.

1. **Aurora-engine exclusion on `aws_db_instance`.** The original check fired on ANY
   `aws_db_instance` missing `storage_encrypted = true`, including an Aurora-engine instance
   (`engine` = `"aurora"`, `"aurora-mysql"`, or `"aurora-postgresql"`), although an Aurora
   instance doesn't control its own storage encryption at all; that attribute lives on the
   owning `aws_rds_cluster`. Such an instance is now skipped entirely by the
   `missing-encryption` rule. This is a rare shape: real Aurora instances are normally declared
   as `aws_rds_cluster_instance`, which this guard has never scanned, so the exclusion closes an
   edge case rather than a common false positive (PR #1162 round-1 M4).
2. **New `aws_rds_cluster.storage_encrypted` rule.** The original check never looked at cluster
   resources, leaving Aurora cluster storage encryption entirely uncovered (as noted under
   "Known bypasses" below, now partially closed). The new `cluster-missing-encryption` rule
   fires when `storage_encrypted` is absent or explicitly `false` on an `aws_rds_cluster`,
   unless the cluster's `engine_mode` attribute is exactly `"serverless"` (Aurora Serverless v1
   doesn't support configuring this attribute the same way, so it is excluded rather than
   guessed at). A cluster created from an existing source -- a `snapshot_identifier` restore,
   a `replication_source_identifier` replica, or a `restore_to_point_in_time { ... }` clone --
   takes its encryption from that source, which the file cannot see, so it is also excluded
   rather than guessed at (PR #1162 round-1 M4; it used to fire HIGH). Both rules share the
   existing `# security: allow-rds-unencrypted` pragma.

## Opt-out

`# security: allow-rds-unencrypted` anywhere in the resource block silences that block's
finding — block-scoped (matched against the whole body text), not file-level, since a file may
contain both a sensitive and a genuinely non-sensitive database.

## Known bypasses / false negatives

| Bypass | Why missed |
|---|---|
| `storage_encrypted = var.encrypt_storage` where the variable defaults to `true` elsewhere | Only a literal `true` is matched; variable-indirection requires resolving `variables.tf` |
| `aws_rds_cluster_instance` | Still deliberately out of scope — it's the cluster MEMBER resource, distinct from both `aws_db_instance` and `aws_rds_cluster`; encryption for it is governed by the parent `aws_rds_cluster`, now covered by `cluster-missing-encryption` |
| Aurora Serverless v1 clusters (`engine_mode = "serverless"`) | Excluded by the `cluster-missing-encryption` rule — that mode doesn't support configuring `storage_encrypted` the same way |
| An `aws_rds_cluster` restored from an unencrypted snapshot, or replicating an unencrypted source | Excluded: the cluster inherits the source's encryption, which this file cannot see. Firing would be a guess. The source must be a top-level attribute that is actually set: `= null`, `= ""` and a same-named `tags` key still fire (PR #1162 round-4 M1). A one-line cluster's source attribute is read the same as the multi-line form (round-5 M1) |
| `snapshot_identifier = var.snapshot_identifier` (the module-wrapper idiom) on a fresh cluster | Excluded: a non-literal source cannot be proven absent, so a variable that is `null` at apply time hides an unencrypted fresh cluster. The same non-literal convention as the rest of the batch |
| An `aws_db_instance` restored from a snapshot or created as a replica (`snapshot_identifier`, `replicate_source_db`) | Not excluded: the instance rule predates the cluster rule and still fires on it, the opposite trade-off (a possible false positive) left unchanged |
| A resource nested inside a `module` block passing `storage_encrypted` through a variable at the call site | The helper only sees the resource's own literal body |

## False positive scenarios

| Scenario | Why it fires | How to handle |
|---|---|---|
| A genuinely non-sensitive scratch/ephemeral test database | The guard cannot distinguish data sensitivity from resource declaration alone | Suppress with `# security: allow-rds-unencrypted` after confirming |

## Checklist mapping

`7-encryption-at-rest` (MANUAL → PARTIAL — this guard covers `aws_db_instance` Terraform
resources specifically; a database provisioned outside Terraform, or an Aurora cluster, is not
covered, so the item stays partial rather than flipping to covered). `applies_when` broadened
from `["sql"]` to `["sql", "terraform"]` so a Terraform-only stack (no ORM/SQL driver import
detected) still sees this item as applicable rather than N/A.

## Standards

- OWASP:A02 (Cryptographic Failures)
- CWE-311 (Missing Encryption of Sensitive Data)

## Related guards

- `rds-publicly-accessible`: same resource family, a different attribute (`publicly_accessible`
  vs `storage_encrypted`) — network exposure vs data-at-rest exposure, both closing gaps in the
  same previously-thin Terraform coverage area.

# Citations

[1] agentsec checklist item `7-encryption-at-rest` (§7)
[2] OWASP:A02
[3] SOC2:CC6.1
