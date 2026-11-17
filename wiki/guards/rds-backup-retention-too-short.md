---
type: Guard
title: "rds-backup-retention-too-short"
description: "RDS/Aurora backup retention period is too short or unset."
timestamp: "2026-10-27T09:00:00Z"
guard_id: "rds-backup-retention-too-short"
checklist_section: ["7"]
standards: ["OWASP:A05"]
---

# RDS/Aurora backup retention period is too short or unset

_Author — 2026-10-25. Revised 2026-10-27 (review H3: the replica exclusion keyed on the wrong
attribute; fixed to `replicate_source_db`)._

---

## The threat

Automated backups are the only rollback path for a database after an accidental `DROP TABLE`, a
bad migration that silently corrupts rows, or a ransomware-style mass-write — but only as far
back as the configured retention window reaches. The Terraform AWS provider defaults
`backup_retention_period` to `0` on `aws_db_instance` when the attribute is never set —
automated backups disabled entirely, not merely a short window — and to `1` day on
`aws_rds_cluster`. Either way, the 7-day floor this guard checks for is this project's own
policy, not a provider default; a provider-default window is rarely enough time for anyone —
an engineer, an incident responder, a customer filing a support ticket — to notice the damage
and restore from a point before it happened. OWASP:A05 (Security Misconfiguration): the cloud
provider's secure-by-default behavior stops at "some backups exist," not "backups exist for
long enough to matter."

## Why it's often introduced

A database is provisioned to satisfy an immediate need and `backup_retention_period` is never
touched, because Terraform doesn't require it and the resource applies cleanly either way:

```hcl
resource "aws_db_instance" "app" {
  engine = "postgres"
  # no backup_retention_period -> AWS defaults it to 0 (backups disabled entirely)
}

resource "aws_rds_cluster" "app" {
  engine                  = "aurora-postgresql"
  backup_retention_period = 1   # set, but not long enough to matter for a real incident window
}
```

## Detection design

1. `applies()` gate — `"terraform" in profile.features`.
2. Scans every `.tf` file under the repo root via `iter_files(root, (".tf",))`, skipping
   non-product paths (`is_nonproduct_path`), using the shared `iter_terraform_resources()`
   helper to isolate each resource block.
3. Two resource types, each with its own rule:
   - **`aws_db_instance`** (rule `rds-backup-retention-too-short/db-instance`) — fires when
     `backup_retention_period` is absent, or present with a literal numeric value less than `7`,
     **unless** the instance is excluded:
     - a **read replica** (`replicate_source_db` is set anywhere in the block) — a replica
       inherits retention behavior from its source; its own setting is meaningless.
       (`source_db_instance_identifier` is a different attribute, used only inside a
       `restore_to_point_in_time { ... }` block on a point-in-time-restored primary — it does
       NOT mark a replica, and an earlier version of this guard wrongly keyed the exclusion on
       it, review H3.)
     - an **Aurora instance** (`engine` is literally `"aurora"`, `"aurora-mysql"`, or
       `"aurora-postgresql"`) — Aurora instances don't control their own backup retention; that
       is configured on the owning `aws_rds_cluster`, covered by the next rule.
   - **`aws_rds_cluster`** (rule `rds-backup-retention-too-short/rds-cluster`) — fires when
     `backup_retention_period` is absent, or present with a literal numeric value less than `7`.
     No exclusion: a cluster resource always controls its own retention directly.
4. Both exclusion checks and the trigger check read a comment-blind view of the block (whole-line
   `#`/`//` comments blanked) so a commented-out `engine = "aurora"` or
   `backup_retention_period = 1` can't participate.
5. `backup_retention_period` set to a non-literal expression (e.g. `var.retention`) is treated as
   "present, value unresolved" and does not fire — no expression evaluation, an accepted false
   negative consistent with every other regex/text-scoped Terraform guard in this codebase.
6. Inline opt-out, anywhere in the resource's own block, as a `#` comment:
   `# security: allow-rds-short-backup-retention`.
7. Severity: `medium` for both rules. Standards: `["OWASP:A05"]`.

## When NOT to flag

- A read replica (`replicate_source_db` set) with any `backup_retention_period` value,
  including absent or short — it isn't the replica's own setting that matters.
- An Aurora-engine `aws_db_instance` with any `backup_retention_period` value — the real control
  is on the parent `aws_rds_cluster`.
- `backup_retention_period` set to `7` or higher on either resource type.
- An audited exception, suppressed with `# security: allow-rds-short-backup-retention` anywhere
  in the resource block.

## Tests

| Test | What it checks |
|---|---|
| `test_db_instance_missing_retention_fires` | Positive: absent attribute on a plain `aws_db_instance` fires. |
| `test_db_instance_short_retention_fires` | Positive: explicit short value fires. |
| `test_db_instance_sufficient_retention_silent` | FP-bait: `backup_retention_period = 7` → silent. |
| `test_db_instance_aurora_engine_missing_retention_stays_silent` | FP-bait: Aurora-engine instance, attribute absent → silent (proves the exclusion). |
| `test_db_instance_aurora_engine_short_retention_stays_silent` | FP-bait: Aurora-engine instance, explicit short value → still silent. |
| `test_db_instance_read_replica_short_retention_stays_silent` | FP-bait: read replica, explicit short value → silent. |
| `test_db_instance_read_replica_missing_retention_stays_silent` | FP-bait: read replica, attribute absent → silent. |
| `test_db_instance_point_in_time_restore_source_attribute_still_fires` | Positive: `source_db_instance_identifier` inside `restore_to_point_in_time` does NOT trigger the replica exclusion (review H3). |
| `test_rds_cluster_missing_retention_fires` | Positive: absent attribute on `aws_rds_cluster` fires. |
| `test_rds_cluster_short_retention_fires` | Positive: explicit short value on a cluster fires. |
| `test_rds_cluster_sufficient_retention_silent` | FP-bait: `backup_retention_period = 7` on a cluster → silent. |
| `test_rds_cluster_high_retention_silent` | FP-bait: a much longer window → silent. |
| `test_pragma_silences_db_instance` / `test_pragma_silences_rds_cluster` | Suppress pragma → silent. |
| `test_applies_gate` / `test_applies_with_terraform` | `applies()` gate. |

## Known bypasses

- **Variable/expression indirection**: `backup_retention_period = var.retention` where the
  variable resolves to a short value elsewhere — only a literal integer on the attribute is
  matched.
- **A resource nested inside a `module` block** passing `backup_retention_period` through at the
  call site, not inside the resource's own body — only the resource's own literal body is
  inspected.
- **Aurora Global Database secondary clusters**, which don't carry their own
  `backup_retention_period` the same way a standalone cluster does — not specifically modeled;
  such a cluster is scanned the same as any other `aws_rds_cluster`.

## What this guard does NOT prove

A silent guard does not confirm the applied infrastructure matches the source (drift), that the
value wasn't overridden via `-var`/`terraform.tfvars` at apply time in a way this static text
can't see, or that a resource provisioned outside Terraform (console, CloudFormation, another IaC
tool) carries the same configuration. It also doesn't evaluate whether the retention window is
long enough for a *specific* team's incident-response process — `7` days is a conservative,
checklist-wide floor, not a tuned recommendation for every workload.

# Citations

[1] agentsec checklist item `7-rds-backup-retention-too-short` (§7)
[2] OWASP:A05
