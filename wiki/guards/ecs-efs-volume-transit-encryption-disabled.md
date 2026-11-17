---
type: Guard
title: "ecs-efs-volume-transit-encryption-disabled"
description: "Terraform aws_ecs_task_definition volume mounting EFS via efs_volume_configuration without transit_encryption enabled."
timestamp: "2026-10-25T09:00:00Z"
guard_id: "ecs-efs-volume-transit-encryption-disabled"
checklist_section: ["7"]
standards: ["OWASP:A05", "CWE-319"]
---

# ECS task's EFS volume mount is not encrypted in transit

_Author — 2026-10-25_

---

## The threat

An ECS task's `volume` block can mount an EFS file system via a nested
`efs_volume_configuration` sub-block. That sub-block's `transit_encryption` attribute
controls whether the NFS traffic between the ECS task and the EFS mount target is wrapped in
TLS. Terraform/AWS defaults this to `"DISABLED"` when omitted, so an unencrypted EFS mount is
silent at `terraform apply` time: anyone positioned on the network path between the task's
ENI and the EFS mount target (another workload in the same VPC, a compromised sidecar, a
misconfigured security-group-based "trusted subnet" assumption) reads the file contents and
any traffic metadata in the clear. CWE-319 (Cleartext Transmission of Sensitive Information),
OWASP:A05.

## Why it's often introduced

A task definition is wired up to mount a shared EFS file system (for shared config, uploads,
or a cache) and `transit_encryption` is simply never set, since `terraform apply` succeeds
without it:

```hcl
resource "aws_ecs_task_definition" "app" {
  family = "app"

  volume {
    name = "efs-mount"

    efs_volume_configuration {
      file_system_id = aws_efs_file_system.app.id
      # no transit_encryption -> defaults to DISABLED
    }
  }
}
```

A task definition can declare multiple `volume` blocks (one task can mount several file
systems); this guard checks each independently and fires once per offending block.

## Detection design

1. `applies()` gate — `"terraform" in profile.features`.
2. Scans every `.tf` file under the repo root via `iter_files(root, (".tf",))`, skipping
   non-product paths (`is_nonproduct_path`).
3. Uses the shared `iter_terraform_resources()` helper to isolate `aws_ecs_task_definition`
   blocks.
4. Within each task definition's body, matches every top-level `volume { ... }` block with a
   brace-aware regex that tolerates up to two levels of nested braces (covering the real-world
   `efs_volume_configuration { ... authorization_config { ... } }` shape, not just the simpler
   one-level form this guard actually checks).
5. For each `volume` block, looks for a nested `efs_volume_configuration { ... }` sub-block. A
   `volume` block with **no** `efs_volume_configuration` at all (a plain Docker/host volume) is
   not EFS-backed and is skipped — out of scope for this guard.
6. For a `volume` block that **is** EFS-backed, fires when the `efs_volume_configuration`
   sub-block's `transit_encryption` attribute is absent, or explicitly set to the literal
   string `"DISABLED"`. Any other explicit value (in practice, `"ENABLED"`) silences it.
7. Inline opt-out, anywhere in the `aws_ecs_task_definition` resource's own block:
   `# security: allow-ecs-efs-plaintext`.
8. Severity: `medium`. Rule id: `ecs-efs-volume-transit-encryption-disabled/missing-encryption`.
   Standards: `["OWASP:A05", "CWE-319"]`.

## When NOT to flag

- A `volume` block with no `efs_volume_configuration` sub-block (a plain Docker/host volume).
- `transit_encryption = "ENABLED"` set explicitly inside the `efs_volume_configuration` block.
- An audited case, suppressed with `# security: allow-ecs-efs-plaintext` anywhere in the
  `aws_ecs_task_definition` resource's own block.

## Tests

| Test | What it checks |
|---|---|
| `test_missing_transit_encryption_fires` | Positive: no `transit_encryption` attribute fires. |
| `test_explicit_disabled_fires` | Positive: `transit_encryption = "DISABLED"` fires. |
| `test_enabled_silent` | FP-bait: `transit_encryption = "ENABLED"` → silent. |
| `test_non_efs_volume_silent` | FP-bait: a plain volume with no `efs_volume_configuration` → silent. |
| `test_multiple_volumes_each_checked_independently` | Multiple `volume` blocks in one task definition are each judged on their own — a good volume and a plain volume don't silence the bad one. |
| `test_pragma_silences` | Suppress pragma → silent. |
| `test_applies_gate` / `test_applies_with_terraform` | `applies()` gate. |

## Known bypasses

- **Variable/expression indirection**: `transit_encryption = var.transit_mode` is not
  resolved — only a literal `"DISABLED"`/absent-attribute check is performed.
- **Deep nesting beyond two brace levels**: the volume-block matcher tolerates up to two
  levels of nested braces inside `volume { ... }`; a hypothetical third level of nesting
  inside `efs_volume_configuration` (none exists in the real provider schema today) would not
  be resolved correctly.
- **A resource nested inside a `module` block** passing these attributes through at the call
  site — only the resource's own literal body is inspected.

## What this guard does NOT prove

A silent guard does not confirm the applied infrastructure matches the source (drift), that
an attribute wasn't overridden via `-var`/`terraform.tfvars` at apply time in a way this
static text can't see, or that a resource provisioned outside Terraform (console,
CloudFormation, another IaC tool) carries the same configuration. This is a presence-based,
source-only check.

# Citations

[1] agentsec checklist item `7-ecs-efs-volume-transit-encryption-disabled-missing-encryption` (§7)
[2] OWASP:A05
[3] CWE-319
