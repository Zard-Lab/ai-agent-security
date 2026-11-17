---
type: Guard
title: "kms-key-disabled"
description: "KMS key explicitly disabled."
timestamp: "2026-07-15T13:31:12+08:00"
guard_id: "kms-key-disabled"
checklist_section: ["7"]
standards: ["OWASP:A05", "SOC2:CC6.1"]
---

# KMS key explicitly disabled

## What it detects

A Terraform `aws_kms_key` resource block setting `is_enabled = false`.

## Why it matters

A disabled KMS key can no longer perform any cryptographic operation. Any resource still
configured to encrypt or decrypt with it — S3 bucket encryption, RDS storage encryption,
Secrets Manager, or application-level envelope encryption — breaks the moment the key state
takes effect, and any data already encrypted under it becomes unreadable until the key is
re-enabled. This is a real-world availability/key-management failure mode checkov's own
`CKV_AWS_227` check exists specifically to catch. The Terraform AWS provider defaults
`is_enabled` to `true`, so an explicit `false` is always a deliberate choice, not an accident
of an unset default — this is why checkov's real check uses
`missing_block_result=CheckResult.PASSED`: an omitted attribute is explicitly treated as safe.

## Detection scope

- Language: Terraform (`.tf`)
- Applies when: `"terraform" in profile.features`
- Scanned files: every `.tf` file under the repo root
- Uses the shared `iter_terraform_resources()` helper (`agentsec/guards/base.py`) to isolate
  each `resource "type" "name" { ... }` block by brace-depth tracking from the resource's own
  opening line, then regex-searches only the lines inside a matching resource type
- Fires when a `resource "aws_kms_key" "..."` block contains a line matching
  `is_enabled\s*=\s*false` — a per-line presence check, not a whole-block absence check, since
  an omitted `is_enabled` is the safe (enabled-by-default) state, not the risk. This mirrors
  `rds-publicly-accessible`'s "only an explicit literal fires" shape, not
  `rds-storage-not-encrypted`'s "absence is also a finding" shape — the two sibling patterns
  diverge here because AWS's own default differs per attribute (RDS storage encryption
  defaults to off; a KMS key's enabled state defaults to on).

## Rules

| Rule ID | Severity | Trigger |
|---|---|---|
| `kms-key-disabled/explicitly-disabled` | LOW | `aws_kms_key` block sets `is_enabled = false` |

## Opt-out

`# security: allow-kms-key-disabled` on the `is_enabled` line silences that one finding —
line-level, not file-level, since a file may legitimately contain both an active key and a
deliberately retired one kept only for decrypt-only historical access review.

## Known bypasses / false negatives

| Bypass | Why missed |
|---|---|
| `is_enabled = var.key_enabled` where the variable defaults to `false` elsewhere | Only a literal `false` on the attribute line is matched; variable-indirection requires resolving `variables.tf`, out of scope for a single-file regex |
| A resource nested inside a `module` block that itself sets `is_enabled` via a passed-through variable at the call site, not inside the resource body | The helper only sees the resource's own literal body |
| A key disabled out-of-band via the AWS Console or CLI after being provisioned enabled by Terraform | Static analysis only sees the declared configuration, not live AWS state |

## False positive scenarios

| Scenario | Why it fires | How to handle |
|---|---|---|
| A deliberately retired key kept disabled on purpose (e.g. during a key-rotation migration window, or for compliance/audit retention of a decrypt-only historical key) | The guard cannot distinguish "disabled by design" from "disabled by mistake" from static config alone | Suppress with `# security: allow-kms-key-disabled` after confirming the retirement is intentional |

## Checklist mapping

Not yet mapped into `agentsec/checklist/checklist.json` — out of scope for this change (guard,
tests, and design doc only). A follow-up pass should map this to a `§7` (Database Security /
key-management) checklist item alongside the other checkov-sourced Terraform guards.

## Standards

- OWASP:A05 (Security Misconfiguration)
- CWE-320 (Key Management Errors)

## Related guards

- `rds-storage-not-encrypted`: same Terraform-resource-family shape (checkov-sourced,
  single-attribute AWS config check), but the inverse omission semantics — that guard treats a
  missing attribute as unsafe (AWS defaults storage encryption off), while this guard treats a
  missing attribute as safe (AWS defaults key state to enabled).
- `rds-publicly-accessible`: the direct structural sibling — both fire only on an explicit
  literal value inside a scoped resource block, using the same `iter_terraform_resources()`
  helper and the same "presence of a dangerous literal, not absence of a safe one" logic.

# Citations

[1] agentsec checklist item `7-kms-key-disabled` (§7)
[2] OWASP:A05
[3] SOC2:CC6.1
