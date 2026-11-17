---
type: Guard
title: "s3-public-access-block-disabled"
description: "S3 public-access-block control not enforced."
timestamp: "2026-07-12T17:13:43+08:00"
guard_id: "s3-public-access-block-disabled"
checklist_section: ["6a"]
standards: ["CWE-284", "OWASP:A05", "SOC2:CC6.6"]
---

# S3 public-access-block control not enforced

## What it detects

A Terraform `aws_s3_bucket_public_access_block` resource block that sets any of the four
Block Public Access controls (`block_public_acls`, `block_public_policy`, `ignore_public_acls`,
`restrict_public_buckets`) to `false`.

## Why it matters

AWS's S3 Block Public Access feature exists specifically so a later accidental public ACL or
bucket policy can't actually make a bucket public — each of the four controls independently
closes one path to that outcome. Explicitly disabling one re-opens that specific path, which is
how a large share of real-world S3 data leaks happen: a developer (or a later teammate)
accidentally applies a public ACL or an over-permissive bucket policy, and with Block Public
Access fully enabled, AWS itself refuses to honor it — with a control disabled, nothing stops
it. checkov's own `CKV_AWS_53`/`CKV_AWS_54`/`CKV_AWS_55`/`CKV_AWS_56` checks exist one per
attribute; this guard covers all four with a single detection pattern.

## Detection scope

- Language: Terraform (`.tf`)
- Applies when: `"terraform" in profile.features`
- Scanned files: every `.tf` file under the repo root
- Uses the shared `iter_terraform_resources()` helper (`agentsec/guards/base.py`)
- Fires per-control inside an `aws_s3_bucket_public_access_block` block: each of the four
  controls (`block_public_acls`, `block_public_policy`, `ignore_public_acls`,
  `restrict_public_buckets`) that is not *explicitly* enabled — set to `false` OR omitted.

**The Terraform AWS provider defaults all four controls to `false`** (unlike the AWS Console,
which defaults new buckets to all-on). So an *omitted* control is just as unprotected as an
explicit `= false` — the common real-world mistake is a block that sets only `bucket` and none
of the four controls, silently providing no protection. This guard therefore flags each control
that is not explicitly `true`. A control set to `true`, or to a non-literal value such as a
variable/expression (which this guard can't evaluate and conservatively treats as addressed),
does not fire. (This corrects the guard's original backwards assumption that silence was safe —
it is not.)

## Rules

| Rule ID | Severity | Trigger |
|---|---|---|
| `s3-public-access-block-disabled/control-disabled` | HIGH | Any of the four Block Public Access controls not explicitly enabled — set to `false` or omitted (both default to `false`) |

## Opt-out

`# security: allow-s3-public-access` anywhere in the resource block silences the whole resource —
resource-level rather than per-line, because an omitted control has no line of its own to anchor
a pragma to. Use it for a deliberately public bucket (e.g. static-asset hosting).

## Known bypasses / false negatives

| Bypass | Why missed |
|---|---|
| `block_public_acls = var.allow_public` where the variable defaults to `false` elsewhere | Only a literal `false` on the attribute line is matched; variable-indirection is out of scope |
| No `aws_s3_bucket_public_access_block` resource exists for a bucket at all | This guard only checks blocks that exist and are misconfigured — a bucket with NO block at all (defaulting to AWS's own account-level defaults, which may or may not be locked down) is a different, cross-resource-correlation check checkov itself needs its graph engine for; out of scope here |
| A resource nested inside a `module` block passing the attribute through a variable at the call site | The helper only sees the resource's own literal body |

## False positive scenarios

| Scenario | Why it fires | How to handle |
|---|---|---|
| A deliberately public static-website or public-asset bucket | The guard cannot distinguish "deliberately public" from "accidentally public" from resource declaration alone | Suppress the specific disabled attribute(s) with `# security: allow-s3-public-access` after confirming the bucket's public exposure is intentional and scoped |

## Checklist mapping

`6a-s3-public-access-block-disabled` (new item, HIGH — no prior coverage)

## Standards

- OWASP:A05 (Security Misconfiguration)
- CWE-284 (Improper Access Control)

## Related guards

- `rds-publicly-accessible` / `rds-storage-not-encrypted`: same batch, same "thin Terraform
  coverage" gap, different resource family (RDS vs S3).
- `s3-bucket-policy-wildcard-principal`: same S3 resource family, a different attack surface
  (an over-permissive bucket *policy* itself, vs the account-level safety net that should catch
  one even if it exists).

# Citations

[1] agentsec checklist item `6a-s3-public-access-block-disabled` (§6a)
[2] CWE-284
[3] OWASP:A05
[4] SOC2:CC6.6
