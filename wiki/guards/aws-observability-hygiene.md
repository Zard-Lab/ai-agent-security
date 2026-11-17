---
type: Guard
title: "aws-observability-hygiene"
description: "AWS Terraform resource missing an observability or durability hygiene control (CloudWatch retention, S3 versioning, S3 access logging)."
timestamp: "2026-08-24T09:00:00Z"
guard_id: "aws-observability-hygiene"
checklist_section: ["7"]
standards: ["OWASP:A05", "OWASP:A09", "CWE-693", "CWE-778"]
---

# AWS Terraform resource missing an observability or durability hygiene control

_Author — 2026-08-24_

---

## The threat

_**2026-10-25 (this session's extension):** added a fourth, independent CloudWatch rule — see
"Detection design" point 9 and "Tests" below for the full description. It does not change any of
the three rules documented in this section._

Three independent missing-config gaps, bundled into one guard because they share the same
root cause (an attribute Terraform's AWS provider leaves unset by default, with no error or
warning to flag the omission):

1. **CloudWatch log group with no `retention_in_days`.** The provider leaves retention
   unset by default, and CloudWatch treats that as "never expire." Logs accumulate
   indefinitely — an unbounded storage cost (CloudWatch Logs bills per GB-month with no
   automatic cap) and a compliance gap for any framework requiring a documented, bounded
   retention window. CWE-778 (Insufficient Logging), OWASP:A09.
2. **S3 bucket with no versioning enabled.** Without versioning, an accidental delete, an
   accidental overwrite, or a ransomware-style mass-encrypt of the bucket's objects has no
   rollback path — the previous object version is simply gone. CWE-693 (Protection
   Mechanism Failure), OWASP:A05.
3. **S3 bucket with no access logging.** With no server-access-log audit trail, there is no
   record of who read, wrote, or deleted objects in the bucket — exactly the record an
   incident response needs after a suspected breach. CWE-778 (Insufficient Logging),
   OWASP:A09.

## Why it's often introduced

A bucket or log group is provisioned to satisfy an immediate need (store app logs, hold
uploaded files) and none of the three attributes is required for `terraform apply` to
succeed, so the omission is silent:

```hcl
resource "aws_cloudwatch_log_group" "app" {
  name = "/app/logs"
  # no retention_in_days -> CloudWatch treats this as "never expire"
}

resource "aws_s3_bucket" "data" {
  bucket = "app-data"
  # no versioning block, no logging block, and no split-resource form anywhere
}
```

Sourced from `iac-security-scanner`'s `TF_AWS_LOG_003/004/005` rules (`TF_AWS_LOG_001/002`,
CloudTrail validation/multi-region, are a different concern already covered by
`cloudtrail_logging_disabled.py` — confirmed by reading that guard before building this one,
no overlap).

## Detection design

1. `applies()` gate — `"terraform" in profile.features`.
2. Scans every `.tf` file under the repo root via `iter_files(root, (".tf",))`, skipping
   non-product paths (`is_nonproduct_path`).
3. Uses the shared `iter_terraform_resources()` helper to isolate `aws_cloudwatch_log_group`,
   `aws_s3_bucket`, `aws_s3_bucket_versioning`, and `aws_s3_bucket_logging` blocks. All four
   resource types are gathered across **every** `.tf` file in the repo before matching, not
   scoped to one file — because the Terraform AWS provider v4+ split-resource form (a
   separate `aws_s3_bucket_versioning`/`aws_s3_bucket_logging` resource referencing the
   bucket) is routinely declared in a different file from the bucket itself
   (`s3.tf`/`versioning.tf`/`logging.tf`).
4. **CloudWatch retention**: fires unless `retention_in_days\s*=` appears anywhere in the log
   group's own block.
5. **S3 versioning**: silent if either an inline `versioning { enabled = true }` block is
   present, or a split-resource `aws_s3_bucket_versioning` referencing this bucket (via a
   `bucket = aws_s3_bucket.<name>.` reference, anchored to the `bucket` attribute
   specifically) has `versioning_configuration { status = "Enabled" }`. Otherwise fires.
6. **S3 logging**: silent if either an inline `logging { ... }` block is present, or a
   split-resource `aws_s3_bucket_logging` referencing this bucket exists at all (no
   configuration to validate beyond presence, unlike versioning's `Enabled`/`Suspended`
   state). Otherwise fires. The bucket-reference match is anchored to the `bucket` attribute,
   never `target_bucket` — on `aws_s3_bucket_logging`, `target_bucket` names the (possibly
   different) destination bucket for the log records, not the bucket being logged.
7. No expression evaluation: a bucket referenced only through a variable or a
   `for_each`-derived resource name is not resolved (accepted false-negative, consistent with
   every other regex/text-scoped Terraform guard in this codebase, e.g.
   `cloudtrail_logging_disabled.py`).
8. Inline opt-outs, per check, anywhere in the resource's own block:
   `# security: allow-cloudwatch-log-retention`, `# security: allow-s3-versioning`,
   `# security: allow-s3-logging`.
9. Severity: `medium` for all three. Rule ids:
   `aws-observability-hygiene/cloudwatch-log-retention-missing`,
   `aws-observability-hygiene/s3-versioning-missing`,
   `aws-observability-hygiene/s3-logging-missing`. Standards: `["OWASP:A09", "CWE-778"]`
   (CloudWatch/logging checks), `["OWASP:A05", "CWE-693"]` (versioning).
10. **(2026-10-25 extension) CloudWatch log retention present but very short.** A fourth,
    independent rule, `aws-observability-hygiene/cloudwatch-log-retention-too-short`, LOW
    severity — deliberately lower than the MEDIUM missing-entirely rule above, since a
    short-but-deliberate retention window is a much weaker signal than no retention policy at
    all. Fires when `retention_in_days` IS present with a literal numeric value from `1` to `2`
    (CloudWatch's only valid value in that range is `1`). `retention_in_days = 0` does NOT fire:
    CloudWatch reads `0` as "never expire", an explicit retention choice (PR #1162 round-1 M5).
    Both CloudWatch rules read the block through `terraform_code_view()`, so a commented-out
    `# retention_in_days = 1` is neither a short window nor a retention policy: it used to fire
    the short rule, and a commented-out long value used to hide a missing one.
    That threshold is deliberately low and conservative: log-retention length is a legitimate
    policy choice many teams make for cost reasons, and this guard only flags the
    clearly-pathological short end (1 or 2 days), never a deliberate 7-or-14-day choice. Mutually
    exclusive with the missing-entirely rule by construction (a log group's
    `retention_in_days` cannot be both absent and present-with-a-value), shares the same
    `# security: allow-cloudwatch-log-retention` pragma, and treats a non-literal value (e.g.
    `retention_in_days = var.retention`) as unresolved rather than guessed at — same
    no-expression-evaluation stance as the rest of this guard. Standards: `["OWASP:A09",
    "CWE-778"]`.

## When NOT to flag

- `retention_in_days` set to `3` or higher, or to `0` ("never expire"), on a
  `aws_cloudwatch_log_group` block (stays silent on both CloudWatch rules).
- An inline `versioning { enabled = true }` block, or a split-resource
  `aws_s3_bucket_versioning` with `status = "Enabled"` referencing the bucket.
- An inline `logging { ... }` block, or any split-resource `aws_s3_bucket_logging`
  referencing the bucket (presence alone is enough — this guard doesn't validate the
  destination bucket/prefix configuration).
- An audited case, suppressed with the matching per-check pragma anywhere in the resource's
  own block.

## Tests

| Test | What it checks |
|---|---|
| `test_cloudwatch_log_group_no_retention_fires` | Positive: no `retention_in_days` fires. |
| `test_cloudwatch_log_group_with_retention_silent` | FP-bait: `retention_in_days` set → silent. |
| `test_cloudwatch_log_group_pragma_silences` | Suppress pragma → silent. |
| `test_cloudwatch_log_group_short_retention_fires_low` | Positive: `retention_in_days = 1` fires the new LOW rule, and NOT the missing-entirely rule. |
| `test_cloudwatch_log_group_longer_retention_silent_on_both_cw_rules` | FP-bait: `retention_in_days = 90` → silent on both CloudWatch rules. |
| `test_cloudwatch_log_group_missing_retention_still_fires_missing_rule_only` | Regression: missing-entirely behavior unchanged by the new rule. |
| `test_cloudwatch_log_group_short_retention_pragma_silences` | Suppress pragma → silent on the new rule too. |
| `test_cloudwatch_retention_zero_is_never_expire_not_short` | Round-1 M5: `retention_in_days = 0` → silent on both CloudWatch rules. |
| `test_cloudwatch_commented_retention_is_neither_short_nor_set` | Round-1 M5: a commented-out `1` or `365` is not a retention policy → fires the missing rule only. |
| `test_cloudwatch_real_retention_with_trailing_comment_is_read` | A real attribute with a trailing comment is still read (long → silent, `1` → LOW). |
| `test_s3_bucket_no_versioning_fires` | Positive: no versioning anywhere fires. |
| `test_s3_bucket_inline_versioning_enabled_silent` | FP-bait: inline `versioning { enabled = true }` → silent. |
| `test_s3_bucket_inline_versioning_disabled_fires` | Positive: inline `versioning { enabled = false }` still fires. |
| `test_s3_bucket_split_versioning_resource_enabled_silent` | FP-bait: split-resource form with `status = "Enabled"` → silent. |
| `test_s3_bucket_split_versioning_resource_suspended_fires` | Positive: split-resource form with `status = "Suspended"` fires. |
| `test_s3_bucket_versioning_resource_for_different_bucket_still_fires` | Positive: a split-resource referencing a DIFFERENT bucket doesn't silence this one. |
| `test_s3_bucket_versioning_pragma_silences` | Suppress pragma → silent. |
| `test_s3_bucket_no_logging_fires` | Positive: no logging anywhere fires. |
| `test_s3_bucket_inline_logging_block_silent` | FP-bait: inline `logging { ... }` block → silent. |
| `test_s3_bucket_split_logging_resource_silent` | FP-bait: split-resource `aws_s3_bucket_logging` referencing the bucket → silent. |
| `test_s3_bucket_logging_pragma_silences` | Suppress pragma → silent. |
| `test_applies_gate` / `test_applies_with_terraform` | `applies()` gate. |

## Known bypasses

- **Variable/expression indirection**: `retention_in_days = var.retention`, or a bucket
  reference built through a `for_each`/`count`-derived name — only literal attribute values
  and a plain `bucket = aws_s3_bucket.<name>.` reference are matched.
- **A resource nested inside a `module` block** passing any of these attributes through at
  the call site — only the resource's own literal body is inspected.
- **The destination configuration of a present logging resource is never validated** — an
  `aws_s3_bucket_logging` resource that exists but points logs at a bucket with no retention
  or write access of its own still silences the finding; presence alone is the bar.

## What this guard does NOT prove

A silent guard does not confirm the applied infrastructure matches the source (drift), that
an attribute wasn't overridden via `-var`/`terraform.tfvars` at apply time in a way this
static text can't see, or that a resource provisioned outside Terraform (console,
CloudFormation, another IaC tool) carries the same configuration. This is a presence-based,
source-only check across three independently-graded conditions.

# Citations

[1] agentsec checklist items `7-cloudwatch-log-retention-missing`, `7-s3-versioning-missing`, `7-s3-logging-missing` (§7)
[2] OWASP:A05, OWASP:A09
[3] CWE-693, CWE-778
[4] iac-security-scanner `TF_AWS_LOG_003/004/005`
