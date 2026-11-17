---
type: Guard
title: "cloudwatch-log-group-not-kms-encrypted"
description: "CloudWatch Log Group without a customer-managed KMS key."
timestamp: "2026-08-16T09:29:01+08:00"
guard_id: "cloudwatch-log-group-not-kms-encrypted"
checklist_section: ["7"]
standards: ["CWE-320", "OWASP:A02"]
---

# CloudWatch Log Group without a customer-managed KMS key

_Author — Marconi, 2026-08-16_

---

## The threat

A Terraform `aws_cloudwatch_log_group` without `kms_key_id` set is encrypted at rest with
an AWS-managed key the account cannot narrow or independently audit. Application logs in
a FastAPI + LLM/RAG stack routinely capture request bodies, stack traces, or (by
accident) secrets — a log group without a customer-managed CMK has no independent
key-policy control over who can decrypt that history, separate from CloudWatch's own IAM
permissions. CWE-320 (Key Management Errors), OWASP:A02.

## Why this guard fits the stack

Every service in this project's target stack writes to CloudWatch Logs by default —
it's the highest-volume, longest-retained data store most deployments have:

```hcl
resource "aws_cloudwatch_log_group" "app" {
  name = "/app/prod"
  # no kms_key_id -> CloudWatch Logs' own AWS-managed key
}
```

Sourced from checkov's `CloudWatchLogGroupKMSKey` check (`CKV_AWS_158`, a
`BaseResourceValueCheck` requiring `kms_key_id` to be set to ANY value; confirmed against
the real fetched source).

## Detection design

1. `applies()` gate — `"terraform" in profile.features`.
2. Scans every `.tf` file via `iter_files(root, (".tf",))`, skipping non-product paths.
3. Uses `iter_terraform_resources()` to isolate each `aws_cloudwatch_log_group` block.
   Comments blanked into `code_body`. Fires unless a non-empty `kms_key_id = ...` is
   found anywhere in the block.
4. Inline opt-out: `# security: allow-cloudwatch-logs-non-kms` anywhere in the block.
5. Severity: `medium` (data IS encrypted by default, just not with a customer-controlled
   key — same reasoning as `dynamodb-table-not-encrypted`/`ecr-repository-not-kms-
   encrypted`). Rule id: `cloudwatch-log-group-not-kms-encrypted/missing-kms-encryption`.
   Standards: `["OWASP:A02", "CWE-320"]`.

## When NOT to flag

- A non-empty `kms_key_id` present anywhere in the block.
- An audited case, suppressed with `# security: allow-cloudwatch-logs-non-kms`.

## Tests

| Test | What it checks |
|---|---|
| `test_cloudwatch_log_group_not_kms_encrypted_flags_missing_attribute` | Positive: no `kms_key_id` at all fires (**verified_by**). |
| `test_cloudwatch_log_group_not_kms_encrypted_silent_when_kms_key_set` | FP-bait: `kms_key_id` set → silent. |
| `test_cloudwatch_log_group_not_kms_encrypted_silent_other_resource` | A non-`aws_cloudwatch_log_group` resource → silent. |
| `test_cloudwatch_log_group_not_kms_encrypted_pragma_silences` | Suppress pragma → silent. |
| `test_cloudwatch_log_group_not_kms_encrypted_comment_does_not_suppress_finding` | A commented `# kms_key_id = ...` does NOT suppress a genuine finding. |
| `test_cloudwatch_log_group_not_kms_encrypted_applies_gate` / `test_cloudwatch_log_group_not_kms_encrypted_applies_with_terraform` | `applies()` gate. |

## Known bypasses

- **Variable indirection**: `kms_key_id = var.cmk_arn` still satisfies the non-empty
  `\S` check as written (matching checkov's own permissive ANY_VALUE semantics).
- **A resource nested inside a `module` block** — only the literal resource body is seen.

## What this guard does NOT prove

A silent guard does not confirm the applied infrastructure matches the source (drift),
that the referenced key actually exists, or that a log group provisioned outside
Terraform uses a CMK. This is a presence-based, source-only check.

# Citations

[1] agentsec checklist item `7-cloudwatch-log-group-not-kms-encrypted` (§7)
[2] CWE-320
[3] OWASP:A02
