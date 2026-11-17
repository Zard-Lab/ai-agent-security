---
type: Guard
title: "sqs-queue-not-encrypted"
description: "SQS queue without customer-managed KMS encryption."
timestamp: "2026-08-16T09:29:01+08:00"
guard_id: "sqs-queue-not-encrypted"
checklist_section: ["7"]
standards: ["CWE-320", "OWASP:A02"]
---

# SQS queue without customer-managed KMS encryption

_Author — Marconi, 2026-08-16. Corrected 2026-08-22 (Dean's review): AWS made SSE-SQS the
default for every newly created queue in October 2022, so the absence case is NOT
plaintext — it is AWS-owned-key encryption missing the customer-managed upgrade. Severity
moved high→medium, CWE-311→CWE-320, to match the DynamoDB/Secrets-Manager/ECR/CloudWatch-
Logs "missing CMK" bucket rather than the genuinely-unencrypted-by-default bucket (EBS,
SNS)._

---

## The threat

AWS made SSE-SQS (an AWS-owned key) the default for every newly created queue over the
TLS/SigV4 endpoints Terraform uses, since October 2022. A Terraform `aws_sqs_queue` with
neither `sqs_managed_sse_enabled = true` nor `kms_master_key_id` set is therefore already
encrypted at rest — but with a key the account cannot independently audit, narrow, or
revoke. Queues routinely carry payloads with PII, tokens, or internal request/response
context between services (a common pattern for async LLM job processing); a
customer-managed CMK adds a second, independently auditable control point over who can
decrypt that storage. CWE-320 (Key Management Errors), OWASP:A02.

## Why this guard fits the stack

SQS is a common async-processing primitive for a FastAPI + LLM/RAG backend (job queues
for long-running LLM calls, webhook fan-out):

```hcl
resource "aws_sqs_queue" "jobs" {
  name = "jobs"
  # no sqs_managed_sse_enabled and no kms_master_key_id -> AWS-owned key, not a CMK
}
```

Sourced from checkov's `SQSQueueEncryption` check (`CKV_AWS_27`, a `BaseResourceCheck`
that fails unless `sqs_managed_sse_enabled` is truthy OR `kms_master_key_id` is set;
confirmed against the real fetched source, including the note that setting
`kms_master_key_id` implicitly sets `sqs_managed_sse_enabled` to false server-side, so
either alone is sufficient).

## Detection design

1. `applies()` gate — `"terraform" in profile.features`.
2. Scans every `.tf` file via `iter_files(root, (".tf",))`, skipping non-product paths.
3. Uses `iter_terraform_resources()` to isolate each `aws_sqs_queue` block. Comments
   blanked into `code_body`. Fires unless `sqs_managed_sse_enabled = true` OR a non-empty
   `kms_master_key_id = ...` is found anywhere in the block.
4. Inline opt-out: `# security: allow-sqs-unencrypted` anywhere in the block.
5. Severity: `medium` (SSE-SQS with an AWS-owned key is on by default, so the absence case
   is a missing customer-managed-key upgrade, not plaintext at rest — same "missing CMK"
   class as `dynamodb-table-not-encrypted`/`secrets-manager-default-kms`, not the
   genuinely-off-by-default bucket EBS/SNS sit in). Rule id:
   `sqs-queue-not-encrypted/missing-encryption`. Standards: `["OWASP:A02", "CWE-320"]`.

## When NOT to flag

- `sqs_managed_sse_enabled = true` present anywhere in the block.
- A non-empty `kms_master_key_id` present anywhere in the block.
- An audited case (e.g. a genuinely non-sensitive scratch queue), suppressed with
  `# security: allow-sqs-unencrypted`.

## Tests

| Test | What it checks |
|---|---|
| `test_sqs_queue_not_encrypted_flags_missing_attributes` | Positive: neither attribute set fires (**verified_by**). |
| `test_sqs_queue_not_encrypted_flags_explicit_managed_sse_false` | Positive: `sqs_managed_sse_enabled = false` (and no KMS key) fires. |
| `test_sqs_queue_not_encrypted_silent_when_managed_sse` | FP-bait: `sqs_managed_sse_enabled = true` → silent. |
| `test_sqs_queue_not_encrypted_silent_when_kms_key_set` | FP-bait: `kms_master_key_id` set → silent. |
| `test_sqs_queue_not_encrypted_silent_other_resource` | A non-`aws_sqs_queue` resource → silent. |
| `test_sqs_queue_not_encrypted_pragma_silences` | Suppress pragma → silent. |
| `test_sqs_queue_not_encrypted_comment_does_not_suppress_finding` | A commented `# sqs_managed_sse_enabled = true` does NOT suppress a genuine finding. |
| `test_sqs_queue_not_encrypted_applies_gate` / `test_sqs_queue_not_encrypted_applies_with_terraform` | `applies()` gate. |

## Known bypasses

- **Variable indirection**: `kms_master_key_id = var.cmk_arn` — an unresolved value with
  no literal `\S` match after the `=` still satisfies the non-empty check as written
  (any non-whitespace token, including a bare `var.x` reference, counts as "set" — this
  is intentionally permissive, matching checkov's own `is not None` semantics rather than
  requiring a resolved literal).
- **A resource nested inside a `module` block** — only the literal resource body is seen.

## What this guard does NOT prove

A silent guard does not confirm the applied infrastructure matches the source (drift),
or that a queue provisioned outside Terraform is encrypted. This is a presence-based,
source-only check.

# Citations

[1] agentsec checklist item `7-sqs-queue-not-encrypted` (§7)
[2] CWE-320
[3] OWASP:A02
[4] [AWS: SSE-SQS default for new queues, Oct 2022](https://aws.amazon.com/about-aws/whats-new/2022/10/amazon-sqs-announces-server-side-encryption-ssq-managed-sse-sqs-default)
