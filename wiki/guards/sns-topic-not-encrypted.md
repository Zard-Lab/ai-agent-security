---
type: Guard
title: "sns-topic-not-encrypted"
description: "SNS topic without encryption at rest."
timestamp: "2026-08-16T09:29:01+08:00"
guard_id: "sns-topic-not-encrypted"
checklist_section: ["7"]
standards: ["CWE-311", "OWASP:A02"]
---

# SNS topic without encryption at rest

_Author — Marconi, 2026-08-16_

---

## The threat

A Terraform `aws_sns_topic` without `kms_master_key_id` set stores published message
bodies unencrypted at rest. SNS server-side encryption is opt-in. Topics routinely fan
out payloads to multiple subscribers (webhook alerts, event notifications carrying PII
or internal event data) — anyone with access to the underlying storage reads them
directly. CWE-311 (Missing Encryption of Sensitive Data), OWASP:A02.

## Why this guard fits the stack

SNS is a common fan-out primitive alongside SQS in a FastAPI + LLM/RAG backend (alerting,
webhook dispatch, multi-consumer event notification):

```hcl
resource "aws_sns_topic" "alerts" {
  name = "alerts"
  # no kms_master_key_id -> plaintext at rest
}
```

Sourced from checkov's `SNSTopicEncryption` check (`CKV_AWS_26`, a
`BaseResourceValueCheck` requiring `kms_master_key_id` to be set to ANY value; confirmed
against the real fetched source).

## Detection design

1. `applies()` gate — `"terraform" in profile.features`.
2. Scans every `.tf` file via `iter_files(root, (".tf",))`, skipping non-product paths.
3. Uses `iter_terraform_resources()` to isolate each `aws_sns_topic` block. Comments
   blanked into `code_body`. Fires unless a non-empty `kms_master_key_id = ...` is found
   anywhere in the block — any literal value counts (an AWS-managed alias like
   `alias/aws/sns` is accepted, mirroring checkov's own ANY_VALUE semantics; the guard
   does not distinguish AWS-managed from customer-managed here since the underlying real
   risk being checked is "opt-in encryption is on at all," not key ownership).
4. Inline opt-out: `# security: allow-sns-unencrypted` anywhere in the block.
5. Severity: `high` (opt-in encryption genuinely off — direct plaintext-at-rest, same
   class as `sqs-queue-not-encrypted`). Rule id: `sns-topic-not-encrypted/missing-encryption`.
   Standards: `["OWASP:A02", "CWE-311"]`.

## When NOT to flag

- A non-empty `kms_master_key_id` present anywhere in the block, including the
  AWS-managed `alias/aws/sns` alias.
- An audited case (e.g. a genuinely non-sensitive scratch topic), suppressed with
  `# security: allow-sns-unencrypted`.

## Tests

| Test | What it checks |
|---|---|
| `test_sns_topic_not_encrypted_flags_missing_attribute` | Positive: no `kms_master_key_id` at all fires (**verified_by**). |
| `test_sns_topic_not_encrypted_silent_when_kms_key_set` | FP-bait: a real key reference → silent. |
| `test_sns_topic_not_encrypted_silent_with_aws_managed_alias` | FP-bait: `"alias/aws/sns"` → silent (ANY_VALUE semantics). |
| `test_sns_topic_not_encrypted_silent_other_resource` | A non-`aws_sns_topic` resource → silent. |
| `test_sns_topic_not_encrypted_pragma_silences` | Suppress pragma → silent. |
| `test_sns_topic_not_encrypted_comment_does_not_suppress_finding` | A commented `# kms_master_key_id = ...` does NOT suppress a genuine finding. |
| `test_sns_topic_not_encrypted_applies_gate` / `test_sns_topic_not_encrypted_applies_with_terraform` | `applies()` gate. |

## Known bypasses

- **Variable indirection**: `kms_master_key_id = var.cmk_arn` still satisfies the
  non-empty `\S` check as written (any non-whitespace token counts, matching checkov's
  own permissive ANY_VALUE semantics — this guard does not attempt to distinguish a
  well-formed key reference from garbage).
- **A resource nested inside a `module` block** — only the literal resource body is seen.

## What this guard does NOT prove

A silent guard does not confirm the applied infrastructure matches the source (drift),
that the referenced key actually exists, or that a topic provisioned outside Terraform
is encrypted. This is a presence-based, source-only check.

# Citations

[1] agentsec checklist item `7-sns-topic-not-encrypted` (§7)
[2] CWE-311
[3] OWASP:A02
