---
type: Guard
title: "kinesis-stream-not-encrypted"
description: "Kinesis data stream without server-side encryption."
timestamp: "2026-10-25T10:00:00+08:00"
guard_id: "kinesis-stream-not-encrypted"
checklist_section: ["7"]
standards: ["CWE-311", "OWASP:A02"]
---

# Kinesis data stream without server-side encryption

_Author — Marconi, 2026-10-25_

---

## The threat

A Terraform `aws_kinesis_stream` without `encryption_type = "KMS"` stores every record
written to every shard in plaintext. Unlike several other AWS data stores in this
family, Kinesis has no AWS-owned-key fallback — a stream with no `encryption_type` set
(or `encryption_type = "NONE"`) is genuinely unencrypted, not merely missing a
customer-managed key. CWE-311 (Missing Encryption of Sensitive Data), OWASP:A02.

## Why this guard fits the stack

Kinesis streams commonly carry event/clickstream or telemetry payloads that include PII
or session data in the FastAPI + LLM/RAG shape this project targets:

```hcl
resource "aws_kinesis_stream" "events" {
  name             = "events"
  shard_count      = 1
  retention_period = 24
  # no encryption_type attribute at all -> stream is created unencrypted
}
```

Sourced from checkov's `KinesisStreamEncryptionType` check (`CKV_AWS_43`, a
`BaseResourceValueCheck` inspecting `encryption_type`, expecting `"KMS"`; confirmed
against the real fetched source).

## Detection design

1. `applies()` gate — `"terraform" in profile.features`.
2. Scans every `.tf` file via `iter_files(root, (".tf",))`, skipping non-product paths.
3. Uses `iter_terraform_resources()` to isolate each `aws_kinesis_stream` block. Comments
   blanked into `code_body`. `_ENCRYPTION_TYPE` captures the literal value of
   `encryption_type` anywhere in the block. Fires unless a literal value other than
   `"NONE"` is found — whether the attribute is missing entirely or explicitly set to
   `"NONE"`.
4. Inline opt-out: `# security: allow-kinesis-unencrypted` anywhere in the block.
5. Severity: `high` (direct, no-encryption-at-all case, same shape as
   `ebs-volume-not-encrypted`/`efs-file-system-not-encrypted`). Rule id:
   `kinesis-stream-not-encrypted/missing-encryption`. Standards:
   `["OWASP:A02", "CWE-311"]`.

## When NOT to flag

- `encryption_type` set to any literal other than `"NONE"` anywhere in the block (this
  guard cannot evaluate a variable reference, so a non-`"NONE"` literal is treated as
  addressed).
- An audited case (e.g. a genuinely non-sensitive scratch stream), suppressed with
  `# security: allow-kinesis-unencrypted`.

## Tests

| Test | What it checks |
|---|---|
| `test_kinesis_stream_not_encrypted_flags_missing_attribute` | Positive: no `encryption_type` attribute at all fires (**verified_by**). |
| `test_kinesis_stream_not_encrypted_flags_explicit_none` | Positive: `encryption_type = "NONE"` fires. |
| `test_kinesis_stream_not_encrypted_silent_when_kms` | FP-bait: `encryption_type = "KMS"` → silent. |
| `test_kinesis_stream_not_encrypted_silent_other_resource` | A non-`aws_kinesis_stream` resource → silent. |
| `test_kinesis_stream_not_encrypted_pragma_silences` | Suppress pragma → silent. |
| `test_kinesis_stream_not_encrypted_comment_does_not_suppress_finding` | A commented `# encryption_type = "KMS"` does NOT suppress a genuine finding. |
| `test_kinesis_stream_not_encrypted_applies_gate` / `test_kinesis_stream_not_encrypted_applies_with_terraform` | `applies()` gate. |

## Known bypasses

- **Variable indirection**: `encryption_type = var.stream_encryption` where the
  variable resolves to `"NONE"` elsewhere — only a literal value is matched.
- **A resource nested inside a `module` block** — only the literal resource body is seen.

## What this guard does NOT prove

A silent guard does not confirm the applied infrastructure matches the source (drift),
or that a stream provisioned outside Terraform is encrypted. This is a presence-based,
source-only check.

# Examples

```hcl
# Flags: missing attribute entirely
resource "aws_kinesis_stream" "events" {
  name             = "events"
  shard_count      = 1
  retention_period = 24
}

# Flags: explicit "NONE"
resource "aws_kinesis_stream" "events" {
  name            = "events"
  encryption_type = "NONE"
}

# Silent: KMS encryption set
resource "aws_kinesis_stream" "events" {
  name            = "events"
  encryption_type = "KMS"
  kms_key_id      = aws_kms_key.events.arn
}
```

# Citations

[1] agentsec checklist item `7-kinesis-stream-not-encrypted` (§7)
[2] CWE-311
[3] OWASP:A02
