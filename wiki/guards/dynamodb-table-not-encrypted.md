---
type: Guard
title: "dynamodb-table-not-encrypted"
description: "DynamoDB table without customer-managed KMS encryption."
timestamp: "2026-08-16T09:29:01+08:00"
guard_id: "dynamodb-table-not-encrypted"
checklist_section: ["7"]
standards: ["CWE-320", "OWASP:A02"]
---

# DynamoDB table without customer-managed KMS encryption

_Author — Marconi, 2026-08-16_

---

## The threat

A Terraform `aws_dynamodb_table` resource without a `server_side_encryption` block using
a customer-managed KMS key (CMK) is still encrypted at rest — DynamoDB always encrypts
with at least an AWS-owned key — but the account has no visibility into or control over
that key: no separate audit trail, no ability to restrict or revoke access independently
of the table's own IAM policy, no cross-account key-policy narrowing. Anyone who reaches
the table via an over-broad IAM grant inherits full read access with no second control
layer to stop them. CWE-320 (Key Management Errors), OWASP:A02.

## Why this guard fits the stack

DynamoDB is a common session/cache/state store in the FastAPI + LLM/RAG shape this
project targets. A table is usually provisioned once, early, to satisfy a "we need a
key-value store" need — encryption-key ownership is rarely revisited:

```hcl
resource "aws_dynamodb_table" "sessions" {
  name         = "sessions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  # no server_side_encryption block -> AWS-owned key, not a CMK
}
```

Sourced from checkov's `DynamoDBTablesEncrypted` check (`CKV_AWS_119`, a
`BaseResourceCheck` requiring `server_side_encryption[0].enabled == [True]` AND
`kms_key_arn` both present; confirmed against the real fetched source).

## Detection design

1. `applies()` gate — `"terraform" in profile.features`.
2. Scans every `.tf` file under the repo root via `iter_files(root, (".tf",))`, skipping
   non-product paths (`is_nonproduct_path`).
3. Uses `iter_terraform_resources()` to isolate each `aws_dynamodb_table "<name>" { ... }`
   block. Comments are blanked (not dropped) into a `code_body` view first. `_SSE_BLOCK`
   extracts the `server_side_encryption { ... }` nested block's own content (a single-level
   `[^{}]*` capture — this block never nests further in practice). If found, the block's
   content must contain both `enabled = true` and a non-empty `kms_key_arn = ...`; if
   either is missing, or the block itself is absent, the guard fires.
4. Inline opt-out: `# security: allow-dynamodb-unencrypted` anywhere in the resource block.
5. Severity: `medium` (data IS encrypted, just not with a customer-controlled key — see
   `kms-key-rotation-not-enabled`'s design doc for the same medium-vs-high reasoning).
   Rule id: `dynamodb-table-not-encrypted/missing-cmk-encryption`. Standards:
   `["OWASP:A02", "CWE-320"]`.

## When NOT to flag

- `server_side_encryption { enabled = true; kms_key_arn = ... }` both set, regardless of
  what else is in the block.
- An audited case (e.g. a genuinely non-sensitive scratch table), suppressed with
  `# security: allow-dynamodb-unencrypted`.

## Tests

| Test | What it checks |
|---|---|
| `test_dynamodb_table_not_encrypted_flags_missing_block` | Positive: no `server_side_encryption` block at all fires (**verified_by**). |
| `test_dynamodb_table_not_encrypted_flags_enabled_without_key` | Positive: `enabled = true` but no `kms_key_arn` still fires. |
| `test_dynamodb_table_not_encrypted_silent_when_cmk_set` | FP-bait: both `enabled = true` and `kms_key_arn` set → silent. |
| `test_dynamodb_table_not_encrypted_silent_other_resource` | A non-`aws_dynamodb_table` resource → silent. |
| `test_dynamodb_table_not_encrypted_pragma_silences` | Suppress pragma → silent. |
| `test_dynamodb_table_not_encrypted_comment_does_not_suppress_finding` | A commented-out `server_side_encryption` block does NOT suppress a genuine finding. |
| `test_dynamodb_table_not_encrypted_applies_gate` / `test_dynamodb_table_not_encrypted_applies_with_terraform` | `applies()` gate. |

## Known bypasses

- **Variable indirection**: `kms_key_arn = var.cmk_arn` where the block is otherwise
  well-formed — only literal presence is checked, not resolved. A variable-driven
  `kms_key_arn` still satisfies the `\S` non-empty check (this is intentional: unlike the
  spec-value check in `kms-key-rotation-not-enabled`, presence of *any* value here is
  sufficient, matching checkov's own `is not None` semantics).
- **Multiple `server_side_encryption` blocks**: only the first match found by the regex
  is inspected; Terraform itself only allows one such block per resource in practice.
- **A resource nested inside a `module` block** passing the attribute through at the call
  site — the helper only sees the resource's own literal body.
- ~~Terraform's `dynamic "server_side_encryption" { ... content { ... } }` form~~ —
  **closed 2026-08-22** (Dean's review, High 2): `_DYNAMIC_SSE_BLOCK` matches the
  `dynamic` wrapper and extracts the nested `content { ... }` block's body the same way
  `_SSE_BLOCK` extracts the plain form's.

## What this guard does NOT prove

A silent guard does not confirm the applied infrastructure matches the source (drift),
that the CMK referenced actually exists or has a sane key policy, or that a table
provisioned outside Terraform is using a CMK. This is a presence-based, source-only check.

# Citations

[1] agentsec checklist item `7-dynamodb-table-not-encrypted` (§7)
[2] CWE-320
[3] OWASP:A02
