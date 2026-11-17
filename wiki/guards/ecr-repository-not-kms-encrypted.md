---
type: Guard
title: "ecr-repository-not-kms-encrypted"
description: "ECR repository without KMS encryption."
timestamp: "2026-08-16T09:29:01+08:00"
guard_id: "ecr-repository-not-kms-encrypted"
checklist_section: ["7"]
standards: ["CWE-320", "OWASP:A02"]
---

# ECR repository without KMS encryption

_Author — Marconi, 2026-08-16_

---

## The threat

A Terraform `aws_ecr_repository` without an `encryption_configuration { encryption_type =
"KMS" }` block is still encrypted at rest (AES256, an AWS-owned key — ECR's default), but
the account has no independently auditable key for the images stored in it. Container
images can embed secrets, private source, or proprietary model weights in a FastAPI +
LLM/RAG deployment pipeline — a repository without a customer-managed CMK has no second
control layer over who can decrypt that history. CWE-320 (Key Management Errors),
OWASP:A02.

## Why this guard fits the stack

ECR holds the container images this project's own delivery model (`agentsec ci add
self-audit`, containerized deploys) and any target application's Docker-based CI/CD
pipeline pushes to:

```hcl
resource "aws_ecr_repository" "app" {
  name = "app"
  # no encryption_configuration block -> AES256 (AWS-owned key), not KMS
}
```

Sourced from checkov's `ECRRepositoryEncrypted` check (`CKV_AWS_136`, a
`BaseResourceValueCheck` requiring `encryption_configuration/[0]/encryption_type ==
"KMS"`; confirmed against the real fetched source).

## Detection design

1. `applies()` gate — `"terraform" in profile.features`.
2. Scans every `.tf` file via `iter_files(root, (".tf",))`, skipping non-product paths.
3. Uses `iter_terraform_resources()` to isolate each `aws_ecr_repository` block. Comments
   blanked into `code_body`. `_ENC_CONFIG_BLOCK` extracts the
   `encryption_configuration { ... }` nested block's content (single-level `[^{}]*`
   capture). If found, the block's content must contain
   `encryption_type = "KMS"` (case-sensitive, matching Terraform's own enum); if the
   block is absent or sets a different `encryption_type` (e.g. `"AES256"`), the guard
   fires.
4. Inline opt-out: `# security: allow-ecr-non-kms-encryption` anywhere in the block.
5. Severity: `medium` (data IS encrypted by default, just not with a customer-controlled
   key — same reasoning as `dynamodb-table-not-encrypted`). Rule id:
   `ecr-repository-not-kms-encrypted/missing-kms-encryption`. Standards:
   `["OWASP:A02", "CWE-320"]`.

## When NOT to flag

- `encryption_configuration { encryption_type = "KMS" }` present, regardless of whether
  `kms_key` is also explicitly set (an omitted `kms_key` with `encryption_type = "KMS"`
  uses the AWS-managed `aws/ecr` KMS key, which is still a real KMS key with its own,
  AWS-controlled key policy — a lesser but genuine improvement over AES256; this guard
  does not further distinguish AWS-managed-KMS from customer-managed-KMS, mirroring
  checkov's own check, which stops at `encryption_type == "KMS"`).
- An audited case, suppressed with `# security: allow-ecr-non-kms-encryption`.

## Tests

| Test | What it checks |
|---|---|
| `test_ecr_repository_not_kms_encrypted_flags_missing_block` | Positive: no `encryption_configuration` block at all fires (**verified_by**). |
| `test_ecr_repository_not_kms_encrypted_flags_aes256` | Positive: `encryption_type = "AES256"` fires. |
| `test_ecr_repository_not_kms_encrypted_silent_when_kms_set` | FP-bait: `encryption_type = "KMS"` → silent. |
| `test_ecr_repository_not_kms_encrypted_silent_other_resource` | A non-`aws_ecr_repository` resource → silent. |
| `test_ecr_repository_not_kms_encrypted_pragma_silences` | Suppress pragma → silent. |
| `test_ecr_repository_not_kms_encrypted_comment_does_not_suppress_finding` | A commented-out `encryption_configuration` block does NOT suppress a genuine finding. |
| `test_ecr_repository_not_kms_encrypted_applies_gate` / `test_ecr_repository_not_kms_encrypted_applies_with_terraform` | `applies()` gate. |

## Known bypasses

- **Variable indirection**: `encryption_type = var.enc_type` — only a literal `"KMS"`
  string is matched.
- **A resource nested inside a `module` block** — only the literal resource body is seen.
- ~~Terraform's `dynamic "encryption_configuration" { ... content { ... } }` form~~ —
  **closed 2026-08-22** (Dean's review, High 2): `_DYNAMIC_ENC_CONFIG_BLOCK` matches the
  `dynamic` wrapper and extracts the nested `content { ... }` block's body the same way
  `_ENC_CONFIG_BLOCK` extracts the plain form's.

## What this guard does NOT prove

A silent guard does not confirm the applied infrastructure matches the source (drift),
that a referenced customer `kms_key` actually exists, or that a repository provisioned
outside Terraform uses KMS encryption. This is a presence-based, source-only check.

# Citations

[1] agentsec checklist item `7-ecr-repository-not-kms-encrypted` (§7)
[2] CWE-320
[3] OWASP:A02
