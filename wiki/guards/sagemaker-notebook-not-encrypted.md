---
type: Guard
title: "sagemaker-notebook-not-encrypted"
description: "SageMaker notebook instance without a customer-managed encryption key."
timestamp: "2026-10-25T10:00:00+08:00"
guard_id: "sagemaker-notebook-not-encrypted"
checklist_section: ["7"]
standards: ["CWE-320", "OWASP:A02"]
---

# SageMaker notebook instance without a customer-managed encryption key

_Author — Marconi, 2026-10-25_

---

## The threat

A Terraform `aws_sagemaker_notebook_instance` without `kms_key_id` has its attached
storage encrypted with a system-managed key. AWS: "For notebook instances, if you don't
specify a KMS key, SageMaker AI encrypts both OS volumes and ML data volumes with a
system-managed KMS key" [4]. The volume is not plaintext, so this is not a missing-encryption
finding. The gap is key control: the account has no independent control over, or audit trail
for, who can decrypt the notebook's own data, training artifacts, and the credentials often
staged on it.

That puts it in the default-key family (`ecr-repository-not-kms-encrypted`,
`cloudwatch-log-group-not-kms-encrypted`, `secrets-manager-default-kms`), distinct from the
no-encryption-at-all family (`ebs-volume-not-encrypted`, `efs-file-system-not-encrypted`), and
it carries that family's mapping: CWE-320 (Key Management Errors), OWASP:A02. An earlier
version mapped it to CWE-311 (Missing Encryption), which overclaimed (PR #1162 round-1 M9).

## Why this guard fits the stack

SageMaker notebooks are a common scratch/experimentation surface for the ML/LLM
workflows this project targets — and are not present in every agentsec user's stack,
hence the lower MEDIUM severity relative to its encryption-guard siblings:

```hcl
resource "aws_sagemaker_notebook_instance" "experiments" {
  instance_type = "ml.t3.medium"
  role_arn      = aws_iam_role.sagemaker.arn
  # no kms_key_id attribute at all -> storage encrypted with a system-managed key
}
```

Sourced from checkov's `SageMakerNotebookEncryption` check (`CKV_AWS_32`, a
`BaseResourceValueCheck` inspecting `kms_key_id`; confirmed against the real fetched
source).

## Detection design

1. `applies()` gate — `"terraform" in profile.features`.
2. Scans every `.tf` file via `iter_files(root, (".tf",))`, skipping non-product paths.
3. Uses `iter_terraform_resources()` to isolate each `aws_sagemaker_notebook_instance`
   block. `_KMS_KEY_ID` searches the block's `terraform_code_view` (comments blanked,
   `${...}` neutralised) for a `kms_key_id` set to something other than `""` or `null`.
   Fires when the attribute is absent, empty, or `null`: all three leave the notebook on the
   system-managed key. Unlike this file family's other guards, there is no boolean "off"
   value to also check.
4. Inline opt-out: `# security: allow-sagemaker-unencrypted` anywhere in the block.
5. Severity: `medium`, the same as the other default-key guards it sits with.
   Rule id: `sagemaker-notebook-not-encrypted/missing-kms-key`. Standards:
   `["OWASP:A02", "CWE-320"]`.

## When NOT to flag

- `kms_key_id` set to any value other than `""` or `null` anywhere in the block.
- An audited case (e.g. a genuinely non-sensitive scratch notebook), suppressed with
  `# security: allow-sagemaker-unencrypted`.

## Tests

| Test | What it checks |
|---|---|
| `test_sagemaker_notebook_not_encrypted_flags_missing_attribute` | Positive: no `kms_key_id` attribute at all fires (**verified_by**). |
| `test_sagemaker_notebook_not_encrypted_silent_when_kms_key_set` | FP-bait: `kms_key_id` set → silent. |
| `test_sagemaker_notebook_not_encrypted_silent_other_resource` | A non-`aws_sagemaker_notebook_instance` resource → silent. |
| `test_sagemaker_notebook_not_encrypted_pragma_silences` | Suppress pragma → silent. |
| `test_sagemaker_notebook_not_encrypted_comment_does_not_suppress_finding` | A commented `# kms_key_id = ...` does NOT suppress a genuine finding. |
| `test_sagemaker_notebook_not_encrypted_flags_empty_or_null_key` | `kms_key_id = ""` and `kms_key_id = null` fire like an omitted key. |
| `test_sagemaker_notebook_not_encrypted_standards_are_default_key_family` | The finding maps to CWE-320 / OWASP:A02, not CWE-311. |
| `test_sagemaker_notebook_not_encrypted_applies_gate` / `test_sagemaker_notebook_not_encrypted_applies_with_terraform` | `applies()` gate. |

## Known bypasses

- **Variable indirection in the opposite direction is not a bypass here** — since any
  non-empty `kms_key_id` value (literal or variable reference) suppresses the finding,
  the risk runs the other way: a variable that resolves to an empty string would still
  suppress even though the result falls back to the system-managed key, not a CMK.
- **A resource nested inside a `module` block** — only the literal resource body is seen.

## What this guard does NOT prove

A silent guard does not confirm the referenced KMS key is a genuine customer-managed key
(as opposed to an alias of the AWS-managed key), or that a notebook provisioned outside
Terraform has a CMK attached. This is a presence-based, source-only check.

# Examples

```hcl
# Flags: missing attribute entirely
resource "aws_sagemaker_notebook_instance" "experiments" {
  instance_type = "ml.t3.medium"
  role_arn      = aws_iam_role.sagemaker.arn
}

# Silent: customer-managed key set
resource "aws_sagemaker_notebook_instance" "experiments" {
  instance_type = "ml.t3.medium"
  role_arn      = aws_iam_role.sagemaker.arn
  kms_key_id    = aws_kms_key.sagemaker.arn
}
```

# Citations

[1] agentsec checklist item `7-sagemaker-notebook-not-encrypted` (§7)
[2] CWE-320
[3] OWASP:A02
[4] AWS, "Notebook instances, SageMaker AI jobs, and Endpoints" (encryption at rest),
https://docs.aws.amazon.com/sagemaker/latest/dg/encryption-at-rest-nbi.html
