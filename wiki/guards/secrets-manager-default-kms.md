---
type: Guard
title: "secrets-manager-default-kms"
description: "Secrets Manager secret without a customer-managed KMS key."
timestamp: "2026-08-16T09:29:01+08:00"
guard_id: "secrets-manager-default-kms"
checklist_section: ["7"]
standards: ["CWE-320", "OWASP:A02"]
---

# Secrets Manager secret without a customer-managed KMS key

_Author — Marconi, 2026-08-16_

---

## The threat

A Terraform `aws_secretsmanager_secret` without an explicit customer-managed `kms_key_id`
is encrypted with the account's default `aws/secretsmanager` AWS-managed key. That key's
policy is controlled by AWS, not the account — there is no way to write a narrower grant,
add a deny condition, or audit access to the key independently of the secret's own IAM
policy. A customer-managed CMK adds a second, independently auditable control point for
what is often the single most sensitive resource type in a stack (database passwords, API
keys, LLM provider credentials). CWE-320 (Key Management Errors), OWASP:A02.

## Why this guard fits the stack

Secrets Manager is the canonical place to store the credentials a FastAPI + LLM/RAG app
needs at runtime (DB password, provider API keys). The default key is silently "good
enough" — no error, no warning:

```hcl
resource "aws_secretsmanager_secret" "db_password" {
  name = "db_password"
  # no kms_key_id -> encrypted with the account's default aws/secretsmanager alias
}
```

Sourced from checkov's `SecretManagerSecretEncrypted` check (`CKV_AWS_149`, a
`BaseResourceCheck` that fails when `kms_key_id` is absent OR its value contains the
literal substring `aws/` — the default-alias prefix; confirmed against the real fetched
source).

## Detection design

1. `applies()` gate — `"terraform" in profile.features`.
2. Scans every `.tf` file via `iter_files(root, (".tf",))`, skipping non-product paths.
3. Uses `iter_terraform_resources()` to isolate each `aws_secretsmanager_secret` block.
   Comments blanked into `code_body`. `_KMS_KEY_ID_VALUE` captures the first token after
   `kms_key_id =` — a quoted literal (`"arn:..."`, `"alias/aws/secretsmanager"`) OR a bare
   token (a resource reference such as `aws_kms_key.app.arn`, a `var.` reference, or the HCL
   keyword `null`). Fires when `kms_key_id` is absent or empty, when the value is the bare
   keyword `null` (Terraform treats a `null`-valued attribute as absent, so the secret still
   falls back to the default AWS-managed key), or when the value contains the substring
   `aws/` (every default-alias form: `alias/aws/secretsmanager`, `aws/secretsmanager`). Any
   other non-empty token — an ARN, key id, custom alias, or a resource/variable reference —
   counts as a customer-managed key and stays silent (matching checkov's `is not None`
   semantics rather than requiring a resolved literal).
4. Inline opt-out: `# security: allow-secrets-manager-default-kms` anywhere in the block.
5. Severity: `medium` (encrypted by default, just not with a customer-controlled key).
   Rule id: `secrets-manager-default-kms/default-aws-managed-key`. Standards:
   `["OWASP:A02", "CWE-320"]`.

## When NOT to flag

- `kms_key_id` set to any non-empty value that is not the bare keyword `null` and does not
  contain `aws/` — a quoted ARN/key id/custom alias, or a bare resource reference
  (`aws_kms_key.<name>.arn`) or `var.` reference. The guard's own remediation tells the user
  to write `kms_key_id = aws_kms_key.<name>.arn`, so that reference form must stay silent.
- An audited case, suppressed with `# security: allow-secrets-manager-default-kms`.

## Tests

| Test | What it checks |
|---|---|
| `test_secrets_manager_default_kms_flags_missing_attribute` | Positive: no `kms_key_id` at all fires (**verified_by**). |
| `test_secrets_manager_default_kms_flags_default_alias` | Positive: `kms_key_id = "alias/aws/secretsmanager"` still fires. |
| `test_secrets_manager_default_kms_flags_explicit_null` | Positive: `kms_key_id = null` fires (Terraform treats it as absent). |
| `test_secrets_manager_default_kms_flags_null_with_trailing_comment` | Positive: `kms_key_id = null  # ...` still fires. |
| `test_secrets_manager_default_kms_silent_when_cmk_set` | FP-bait: a real quoted ARN → silent. |
| `test_secrets_manager_default_kms_silent_when_cmk_referenced` | FP-bait: a resource reference `aws_kms_key.app.arn` (the remediation form) → silent. |
| `test_secrets_manager_default_kms_resource_reference_still_silent_after_null_fix` | FP-bait: the `null` fix must not reopen the resource-reference silence. |
| `test_secrets_manager_default_kms_ternary_ending_in_null_is_a_disclosed_gap` | Pins the disclosed first-token-only gap: a ternary ending in `null` stays silent. |
| `test_secrets_manager_default_kms_silent_other_resource` | A non-`aws_secretsmanager_secret` resource → silent. |
| `test_secrets_manager_default_kms_pragma_silences` | Suppress pragma → silent. |
| `test_secrets_manager_default_kms_comment_does_not_suppress_finding` | A commented-out `kms_key_id` does NOT suppress a genuine finding. |
| `test_secrets_manager_default_kms_applies_gate` / `test_secrets_manager_default_kms_applies_with_terraform` | `applies()` gate. |

## Known bypasses

- **A bare `var.`/resource reference stays silent**: `kms_key_id = var.cmk_arn` (or
  `aws_kms_key.app.arn`) is a non-empty token that is not `null` and carries no `aws/`
  substring, so it counts as a customer-managed key and the guard goes silent — it does not
  resolve the reference. This matches checkov's `is not None` semantics, and is required so
  the guard's own remediation (`kms_key_id = aws_kms_key.<name>.arn`) actually clears the
  finding.
- **Multi-token ternary ending in `null`**: `kms_key_id = var.use_cmk ? aws_kms_key.app.arn
  : null` captures only the first token (`var.use_cmk`) and stays silent even on the branch
  that resolves to `null` — a disclosed, accepted gap (pinned by
  `test_secrets_manager_default_kms_ternary_ending_in_null_is_a_disclosed_gap`); closing it
  needs capturing the whole expression, out of this guard's scope.
- **A resource nested inside a `module` block** — only the literal resource body is seen.

## What this guard does NOT prove

A silent guard does not confirm the referenced CMK actually exists, has a sane key
policy, or that a secret provisioned outside Terraform uses a CMK. This is a
presence-based, source-only check.

# Citations

[1] agentsec checklist item `7-secrets-manager-default-kms` (§7)
[2] CWE-320
[3] OWASP:A02
