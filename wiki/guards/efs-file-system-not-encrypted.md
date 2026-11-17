---
type: Guard
title: "efs-file-system-not-encrypted"
description: "EFS file system without encryption at rest."
timestamp: "2026-10-25T10:00:00+08:00"
guard_id: "efs-file-system-not-encrypted"
checklist_section: ["7"]
standards: ["CWE-311", "OWASP:A02"]
---

# EFS file system without encryption at rest

_Author — Marconi, 2026-10-25_

---

## The threat

A Terraform `aws_efs_file_system` without `encrypted = true` stores file contents on
disk in plaintext. Like EBS, EFS encryption at rest is opt-in per file system and
defaults to `false` — anyone with access to the underlying storage layer reads the raw
file contents directly, no application-level bug required. This mirrors the exact risk
shape of `ebs-volume-not-encrypted`, a different storage layer in the same stack. CWE-311
(Missing Encryption of Sensitive Data), OWASP:A02.

## Why this guard fits the stack

EFS file systems back shared storage for EC2/ECS-hosted workloads (shared model
artifacts, uploaded files, a shared cache) in the FastAPI + LLM/RAG shape this project
targets:

```hcl
resource "aws_efs_file_system" "shared" {
  creation_token = "shared-data"
  # no encrypted attribute at all -> AWS defaults it to false
}
```

Sourced from checkov's `EFSEncryptionEnabled` check (`CKV_AWS_42`, a
`BaseResourceValueCheck` inspecting `encrypted`; confirmed against the real fetched
source).

## Detection design

1. `applies()` gate — `"terraform" in profile.features`.
2. Scans every `.tf` file via `iter_files(root, (".tf",))`, skipping non-product paths.
3. Uses `iter_terraform_resources()` to isolate each `aws_efs_file_system` block.
   Comments blanked into `code_body`. `_ENCRYPTED_TRUE` searches for `encrypted = true`
   anywhere in the block. Fires unless found — whether the attribute is missing entirely
   or set to `false`.
4. Inline opt-out: `# security: allow-efs-unencrypted` anywhere in the block.
5. Severity: `high` (direct, no-encryption-at-all case, same shape as
   `ebs-volume-not-encrypted`). Rule id: `efs-file-system-not-encrypted/missing-encryption`.
   Standards: `["OWASP:A02", "CWE-311"]`.

## When NOT to flag

- `encrypted = true` present anywhere in the block.
- An audited case (e.g. a genuinely non-sensitive scratch file system), suppressed with
  `# security: allow-efs-unencrypted`.
- This guard checks only the plain `aws_efs_file_system` resource's own at-rest
  encryption flag — it is NOT about transit encryption on an EFS mount inside an ECS
  task, which is a separate, narrower guard.

## Tests

| Test | What it checks |
|---|---|
| `test_efs_file_system_not_encrypted_flags_missing_attribute` | Positive: no `encrypted` attribute at all fires (**verified_by**). |
| `test_efs_file_system_not_encrypted_flags_explicit_false` | Positive: `encrypted = false` fires. |
| `test_efs_file_system_not_encrypted_silent_when_true` | FP-bait: `encrypted = true` → silent. |
| `test_efs_file_system_not_encrypted_silent_other_resource` | A non-`aws_efs_file_system` resource → silent. |
| `test_efs_file_system_not_encrypted_pragma_silences` | Suppress pragma → silent. |
| `test_efs_file_system_not_encrypted_comment_does_not_suppress_finding` | A commented `# encrypted = true` does NOT suppress a genuine finding. |
| `test_efs_file_system_not_encrypted_applies_gate` / `test_efs_file_system_not_encrypted_applies_with_terraform` | `applies()` gate. |

## Known bypasses

- **Variable indirection**: `encrypted = var.encrypt_fs` where the variable defaults to
  `true` elsewhere — only a literal value is matched.
- **Region/account default-encryption settings**: EFS has no account-level
  "encryption by default" setting analogous to EBS, so this bypass class does not apply
  here the way it does for `ebs-volume-not-encrypted`.
- **A resource nested inside a `module` block** — only the literal resource body is seen.
- **Not a bypass any more: a same-named `tags` key.** The attribute is read from the resource's
  own top-level attributes (`top_level_attribute_text` of the code view), and
  `literal_bool_state` only matches an attribute that starts its line. A tag such as
  `tags = { encrypted = "true" }`, on one line or several, therefore neither satisfies nor
  triggers the check (PR #1162 round-4 M2). A resource written on one line,
  `resource "aws_efs_file_system" "x" { encrypted = true }`, is read the same as its multi-line
  form: the helper returns the opening line's own attribute (PR #1162 round-5 M1;
  `tests/test_terraform_layout_invariance.py` pins the layout invariant).

## What this guard does NOT prove

A silent guard does not confirm the applied infrastructure matches the source (drift),
or that a file system provisioned outside Terraform is encrypted. This is a
presence-based, source-only check.

# Examples

```hcl
# Flags: missing attribute entirely
resource "aws_efs_file_system" "shared" {
  creation_token = "shared-data"
}

# Flags: explicit false
resource "aws_efs_file_system" "shared" {
  creation_token = "shared-data"
  encrypted      = false
}

# Silent: encrypted at rest
resource "aws_efs_file_system" "shared" {
  creation_token = "shared-data"
  encrypted      = true
}
```

# Citations

[1] agentsec checklist item `7-efs-file-system-not-encrypted` (§7)
[2] CWE-311
[3] OWASP:A02
