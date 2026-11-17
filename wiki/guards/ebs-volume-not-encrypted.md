---
type: Guard
title: "ebs-volume-not-encrypted"
description: "EBS volume without encryption at rest."
timestamp: "2026-08-16T09:29:01+08:00"
guard_id: "ebs-volume-not-encrypted"
checklist_section: ["7"]
standards: ["CWE-311", "OWASP:A02"]
---

# EBS volume without encryption at rest

_Author — Marconi, 2026-08-16_

---

## The threat

A Terraform `aws_ebs_volume` without `encrypted = true` stores data on disk in plaintext.
EBS encryption is opt-in per volume and defaults to `false` — anyone with access to the
underlying storage (a snapshot, a detached-and-reattached volume, a misconfigured
storage-layer IAM grant) reads the raw data directly, no application-level bug required.
This mirrors the exact risk shape of `rds-storage-not-encrypted`, one layer down the
stack. CWE-311 (Missing Encryption of Sensitive Data), OWASP:A02.

## Why this guard fits the stack

EBS volumes back EC2-hosted workloads (a self-managed vector DB, a worker node, a queue
consumer) in the FastAPI + LLM/RAG shape this project targets:

```hcl
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  # no encrypted attribute at all -> AWS defaults it to false
}
```

Sourced from checkov's `EBSEncryption` check (`CKV_AWS_3`, a `BaseResourceValueCheck`
inspecting `encrypted`; confirmed against the real fetched source).

## Detection design

1. `applies()` gate — `"terraform" in profile.features`.
2. Scans every `.tf` file via `iter_files(root, (".tf",))`, skipping non-product paths.
3. Uses `iter_terraform_resources()` to isolate each `aws_ebs_volume` block. Comments
   blanked into `code_body`. `_ENCRYPTED_TRUE` searches for `encrypted = true` anywhere
   in the block. Fires unless found — whether the attribute is missing entirely or set to
   `false`.
4. Inline opt-out: `# security: allow-ebs-unencrypted` anywhere in the block.
5. Severity: `high` (this is a direct, no-encryption-at-all case, not a
   default-key-vs-CMK nuance — mirrors `rds-storage-not-encrypted`). Rule id:
   `ebs-volume-not-encrypted/missing-encryption`. Standards: `["OWASP:A02", "CWE-311"]`.

## When NOT to flag

- `encrypted = true` present anywhere in the block.
- An audited case (e.g. a genuinely non-sensitive scratch volume), suppressed with
  `# security: allow-ebs-unencrypted`.

## Tests

| Test | What it checks |
|---|---|
| `test_ebs_volume_not_encrypted_flags_missing_attribute` | Positive: no `encrypted` attribute at all fires (**verified_by**). |
| `test_ebs_volume_not_encrypted_flags_explicit_false` | Positive: `encrypted = false` fires. |
| `test_ebs_volume_not_encrypted_silent_when_true` | FP-bait: `encrypted = true` → silent. |
| `test_ebs_volume_not_encrypted_silent_other_resource` | A non-`aws_ebs_volume` resource → silent. |
| `test_ebs_volume_not_encrypted_pragma_silences` | Suppress pragma → silent. |
| `test_ebs_volume_not_encrypted_comment_does_not_suppress_finding` | A commented `# encrypted = true` does NOT suppress a genuine finding. |
| `test_ebs_volume_not_encrypted_applies_gate` / `test_ebs_volume_not_encrypted_applies_with_terraform` | `applies()` gate. |

## Known bypasses

- **Variable indirection**: `encrypted = var.encrypt_volumes` where the variable
  defaults to `true` elsewhere — only a literal value is matched.
- **Region/account default-encryption settings**: some AWS accounts enable
  "encryption by default" for all new EBS volumes at the account/region level; a
  volume with no `encrypted` attribute may still be encrypted in practice if that
  setting is on. This guard cannot see account-level settings — a real FP risk, same
  class already accepted for `rds-storage-not-encrypted`-style checks (source-only,
  no live-account visibility).
- **A resource nested inside a `module` block** — only the literal resource body is seen.

## What this guard does NOT prove

A silent guard does not confirm the applied infrastructure matches the source (drift),
or that a volume provisioned outside Terraform is encrypted. This is a presence-based,
source-only check.

# Citations

[1] agentsec checklist item `7-ebs-volume-not-encrypted` (§7)
[2] CWE-311
[3] OWASP:A02
