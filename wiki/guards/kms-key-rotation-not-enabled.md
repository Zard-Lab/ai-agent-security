---
type: Guard
title: "kms-key-rotation-not-enabled"
description: "Customer-managed KMS key without rotation enabled."
timestamp: "2026-07-15T13:36:23+08:00"
guard_id: "kms-key-rotation-not-enabled"
checklist_section: ["7"]
standards: ["CWE-320", "OWASP:A02", "SOC2:CC6.1"]
---

# Customer-managed KMS key without rotation enabled

_Author — Marconi, 2026-07-15_

---

## The threat

A customer-managed `aws_kms_key` Terraform resource without `enable_key_rotation = true`
never rotates its key material. The same cryptographic key then protects data
indefinitely — the longer a single key is used, the larger the blast radius if it is
ever compromised. A leaked key, an over-broad IAM grant on the key, or a misissued grant
to a compromised principal decrypts *everything* that key ever touched, not just data
encrypted after the compromise. Anyone who reaches the key (via IAM, a snapshot restore
path, or a supply-chain compromise of a principal holding `kms:Decrypt`) inherits the
entire historical blast radius. CWE-320 (Key Management Errors), OWASP:A02
(Cryptographic Failures / insecure design).

## Why it's often introduced

`aws_kms_key` is usually declared once, early, and rarely revisited — a developer
provisions a key to satisfy an encryption requirement elsewhere (`aws_db_instance`,
`aws_s3_bucket`, a secrets store) and moves on:

```hcl
resource "aws_kms_key" "app" {
  description = "app data key"
  # no enable_key_rotation attribute at all -> key material is never rotated
}
```

`enable_key_rotation` is not required by Terraform and AWS does not enable it by
default, so the omission is silent — there's no error, no warning, the key just works.
This is checkov's `KMSRotation` check (`CKV_AWS_7`), a `BaseResourceValueCheck` whose
default `missing_block_result` is `FAILED` (confirmed against the real fetched
checkov source: `checkov/terraform/checks/resource/aws/KMSRotation.py` extends
`BaseResourceValueCheck` and never overrides `missing_block_result`) — an omitted
attribute fires exactly like an explicit `false`.

## Detection design

1. `applies()` gate — `"terraform" in profile.features`.
2. Scans every `.tf` file under the repo root via `iter_files(root, (".tf",))`, skipping
   non-product paths (`is_nonproduct_path`).
3. Uses the shared `iter_terraform_resources()` helper (`agentsec/guards/base.py`) to
   isolate each `aws_kms_key "<name>" { ... }` block (brace/string/heredoc-aware, so a
   stray `}` in a tag value or a heredoc body can't truncate the block early).
4. Within each block:
   - Comments are blanked (not dropped, so line numbers are preserved) into a
     `code_body` view before either pattern is evaluated, so a commented-out
     `# enable_key_rotation = true` or `# customer_master_key_spec = "..."` cannot
     influence the decision on a genuinely non-rotating key.
   - `_CMKS_VALUE` extracts a literal, quoted `customer_master_key_spec = "..."` value.
     If present and its value (uppercased, trimmed) is anything other than
     `SYMMETRIC_DEFAULT`, the block is **skipped entirely** — only a symmetric-default
     CMK supports automatic rotation; `RSA_*`/`ECC_*`/`SM2` (asymmetric) and `HMAC_*`
     specs cannot rotate at all, so flagging them would be a false positive. A
     variable-/expression-driven value (`customer_master_key_spec = var.spec`) is left
     unresolved and falls through to the normal check — conservative by design.
   - `_ROTATION_TRUE` searches `code_body` for `enable_key_rotation = true` anywhere in
     the block. If found, silent.
   - Otherwise, fires.
5. Inline opt-out: `# security: allow-kms-key-rotation` anywhere in the resource block
   (checked against the comment-only view of the body text, #424, since the pragma itself is a
   comment).
6. Severity: `medium`. Rule id: `kms-key-rotation-not-enabled/missing-rotation`.
   Standards: `["OWASP:A02", "CWE-320"]`.

### Deliberate divergence from real checkov

The real `KMSRotation.scan_resource_conf` only skips (`CheckResult.UNKNOWN`) when the
spec is present, is not `SYMMETRIC_DEFAULT`, **and** does not contain `HMAC` — i.e. real
checkov still runs the normal rotation check against HMAC keys, which would perpetually
fail them, since AWS never allows `enable_key_rotation` on an HMAC CMK either. This
guard treats "spec present and not `SYMMETRIC_DEFAULT`" as the single skip condition
(covering asymmetric AND HMAC specs alike), avoiding that false-positive class rather
than reproducing it.

## When NOT to flag

- `enable_key_rotation = true` present anywhere in the block, regardless of what else is
  set.
- `customer_master_key_spec` set to a literal, non-`SYMMETRIC_DEFAULT` value (asymmetric
  or HMAC) — these key types do not support automatic rotation at all.
- An audited case (e.g. a short-lived key by design), suppressed with
  `# security: allow-kms-key-rotation` anywhere in the resource block.

## Tests

| Test | What it checks |
|---|---|
| `test_kms_key_rotation_not_enabled_flags_missing_attribute` | Positive: no `enable_key_rotation` at all fires (**verified_by**). |
| `test_kms_key_rotation_not_enabled_flags_explicit_false` | Positive: `enable_key_rotation = false` fires. |
| `test_kms_key_rotation_not_enabled_silent_when_true` | FP-bait: `enable_key_rotation = true` → silent. |
| `test_kms_key_rotation_not_enabled_silent_asymmetric_spec` | FP-bait: `customer_master_key_spec = "ECC_NIST_P256"`, no rotation → silent. |
| `test_kms_key_rotation_not_enabled_silent_hmac_spec` | FP-bait: `customer_master_key_spec = "HMAC_256"`, no rotation → silent. |
| `test_kms_key_rotation_not_enabled_fires_symmetric_default_spec` | `customer_master_key_spec = "SYMMETRIC_DEFAULT"` explicitly, no rotation → still fires (symmetric-default rotates). |
| `test_kms_key_rotation_not_enabled_silent_other_resource` | A non-`aws_kms_key` resource → silent. |
| `test_kms_key_rotation_not_enabled_pragma_silences` | Suppress pragma → silent. |
| `test_kms_key_rotation_not_enabled_comment_does_not_suppress_finding` | A commented `# enable_key_rotation = true` does NOT suppress a genuine finding. |
| `test_kms_key_rotation_not_enabled_applies_gate` / `test_kms_key_rotation_not_enabled_applies_with_terraform` | `applies()` gate. |

## Known bypasses

- **Variable indirection**: `enable_key_rotation = var.rotate` where the variable
  defaults to `true` elsewhere, or `customer_master_key_spec = var.spec` where the
  variable resolves to an asymmetric/HMAC spec — only a literal value is matched;
  resolving `variables.tf` is out of scope for a regex-based guard.
- **A resource nested inside a `module` block** passing either attribute through at the
  call site — the helper only sees the resource's own literal body.
- **Whitespace/formatting extremes** beyond what `\s*` tolerates are not expected in
  practice (Terraform is `terraform fmt`-normalized in most repos), but an exotic
  non-standard formatter could theoretically evade the regex.

## What this guard does NOT prove

A silent guard does not mean the key is actually rotating in AWS — it only means a
literal `enable_key_rotation = true` (or a skip-eligible `customer_master_key_spec`) was
found in the Terraform source at audit time. It does not confirm the applied
infrastructure matches the source (drift), that the attribute wasn't overridden via
`-var`/`terraform.tfvars` at apply time in a way this static text can't see, or that a
key provisioned outside Terraform (console, CloudFormation, another IaC tool) is
rotating. This is a presence-based, source-only check.

# Citations

[1] agentsec checklist item `7-kms-key-rotation-not-enabled` (§7)
[2] CWE-320
[3] OWASP:A02
[4] SOC2:CC6.1
