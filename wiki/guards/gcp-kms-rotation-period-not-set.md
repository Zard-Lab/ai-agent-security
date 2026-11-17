---
type: Guard
title: "gcp-kms-rotation-period-not-set"
description: "GCP KMS crypto key without a rotation period."
timestamp: "2026-07-15T13:32:13+08:00"
guard_id: "gcp-kms-rotation-period-not-set"
checklist_section: ["7"]
standards: ["CWE-320", "OWASP:A02", "SOC2:CC6.1"]
---

# GCP KMS crypto key without a rotation period

## What it detects

A Terraform `google_kms_crypto_key` resource block that does not set `rotation_period`
anywhere in its body, skipping keys whose `purpose` is asymmetric
(`ASYMMETRIC_DECRYPT`/`ASYMMETRIC_SIGN`).

## Why it matters

A GCP KMS symmetric crypto key with no `rotation_period` set is never rotated
automatically — the same key version stays in use indefinitely. If that key version is
ever leaked or compromised (an over-broad IAM grant, an insider, a misconfigured
service account), every ciphertext ever produced under it, past and future, is exposed
until someone notices and rotates manually. checkov's own `CKV_GCP_43`
(`GoogleKMSRotationPeriod.py`) exists specifically to catch this. CWE-320 (Key
Management Errors), OWASP:A02 (Cryptographic Failures).

Asymmetric keys (`purpose = "ASYMMETRIC_SIGN"` / `"ASYMMETRIC_DECRYPT"`) are excluded:
GCP KMS does not support automatic rotation for asymmetric key purposes at all, so
flagging a missing `rotation_period` there would be a guaranteed false positive — the
attribute is inapplicable, not omitted by oversight. This mirrors the same
"skip a class that structurally can't be rotated" logic used by this project's AWS KMS
rotation guard.

## Simplification from checkov's real check (deliberate, scope-narrowing)

checkov's real `CKV_GCP_43` parses the `rotation_period` duration string (Terraform
duration format `"NNNNNNNs"`, e.g. `"7776000s"`) and bounds-checks the parsed value to
1-90 days — a `rotation_period` present but set to, say, 400 days would still fail
checkov's real check. **This guard does not do that.** It is deliberately narrowed to
an absence-only check: any `rotation_period` value present in the block, however long
or short, satisfies this guard. Validating the actual duration value is explicitly out
of scope for this port — parsing/bounding it is a separate, more invasive piece of work
that was not undertaken here. This is a conscious scope decision made during the
research pass that sourced this guard from checkov, not an oversight to be
"fixed" later without deliberately deciding to extend scope.

## Detection scope

- Language: Terraform (`.tf`)
- Applies when: `"terraform" in profile.features`
- Scanned files: every `.tf` file under the repo root
- Uses `iter_terraform_resources()` (`agentsec/guards/base.py`) to isolate
  `google_kms_crypto_key` resource blocks
- Within each block, the body is comment-blanked first (matching
  `rds-storage-not-encrypted`'s approach) so a commented-out `# purpose = "ASYMMETRIC..."`
  or `# rotation_period = ...` can never be read as the real attribute
- Skip condition (checked first): the comment-blanked body contains a `purpose`
  attribute whose quoted value contains `ASYMMETRIC` (case-insensitive) — the block is
  silently skipped, no finding emitted
- Fire condition: the comment-blanked body does NOT contain `rotation_period\s*=`
  anywhere — an absence check across the whole block, not a per-line check, since the
  finding is "this attribute was never set," not "this specific line is dangerous"

## Rules

| Rule ID | Severity | Trigger |
|---|---|---|
| `gcp-kms-rotation-period-not-set/missing-rotation-period` | MEDIUM | `google_kms_crypto_key` block has no `rotation_period` anywhere in its body, and `purpose` is not asymmetric |

## Opt-out

`# security: allow-gcp-kms-rotation-period` anywhere in the resource block silences
that block's finding — block-scoped (matched against the whole body text before the
comment-blank pass), not file-level, since a file may declare both a key that should
rotate and one that is deliberately exempt (e.g. HSM-backed, externally managed
rotation).

## When NOT to flag

- `purpose = "ASYMMETRIC_SIGN"` or `"ASYMMETRIC_DECRYPT"` — asymmetric keys don't
  support rotation in GCP KMS at all; flagging them would be a guaranteed false
  positive, so the guard skips them silently rather than firing and requiring a pragma.
- Any `rotation_period` value present, regardless of the actual duration (this guard's
  deliberate simplification — see above).

## Tests

| Test | What it checks |
|---|---|
| `test_gcp_kms_rotation_period_flags_missing_attribute` | Fires MEDIUM when `rotation_period` is absent entirely |
| `test_gcp_kms_rotation_period_silent_when_present` | Silent when `rotation_period = "7776000s"` is present (any value satisfies this guard) |
| `test_gcp_kms_rotation_period_skips_asymmetric_key` | Silent when `purpose = "ASYMMETRIC_SIGN"` and no `rotation_period` (asymmetric keys skipped) |
| `test_gcp_kms_rotation_period_skips_asymmetric_decrypt_key` | Same skip for `purpose = "ASYMMETRIC_DECRYPT"` |
| `test_gcp_kms_rotation_period_silent_other_resource` | Silent on an unrelated resource type (`google_kms_key_ring`) |
| `test_gcp_kms_rotation_period_pragma_silences` | `# security: allow-gcp-kms-rotation-period` suppresses the finding |
| `test_gcp_kms_rotation_period_applies_gate` | `applies()` is `False` without `terraform` in `profile.features` |
| `test_gcp_kms_rotation_period_applies_with_terraform` | `applies()` is `True` with `terraform` in `profile.features` |
| `test_gcp_kms_rotation_period_commented_purpose_does_not_suppress` | A commented-out `# purpose = "ASYMMETRIC_SIGN"` does not suppress a genuine finding on a symmetric key missing rotation |
| `test_gcp_kms_rotation_period_commented_rotation_does_not_suppress` | A commented-out `# rotation_period = ...` does not suppress a genuine finding |

## Known bypasses

| Bypass | Why missed |
|---|---|
| `rotation_period = "31536000s"` (365 days — well outside checkov's real 1-90 day bound) | Deliberate scope-narrowing: this guard is absence-only and does not parse or bounds-check the duration value (see Simplification section above) |
| `rotation_period = var.key_rotation` where the variable is undefined/empty elsewhere | Only literal presence of the attribute is checked; variable-indirection is not resolved against `variables.tf` |
| `purpose` set via a variable reference (e.g. `purpose = var.key_purpose`) that resolves to an asymmetric value | The asymmetric-skip match requires a literal quoted `ASYMMETRIC*` string in the block; variable indirection is not resolved |
| A resource nested inside a `module` block passing `rotation_period` through at the call site | The helper only sees the resource's own literal body |

## What this guard does NOT prove

A present `rotation_period` of any length (including one that exceeds checkov's real
90-day bound, or is absurdly long, e.g. multi-year) is treated as fully satisfying this
guard. This guard proves only that automatic rotation is configured at all — it says
nothing about whether the configured cadence is actually adequate for the data the key
protects. That validation is out of scope for this port.

## Checklist mapping

Proposed: `7-encryption-at-rest` family (§7, Database/Data Security) — a GCP KMS
analogue to `rds-storage-not-encrypted`'s AWS coverage, but for key lifecycle
management rather than the encryption-at-rest bit itself. Not wired into
`checklist.json` by this change (out of scope for this guard's build — registry and
checklist wiring are handled separately).

## Standards

- OWASP:A02 (Cryptographic Failures)
- CWE-320 (Key Management Errors)

## Related guards

- This project's AWS KMS key-rotation guard (`rc061` batch): same underlying concern
  (a KMS key that never rotates), same "skip asymmetric keys" logic, different cloud
  provider and Terraform resource shape (`aws_kms_key` vs `google_kms_crypto_key`).
- `rds-storage-not-encrypted`: same "attribute absence across the whole block" detection
  shape and comment-blanking approach, a different resource family and concern
  (encryption-at-rest vs key rotation).

# Citations

[1] agentsec checklist item `7-gcp-kms-rotation-period-not-set` (§7)
[2] CWE-320
[3] OWASP:A02
[4] SOC2:CC6.1
