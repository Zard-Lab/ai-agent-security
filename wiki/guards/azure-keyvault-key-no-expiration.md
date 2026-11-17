---
type: Guard
title: "azure-keyvault-key-no-expiration"
description: "Azure Key Vault key with no expiration date."
timestamp: "2026-07-15T13:32:17+08:00"
guard_id: "azure-keyvault-key-no-expiration"
checklist_section: ["7"]
standards: ["CWE-320", "OWASP:A02", "SOC2:CC6.1"]
---

# Azure Key Vault key with no expiration date

## What it detects

A Terraform `azurerm_key_vault_key` resource block that does not set `expiration_date`
anywhere in its body — the key is created with no expiration at all.

## Why it matters

An Azure Key Vault key with no `expiration_date` never expires. Without a forced expiration
point, there is nothing that makes an operator notice and rotate the key on a cadence — a
compromised or leaked key stays valid indefinitely, and the blast radius of that compromise
only grows the longer it goes unnoticed. This is CWE-320 (Key Management Errors), OWASP:A02
(Insecure Design — no enforced rotation control on a cryptographic key).

checkov's own `CKV_AZURE_40` (`KeyExpirationDate.py`) exists specifically to catch this. It uses
checkov's `ANY_VALUE` sentinel: the check only requires the attribute to be present with *some*
value, and does not validate the date itself. It has no `missing_block_result` override, so
checkov's default `FAILED` applies when the attribute is omitted entirely. This guard mirrors
that scope exactly — presence, not correctness, of `expiration_date`.

## Detection scope

- Language: Terraform (`.tf`)
- Applies when: `"terraform" in profile.features`
- Scanned files: every `.tf` file under the repo root
- Uses the shared `iter_terraform_resources()` helper (`agentsec/guards/base.py`)
- Resource type: `azurerm_key_vault_key` only — a sibling `azurerm_key_vault` resource (the
  vault itself, a container the key lives inside) is a different resource type and is never
  matched by this guard, even if it also lacks an `expiration_date`-shaped attribute
- Fires when a matched resource block's full (comment-blanked) body text does NOT contain a
  match for `\bexpiration_date\s*=` — an absence check across the whole block, not a per-line
  presence check, since the finding is "this key has no expiration configured," not "this
  specific line is dangerous". The value on the right-hand side is never inspected: any real,
  uncommented `expiration_date = ...` assignment silences the finding, matching checkov's
  `ANY_VALUE` semantics.

## Rules

| Rule ID | Severity | Trigger |
|---|---|---|
| `azure-keyvault-key-no-expiration/missing-expiration-date` | LOW | `azurerm_key_vault_key` block has no `expiration_date` anywhere in its body |

## Opt-out

`# security: allow-azure-keyvault-key-expiration` anywhere in the resource block silences that
block's finding — block-scoped (matched against the whole body text), not file-level, since a
file may declare both a covered and an uncovered key.

## When NOT to flag

A key that is genuinely short-lived and already rotated by an external process (e.g. a CI job
that recreates the resource on a schedule, or a key vault soft-delete/purge policy that bounds
its practical lifetime some other way) still benefits from an explicit `expiration_date` as
defense in depth, but a team that has consciously decided an external control already covers
rotation should suppress with the pragma rather than have the guard try to infer that context —
this guard cannot see outside the Terraform file.

## Tests

| Test | What it checks |
|---|---|
| `test_azure_keyvault_key_no_expiration_flags_missing_attribute` | Fires when `expiration_date` is absent entirely |
| `test_azure_keyvault_key_no_expiration_silent_when_set` | Silent when `expiration_date` is set to a real-looking value |
| `test_azure_keyvault_key_no_expiration_silent_other_resource` | Silent on a sibling `azurerm_key_vault` (the vault, not the key) even though it also lacks the attribute |
| `test_azure_keyvault_key_no_expiration_pragma_silences` | The `# security: allow-azure-keyvault-key-expiration` pragma silences the block |
| `test_azure_keyvault_key_no_expiration_applies_gate` | `applies()` is false without `terraform` in `profile.features` |
| `test_azure_keyvault_key_no_expiration_applies_with_terraform` | `applies()` is true with `terraform` in `profile.features` |
| `test_azure_keyvault_key_no_expiration_comment_does_not_suppress_finding` | A commented-out `# expiration_date = ...` does not silence a genuinely missing attribute |
| `test_azure_keyvault_key_no_expiration_brace_in_string_does_not_truncate_block` | An unbalanced `}` inside a tag string value does not truncate the block and drop a real `expiration_date` below it |

## Known bypasses

| Bypass | Why missed |
|---|---|
| `expiration_date = var.key_expiry` where the variable is undefined/null elsewhere | Only presence of the attribute name is checked; variable-indirection requires resolving `variables.tf`, out of scope |
| A resource nested inside a `module` block whose `expiration_date` is set at the call site via a variable | The helper only sees the resource's own literal body |
| An `expiration_date` set to an already-past timestamp | Deliberately out of scope — this guard mirrors checkov's `ANY_VALUE` semantics (presence only), not date validity |

## What this guard does NOT prove

A finding here means only that the Terraform declaration has no visible `expiration_date`. It
does not confirm that a key created outside Terraform (via the Azure CLI/portal, or imported)
lacks an expiration, that a key with an expiration is actually rotated before that date, or that
the key's `key_opts`/access policy are otherwise sound. Silence does not mean the key expires on
a *sensible* cadence — only that some value was assigned to the attribute.

## Checklist mapping

`7-encryption-at-rest` — not modified in this change (`agentsec/checklist/checklist.json` is
out of scope here); this guard closes the same Terraform-key-management gap the sibling
`azurerm_key_vault`-scoped guard (`rc063`) started closing, one resource type down (the key
inside the vault, not the vault itself).

## Standards

- OWASP:A02 (Cryptographic Failures)
- CWE-320 (Key Management Errors)

## Related guards

- The sibling `azurerm_key_vault` Terraform guard (a different resource type — the vault itself,
  not a key stored inside it) covers vault-level configuration; this guard covers key-level
  rotation posture.
- `rds-storage-not-encrypted`: same "attribute absent across the whole resource block, using
  `iter_terraform_resources()`" detection shape, applied to a different cloud/resource pair.

# Citations

[1] agentsec checklist item `7-azure-keyvault-key-no-expiration` (§7)
[2] CWE-320
[3] OWASP:A02
[4] SOC2:CC6.1
