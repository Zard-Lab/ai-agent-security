---
type: Guard
title: "azure-keyvault-purge-protection-disabled"
description: "Azure Key Vault without purge protection."
timestamp: "2026-07-15T13:31:11+08:00"
guard_id: "azure-keyvault-purge-protection-disabled"
checklist_section: ["7"]
standards: ["OWASP:A05", "SOC2:CC6.1"]
---

# Azure Key Vault without purge protection

_Author — 2026-07-15_

---

## The threat

An `azurerm_key_vault` Terraform resource without `purge_protection_enabled = true` can be
**permanently, irrecoverably deleted** — vault and every secret/key/certificate it holds — by
anyone who reaches `purge` permission on it: a compromised or over-privileged identity, a
malicious insider, or simply an operator running the wrong `az keyvault purge` / Terraform
`destroy` against production. Azure Key Vault's soft-delete (on by default since 2020) only
gives a *recovery window* after deletion; it does not stop a `purge` call from skipping that
window entirely. `purge_protection_enabled` is the attribute that closes that gap, and — like
several Azure resource security settings — it is opt-in, defaulting to `false` when never set.
Standards: OWASP:A05 (Security Misconfiguration), CWE-320 (Key Management Errors).

## Why this guard fits the stack

This is agentsec's **first Azure-specific guard**. Every prior Terraform guard targets an
`aws_*` resource type; `azurerm_key_vault` is a genuinely new resource-type family for the
codebase, not a variant of an existing AWS check. It was sourced from checkov's real
`KeyVaultEnablesPurgeProtection` (`CKV_AZURE_110`) check, verified against fetched source in an
earlier research pass: the checkov check sets no override on `missing_block_result`, so the
base class's default `FAILED` applies — an omitted attribute fires exactly like an explicit
`false`. This guard reproduces that behavior rather than only flagging the explicit-false case.

Example of the flagged pattern:

```hcl
resource "azurerm_key_vault" "app" {
  name     = "app-kv"
  sku_name = "standard"
  # no purge_protection_enabled attribute at all -> defaults to false
}
```

## Detection design

1. `applies()` gate: `"terraform" in profile.features`. `agentsec/detect.py` has no
   Azure-vs-AWS-specific Terraform feature flag — `terraform` is set generically from `.tf`
   file presence (`detect.py`'s `feats.add("terraform")` block), with no cloud-provider
   discrimination anywhere in detection. Gating on the generic `terraform` feature is therefore
   correct and matches how every existing Terraform guard in this family already works (e.g.
   `rds_storage_not_encrypted.py`, `rds_publicly_accessible.py`).
2. Scanned files: every `.tf` file under the repo root, via `iter_files(root, (".tf",))`,
   skipping non-product paths (`is_nonproduct_path`).
3. Uses the shared, resource-type-agnostic `iter_terraform_resources()` helper
   (`agentsec/guards/base.py`) to isolate each `azurerm_key_vault` resource block (brace-depth
   tracked, string/comment/heredoc-aware — see the helper's own docstring). Within each block,
   the guard checks the block's own body text for `purge_protection_enabled\s*=\s*true`
   (`_PURGE_PROTECTION_TRUE`) against a comment-blanked view of the body, so a commented-out
   `# purge_protection_enabled = true` cannot suppress a genuine finding. This is a whole-block
   absence check, not a per-line presence check — the finding is "this attribute was never
   correctly set anywhere in the block."
4. Inline opt-out pragma: `# security: allow-azure-keyvault-purge-protection` anywhere in the
   resource block (checked against the raw, unblanked body text, before the comment-blank
   step — matching the `rds-storage-not-encrypted` precedent).
5. Severity: MEDIUM (one level below `rds-storage-not-encrypted`'s HIGH — a purgeable vault
   requires an attacker/operator to actually reach and invoke `purge`, a narrower and more
   deliberate action than passively reading unencrypted storage). Rule id:
   `azure-keyvault-purge-protection-disabled/missing-purge-protection`. Standards:
   `["OWASP:A05", "CWE-320"]`.

## When NOT to flag

A genuinely disposable dev/scratch/CI vault that is torn down routinely and holds no real
secrets is a legitimate case where purge protection is intentionally absent (protection would
otherwise block the routine `terraform destroy` teardown). The guard cannot distinguish
"scratch vault" from "production vault" by resource declaration alone — suppress the audited
case with `# security: allow-azure-keyvault-purge-protection` in the block after confirming the
vault genuinely holds no sensitive material and the missing protection is deliberate.

## Tests

| Test | What it checks |
|---|---|
| `test_azure_keyvault_purge_protection_flags_missing_attribute` | Fires when `purge_protection_enabled` is omitted entirely |
| `test_azure_keyvault_purge_protection_flags_explicit_false` | Fires when `purge_protection_enabled = false` |
| `test_azure_keyvault_purge_protection_silent_when_true` | Silent when `purge_protection_enabled = true` |
| `test_azure_keyvault_purge_protection_silent_other_resource` | Silent on an unrelated resource type (`azurerm_key_vault_secret`) |
| `test_azure_keyvault_purge_protection_pragma_silences` | The `# security: allow-azure-keyvault-purge-protection` pragma suppresses the finding |
| `test_azure_keyvault_purge_protection_applies_gate` | `applies()` is `False` without `terraform` in features |
| `test_azure_keyvault_purge_protection_applies_with_terraform` | `applies()` is `True` with `terraform` in features |
| `test_azure_keyvault_purge_protection_brace_in_string_does_not_truncate_block` | An unbalanced `}` inside a tag string value doesn't truncate the block and cause a false positive |
| `test_azure_keyvault_purge_protection_comment_does_not_suppress_finding` | A commented-out `# TODO: purge_protection_enabled = true` does not suppress a real finding |

## Known bypasses

- `purge_protection_enabled = var.enable_purge_protection` where the variable defaults to
  `true` elsewhere — only a literal `true` is matched; variable-indirection would require
  resolving `variables.tf`/`terraform.tfvars`, out of scope for a single-file regex guard.
- A resource nested inside a `module` block that sets `purge_protection_enabled` via a variable
  passed at the call site — the helper only sees the resource's own literal body, not the
  module's internal implementation.
- Whitespace/formatting variants the regex doesn't anticipate are unlikely (`\s*=\s*` already
  tolerates arbitrary spacing), but a non-standard HCL formatter that splits the assignment
  across multiple lines (`purge_protection_enabled\n= true`) would be missed — real-world
  `terraform fmt` output never does this.

## What this guard does NOT prove

- It does not confirm the vault is actually reachable by an attacker, or that its contents are
  sensitive — it only proves the Terraform declaration lacks the setting.
- It does not cover Key Vaults provisioned outside Terraform (ARM templates, Bicep, the Azure
  Portal, or the CLI) — this guard is Terraform-source-only.
- It does not verify RBAC/access-policy scoping on the vault — a vault could have purge
  protection enabled and still be badly over-permissioned; that is a separate concern this
  guard does not touch.
- Passing this guard does not mean the vault is secure — only that this one specific,
  irreversible-deletion gap is closed.

## Checklist mapping

Not registered in `agentsec/checklist/checklist.json` by this change — per the task scope, only
the guard module, its test file, and this design doc were touched. The checklist/registry wiring
is left to the reviewing maintainer per the repo's registry-canonical rule.

## Standards

- OWASP:A05 (Security Misconfiguration)
- CWE-320 (Key Management Errors)

## Related guards

- `rds-storage-not-encrypted`: same "omitted OR explicit-false, both fire" detection shape and
  the same `iter_terraform_resources()` helper, but AWS/`aws_db_instance`-shaped and about
  data-at-rest encryption rather than deletion protection.

# Citations

[1] agentsec checklist item `7-azure-keyvault-purge-protection-disabled` (§7)
[2] OWASP:A05
[3] SOC2:CC6.1
