---
type: Guard
title: "azure-storage-account-https-only"
description: "Azure Storage Account does not enforce HTTPS-only traffic (enable_https_traffic_only / https_traffic_only_enabled not true)."
timestamp: "2026-09-05T00:00:00Z"
guard_id: "azure-storage-account-https-only"
checklist_section: ["6a"]
standards: ["OWASP:A02", "CWE-319", "SOC2:CC6.1"]
---

# Azure Storage Account does not enforce HTTPS-only traffic

_Author — 2026-09-05_

---

## The threat

An Azure Storage Account can be reached over plain HTTP unless it is explicitly told to
require HTTPS for every request. Requests to a storage account routinely carry
authentication material — SAS tokens, storage account keys in a header or query string — and
application data (uploads, generated documents, exports). Allowing that traffic over
cleartext HTTP means any network position between the client and Azure (shared Wi-Fi, a
compromised router, a misconfigured corporate proxy) can read or tamper with it, including the
credentials that authenticate to the account itself. CWE-319 (Cleartext Transmission of
Sensitive Information), OWASP:A02 (Cryptographic Failures).

## Why this guard fits the stack

Azure Blob Storage backing a FastAPI + React app's uploads or generated documents needs this
enforced at the account level — an application-level HTTPS redirect elsewhere in the stack
does nothing to stop a direct HTTP request to the storage endpoint itself:

```hcl
resource "azurerm_storage_account" "app" {
  name                     = "appstorage"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  # no enable_https_traffic_only / https_traffic_only_enabled attribute at all
}
```

Sourced from KICS's `storage_account_not_forcing_https` query, verified against the real
fetched `query.rego`: the query explicitly handles BOTH the pre-v4 attribute name
`enable_https_traffic_only` and its Terraform AzureRM provider v4 rename
`https_traffic_only_enabled`. This matters in practice — a guard hard-coded to only the old
name would silently stop firing the moment a project upgrades its AzureRM provider past v4 and
migrates the attribute name, exactly the kind of "passed before, fails silently now" regression
this codebase's review doctrine calls out.

## Detection design

1. `applies()` gate: `"terraform" in profile.features`.
2. Scanned files: every `.tf` file under the repo root (via `iter_files(root, (".tf",))`),
   skipping non-product paths (`is_nonproduct_path`).
3. Uses `iter_terraform_resources()` to isolate `azurerm_storage_account` blocks. Within each
   such block, a comment-blanked view of the body is searched for either
   `enable_https_traffic_only = true` OR `https_traffic_only_enabled = true` (regex
   `\b(?:enable_https_traffic_only|https_traffic_only_enabled)\s*=\s*true\b`); if neither is
   found — whether both attributes are missing, or the one present is `false` — the resource
   fires.
4. Inline opt-out pragma: `# security: allow-azure-storage-https-only` anywhere in the resource
   block.
5. Severity: MEDIUM. Rule id: `azure-storage-account-https-only/missing-or-disabled`.
   Standards: `["OWASP:A02", "CWE-319"]`.

## When NOT to flag

A resource that sets either attribute name to `true` does not fire — HTTPS enforcement checks
the semantic setting, not which of the two provider-version attribute names was used. The
pragma exists for a genuinely-audited exception, e.g. a legacy client that cannot yet be
migrated off plain HTTP during a transition window.

## Tests

| Test | What it checks |
|---|---|
| `test_azure_storage_https_only_flags_missing_attribute` | neither attribute present fires |
| `test_azure_storage_https_only_flags_legacy_attribute_false` | `enable_https_traffic_only = false` fires |
| `test_azure_storage_https_only_flags_v4_attribute_false` | `https_traffic_only_enabled = false` (the v4 rename) fires |
| `test_azure_storage_https_only_silent_with_legacy_attribute_true` | `enable_https_traffic_only = true` stays silent |
| `test_azure_storage_https_only_silent_with_v4_attribute_true` | `https_traffic_only_enabled = true` (the v4 rename) stays silent |
| `test_azure_storage_https_only_silent_other_resource` | a non-`azurerm_storage_account` resource carrying the same attribute name is not scoped in |
| `test_azure_storage_https_only_silent_comment_mention` | a commented-out `# https_traffic_only_enabled = true` does NOT suppress a real missing-attribute finding |
| `test_azure_storage_https_only_pragma_silences` | `# security: allow-azure-storage-https-only` in the block suppresses an otherwise-firing violation |
| `test_azure_storage_https_only_applies_gate` | `applies()` is `False` without `"terraform"` in `profile.features` |
| `test_azure_storage_https_only_applies_with_terraform` | `applies()` is `True` with `"terraform"` in `profile.features` |

## Known bypasses

- **Indirection via a variable/local**: `https_traffic_only_enabled = var.enforce_https` — the
  literal `true` never appears in the resource block itself, so the scan misses it.
- A **third, not-yet-renamed attribute name** introduced by a future AzureRM provider major
  version would not be recognized until this guard's regex is updated to include it — the same
  residual risk any literal-attribute-name guard carries across a provider's lifetime.

## What this guard does NOT prove

A silent guard proves only that the scanned `.tf` files set one of the two recognized
attribute names to `true` on this resource. It does not verify the *effective* setting in the
live Azure subscription (drift between Terraform state and reality is out of scope for any
static guard in this codebase), does not check the account's minimum TLS version
(`min_tls_version`, a separate attribute this guard does not inspect), and does not resolve
variable/local indirection.

## Checklist mapping

`6a-azure-storage-account-https-only` (§6a).

## Standards

- OWASP:A02 (Cryptographic Failures)
- CWE-319 (Cleartext Transmission of Sensitive Information)

## Related guards

- `azure-storage-account-public-blob-access`: the sibling Azure Storage Account guard from the
  same KICS batch, checking public-access ACLs instead of TLS/transit enforcement.
- `pg-ssl-required`: the same "require encryption in transit" shape, applied to a Postgres
  connection string's `sslmode` instead of a Terraform attribute.

# Citations

[1] agentsec checklist item `6a-azure-storage-account-https-only` (§6a)
[2] OWASP:A02
[3] CWE-319
