---
type: Guard
title: "azure-storage-account-public-blob-access"
description: "Azure Storage Account allows public blob access (allow_blob_public_access not explicitly false)."
timestamp: "2026-09-05T00:00:00Z"
guard_id: "azure-storage-account-public-blob-access"
checklist_section: ["6a"]
standards: ["OWASP:A05", "CWE-284", "SOC2:CC6.6"]
---

# Azure Storage Account allows public blob access

_Author — 2026-09-05_

---

## The threat

`allow_blob_public_access` is the account-wide guardrail that decides whether ANY container
inside an Azure Storage Account can be configured for anonymous, unauthenticated public read
access. It does not itself publish anything — a container's own access level (private/blob/
container) still has to be set — but when the account-level flag is left permissive, nothing
stops that container ACL from being flipped to public later: a copy-pasted Terraform module, a
manual Azure Portal or CLI change, or an application bug that provisions containers
dynamically. Once a container is public, every blob in it is readable by anyone with the URL,
no authentication required — the same real-world exposure class as an S3 bucket losing its
Block Public Access controls. CWE-284 (Improper Access Control), OWASP:A05 (Security
Misconfiguration).

## Why this guard fits the stack

Azure Blob Storage is a common choice for user uploads, generated documents, and static assets
in a FastAPI + React app deployed on Azure, and `allow_blob_public_access` is opt-out rather
than opt-in in the sense that matters here: a developer who never thinks about it gets the
provider's default, which does not lock the account down.

```hcl
resource "azurerm_storage_account" "app" {
  name                     = "appstorage"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  # no allow_blob_public_access attribute at all -> not explicitly disabled
}
```

Sourced from KICS's `public_storage_account` query, verified against the real fetched
`query.rego`: `storage.allow_blob_public_access != false` is one of several sub-checks in that
query. This guard scopes to just that boolean-flag sub-case — the query's `network_rules`/
`ip_rules` 0.0.0.0/0 sub-cases are a materially different check (a network firewall allowlist,
not an ACL guardrail) and are out of scope for this guard.

## Detection design

1. `applies()` gate: `"terraform" in profile.features`.
2. Scanned files: every `.tf` file under the repo root (via `iter_files(root, (".tf",))`),
   skipping non-product paths (`is_nonproduct_path`).
3. Uses `iter_terraform_resources()` to isolate `azurerm_storage_account` blocks. Within each
   such block, a comment-blanked view of the body is searched for
   `allow_blob_public_access = false` (regex `\ballow_blob_public_access\s*=\s*false\b`); if
   not found — whether because the attribute is missing entirely, or present as `true` — the
   resource fires. Mirrors the established "omitted OR explicit-unsafe-value, both fire" shape
   used by `rds-storage-not-encrypted` and `azure-keyvault-purge-protection-disabled`.
4. Inline opt-out pragma: `# security: allow-azure-storage-public-blob-access` anywhere in the
   resource block.
5. Severity: HIGH. Rule id: `azure-storage-account-public-blob-access/missing-or-enabled`.
   Standards: `["OWASP:A05", "CWE-284"]`.

## When NOT to flag

A resource that explicitly sets `allow_blob_public_access = false` does not fire — that is the
account-wide guardrail actually in place. The pragma exists for a genuinely-audited exception,
e.g. a storage account deliberately used to serve public static assets (a marketing site's
image bucket) where public blob access is the intended design, not a misconfiguration.

## Tests

| Test | What it checks |
|---|---|
| `test_azure_storage_public_blob_flags_missing_attribute` | no `allow_blob_public_access` attribute at all fires |
| `test_azure_storage_public_blob_flags_explicit_true` | `allow_blob_public_access = true` fires |
| `test_azure_storage_public_blob_silent_when_explicitly_false` | `allow_blob_public_access = false` stays silent |
| `test_azure_storage_public_blob_silent_other_resource` | a non-`azurerm_storage_account` resource carrying the same attribute name is not scoped in |
| `test_azure_storage_public_blob_silent_comment_mention` | a commented-out `# allow_blob_public_access = false` does NOT suppress a real missing-attribute finding on the same resource |
| `test_azure_storage_public_blob_pragma_silences` | `# security: allow-azure-storage-public-blob-access` in the block suppresses an otherwise-firing violation |
| `test_azure_storage_public_blob_applies_gate` | `applies()` is `False` without `"terraform"` in `profile.features` |
| `test_azure_storage_public_blob_applies_with_terraform` | `applies()` is `True` with `"terraform"` in `profile.features` |

## Known bypasses

- **Indirection via a variable/local**: `allow_blob_public_access = var.public_ok` where the
  variable defaults to `true` elsewhere — the literal `false` never appears in the resource
  block itself, so the scan misses it. Same class of limitation as every other literal-string
  Terraform guard in this codebase.
- **A `false` value that is itself computed** (e.g. an expression, ternary, or a `for_each`
  with a dynamic per-instance value) is not resolved; the guard only searches for the literal
  token `false` after the `=`.

## What this guard does NOT prove

A silent guard proves only that the scanned `.tf` files contain `allow_blob_public_access =
false` on this resource. It does not evaluate the account's actual `network_rules`/firewall
configuration, does not resolve variable/local indirection, does not inspect the *effective*
setting in the live Azure subscription (drift between Terraform state and reality is out of
scope for any static guard in this codebase), and does not check whether any individual
container's own access level is itself public (a container ACL is a separate, per-container
setting this guard does not inspect).

## Checklist mapping

`6a-azure-storage-account-public-blob-access` (§6a).

## Standards

- OWASP:A05 (Security Misconfiguration)
- CWE-284 (Improper Access Control)

## Related guards

- `s3-public-access-block-disabled`: the AWS analog — S3's Block Public Access controls instead
  of Azure's account-wide blob-public-access flag.
- `azure-storage-account-https-only`: the sibling Azure Storage Account guard from the same KICS
  batch, checking TLS/transit enforcement instead of public-access ACLs.

# Citations

[1] agentsec checklist item `6a-azure-storage-account-public-blob-access` (§6a)
[2] OWASP:A05
[3] CWE-284
