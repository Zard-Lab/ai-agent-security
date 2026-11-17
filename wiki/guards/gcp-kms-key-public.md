---
type: Guard
title: "gcp-kms-key-public"
description: "GCP KMS key / Cloud Storage bucket IAM policy grants access to allUsers/allAuthenticatedUsers."
timestamp: "2026-09-05T00:00:00Z"
guard_id: "gcp-kms-key-public"
checklist_section: ["7"]
standards: ["CWE-284", "OWASP:A01", "SOC2:CC6.1"]
---

# GCP KMS key / Cloud Storage bucket IAM policy grants access to allUsers/allAuthenticatedUsers

_Author — 2026-07-15, extended 2026-09-05 (KICS batch)_

---

## The threat

A GCP KMS crypto key's IAM policy/binding/member is how encrypt/decrypt access to that
key is granted. If a `google_kms_crypto_key_iam_policy`, `_iam_binding`, or `_iam_member`
resource names the special identity `allUsers` as a member, ANY caller on the internet —
authenticated or not — can invoke that key's encrypt/decrypt operations. `allAuthenticatedUsers`
narrows the pool only to "holds any Google account," which is still effectively public: no
membership in the owning project or org is required. A KMS key is typically the root of trust
protecting other encrypted data (database columns, secrets, application data at rest), so a
public grant on the key itself undermines everything it protects. CWE-284 (Improper Access
Control), OWASP:A01 (Broken Access Control).

## Why this guard fits the stack

This is agentsec's first GCP-specific guard — every existing Terraform guard up to this point
(`rds-publicly-accessible`, `iam-role-public-assume`, `s3-bucket-policy-wildcard-principal`, …)
is AWS/Azure-shaped. A GCP-hosted deployment of the target stack that provisions its own KMS
keys via Terraform is exactly the kind of infra-as-code mistake this class of guard exists to
catch — a one-line typo or copy-pasted example (`member = "allUsers"` appears verbatim in a lot
of GCP IAM documentation snippets) silently makes a key public:

```hcl
resource "google_kms_crypto_key_iam_member" "bad" {
  crypto_key_id = google_kms_crypto_key.key.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "allUsers"
}
```

Sourced from checkov's `GoogleKMSKeyIsPublic.py` (`CKV_GCP_112`), verified against the real
fetched source: checkov's own check is a straightforward string-literal search for `allUsers`/
`allAuthenticatedUsers` across the same three resource-type variants, on the `member`/`members`/
`policy_data` attributes — no JSON policy parsing. This guard mirrors that scope deliberately.

**Extended 2026-09-05 (KICS batch)** to also cover `google_storage_bucket_iam_policy`/
`_binding`/`_member` — verified against KICS's real `query.rego` for
`cloud_storage_anonymous_or_publicly_accessible`, which checks `resource.members[_]` for the
same literal strings. It is the direct GCP analog of the AWS S3-public-access family
(`6a-s3-public-access-block-disabled`): a Cloud Storage bucket's IAM policy granting
`allUsers`/`allAuthenticatedUsers` makes the bucket's granted role (read/write/admin) reachable
by anyone, the same shape as an S3 bucket losing its Block Public Access controls. Not a new
detection technique — the same plain string/list attribute shape as the KMS IAM family, so it
was folded into this guard rather than shipped as a separate one (see
`s3-bucket-policy-wildcard-principal` for the precedent of extending an existing guard's
resource-type set instead of duplicating the detection logic).

## Detection design

1. `applies()` gate: `"terraform" in profile.features`.
2. Scanned files: every `.tf` file under the repo root (via `iter_files(root, (".tf",))`),
   skipping non-product paths (`is_nonproduct_path`).
3. Uses `iter_terraform_resources()` to isolate blocks whose resource type is one of
   `google_kms_crypto_key_iam_policy`, `google_kms_crypto_key_iam_binding`,
   `google_kms_crypto_key_iam_member`, `google_storage_bucket_iam_policy`,
   `google_storage_bucket_iam_binding`, or `google_storage_bucket_iam_member`. Within each such
   block, every non-comment line is searched for the literal string `allUsers` or
   `allAuthenticatedUsers` (word-boundaried regex `\b(?:allUsers|allAuthenticatedUsers)\b`) —
   deliberately simple, matching checkov's/KICS's own approach. No attempt is made to parse
   `policy_data` as JSON or resolve which specific attribute (`member` vs `members` vs an inline
   policy string) carries the match; the whole resource body is fair game, same as checkov's own
   `search_deep_keys`-style literal search.
4. Inline opt-out pragma: `# security: allow-gcp-kms-key-public` anywhere in the resource block
   (shared across both resource families — one pragma, one guard).
5. Severity: HIGH. Rule id: `gcp-kms-key-public/public-member` (shared across both resource
   families — the finding `message` distinguishes "KMS access" from "Cloud Storage bucket
   access" by resource type, but the rule id and severity are the same, matching the
   `s3-bucket-policy-wildcard-principal` precedent). Standards: `["OWASP:A01", "CWE-284"]`.

## When NOT to flag

A block naming only specific principals (`user:foo@example.com`, `serviceAccount:...@...`,
`group:...`, `domain:...`) does not fire — those are ordinary least-privilege grants. A `#`
comment line that merely mentions `allUsers` (e.g. a warning comment telling engineers NOT to
use it) is skipped, since comment lines are excluded from the scan before the literal-string
check runs. The pragma exists for a genuinely-audited public key (e.g. a key intentionally
used to verify a publicly-distributed signature) — narrow and rare, but real.

## Tests

| Test | What it checks |
|---|---|
| `test_gcp_kms_key_public_flags_iam_member_all_users` | `google_kms_crypto_key_iam_member` with `member = "allUsers"` fires |
| `test_gcp_kms_key_public_flags_iam_binding_all_authenticated_users` | `google_kms_crypto_key_iam_binding` with `members = ["allAuthenticatedUsers", "user:foo@example.com"]` fires |
| `test_gcp_kms_key_public_flags_iam_policy_data` | `google_kms_crypto_key_iam_policy` with a literal `allUsers` mention anywhere in the block fires |
| `test_gcp_kms_key_public_silent_specific_user` | `member = "user:foo@example.com"` (specific principal, safe) stays silent |
| `test_gcp_kms_key_public_silent_comment_mention` | a `#`-comment line mentioning `allUsers` stays silent |
| `test_gcp_kms_key_public_silent_other_resource_type` | a `google_kms_crypto_key` resource (not an IAM resource type) stays silent even mentioning `allUsers` in a comment |
| `test_gcp_kms_key_public_pragma_silences` | `# security: allow-gcp-kms-key-public` in the block suppresses an otherwise-firing violation |
| `test_gcp_kms_key_public_applies_gate` | `applies()` is `False` without `"terraform"` in `profile.features` |
| `test_gcp_kms_key_public_applies_with_terraform` | `applies()` is `True` with `"terraform"` in `profile.features` |
| `test_gcp_kms_key_public_flags_storage_bucket_iam_member_all_users` | `google_storage_bucket_iam_member` with `member = "allUsers"` fires with a Cloud-Storage-specific message |
| `test_gcp_kms_key_public_flags_storage_bucket_iam_binding_all_authenticated_users` | `google_storage_bucket_iam_binding` with `allAuthenticatedUsers` mixed into a `members` list fires |
| `test_gcp_kms_key_public_storage_bucket_silent_specific_member` | a storage bucket IAM member naming a specific service account stays silent |
| `test_gcp_kms_key_public_storage_bucket_pragma_silences` | the shared pragma suppresses a storage-bucket finding too |
| `test_gcp_kms_key_public_still_flags_kms_after_storage_extension` | narrowing-direction control: KMS detection and its original message wording are unaffected by the storage-bucket resource-type-set addition |

## Known bypasses

- **Indirection via a variable/local**: `member = var.public_member` where the variable is
  defined elsewhere as `"allUsers"` — the literal string never appears in the resource block
  itself, so the scan misses it. Same class of limitation as every other literal-string
  Terraform guard in this codebase (e.g. `rds-publicly-accessible`'s `publicly_accessible = true`
  check would miss `publicly_accessible = var.is_public` too).
- **`for_each`/dynamic member lists** built from a data source or external file — the actual
  member value is not visible as static text in the `.tf` file.
- **`policy_data` referencing an external `data.google_iam_policy` source** whose `binding {}`
  blocks (where the real `members = ["allUsers"]` would live) are defined in a *different*
  resource/data block entirely — this guard only scans the IAM-resource block itself, not
  transitively through references to other blocks in the same file.

## What this guard does NOT prove

A silent guard does not prove the KMS key is private — it proves only that no `google_kms_crypto_key_iam_*`
Terraform resource in the scanned files contains the literal strings `allUsers` or
`allAuthenticatedUsers`. It does not evaluate org-policy constraints, does not resolve
variables/locals/data-source indirection, does not inspect the *effective* IAM policy actually
applied in the live GCP project (drift between Terraform state and reality is out of scope for
any static guard in this codebase), and does not flag a key made public through the GCP Console
or `gcloud` CLI outside of Terraform entirely.

## Checklist mapping

`7-gcp-kms-key-public` (proposed; not yet added to `checklist.json` — out of scope for this change).

## Standards

- OWASP:A01 (Broken Access Control)
- CWE-284 (Improper Access Control)

## Related guards

- `iam-role-public-assume`: the same "wildcard/public principal" shape, but for an AWS IAM role's
  trust policy (JSON `Principal.AWS: "*"`) rather than a GCP KMS IAM member list.
- `s3-bucket-policy-wildcard-principal`: parses `Effect`/`Principal`/`Condition` out of a JSON
  bucket policy — a materially harder problem than this guard's plain string-literal search,
  because S3 bucket policies are JSON documents with negation/condition semantics that GCP's
  KMS IAM member lists don't have.

# Citations

[1] agentsec checklist item `7-gcp-kms-key-public` (§7)
[2] CWE-284
[3] OWASP:A01
[4] SOC2:CC6.1
