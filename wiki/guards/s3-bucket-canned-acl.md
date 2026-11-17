---
type: Guard
title: "s3-bucket-canned-acl"
description: "S3 bucket AccessControl is not set to a public canned ACL (PublicRead/PublicReadWrite)."
timestamp: "2026-10-25T09:00:00Z"
guard_id: "s3-bucket-canned-acl"
checklist_section: ["6a"]
standards: ["OWASP:A01", "CWE-284"]
---

# S3 bucket AccessControl is not set to a public canned ACL (PublicRead/PublicReadWrite)

_Author — Marconi, 2026-10-25_

---

## The threat

A canned ACL of `public-read` or `public-read-write` on an S3 bucket grants read (or read+write)
access to anyone, including anonymous, unauthenticated requests — independently of any bucket
policy. `authenticated-read` is also flagged: it grants read access to any authenticated AWS user
in any AWS account on the planet, not just this one, which is a materially public grant even
though it technically requires some AWS identity. CWE-284 (Improper Access Control), OWASP:A01.

## Why this guard fits the stack

This is the Terraform-side sibling of `cfn-s3-public-access-canned-acl` — the exact same legacy
canned-ACL mechanism, expressed through Terraform's HCL `acl` attribute instead of
CloudFormation's `AccessControl` property:

```hcl
resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"
}
```

A bucket started as a quick upload/share target, or copied from an old tutorial that predates
provider v4, can end up with this before anyone wires a scoped bucket policy or presigned URLs.

## Detection design

1. `applies()` gate — `"terraform" in profile.features`.
2. Scans every `.tf` file via `iter_files(root, (".tf",))`, skipping non-product paths.
3. Covers Terraform's two generations of setting a bucket's ACL, the same old/new split as
   `s3-mfa-delete-disabled`'s versioning check:
   - **Rule A — legacy inline form** (`s3-bucket-canned-acl/inline-acl-attribute`): the `acl`
     attribute set directly on an `aws_s3_bucket` resource (provider v3 and earlier).
   - **Rule B — split-resource form** (`s3-bucket-canned-acl/acl-resource`): a separate
     `aws_s3_bucket_acl` resource (provider v4+, which removed `acl` from `aws_s3_bucket`
     entirely).

   Both read every line of the resource body that starts with `acl = "..."`, so a `#`/`//`
   comment line is not read, and fire when any of them carries a public value. The read fails
   closed: a nested block's `acl` key counts too, a private `acl` earlier in the body does not
   hide a later public one (PR #1162 round 7), and a `{` inside a `/* */` block comment cannot
   hide the attribute (round 6). The cost is that an `acl = "..."` line which is not the
   attribute (inside a tags map, a heredoc or a multi-line `/* */` comment) also fires. A one-line
   `resource "aws_s3_bucket_acl" "x" { acl = "public-read" }` is read through
   `top_level_attribute_text`, so it fires like its multi-line form (it used to be missed).
4. Both forms fire on the exact same three literal, case-sensitive string values —
   `"public-read"`, `"public-read-write"`, `"authenticated-read"` — matching Terraform's own `acl`
   enum. Every other valid value (`"private"`, `"log-delivery-write"`, `"aws-exec-read"`,
   `"bucket-owner-read"`, `"bucket-owner-full-control"`) is left alone.
5. For the split-resource form, the bucket it targets is resolved for reporting purposes only,
   via the same `bucket = aws_s3_bucket.<name>.` reference pattern used elsewhere in this guard
   family — but the referenced bucket resource does not need to exist in the scanned files for
   this guard to fire; the `aws_s3_bucket_acl` resource's own `acl` value is sufficient on its own.
6. Inline opt-out: `# security: allow-s3-canned-acl` anywhere in the resource block carrying the
   `acl` attribute.
7. Severity: `high` (a direct, unconditionally public grant — mirrors
   `cfn-s3-public-access-canned-acl`). Standards: `["OWASP:A01", "CWE-284"]`.

## When NOT to flag

- `acl` set to any value other than `"public-read"`, `"public-read-write"`, or
  `"authenticated-read"` (e.g. `"private"`, `"log-delivery-write"`).
- No `acl` attribute present at all.
- An audited case (e.g. a deliberately public static-website bucket), suppressed with
  `# security: allow-s3-canned-acl`.

## Tests

| Test | What it checks |
|---|---|
| `test_inline_acl_public_read_fires` | Positive: inline `acl = "public-read"` fires (**verified_by**). |
| `test_inline_acl_public_read_write_fires` | Positive: inline `acl = "public-read-write"` fires. |
| `test_inline_acl_authenticated_read_fires` | Positive: inline `acl = "authenticated-read"` fires. |
| `test_inline_acl_private_silent` | FP-bait: `acl = "private"` → silent. |
| `test_inline_acl_log_delivery_write_silent` | FP-bait: another valid, non-public ACL → silent. |
| `test_inline_acl_no_attribute_silent` | No `acl` attribute at all → silent. |
| `test_inline_acl_pragma_silences` | Suppress pragma → silent. |
| `test_split_resource_acl_public_read_fires` | Positive: split-resource `aws_s3_bucket_acl` with `acl = "public-read"` fires. |
| `test_split_resource_acl_public_read_write_fires` | Positive: split-resource `acl = "public-read-write"` fires. |
| `test_split_resource_acl_private_silent` | FP-bait: split-resource `acl = "private"` → silent. |
| `test_split_resource_acl_does_not_need_bucket_resource_to_exist` | The split-resource rule fires even when the referenced bucket resource is absent from the scanned files. |
| `test_split_resource_pragma_silences` | Suppress pragma on the split resource → silent. |
| `test_applies_gate` / `test_applies_with_terraform` | `applies()` gate. |

## Known bypasses

- **Variable/expression indirection**: `acl = var.bucket_acl`, or a bucket reference built
  through a `for_each`/`count`-derived name — only literal attribute values and a plain `bucket =
  aws_s3_bucket.<name>.` reference are matched.
- **A resource nested inside a `module` block** passing `acl` through at the call site — only the
  resource's own literal body is inspected.
- **Public access granted through S3 Block Public Access settings being disabled, rather than a
  canned ACL** is a different mechanism entirely, not covered here.

## What this guard does NOT prove

A silent guard does not confirm the applied infrastructure matches the source (drift), or that
Block Public Access or bucket-policy settings don't independently make the bucket public through
a different mechanism. This is a presence-based, source-only check of the `acl` attribute alone.

# Citations

[1] agentsec checklist item `6a-s3-bucket-canned-acl` (§6a)
[2] OWASP:A01
[3] CWE-284
[4] cfripper `s3_public_access.py` (`Skyscanner/cfripper`) — the CloudFormation-side pattern this
    Terraform guard mirrors
