---
type: Guard
title: "s3-mfa-delete-disabled"
description: "S3 bucket versioning does not require MFA for object deletion."
timestamp: "2026-10-27T09:00:00Z"
guard_id: "s3-mfa-delete-disabled"
checklist_section: ["7"]
standards: ["OWASP:A05", "CWE-306"]
---

# S3 bucket versioning does not require MFA for object deletion

_Author — Marconi, 2026-10-25. Revised 2026-10-27 (review H7: the bare-label cross-file match
could let one module's enabled versioning silence a different module's disabled one; fixed)._

---

## The threat

S3 versioning protects against an accidental or malicious object delete by keeping the prior
version around. Without MFA Delete, that protection itself has no second factor: a single
compromised set of IAM credentials can permanently delete a specific object version (as opposed
to merely creating a delete marker), or suspend versioning altogether, with nothing beyond normal
IAM permissions required. MFA Delete forces a one-time MFA code from the bucket owner's root
account on exactly those two destructive calls, so stolen long-lived credentials alone are not
enough. CWE-306 (Missing Authentication for Critical Function), OWASP:A05.

## Why this guard fits the stack

A bucket holding durable application data (uploads, backups, exported records) in the
FastAPI + LLM/RAG shape this project targets is routinely given versioning for rollback safety,
but MFA Delete is easy to miss — it isn't implied by `enabled = true`/`status = "Enabled"` and
Terraform can't even apply it through a normal IAM role (it needs the root account's own
credentials and an MFA device at apply time), so it's commonly left off entirely:

```hcl
resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
    # no mfa_delete -> deletions/version-suppressions need no MFA at all
  }
}
```

Verified against the real-world rule this pattern is drawn from (the `versioning.mfa_delete` /
`versioning_configuration.mfa_delete` attribute shape); the two Terraform provider generations
are confirmed against the live AWS provider docs, not cited by source name per this codebase's
internal-attribution convention for guard code.

## Detection design

1. `applies()` gate — `"terraform" in profile.features`.
2. Scans every `.tf` file via `iter_files(root, (".tf",))`, skipping non-product paths, and
   gathers `aws_s3_bucket` and `aws_s3_bucket_versioning` resources across **every** `.tf` file in
   the repo before matching (the split-resource form is routinely declared in a separate file,
   e.g. `versioning.tf`) — the same cross-file approach `aws_observability_hygiene.py` uses.
3. **Rule A — legacy inline form** (`s3-mfa-delete-disabled/inline-versioning-block`): only
   evaluated when the bucket has NO linked split-resource form. If the bucket's own inline
   `versioning { ... }` block is absent entirely, this guard stays silent (that gap is
   `aws-observability-hygiene/s3-versioning-missing`'s job). If the block is present but its
   `enabled` is not literally `true` (it is `false`, a variable, or omitted, which defaults to
   `false`), versioning is not on and the guard stays silent. Otherwise it fires unless
   `mfa_delete = true` (a bool) appears inside it.
4. **Rule B — split-resource form** (`s3-mfa-delete-disabled/versioning-configuration-resource`):
   a bucket is linked to an `aws_s3_bucket_versioning` resource via a `bucket = aws_s3_bucket.<name>.`
   reference on the split resource's own `bucket` attribute (anchored the same way as the sibling
   guards' bucket-reference helper). When linked, that resource's `versioning_configuration { ... }`
   block decides the verdict. It is only in scope when its `status` is literally `"Enabled"`;
   `"Suspended"`, `"Disabled"` or a variable stays silent. When in scope, it fires unless
   `mfa_delete = "Enabled"` (a **string** enum, not a bool) appears inside it. A linked split resource always wins over the legacy inline block for
   that bucket, so a bucket is never double-reported. A bucket links only to split resources in
   its own directory (Terraform scopes a resource reference to its module), so two
   `aws_s3_bucket.logs` / `aws_s3_bucket_versioning.logs` pairs in different directories never
   decide each other (review H7, and its inline form in PR #1162 round-2 Low). Every DISTINCT
   linked split resource is judged on its own, once.
   Both rules read the block through `terraform_code_view()` (`guards/base.py`), so a
   commented-out `# mfa_delete = true` or `# status = "Enabled"` is not configuration (PR #1162
   round-1 M6: a commented `mfa_delete` used to satisfy the check, and a suspended configuration
   used to fire). The pragma is still read from the raw block.
5. No expression evaluation: a bucket referenced only through a variable or a
   `for_each`-derived resource name is not resolved (accepted false-negative, consistent with
   every other regex/text-scoped Terraform guard in this codebase).
6. Inline opt-out: `# security: allow-s3-mfa-delete` anywhere in the resource block carrying the
   finding (the `aws_s3_bucket` block for Rule A, the `aws_s3_bucket_versioning` block for Rule B).
7. Severity: `medium`. Standards: `["OWASP:A05", "CWE-306"]`.

## When NOT to flag

- No versioning configured at all (no inline block, no linked split resource) — owned by
  `aws-observability-hygiene/s3-versioning-missing`, not this guard.
- Versioning not provably on: inline `enabled = false` / omitted / a variable, or a split
  `status = "Suspended"` / `"Disabled"` / a variable.
- `mfa_delete = true` present in the legacy inline `versioning` block.
- `mfa_delete = "Enabled"` present in the split resource's `versioning_configuration` block.
- An audited case, suppressed with `# security: allow-s3-mfa-delete`.

## Tests

| Test | What it checks |
|---|---|
| `test_inline_versioning_missing_mfa_delete_fires` | Positive: inline `versioning` block with no `mfa_delete` fires (**verified_by**). |
| `test_inline_versioning_explicit_mfa_delete_false_fires` | Positive: `mfa_delete = false` inline fires. |
| `test_inline_versioning_mfa_delete_true_silent` | FP-bait: `mfa_delete = true` inline → silent. |
| `test_bucket_with_no_versioning_at_all_stays_silent` | FP-bait: no versioning configured anywhere → silent (not this guard's job). |
| `test_inline_versioning_pragma_silences` | Suppress pragma → silent. |
| `test_split_resource_missing_mfa_delete_fires` | Positive: split-resource form with no `mfa_delete` fires. |
| `test_split_resource_mfa_delete_disabled_string_fires` | Positive: `mfa_delete = "Disabled"` fires. |
| `test_split_resource_mfa_delete_enabled_string_silent` | FP-bait: `mfa_delete = "Enabled"` → silent. |
| `test_split_resource_wins_over_legacy_inline_no_double_report` | A bucket with both forms is judged once, by the split resource. |
| `test_split_resource_for_different_bucket_does_not_silence` | A split resource referencing a DIFFERENT bucket doesn't silence this one. |
| `test_two_modules_same_bare_label_both_judged` | Review H7: two unrelated buckets in different directories sharing the bare label "logs" — the unprotected one still fires. |
| `test_split_resource_pragma_silences` | Suppress pragma on the split resource → silent. |
| `test_versioning_not_on_is_out_of_scope` | Round-1 M6: inline `enabled = false`/omitted/variable and split `Suspended`/`Disabled`/variable → silent (each used to fire). |
| `test_versioning_on_without_mfa_still_fires_in_both_forms` | Still-fires partner: versioning on (`enabled = true`, quoted `"true"`, `status = "Enabled"`) without MFA fires. |
| `test_commented_out_mfa_delete_does_not_suppress` | Round-1 M6: a commented-out `mfa_delete` no longer satisfies the check; the real attribute with a trailing comment does. |
| `test_commented_out_enabled_status_is_not_versioning_on` | A commented-out `status = "Enabled"` above `"Suspended"` → silent. |
| `test_inline_bucket_is_not_judged_by_a_split_resource_in_another_directory` | Round-2 Low: modA's inline no-MFA bucket fires although modB's same-labelled split resource requires MFA. |
| `test_split_resource_in_another_file_of_the_same_directory_still_links` | Still-fires partner: a split resource in `versioning.tf` of the same directory still decides the bucket. |
| `test_applies_gate` / `test_applies_with_terraform` | `applies()` gate. |

## Known bypasses

- **Variable/expression indirection**: `mfa_delete = var.require_mfa_delete`, or a bucket
  reference built through a `for_each`/`count`-derived name — only literal attribute values and a
  plain `bucket = aws_s3_bucket.<name>.` reference are matched.
- **A resource nested inside a `module` block** passing `mfa_delete` through at the call site —
  only the resource's own literal body is inspected.
- MFA Delete can only ever be enabled by the bucket owner's root credentials via the CLI/API
  outside Terraform's normal apply path; this guard cannot see whether that out-of-band step was
  actually performed to match a `mfa_delete = "Enabled"` declaration that drifted.

## What this guard does NOT prove

A silent guard does not confirm the applied infrastructure matches the source (drift), or that
MFA Delete was actually turned on out-of-band to match a declared `"Enabled"` value. This is a
presence-based, source-only check.

# Citations

[1] agentsec checklist item `7-s3-mfa-delete-disabled` (§7)
[2] OWASP:A05
[3] CWE-306
