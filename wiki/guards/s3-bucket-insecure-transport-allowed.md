---
type: Guard
title: "s3-bucket-insecure-transport-allowed"
description: "S3 bucket policy does not deny insecure (non-TLS) transport."
timestamp: "2026-10-27T09:00:00Z"
guard_id: "s3-bucket-insecure-transport-allowed"
checklist_section: ["6a"]
standards: ["OWASP:A02", "CWE-319"]
---

# S3 bucket policy does not deny insecure (non-TLS) transport

_Author — Marconi, 2026-10-25. Revised 2026-10-27 (review H8: a policy built from a
`data.aws_iam_policy_document` or `file()`/`var.*` reference used to fire as an FP; now resolved
or left silent)._

---

## The threat

S3 does not encrypt requests in transit by default. A client, proxy, or script that reaches the
bucket over plain HTTP (or a downgraded TLS connection) sends and receives object data and
credentials unencrypted on the wire. The standard mitigation is a bucket-policy statement that
explicitly denies any request where `aws:SecureTransport` is false; without one, nothing in the
bucket's own policy stops an insecure client from working. CWE-319 (Cleartext Transmission of
Sensitive Information), OWASP:A02.

## Why this guard fits the stack

Teams hand-write a bucket policy once they need something beyond the account defaults — a
cross-account grant, a VPC endpoint restriction, a CloudFront OAC statement — and it's easy to
ship that policy without also adding the unrelated-looking "deny insecure transport" statement:

```hcl
resource "aws_s3_bucket_policy" "app" {
  bucket = aws_s3_bucket.app.id
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.app.arn}/*"
    }]
    # no statement anywhere denies non-TLS requests
  })
}
```

## Detection design

1. `applies()` gate — `"terraform" in profile.features`.
2. Scans every `.tf` file via `iter_files(root, (".tf",))`, skipping non-product paths.
3. Deliberately narrow scope (a disclosed design decision, the same trade-off
   `s3_bucket_policy_wildcard_principal.py` makes with its `Condition`-presence heuristic): **only
   buckets that already have an explicit `aws_s3_bucket_policy` resource are evaluated.** A
   bucket with no custom policy at all is never flagged — that would fire on nearly every
   ordinary bucket and swamp the signal.
4. For each `aws_s3_bucket_policy` resource, its policy body is walked statement-by-statement via
   the shared `iter_policy_statement_blocks` helper (`agentsec/guards/base.py`) — the same walker
   `s3_bucket_policy_wildcard_principal.py` uses, string/comment/heredoc aware.
5. A statement satisfies the mitigation when it has BOTH `Effect` equal to the literal,
   case-sensitive string `"Deny"` AND a `Condition` key present whose text mentions
   `SecureTransport` anywhere — the exact boolean comparison (`Bool`/`StringEquals`, `"true"` vs
   `"false"`) is not parsed, only confirmed present, a known and accepted simplification for what
   a text-only scan can reliably assert.
6. Fires once per `aws_s3_bucket_policy` resource when NONE of its statements satisfy both
   conditions; stays silent if at least one does. `policy` is not always an inline
   `jsonencode({ ... })` literal (review H8): a `policy = data.aws_iam_policy_document.<label>.json`
   reference is resolved only within the referencing resource's own directory (every `.tf` file
   in that same directory, not the whole repo — round-2 review, H-4: a repo-global lookup by
   label alone let one module's same-labelled data source silence a different module's policy of
   the same name, `"policy"` being a very common label) and its `statement { ... }` HCL blocks are
   checked the same way via `_denies_insecure_transport_hcl`; if the referenced data source can't
   be found in that directory, this guard stays silent rather than guess. The reference may
   carry a `count`/`for_each` index (`...tls[0].json`) or the legacy `"${...}"` wrapper. Data
   sources are read through `terraform_code_view()`, so an interpolation inside a statement
   (`resources = ["${aws_s3_bucket.b.arn}/*"]`) cannot break the nested-block match.
   Only a policy whose content is written in the resource -- `jsonencode({`, a `<<EOF` heredoc,
   or a quoted JSON string -- is scanned statement by statement. Every other right-hand side
   (`file(...)`, `templatefile(...)`, `var.*`, `local.*`, a module output) is content this guard
   cannot read, and stays silent (PR #1162 round-2 M-4: these used to be treated as an empty
   literal policy and fired even when the content held a correct Deny).
7. Inline opt-out: `# security: allow-s3-insecure-transport` anywhere in the
   `aws_s3_bucket_policy` resource block.
8. Severity: `medium`. Rule id: `s3-bucket-insecure-transport-allowed/no-deny-insecure-transport`.
   Standards: `["OWASP:A02", "CWE-319"]`.

## When NOT to flag

- A bucket with no `aws_s3_bucket_policy` resource at all — out of scope by design.
- A statement with `Effect = "Deny"` and a `Condition` block mentioning `SecureTransport`
  anywhere in its text.
- An audited case (e.g. TLS enforced upstream by a CloudFront/ALB listener policy instead),
  suppressed with `# security: allow-s3-insecure-transport`.

## Tests

| Test | What it checks |
|---|---|
| `test_policy_with_no_deny_statement_fires` | Positive: policy with only an Allow statement fires (**verified_by**). |
| `test_policy_with_deny_but_no_condition_fires` | Positive: a Deny statement with no `Condition` still fires. |
| `test_policy_with_deny_secure_transport_condition_silent` | FP-bait: a Deny + `Condition` mentioning `SecureTransport` → silent. |
| `test_policy_from_data_source_with_deny_silent` | FP-bait: `policy = data.aws_iam_policy_document.<label>.json` with a real Deny/SecureTransport statement → silent (review H8). |
| `test_policy_from_data_source_without_deny_fires` | Positive: same data-source shape, no mitigation → fires. |
| `test_policy_from_unresolved_data_source_stays_silent` | FP-bait: referenced data source not found in the resource's own directory → silent (can't prove it's missing). |
| `test_data_source_label_resolved_only_within_its_own_directory` | Both directions: a same-labelled data source in a DIFFERENT directory must not resolve — the referencing resource's own Allow-only policy still fires, and an unrelated module's Deny-bearing policy of the same label stays silent for its own resource (review H-4). |
| `test_policy_from_file_function_stays_silent` | FP-bait: `policy = file(...)` → silent (content unreadable). |
| `test_policy_from_variable_stays_silent` | FP-bait: `policy = var.*` → silent. |
| `test_bucket_with_no_policy_resource_stays_silent` | FP-bait: no `aws_s3_bucket_policy` resource at all → silent (the narrowed scope). |
| `test_pragma_silences` | Suppress pragma → silent. |
| `test_non_inline_policy_shapes_with_a_deny_stay_silent` | Round-2 M-4: `local.*`, `...tls[0].json`, `"${data...json}"` and a module output → silent (each used to fire). |
| `test_indexed_and_legacy_data_references_still_resolve_and_fire` | Still-fires partner: the `[0]` and `"${...}"` forms resolve to an Allow-only data source and fire. |
| `test_literal_heredoc_policy_without_deny_still_fires` | A heredoc is a literal policy and is still scanned. |
| `test_commented_out_inline_policy_is_not_read_as_the_policy` | A `# policy = jsonencode({` comment is not a literal policy to scan. |
| `test_commented_out_data_reference_is_not_the_policy` | Round-4 L1: a `# policy = data....json` comment no longer wins over the real Allow-only literal policy, which fires; a real data reference with a trailing comment still resolves. |
| `test_applies_gate` / `test_applies_with_terraform` | `applies()` gate. |

## Known bypasses

- **The exact condition operator/value is never parsed** — a `Condition` that mentions
  `SecureTransport` but is subtly miswritten (e.g. requiring secure transport rather than denying
  its absence) is accepted as satisfying the check; a text-only scan cannot reliably tell the two
  apart without a JSON/HCL evaluator.
- **A `data.aws_iam_policy_document` reference the data source resolution can't find in the
  referencing resource's own directory** (e.g. it lives in a different module) stays silent
  rather than guessing.
- **`policy = file(...)`, `templatefile(...)`, `var.*`, `local.*`, or a module output** --
  content this guard cannot read at all -- stays silent, so a policy assembled in a `locals`
  block without the Deny is a false negative.
- **TLS enforcement applied at another layer** (account-wide SCP, a bucket's own default
  encryption-in-transit setting if AWS ever exposes one outside policy) is invisible to a
  source-only scan of this one resource.

## What this guard does NOT prove

A silent guard does not confirm the applied infrastructure matches the source (drift), that the
policy as deployed actually enforces TLS at request time, or that no other mechanism (an SCP, an
upstream proxy) already covers this. This is a presence-based, source-only check limited to one
bucket policy resource at a time.

# Citations

[1] agentsec checklist item `6a-s3-bucket-insecure-transport-allowed` (§6a)
[2] OWASP:A02
[3] CWE-319
