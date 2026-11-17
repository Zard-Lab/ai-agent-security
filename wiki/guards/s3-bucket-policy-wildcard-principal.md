---
type: Guard
title: "s3-bucket-policy-wildcard-principal"
description: "Resource policy grants an action to any AWS principal (S3 bucket / KMS key)."
timestamp: "2026-07-12T17:17:48+08:00"
guard_id: "s3-bucket-policy-wildcard-principal"
checklist_section: ["6a"]
standards: ["CWE-284", "OWASP:A01"]
---

# Resource policy grants an action to any AWS principal (S3 bucket / KMS key)

## What it detects

A Terraform `aws_s3_bucket_policy` (or `aws_s3_bucket`), or an `aws_kms_key`, resource whose
policy body contains `"Principal": "*"` / `Principal = "*"` (or the nested `{"AWS": "*"}` /
`{ AWS = "*" }` shape), with no `Condition`/`condition` key anywhere in the resource.

**Scope history:** originally S3-only (checkov `CKV_AWS_70`); extended in a later batch to
also cover `aws_kms_key.policy` (checkov `CKV_AWS_33`) — see "KMS key policy" section below
for why this was a generalization rather than a new guard.

## Why it matters

A resource policy statement with `Effect: Allow` and `Principal: "*"` grants the action to
every AWS account in existence — and, for an S3 bucket policy, to anyone on the internet with
no AWS account at all if the bucket isn't otherwise locked down (Block Public Access, a
restrictive ACL); for a KMS key policy, to every principal in the account (or every AWS
account) able to `Decrypt`/`Encrypt`/`GenerateDataKey` with the key, which typically defeats
the purpose of encrypting data at rest. A `Condition` block can legitimately narrow a
wildcard principal to something safe (a specific VPC endpoint, a specific AWS Organization).
checkov's own `CKV_AWS_70` (S3) and `CKV_AWS_33` (KMS) checks each spend roughly 80 lines
walking every recognized condition-key shape (`ArnEquals`/`ArnLike`, `StringEquals`/
`StringLike`, a specific allowlist of condition variable names) to decide whether a given
`Condition` actually narrows the grant or is too broad to count.

## Detection scope

- Language: Terraform (`.tf`)
- Applies when: `"terraform" in profile.features`
- Scanned files: every `.tf` file under the repo root
- Resource types scanned: `aws_s3_bucket_policy`, `aws_s3_bucket`, `aws_kms_key`
  (`_WILDCARD_PRINCIPAL_RESOURCE_TYPES`)
- Uses the shared `iter_terraform_resources()` helper (`agentsec/guards/base.py`)
- Searches the WHOLE resource body as one blob (not per-line) for `Principal`/`"Principal"`
  set to `"*"` or `{"AWS": "*"}` — the nested-`AWS` form frequently spans multiple physical
  lines in real Terraform, so a per-line-only regex would silently miss it
- The nested-`AWS` form is matched in its **list** spelling too (#422) —
  `"Principal": {"AWS": ["*"]}` and `Principal = { AWS = ["*", "arn:..."] }`. IAM accepts a list
  wherever it accepts a scalar principal, and a `"*"` element grants to every AWS account just the
  same, so the scalar-only pattern missed a real public grant entirely. The wildcard may sit at
  **any position** in the list (mixed in with real ARNs it is still a wildcard grant), while the
  search stays inside the brackets. The element is matched as the whole quoted token `"*"`, so a
  scoped ARN that merely ends in a star (`"arn:aws:iam::123456789012:role/*"`) does **not** match:
  the character before that `*` is a `/`, not the opening quote
- Fires only if the same resource body contains NO `Condition`/`condition` key at all

**Deliberate simplification vs. checkov:** rather than re-implementing checkov's ~80-line
condition-key allowlist logic in regex, this guard treats ANY `Condition` present anywhere in
the resource as a plausible narrowing and stays silent — trading some false negatives (a
`Condition` that doesn't actually narrow the grant, e.g. `aws:SourceIp` alone, which checkov's
own code explicitly does NOT treat as narrowing) for a much lower false positive rate than a
naive re-implementation would produce. This is documented as a real, deliberate false-negative
scope, not an oversight.

## KMS key policy (`aws_kms_key`)

checkov's `KMSKeyWildcardPrincipal.py` (`CKV_AWS_33`) checks an `aws_kms_key` resource's own
`policy` attribute — the KMS key policy that governs who can `Decrypt`/`Encrypt`/
`GenerateDataKey`/etc. with the key — for exactly the same shape this guard already looked
for on S3 bucket policies: a JSON policy document with `Effect`/`Principal`/`Condition`
keys (checkov's own KMS check explicitly skips `Deny` statements before checking the
principal) and the wildcard principal expressed either as a bare `"Principal": "*"` or the
nested `{"AWS": "*"}` form. This guard's own heuristic does not parse `Effect` at all
(neither for S3 nor now for KMS) — see "Known bypasses / false negatives" below, an existing
S3 scope limitation this generalization simply inherits rather than introduces.

Because it is structurally the same JSON-policy check applied to a different Terraform
resource type — not a new detection technique — this guard was generalized rather than
forked into a second guard: `_S3_POLICY_RESOURCE_TYPES` was renamed to
`_WILDCARD_PRINCIPAL_RESOURCE_TYPES` and `"aws_kms_key"` was added to the set. The
`Principal`-wildcard regex, the whole-resource `Condition`-presence check, and the pragma
opt-out are all reused unchanged. The only KMS-specific code is message wording: the finding
text now says "KMS key policy" instead of "S3 bucket policy" and describes the blast radius
in KMS terms (any principal in the account gaining key-usage permissions, rather than public
internet exposure) — see `resource_type in _KMS_RESOURCE_TYPES` in the guard module.

A wildcard `Principal` on a KMS key policy is a distinct risk shape from a wildcard on an S3
bucket: a KMS key is rarely internet-reachable the way a misconfigured bucket can be, but a
wildcard principal on the key policy still hands out `kms:Decrypt`/`kms:GenerateDataKey` to
every principal in the account (or, if not scoped to `aws:PrincipalOrgID`/`aws:SourceAccount`
via `Condition`, to every AWS account), which typically defeats the purpose of encrypting
data at rest in the first place if the ciphertext is also reachable.

**Guard id/title decision:** the guard id `s3-bucket-policy-wildcard-principal` was kept
unchanged for check_id/checklist-mapping continuity — the checklist item
`6a-s3-bucket-policy-wildcard-principal` and any existing exceptions/baselines keyed on this
id stay valid. Only the `title` field was broadened ("S3 bucket policy grants an action to
any AWS principal" -> "Resource policy grants an action to any AWS principal (S3 bucket /
KMS key)") to describe the wider scope without breaking anything keyed on `id`.

## Rules

| Rule ID | Severity | Trigger |
|---|---|---|
| `s3-bucket-policy-wildcard-principal/unconditional-wildcard` | HIGH | Wildcard `Principal` with no `Condition` anywhere in the resource (S3 bucket policy or KMS key policy) |

## Opt-out

`# security: allow-s3-wildcard-principal` anywhere in the resource block silences the whole
block — a deliberately public bucket, or a `Condition` shape this heuristic's simplification
doesn't recognize as narrowing.

## Known bypasses / false negatives

| Bypass | Why missed |
|---|---|
| A `Condition` present but not actually narrowing (e.g. only `aws:SourceIp`, which checkov's own logic explicitly excludes from "narrowing") | Deliberate simplification — see above |
| `Principal = var.policy_principal` where the variable resolves to `"*"` elsewhere | Only a literal `"*"` is matched; variable-indirection is out of scope |
| A policy built via `data.aws_iam_policy_document` and referenced by name rather than inlined with `jsonencode()` | The wildcard principal lives in a separate `data` block this guard does not follow |

## False positive scenarios

| Scenario | Why it fires | How to handle |
|---|---|---|
| A deliberately public read-only bucket (public documentation, open dataset) with no `Condition` | The guard cannot distinguish "deliberately public" from "accidentally public" from the policy text alone | Suppress with `# security: allow-s3-wildcard-principal` after confirming the exposure is intentional |
| A `"Effect": "Deny"` statement with `Principal: "*"` (an explicit deny — harmless, often used to block a wildcard elsewhere in the same policy) | The guard's regex never parses `Effect` (a pre-existing S3 simplification the KMS extension inherits unchanged); unlike checkov's own KMS/S3 checks, which skip `Deny` statements before evaluating the principal, this guard would still fire | Suppress with `# security: allow-s3-wildcard-principal` after confirming the statement is a `Deny`, not an `Allow` |

## Checklist mapping

`6a-s3-bucket-policy-wildcard-principal` (HIGH; distinct from `iam-wildcard`, which checks
`Action`/`Resource` wildcards in general IAM policies, not `Principal` wildcards
specifically). The checklist `check_ids` mapping is unchanged by the KMS extension — the
guard id stayed stable, so the existing mapping already covers the KMS case with no
`checklist.json` edit required.

## Standards

- OWASP:A01 (Broken Access Control)
- CWE-284 (Improper Access Control)

## Related guards

- `iam-wildcard`: checks `"Action": "*"`/`"Resource": "*"` — a different field of the same
  policy-statement shape, not a duplicate.
- `s3-public-access-block-disabled`: the account-level safety net that should catch an
  over-permissive S3 bucket policy even if one slips through — same batch, complementary
  layers. (No equivalent account-level safety net exists for KMS key policies; a wildcard
  principal there has no analogous second line of defense, which is part of why the KMS
  case is worth its own coverage rather than relying on other guards.)

# Citations

[1] agentsec checklist item `6a-s3-bucket-policy-wildcard-principal` (§6a)
[2] CWE-284
[3] OWASP:A01
