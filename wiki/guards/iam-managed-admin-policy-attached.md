---
type: Guard
title: "iam-managed-admin-policy-attached"
description: "AWS-managed AdministratorAccess or *FullAccess-family policy attached directly."
timestamp: "2026-07-14T14:41:12+08:00"
guard_id: "iam-managed-admin-policy-attached"
checklist_section: ["6c"]
standards: ["CWE-269", "OWASP:A01", "SOC2:CC6.3"]
---

# AWS-managed AdministratorAccess or *FullAccess policy attached directly

## What it detects

A Terraform IAM role, user, group, or SSO permission-set resource that attaches the
AWS-managed `AdministratorAccess` policy via a `policy_arn`, `managed_policy_arn`, or
`managed_policy_arns` attribute referencing
`arn:aws:iam::aws:policy/AdministratorAccess` — **or** (2026-09-05 extension, Pike batch)
an AWS-managed policy ARN whose name ends in `FullAccess`
(`AmazonS3FullAccess`, `AmazonEC2FullAccess`, `IAMFullAccess`, ...).

## Why it matters

The AWS-managed `AdministratorAccess` policy grants unrestricted `Action: "*"` /
`Resource: "*"` on every AWS service. Attaching it directly is the single-ARN
equivalent of the wildcard IAM statement the existing `iam-wildcard` guard catches,
but expressed as a managed-policy reference rather than an inline JSON statement — so
`iam-wildcard`'s `"Statement"`/`"Effect"` gate never sees it (verified by reading its
source before building this guard, per the skill's duplicate-check step; the two
guards are complementary, not overlapping). Checkov's own `CKV_AWS_274` check exists
specifically to catch this attachment pattern.

**2026-09-05 extension (Pike batch):** the AWS-managed `*FullAccess` family
(`AmazonS3FullAccess`, `AmazonEC2FullAccess`, `IAMFullAccess`, and every other AWS-managed
policy whose name ends in `FullAccess`) is a real, distinct escalation surface from
`AdministratorAccess` — each one grants unrestricted `Action: "*"` on ONE service rather than
every service (the managed-policy equivalent of the `iam-service-wildcard` inline-statement
guard, built in the same batch), which is still enough to delete every S3 bucket, terminate
every EC2 instance, or (for `IAMFullAccess`) grant a direct path to full account takeover via
`iam:*`. Modeled on Pike's `AWS006` audit rule (github.com/JamesWoolfenden/pike,
`src/audit_aws.go`), read in full before extending this guard. Kept in this same guard rather
than split into a new one — it extends the existing `AdministratorAccess`-only scope with the
same attribute/resource-type detection, not a new detection technique.

## Detection scope

- Language: Terraform (`.tf`)
- Applies when: `"terraform" in profile.features`
- Scanned files: every `.tf` file under the repo root
- Uses `iter_terraform_resources()` to isolate `aws_iam_role`,
  `aws_iam_policy_attachment`, `aws_iam_role_policy_attachment`,
  `aws_iam_user_policy_attachment`, `aws_iam_group_policy_attachment`, and
  `aws_ssoadmin_managed_policy_attachment` resource blocks
- Fires when a line inside the block contains both a `policy_arn`/`managed_policy_arn(s)`
  attribute name and the literal ARN `arn:aws:iam::aws:policy/AdministratorAccess`,
  **end-anchored** (`(?=["'\s]|$)`) so it matches ONLY the full-admin policy — not the many
  narrower AWS-managed policies whose name merely starts with it (`AdministratorAccess-Amplify`,
  `AdministratorAccess-AWSElasticBeanstalk`, ...). In HCL the ARN is always a quoted string, so
  the real policy is always followed by a quote/whitespace/end; a `-<suffix>` never is.
- **(extension)** OR fires when that same attribute line references an AWS-managed policy ARN
  whose name ends in `FullAccess` (`_FULLACCESS_ARN`, same end-anchoring discipline). The two
  patterns are mutually exclusive by construction — no ARN can match both — so `_scan` checks
  `AdministratorAccess` first purely to keep its existing rule id/message unchanged, and only
  checks `*FullAccess` when that didn't match.

## Rules

| Rule ID | Severity | Trigger |
|---|---|---|
| `iam-managed-admin-policy-attached/administrator-access` | HIGH | Attribute line references the AdministratorAccess managed-policy ARN |
| `iam-managed-admin-policy-attached/full-access-family` | HIGH | Attribute line references an AWS-managed policy ARN whose name ends in `FullAccess` |

## Opt-out

`# security: allow-iam-admin-policy` on the attribute line.

## Known bypasses / false negatives

| Bypass | Why missed |
|---|---|
| ARN built via string interpolation or a local variable (`"arn:aws:iam::aws:policy/${var.policy_name}"`) | Only the literal ARN string is matched |
| A `managed_policy_arns` list where the ARN is on its own line, not the `managed_policy_arns =` line itself | Conservative single-line seed, matching the project's established tradeoff (see `rds-publicly-accessible`'s design doc for the same class of tradeoff) |

## False positive scenarios

None identified. The earlier unanchored pattern substring-matched
`AdministratorAccess-Amplify` (a real, much narrower AWS-managed policy) as full admin; the
end-anchor (`(?=["'\s]|$)`) fixes that, verified by
`test_iam_managed_admin_policy_attached_silent_administrator_access_amplify`.
`ReadOnlyAccess` and other AWS-managed policies that neither equal `AdministratorAccess` nor end
in `FullAccess` are silent, verified by
`test_iam_managed_admin_policy_attached_silent_readonly_access`.

## Tests (extension additions, 2026-09-05)

| Test | What it checks |
|---|---|
| `test_iam_managed_admin_policy_attached_flags_s3_fullaccess` | `AmazonS3FullAccess` via `policy_arn` fires `.../full-access-family` |
| `test_iam_managed_admin_policy_attached_flags_iamfullaccess_in_managed_policy_arns` | `IAMFullAccess` via `managed_policy_arns` fires the same rule |
| `test_iam_managed_admin_policy_attached_silent_readonly_access` | FP-bait: `ReadOnlyAccess` (matches neither pattern) stays silent |
| `test_iam_managed_admin_policy_attached_pragma_silences_fullaccess` | the existing pragma also suppresses a `*FullAccess` finding |
| `test_iam_managed_admin_policy_attached_administrator_access_still_uses_its_own_rule` | regression: `AdministratorAccess` still fires its own rule id, unaffected by the new branch |

## Checklist mapping

`6c-iam-managed-admin-policy-attached` (new item, HIGH)

## Standards

- OWASP:A01 (Broken Access Control)
- CWE-269 (Improper Privilege Management)

## Related guards

- `iam-wildcard`: inline JSON `Action: "*"` / `Resource: "*"` — a different attribute
  shape (JSON policy document vs. managed-policy ARN reference) covering the same
  underlying "too much privilege" risk from a different angle.

# Citations

[1] agentsec checklist item `6c-iam-managed-admin-policy-attached` (§6c)
[2] CWE-269
[3] OWASP:A01
[4] SOC2:CC6.3
