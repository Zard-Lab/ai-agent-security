---
type: Guard
title: "iam-policy-attached-to-user-directly"
description: "IAM policy attached directly to a user instead of a group/role."
timestamp: "2026-07-14T14:41:42+08:00"
guard_id: "iam-policy-attached-to-user-directly"
checklist_section: ["6c"]
standards: ["CWE-269", "OWASP:A01", "SOC2:CC6.3"]
---

# IAM policy attached directly to a user instead of a group/role

## What it detects

A Terraform `aws_iam_user_policy` or `aws_iam_user_policy_attachment` resource
(attaching a policy directly to an individual IAM user), or an
`aws_iam_policy_attachment` resource whose `users` list is non-empty.

## Why it matters

Attaching policies directly to individual IAM users, instead of to a group or role
the user is a member of, means every permission change has to be made per-user —
permissions drift silently as people join, change roles, and leave, with no single
place to audit "what can this team do." `aws_iam_user_policy` and
`aws_iam_user_policy_attachment` exist specifically for user-direct attachment (there
is no other legitimate use of either resource type — the resource *declaration
itself* is the signal, no attribute inspection needed);
`aws_iam_policy_attachment` can target users, roles, or groups via separate
arguments, so it only fires when its `users` argument is actually populated.
Checkov's own `CKV_AWS_40` check exists for the same reason.

## Detection scope

- Language: Terraform (`.tf`)
- Applies when: `"terraform" in profile.features`
- Scanned files: every `.tf` file under the repo root
- Uses `iter_terraform_resources()` to isolate resource blocks
- Fires MEDIUM on every `aws_iam_user_policy` / `aws_iam_user_policy_attachment`
  resource declaration (the resource's own opening line)
- Fires MEDIUM on an `aws_iam_policy_attachment` resource whose `users` attribute is
  a non-empty list. The list is **joined across physical lines** up to the matching `]`,
  so a `terraform fmt`-split multi-line list is seen; a list holding only whitespace or
  comments (`users = []`, or a multi-line list with only a `# comment`) stays silent.
  Comments are stripped from each line **before** the `]`-termination test, so a stray `]`
  inside a comment cannot end the join early and drop a real user element below it.

## Rules

| Rule ID | Severity | Trigger |
|---|---|---|
| `iam-policy-attached-to-user-directly/direct-user-attachment` | MEDIUM | `aws_iam_user_policy`/`aws_iam_user_policy_attachment` declared, or `aws_iam_policy_attachment.users` non-empty |

## Opt-out

`# security: allow-iam-user-policy` anywhere in the resource block.

## Known bypasses / false negatives

| Bypass | Why missed |
|---|---|
| `users = var.user_list` where the variable resolves to a non-empty list | Only a literal `[...]` with visible content is matched; variable indirection is out of scope for a single-file regex, same tradeoff as sibling checkov-sourced guards |

## False positive scenarios

None identified — `aws_iam_user_policy`/`aws_iam_user_policy_attachment` have no
legitimate non-user-attachment use, and the `users`-list check requires visible
non-empty content.

## Checklist mapping

`6c-iam-policy-attached-to-user-directly` (new item, MEDIUM)

## Standards

- OWASP:A01 (Broken Access Control)
- CWE-269 (Improper Privilege Management)

## Related guards

- `iam-wildcard`, `iam-managed-admin-policy-attached`: both flag *what* a policy
  grants; this guard flags *how* a policy is attached (structurally harder to audit),
  a distinct IAM-hygiene axis.

# Citations

[1] agentsec checklist item `6c-iam-policy-attached-to-user-directly` (§6c)
[2] CWE-269
[3] OWASP:A01
[4] SOC2:CC6.3
