---
type: Guard
title: "iam-resource-scopable-wildcard"
description: "IAM policy statement grants a resource-level-permission-eligible action with Resource: \"*\"."
timestamp: "2026-09-05T12:00:00Z"
guard_id: "iam-resource-scopable-wildcard"
checklist_section: ["6c"]
standards: ["OWASP:A01", "CWE-269"]
---

# IAM policy statement grants a resource-scopable action with Resource: "*"

Flags an `Effect: Allow` IAM policy statement whose `Action` is a specific, ordinary permission
that AWS lets you scope to a particular ARN (`s3:GetObject`, `dynamodb:GetItem`, `kms:Decrypt`, ...)
but whose `Resource` is the bare wildcard `"*"` anyway. Closes checklist item
`6c-iam-resource-scopable-wildcard`. Scans Terraform `.tf` files.

_Author — 2026-09-05_

---

## The threat

`iam-wildcard` only fires on `Resource: "*"` when it's paired with an all-actions grant — a
statement whose Action is a single, ordinary permission with `Resource: "*"` is invisible to it. But
AWS's own IAM Action reference marks each of these actions as supporting "resource-level
permissions": the API accepts an ARN in `Resource`, so `Resource: "*"` is an authoring choice, not a
limitation of the action. It multiplies the blast radius of a stolen credential from "one bucket" to
"every bucket the account owns" (or every table, every key, every secret). CWE-269, OWASP:A01.

## Why it fits the stack

Modeled on Pike's `AWS003` audit rule / `hasResourceScopableAction`
(github.com/JamesWoolfenden/pike, `src/audit_aws.go`), read in full before building this guard. Not
a duplicate of `iam-wildcard` (checked before building): that guard's own `_RESOURCE_STAR` regex
only fires when paired with the all-actions `Action: "*"` shape in the same file-level scan; a
`Resource: "*"` alongside an ordinary single Action is genuinely outside its scope.

```hcl
resource "aws_iam_role_policy" "app" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:GetObject"     # AWS supports Resource = "<bucket-arn>/*" for this action
      Resource = "*"                # ...but every bucket in the account was granted instead
    }]
  })
}
```

`_RESOURCE_SCOPABLE_ACTIONS` (in `iam_resource_scopable_wildcard.py`) is a curated, conservative list
of common data-plane actions across S3, DynamoDB, KMS, Secrets Manager, SSM, Lambda, SQS, SNS, EC2,
RDS, and CloudWatch Logs — actions AWS documents as resource-level-permission-eligible AND that
appear routinely in application IAM policies. It is deliberately NOT an attempt to enumerate every
eligible action in the AWS API surface (that runs into the thousands and grows as AWS ships new
services); a missing eligible action is a false negative, not a false positive risk, so the list
favors precision over recall.

## Detection design

1. **`applies()` gate** — `"terraform" in profile.features`.
2. **Files scanned** — every `.tf` file, via `iter_files`, skipping `is_nonproduct_path`.
3. **Statement parsing** — `iter_policy_statement_blocks` (shared walker). Within an
   `Effect: Allow` statement: extract every `Action` value (`_ACTION_ASSIGN`, `NotAction` excluded),
   check membership (case-insensitive) in `_RESOURCE_SCOPABLE_ACTIONS`; extract every `Resource`
   value (`_RESOURCE_ASSIGN`, `NotResource` excluded) and check for a bare `"*"` entry. Both
   conditions must hold for the statement to fire.
4. **Inline opt-out pragma** — `# security: allow-iam-resource-scopable-wildcard`.
5. **Severity / rule / standards** — **HIGH**, `rule = "iam-resource-scopable-wildcard/unscoped-
   resource"`, `standards = ["OWASP:A01", "CWE-269"]`. One finding per statement (names the first
   matched scopable action; a count of "and N more" is appended when several match).

## When NOT to flag

- The named action scoped to a specific ARN (`Resource = "arn:aws:s3:::my-bucket/*"`) — the exact
  case named in the build brief — stays silent.
- An action NOT on the curated list (e.g. `iam:ListRoles`, which is inherently account-wide) with
  `Resource: "*"` stays silent — that's a different, legitimately-unscopable shape.
- A `Deny` statement — a lockdown, not a grant.
- An audited case — suppress with `# security: allow-iam-resource-scopable-wildcard`.

## Tests

| Test | What it checks |
|---|---|
| `test_iam_resource_scopable_wildcard_flags_s3_getobject` | `s3:GetObject` + `Resource: "*"` fires |
| `test_iam_resource_scopable_wildcard_flags_action_list` | a scopable action inside a multi-element `Action` array is still caught |
| `test_iam_resource_scopable_wildcard_silent_scoped_to_bucket` | FP-bait: scoped to a specific bucket ARN stays silent |
| `test_iam_resource_scopable_wildcard_silent_non_scopable_action` | FP-bait: an action not on the curated list stays silent |
| `test_iam_resource_scopable_wildcard_silent_in_deny_statement` | FP-bait: a `Deny` statement stays silent |
| `test_iam_resource_scopable_wildcard_pragma_suppresses` | the inline pragma silences a real finding |
| `test_iam_resource_scopable_wildcard_applies_gate` | `applies()` gates correctly |
| `test_iam_resource_scopable_wildcard_nonproduct_path_skipped` | a finding under `examples/` is skipped |

## Known bypasses

- The curated action list is finite by design (see above) — an eligible action outside it is a
  known, accepted false negative, not a bug.
- A `Resource` array containing `"*"` mixed with real ARNs (an unusual authoring pattern) is still
  treated as unscoped, since `"*"` alone grants every matching resource regardless of what else is
  listed alongside it.
- Values built via string interpolation/locals are not evaluated — only literal quoted strings.

## What this guard does NOT prove

It flags a literal action+`Resource: "*"` pairing; it does not evaluate whether the broader Resource
scope was actually necessary for the workload, nor does it evaluate resource-based policies (bucket
policies, key policies — see `s3-bucket-policy-wildcard-principal` for that different angle).
Absence of a finding does not mean the policy is minimally scoped.

# Citations

[1] agentsec checklist item `6c-iam-resource-scopable-wildcard` (§6c)
[2] OWASP:A01
[3] CWE-269
[4] Pike (github.com/JamesWoolfenden/pike), `src/audit_aws.go`, rule `AWS003`
[5] AWS IAM documentation — "Actions, resources, and condition keys" (per-service resource-level
    permissions reference)
