---
type: Guard
title: "iam-service-wildcard"
description: "IAM policy statement grants a full service-wide wildcard action such as iam:* or s3:*."
timestamp: "2026-09-05T12:00:00Z"
guard_id: "iam-service-wildcard"
checklist_section: ["6c"]
standards: ["OWASP:A01", "CWE-269"]
---

# IAM policy statement grants a full service-wide wildcard action

Flags an `Effect: Allow` IAM policy statement whose `Action` is a genuine service-wide wildcard —
`iam:*`, `s3:*`, `ec2:*` — one colon, ending in a bare `*`. Closes checklist item
`6c-iam-service-wildcard-action`. Scans Terraform `.tf` files.

_Author — 2026-09-05_

---

## The threat

An identity holding a service-wide wildcard action can do anything that service's API allows: `iam:*`
grants `PutRolePolicy`, `AttachRolePolicy`, `PassRole` and every other action on the 15-action
privilege-escalation list `iam-escalation-action-no-condition` (this same batch) enumerates; `s3:*`
grants `PutBucketPolicy`/`DeleteBucket` on every bucket the account owns. This is CWE-269 (Improper
Privilege Management), OWASP:A01. Reachable by anything that can act as the role/user carrying the
policy — a stolen credential or a prompt-injected agent with tool access to Terraform-managed infra.

## Why it fits the stack

`iam-wildcard`, this repo's existing guard, deliberately does NOT flag this shape — read before
building this guard, per the duplicate-check step: its own docstring states "Scoped service
wildcards (`s3:*`) are common and not flagged; the all-actions/all-resources grant is the egregious
case this catches." That's a defensible line for baseline hygiene (a service wildcard is far more
common and often intentional for infra-management roles), but it leaves a real, distinct
escalation surface uncovered. Modeled on Pike's `AWS002` audit rule
(github.com/JamesWoolfenden/pike, `src/audit_aws.go`), read in full before building this guard.

```hcl
resource "aws_iam_role_policy" "app" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "iam:*"     # every IAM action, not just the ones this role needs
      Resource = "*"
    }]
  })
}
```

## Detection design

1. **`applies()` gate** — `"terraform" in profile.features`.
2. **Files scanned** — every `.tf` file under the repo root, via `iter_files`, skipping
   `is_nonproduct_path` (examples/tests/fixtures/archived trees).
3. **Statement parsing** — the shared `iter_policy_statement_blocks` walker (string/comment/heredoc-
   aware; the same one `iam-wildcard` and `s3-bucket-policy-wildcard-principal` use), tolerant of
   both the JSON-literal (`"Effect": "Allow"`) and idiomatic HCL `jsonencode()` (`Effect = "Allow"`)
   key forms. Within an `Effect: Allow` statement, `_ACTION_ASSIGN` extracts the `Action` key's
   scalar-or-array value (never `NotAction`, excluded via a `(?<!Not)` lookbehind — the same
   technique `s3-bucket-policy-wildcard-principal` uses for `NotPrincipal`), and `_SERVICE_WILDCARD`
   (`^[A-Za-z0-9]+:\*$`) tests each extracted action string.
4. **Inline opt-out pragma** — `# security: allow-iam-service-wildcard` anywhere in the file.
5. **Severity / rule / standards** — fires **HIGH**, `rule = "iam-service-wildcard/service-action"`,
   `standards = ["OWASP:A01", "CWE-269"]`.

## When NOT to flag

- The bare all-actions `"*"` grant — that's `iam-wildcard`'s territory, not this guard's.
- A scoped single action (`s3:GetObject`) — no colon-terminated `*`.
- A Resource ARN ending in `*` (`arn:aws:s3:::bucket/*`) — no colon precedes that star, so it can
  never match `_SERVICE_WILDCARD`, and this guard only ever inspects the `Action` key.
- A wildcard action inside an explicit `Deny` statement — a lockdown, not a grant.
- `NotAction: "iam:*"` — a different shape, `iam-notaction-with-allow`'s territory.
- An audited case — suppress with `# security: allow-iam-service-wildcard`.

## Tests

| Test | What it checks |
|---|---|
| `test_iam_service_wildcard_flags_hcl_form` | idiomatic `jsonencode()` HCL form (`Effect = "Allow"`, `Action = "iam:*"`) fires |
| `test_iam_service_wildcard_flags_json_literal_form` | a JSON-literal policy embedded in a heredoc fires the same way |
| `test_iam_service_wildcard_flags_action_in_list` | a service wildcard mixed into a multi-element `Action` array is still caught |
| `test_iam_service_wildcard_silent_on_scoped_action` | FP-bait: a single scoped action stays silent |
| `test_iam_service_wildcard_silent_on_all_actions_wildcard` | FP-bait: the bare `"*"` grant (iam-wildcard's territory) stays silent |
| `test_iam_service_wildcard_silent_in_deny_statement` | FP-bait: a service wildcard inside `Deny` stays silent |
| `test_iam_service_wildcard_silent_on_notaction` | FP-bait: `NotAction` is excluded |
| `test_iam_service_wildcard_pragma_suppresses` | the inline pragma silences a real finding |
| `test_iam_service_wildcard_applies_gate` | `applies()` gates correctly on the `terraform` feature |
| `test_iam_service_wildcard_nonproduct_path_skipped` | a finding under `examples/` is skipped |

## Known bypasses

- A service wildcard built via string interpolation or a local variable is not evaluated — only a
  literal quoted action string is matched.
- An `Action` array spanning a nested structure the regex's `[^\]]*` bound can't traverse (deeply
  nested brackets) would be missed — not expected in real IAM policy JSON/HCL, which never nests
  brackets inside an action list.
- The curated escalation-relevance framing in this doc is exposition, not a detection input: any
  `<service>:*` shape fires, regardless of how dangerous that particular service's wildcard is in
  practice.

## What this guard does NOT prove

It flags a literal `<service>:*` action string in a policy document; it does not evaluate effective
permissions, policies attached indirectly via managed-policy ARNs (see
`iam-managed-admin-policy-attached`'s `*FullAccess` coverage for that shape), or runtime-constructed
policies. Absence of a finding does not mean the identity's permissions are actually scoped tightly.

# Citations

[1] agentsec checklist item `6c-iam-service-wildcard-action` (§6c)
[2] OWASP:A01
[3] CWE-269
[4] Pike (github.com/JamesWoolfenden/pike), `src/audit_aws.go`, rule `AWS002`
