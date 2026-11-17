---
type: Guard
title: "iam-notaction-with-allow"
description: "IAM policy statement combines Effect: \"Allow\" with NotAction."
timestamp: "2026-09-05T12:00:00Z"
guard_id: "iam-notaction-with-allow"
checklist_section: ["6c"]
standards: ["OWASP:A01", "CWE-269"]
---

# IAM policy statement combines Effect: "Allow" with NotAction

Flags an IAM policy statement that combines `Effect: "Allow"` with a `NotAction` key — an
"allow every action AWS has, except the ones listed" grant. Closes checklist item
`6c-iam-notaction-with-allow`. Scans Terraform `.tf` files and bare IAM policy `.json` documents.

_Author: 2026-09-05 (widened to bare JSON 2026-10-08)_

---

## The threat

`Allow` + `NotAction` grants every action in the AWS API surface except the ones explicitly listed.
AWS adds new actions — and even new services — continuously, and every one of them is silently
INCLUDED in this statement's grant the moment it exists; the policy author never has to touch the
file again for the blast radius to grow. This "over-grants as the API surface grows" failure mode is
called out explicitly by both AWS's own IAM best-practices guidance and IAM Access Analyzer's policy
checks. CWE-269, OWASP:A01.

## Why it fits the stack

Modeled on Pike's `AWS005` audit rule (github.com/JamesWoolfenden/pike, `src/audit_aws.go`), read in
full before building this guard. `Deny` + `NotAction` ("deny everything except these") is a common
and legitimate guardrail pattern — a permission boundary or SCP that blocks everything but a small
allow-list — and this guard deliberately does not flag it; only the `Allow` pairing is the risky
shape.

```hcl
resource "aws_iam_role_policy" "app" {
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      NotAction = ["iam:*", "organizations:*"]   # "allow everything EXCEPT these"
      Resource  = "*"
    }]
  })
}
```

## Detection design

1. **`applies()` gate**: universal (`return True`, 2026-10-08): an IAM policy, bare JSON or
   Terraform, can live in any repo with no stack feature required (same reasoning `iam-wildcard`
   already uses). Previously gated on `"terraform" in profile.features`, which silently missed
   every repo that ships an AI agent's execution-role policy as a standalone JSON file (the body
   passed to `boto3.create_policy()`, or committed for review alongside a Bedrock/SageMaker agent
   definition) with no Terraform/CloudFormation anywhere in the repo at all.
2. **Files scanned**: every `.tf` and `.json` file, via `iter_files`, skipping
   `is_nonproduct_path`. A `.json` file is pre-filtered on a cheap `"Statement"` key check (on the
   comment/heredoc-blanked view) before paying for the full statement walk, mirroring `iam-wildcard`'s
   own gating, so an ordinary `package.json`/`tsconfig.json` never reaches `iter_policy_statement_blocks`.
3. **Statement parsing**: `iter_policy_statement_blocks` (shared walker, already format-agnostic:
   the same walker `iam-wildcard` uses for both `.tf` and `.json`). A statement fires when it
   carries BOTH `Effect: Allow` and a `NotAction` key, regardless of what either is scoped to (a
   `Condition` narrows WHICH principal/request the grant applies to, not the fact that the grant
   itself is open-ended over the AWS action surface, so (unlike `iam-escalation-action-no-condition`)
   a `Condition` does not suppress this finding).
4. **Inline opt-out pragma**: `# security: allow-iam-notaction-with-allow` in a `.tf` file (a real
   comment, via `comment_dialect_for`); the literal string anywhere in a `.json` file (JSON has no
   comment syntax, the same fallback `iam-wildcard` already uses, #424).
5. **Severity / rule / standards** — **HIGH**, `rule = "iam-notaction-with-allow/allow-notaction"`,
   `standards = ["OWASP:A01", "CWE-269"]`. One finding per statement.

## When NOT to flag

- `Deny` + `NotAction` — the common, legitimate "deny everything except X" guardrail pattern.
- An ordinary `Action` allow-list (no `NotAction` at all).
- An audited case — suppress with `# security: allow-iam-notaction-with-allow`.

## Tests

| Test | What it checks |
|---|---|
| `test_iam_notaction_with_allow_flags_allow_notaction` | `Allow` + `NotAction` array fires |
| `test_iam_notaction_with_allow_flags_json_literal_form` | a JSON-literal policy embedded in a heredoc fires the same way |
| `test_iam_notaction_with_allow_silent_deny_notaction` | FP-bait: `Deny` + `NotAction` stays silent |
| `test_iam_notaction_with_allow_silent_plain_action` | FP-bait: an ordinary `Action` allow-list stays silent |
| `test_iam_notaction_with_allow_pragma_suppresses` | the inline pragma silences a real finding |
| `test_iam_notaction_with_allow_applies_gate` | `applies()` is universal (True with no stack features at all) |
| `test_iam_notaction_with_allow_nonproduct_path_skipped` | a finding under `examples/` is skipped |
| `test_iam_notaction_with_allow_flags_bare_json_policy` | `Allow` + `NotAction` in a standalone `.json` policy fires |
| `test_iam_notaction_with_allow_json_pragma_suppresses` | the literal-string pragma suppresses in `.json` (no comment syntax) |
| `test_iam_notaction_with_allow_silent_on_unrelated_json` | FP-bait: an ordinary `package.json` (no `"Statement"` key) stays silent |

## Known bypasses

- This guard does not evaluate WHAT is excluded — even a `NotAction` list that excludes a large,
  sensible set of dangerous actions still fires, because the fundamental "over-grants as AWS's API
  surface grows" property holds regardless of how the exclusion list is chosen.
- A `NotAction` value built via string interpolation/locals is not specifically inspected — the key's
  mere presence is the signal, so this doesn't matter for detection, but the finding's message
  cannot describe what's excluded in that case.

## What this guard does NOT prove

It flags the presence of `Effect: "Allow"` + `NotAction` in a statement; it does not evaluate how
large the excluded set is, how the statement's Resource is scoped, or whether the policy is
otherwise defense-in-depth (a permission boundary elsewhere in the account). Absence of a finding
does not mean the policy is minimally scoped — an explicit `Action` allow-list can still be
over-broad.

# Citations

[1] agentsec checklist item `6c-iam-notaction-with-allow` (§6c)
[2] OWASP:A01
[3] CWE-269
[4] Pike (github.com/JamesWoolfenden/pike), `src/audit_aws.go`, rule `AWS005`
