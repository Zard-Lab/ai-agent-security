---
type: Guard
title: "iam-escalation-action-no-condition"
description: "Privilege-escalation-class IAM action granted under Effect: Allow with no scoping Condition."
timestamp: "2026-09-05T12:00:00Z"
guard_id: "iam-escalation-action-no-condition"
checklist_section: ["6c"]
standards: ["OWASP:A01", "CWE-269"]
---

# Privilege-escalation IAM action granted with no scoping Condition

Flags an `Effect: Allow` IAM policy statement that grants one of 15 known privilege-escalation
actions (`iam:PassRole`, `iam:PutRolePolicy`, `sts:AssumeRole`, ...) with no `Condition` anywhere in
the statement to narrow it, plus, for `iam:PassRole` specifically, a `Condition` that is present
but is not the one AWS's own docs name as the real mitigation (`iam:PassedToService`). Closes
checklist item `6c-iam-escalation-action-no-condition`. Scans Terraform `.tf` files and bare IAM
policy `.json` documents.

_Author: 2026-09-05 (PassRole precision check + bare-JSON widening 2026-10-08)_

---

## The threat

These 15 actions are the classic AWS IAM privilege-escalation primitives (Spencer Gietzen's 2018
"AWS IAM Privilege Escalation — Methods and Mitigation" research; the basis for cloud-security
tools' own escalation checks, including Pike's `escalation.go::escalationAWS` map and cfripper's
CloudFormation-format `privilege_escalation.py` check): each lets an identity that already has SOME
access expand it further — attach a new policy to itself or another principal
(`PutRolePolicy`/`AttachRolePolicy`/`AttachUserPolicy`/`AttachGroupPolicy`/`PutUserPolicy`/
`PutGroupPolicy`), create a policy version that IS the attack payload
(`CreatePolicyVersion`/`SetDefaultPolicyVersion`), rewrite what a role trusts
(`UpdateAssumeRolePolicy`), hand its own or another role's permissions to something it controls
(`PassRole`/`sts:AssumeRole`), mint new long-lived credentials
(`CreateAccessKey`/`CreateLoginProfile`/`UpdateLoginProfile`), or join a more-privileged group
(`AddUserToGroup`). CWE-269, OWASP:A01.

## Why it fits the stack

Modeled on Pike's `AWS004` audit rule (github.com/JamesWoolfenden/pike, `src/audit_aws.go` +
`escalation.go`), read in full before building this guard. Complements (not duplicates) cfripper's
CloudFormation-format `privilege_escalation.py` finding surfaced in an earlier corpus scan — this is
the Terraform-format, Condition-aware version of the same idea. The Condition-awareness is the
material difference from a bare dangerous-action-list check: an escalation action IS sometimes
legitimately needed (an infra-automation role that must `PassRole` to a specific service), and the
`Condition` (`iam:PassedToService`, `aws:ResourceTag/...`) is exactly how AWS's own documentation
recommends narrowing it, rather than removing the action outright.

```hcl
resource "aws_iam_role_policy" "app" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "iam:PassRole"   # can hand ANY role this identity can reach to a service
      Resource = "*"              # ...with no aws:PassedToService / ResourceTag condition
    }]
  })
}
```

## Detection design

1. **`applies()` gate**: universal (`return True`, 2026-10-08), for the same reasoning as
   `iam-notaction-with-allow`/`iam-wildcard`: a bare IAM policy JSON can live in any repo with no
   Terraform feature detected at all. Previously gated on `"terraform" in profile.features`.
2. **Files scanned**: every `.tf` and `.json` file, via `iter_files`, skipping
   `is_nonproduct_path`. A `.json` file is pre-filtered on a cheap `"Statement"` key check (on the
   comment/heredoc-blanked view) before paying for the full statement walk.
3. **Statement parsing**: `iter_policy_statement_blocks` (shared walker, format-agnostic). Within
   an `Effect: Allow` statement, extract every `Action` value and check membership
   (case-insensitive) against the fixed 15-action list. Two independent rules:
   - **`unconditional-grant`**: NO `Condition` key present anywhere in the statement
     (`_CONDITION_PRESENT`, the same conservative "any Condition = plausible narrowing" heuristic
     `s3-bucket-policy-wildcard-principal` uses, trading some false negatives for a much lower
     false positive rate than re-implementing AWS's own condition-key semantics).
   - **`passrole-missing-passed-to-service`** (2026-10-08, closes a gap this guard's own docs
     already disclosed below): fires ONLY for `iam:PassRole`, ONLY when a `Condition` IS present
     (so it never double-fires with `unconditional-grant`) but that `Condition` does not contain
     the literal key `iam:PassedToService`, which is AWS's own documented mitigation for `PassRole`
     specifically. A `Condition` scoped on something else entirely (`aws:RequestedRegion`, a
     resource tag unrelated to the service being passed to) still lets the role be handed to ANY
     service that will accept it.
4. **Inline opt-out pragma**: `# security: allow-iam-escalation-no-condition` in a `.tf` file (a
   real comment); the literal string anywhere in a `.json` file (JSON has no comment syntax).
5. **Severity / rule / standards**: **HIGH** for both rules, `standards = ["OWASP:A01", "CWE-269"]`.
   One finding per distinct matched escalation action per statement (`unconditional-grant`), plus
   one additional finding specifically for an under-scoped `PassRole`
   (`passrole-missing-passed-to-service`).

## When NOT to flag

- The SAME escalation action WITH a `Condition` present anywhere in the statement stays silent
  under `unconditional-grant`: the heuristic treats presence, not correctness, as the narrowing
  signal for the other 14 actions (unchanged for them; only `PassRole` gets the stricter check).
- `iam:PassRole` WITH a `Condition` that DOES contain `iam:PassedToService` stays silent entirely:
  the actual documented mitigation is present.
- An action not on the fixed 15-action list stays silent, even if it "sounds" escalation-adjacent —
  the list is exact, not fuzzy, to keep this guard predictable.
- A `Deny` statement — a lockdown, not a grant.
- A statement that names a `Principal` or `NotPrincipal` (PR #1051 review, M3): a role's trust
  policy (`assume_role_policy`, or a bare trust-policy `.json`) or a resource policy. Its
  `sts:AssumeRole` says who may assume THIS role; it grants nothing to an identity. This narrowed
  the pre-existing `.tf` behaviour too: origin/main fired `unconditional-grant` on every
  `aws_iam_role` trust statement. An identity policy granting `sts:AssumeRole` on `*` with no
  Condition still fires.
- An ordinary `.json` file with no `"Statement"` key (e.g. `package.json`) is pre-filtered out
  before the statement walk even runs.
- An audited case — suppress with `# security: allow-iam-escalation-no-condition`.

## Tests

| Test | What it checks |
|---|---|
| `test_iam_escalation_no_condition_flags_passrole` | `iam:PassRole` with no Condition fires |
| `test_iam_escalation_no_condition_flags_sts_assumerole` | `sts:AssumeRole` with no Condition fires |
| `test_iam_escalation_no_condition_flags_multiple_actions_once_each` | two distinct escalation actions in one statement produce two findings |
| `test_iam_escalation_no_condition_silent_with_condition` | FP-bait: the same action WITH a `Condition` stays silent |
| `test_iam_escalation_no_condition_silent_non_escalation_action` | FP-bait: an ordinary action stays silent |
| `test_iam_escalation_no_condition_silent_in_deny_statement` | FP-bait: a `Deny` statement stays silent |
| `test_iam_escalation_no_condition_pragma_suppresses` | the inline pragma silences a real finding |
| `test_iam_escalation_no_condition_applies_gate` | `applies()` is universal (True with no stack features at all) |
| `test_iam_escalation_no_condition_nonproduct_path_skipped` | a finding under `examples/` is skipped |
| `test_iam_escalation_no_condition_flags_bare_json_policy` | the same escalation shape in a standalone `.json` policy fires |
| `test_iam_escalation_no_condition_silent_on_unrelated_json` | FP-bait: an ordinary `package.json` stays silent |
| `test_iam_escalation_no_condition_passrole_wrong_condition_fires` | `PassRole` + a Condition that is NOT `iam:PassedToService` fires the precise rule, and the general rule stays silent |
| `test_iam_escalation_no_condition_passrole_with_passed_to_service_stays_silent` | FP-bait: `PassRole` + the actual documented mitigation stays silent entirely |
| `test_iam_escalation_no_condition_other_action_with_unrelated_condition_stays_silent` | FP-bait: the PassRole-specific rule does not leak onto a different escalation action |
| `test_iam_escalation_no_condition_json_trust_policy_is_not_a_grant` | FP-bait (review M3): an ECS task trust policy `.json` stays silent |
| `test_iam_escalation_no_condition_tf_assume_role_policy_is_not_a_grant` | FP-bait (review M3): an `aws_iam_role` trust statement stays silent |
| `test_iam_escalation_no_condition_json_identity_assumerole_on_star_still_fires` | Still-fires: an identity policy granting `sts:AssumeRole` on `*` unconditionally |
| `test_iam_escalation_no_condition_trust_and_grant_in_one_tf_only_grant_fires` | Still-fires: the role's policy grant fires, its trust statement does not |

## Known bypasses

- **A `Condition` that doesn't actually narrow anything still suppresses `unconditional-grant` for
  the OTHER 14 actions**: the accepted trade-off inherited from the same heuristic
  `s3-bucket-policy-wildcard-principal` uses. (2026-10-08: this exact gap is now closed for
  `iam:PassRole` specifically by `passrole-missing-passed-to-service`, since AWS documents one
  clear, checkable condition key for that action; the other 14 actions don't have a single
  universally-correct condition key to check against, so they still rely on "any Condition is a
  plausible narrowing.")
- The 15-action list is exact and does not expand to cover a service-wildcard action that implies
  one of them (`iam:*` implies `iam:PassRole`) — that's `iam-service-wildcard`'s territory, checked
  independently.
- Values built via string interpolation/locals are not evaluated.
- A native HCL `data "aws_iam_policy_document"` source is not read at all: its `statement { ... }`
  blocks carry lowercase `actions = [...]` / `resources = [...]` lists (and often no `effect`), which
  the shared statement walker does not recognise as `Action`/`Resource` keys. This is a pre-existing
  blind spot of the whole IAM-policy guard family, not specific to this guard (PR #1051 re-review,
  L3; measured: a document granting `iam:PassRole`, `sts:AssumeRole`, `bedrock:CreateAgent` and
  `lambda:InvokeFunction` on `*` produced no finding from any of the seven guards).
- A `{`/`}` inside a quoted string within a `${...}` interpolation (`"${replace(var.arn, "{",
  "")}"`), or an unterminated `${` (`"x${"`, HCL `"x$${"`), makes the brace-depth interpolation scan
  run on past the string, so `Action`/`Resource`/`Principal` values LATER in the same statement go
  unread. Scope: the rest of that enclosing statement object only; other statements are unaffected.
  Known gap from the PR #1051 final review (F1), deferred; pinned by
  `tests/test_iam_policy_guard_prechecks.py::test_known_gap_brace_in_interpolation_string_hides_later_values`.

## What this guard does NOT prove

It flags a literal escalation-action grant with no visible `Condition`; it does not evaluate whether
a present `Condition` is actually restrictive, whether the escalation path is reachable end-to-end
in practice (it may require a second, separately-held permission), or managed-policy-attached
escalation actions (out of scope — this guard reads inline policy statements only). Absence of a
finding does not mean the identity cannot escalate privilege by some other path.

# Citations

[1] agentsec checklist item `6c-iam-escalation-action-no-condition` (§6c)
[2] OWASP:A01
[3] CWE-269
[4] Pike (github.com/JamesWoolfenden/pike), `src/audit_aws.go` + `escalation.go`, rule `AWS004`
[5] Spencer Gietzen, "AWS IAM Privilege Escalation — Methods and Mitigation" (Rhino Security Labs,
    2018)
