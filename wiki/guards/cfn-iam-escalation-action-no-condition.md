---
type: Guard
title: "cfn-iam-escalation-action-no-condition"
description: "No CloudFormation IAM policy statement grants a privilege-escalation-class action under Effect: Allow with no scoping Condition."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "cfn-iam-escalation-action-no-condition"
checklist_section: ["6c"]
standards: ["OWASP:A01", "CWE-269"]
---

# Privilege-escalation IAM action granted with no scoping Condition (CloudFormation)

Flags `AWS::IAM::Policy` / `AWS::IAM::ManagedPolicy` / `AWS::IAM::Role` resources whose inline
`Policies` grant a curated privilege-escalation-class IAM action under `Effect: Allow` with no
`Condition` anywhere in the resource. Closes checklist item `6c-iam-escalation-action-no-condition`
— the CloudFormation counterpart to the existing `iam-escalation-action-no-condition` (Terraform)
guard, extending the same checklist item rather than duplicating it.

## The threat

Spencer Gietzen's 2018 "AWS IAM Privilege Escalation" research catalogued the IAM actions that let
an identity which already has SOME access expand it further: attach a new policy to itself or
another principal, create a new policy version that is itself the attack payload, rewrite what a
role trusts, hand its own or another role's permissions to something it controls, mint new
long-lived credentials, or join a more-privileged group. cfripper's own source flags the same
technique for CloudFormation (`privilege_escalation.py`, `Skyscanner/cfripper`) — cited here for
provenance; the detection logic in this guard is original, developed independently against the
pattern description and the Terraform sibling guard's curated action list. CWE-269 (Improper
Privilege Management), OWASP:A01.

## Exploitability rationale

HIGH. An identity holding one of these permissions with no scoping condition can use it directly to
expand its own (or another principal's) access — this is not a defense-in-depth gap, it is the
escalation primitive itself. Same severity as the Terraform sibling guard, for the same reason.

## The curated action list

The SAME 15 actions as the Terraform sibling guard (`agentsec/guards/iam_escalation_action_no_
condition.py`), compared case-insensitively, so the two guards agree on what counts as dangerous:

`iam:PutRolePolicy`, `iam:AttachRolePolicy`, `iam:CreatePolicyVersion`,
`iam:SetDefaultPolicyVersion`, `iam:UpdateAssumeRolePolicy`, `iam:PassRole`,
`iam:CreateAccessKey`, `sts:AssumeRole`, `iam:AttachUserPolicy`, `iam:AttachGroupPolicy`,
`iam:PutUserPolicy`, `iam:PutGroupPolicy`, `iam:AddUserToGroup`, `iam:CreateLoginProfile`,
`iam:UpdateLoginProfile`.

## What counts as a hit (and what doesn't)

- An `AWS::IAM::Policy` / `AWS::IAM::ManagedPolicy` / `AWS::IAM::Role` resource whose block
  contains `Effect: Allow` (or `"Effect": "Allow"`) **anywhere**, one of the curated actions as an
  `Action` value (singular, or inside a YAML/JSON `Action` list) **anywhere**, and NO `Condition`
  key **anywhere** in the whole resource → fires once per distinct dangerous action found.
- The action must appear as an `Action` value, not a `NotAction` value — the guard tracks the
  nearest preceding `Action`/`NotAction` keyword before each matched action token and skips
  `NotAction` occurrences.
- `Effect: Deny` → silent (the opposite of a grant).
- A `Condition` key anywhere in the resource → silent, the same conservative "any Condition is a
  plausible narrowing" heuristic the Terraform sibling and `s3-bucket-policy-wildcard-principal`
  both use, trading some false negatives (a `Condition` that doesn't actually narrow anything) for
  a much lower false-positive rate than re-implementing AWS's own condition-key semantics in regex.
- An action not on the curated list (e.g. `s3:GetObject`) → silent.
- Both YAML and JSON template formats are scanned identically (see `agentsec/cfn.py`'s module
  docstring for how the two formats converge on one `block` text every CFN guard scans the same
  way).

## A key difference from the Terraform sibling: resource-level, not statement-level scope

The Terraform guard walks individual policy *statement* blocks (`iter_policy_statement_blocks`) and
only fires when the SAME statement that grants the action also lacks a Condition. This guard uses a
coarser, pragmatic **whole-resource-block** scope instead — the same granularity every `cfn-*` guard
in this batch uses (file-level findings, no real statement parser). A `Condition` on one statement in
a resource silences a dangerous action granted by a *different*, unconditioned statement in the same
resource, and conversely a dangerous action in one statement can fire even though the Condition that
scopes it lives in a sibling statement. This is a deliberate scope trade documented here, not an
oversight — see Known bypasses below.

## Suppressing a finding (the pragma)

Suppress an audited resource with a comment containing `security: allow-iam-escalation-no-condition`
anywhere in the resource's block (YAML `#` comment; not meaningful in JSON, which has no comment
syntax — a JSON-authored template cannot carry this pragma at all, the same known limitation every
CFN guard in this batch discloses):

```yaml
Resources:
  DeploymentRole:
    Type: AWS::IAM::Role
    Properties:
      Policies:
        - PolicyName: audited-escalation
          PolicyDocument:
            Statement:
              - Effect: Allow
                Action: iam:PassRole  # security: allow-iam-escalation-no-condition
                Resource: '*'
```

## Known bypasses (honest limits)

- **No dataflow, no cross-resource reasoning.** Fires on the property's textual presence, not on
  whether the role is ever actually assumed or attached anywhere.
- **Resource-level, not statement-level, Condition scoping** (see above) — a genuine, deliberate
  trade against the Terraform sibling's finer granularity, so this guard can both over-fire (an
  unrelated conditioned statement's Condition doesn't actually cover the dangerous grant) and
  under-fire (a Condition anywhere silences the whole resource, including a genuinely unconditioned
  sibling statement) relative to true per-statement analysis.
- **File-level location, not line-level** — like every CFN guard in this batch, the finding reports
  the template file, not a specific line (a JSON block is a `json.dumps` reconstruction with no
  original line mapping to report; see `agentsec/cfn.py`'s module docstring).
- **JSON templates cannot carry the suppression pragma** — JSON has no comment syntax.
- **A trust-policy `Action: sts:AssumeRole` statement commonly has no Condition by design** (it's
  scoped by `Principal`, not `Condition`) — since this guard's scope is the whole resource, an
  `AWS::IAM::Role`'s own unconditioned `AssumeRolePolicyDocument` can itself be the reason a
  resource has no Condition anywhere, even when its inline `Policies` grant is a separate concern.
  Not treated as a special case; document the residual instead of adding asymmetric logic.
- **`NotAction` exclusion is nearest-keyword-based, not a real parser** — a pathological block where
  an unrelated `NotAction` keyword appears between a genuine dangerous `Action` value and that
  value's own `Action:` keyword could misattribute context; not observed as a practical FP source.

## What this guard does NOT prove

A clean scan means no IAM resource in the scanned templates textually grants a curated escalation
action under an unconditioned `Effect: Allow` — it says nothing about a policy attached outside
CloudFormation entirely (the AWS Console, a different IaC tool, a nested stack this scan didn't
independently discover), a `Condition` that is present but does not actually narrow the grant in
practice, or an escalation path built from actions outside the curated 15.

## Canary plant

`cfn_iam_escalation.yaml` — an `AWS::IAM::Role` with an inline policy statement granting
`iam:PassRole` under `Effect: Allow` with no `Condition`. Expected rule:
`cfn-iam-escalation-action-no-condition/allow-no-condition`.

# Citations

[1] agentsec checklist item `6c-iam-escalation-action-no-condition` (§6c)
[2] Spencer Gietzen, "AWS IAM Privilege Escalation — Methods and Mitigation" (2018) — the 15-action
    curated list's origin, shared with the Terraform sibling guard
[3] `agentsec/guards/iam_escalation_action_no_condition.py` — the Terraform sibling this guard
    extends the same checklist item alongside
[4] cfripper (`Skyscanner/cfripper`) — `privilege_escalation.py` (provenance only; detection logic
    here is original)
[5] OWASP:A01 (Broken Access Control)
[6] CWE-269 (Improper Privilege Management)
