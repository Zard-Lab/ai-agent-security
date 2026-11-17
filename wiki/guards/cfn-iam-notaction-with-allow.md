---
type: Guard
title: "cfn-iam-notaction-with-allow"
description: "Flags CloudFormation IAM policy statements that combine Effect: Allow with NotAction."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "cfn-iam-notaction-with-allow"
checklist_section: ["6c"]
standards: ["OWASP:A01", "CWE-269"]
---

# IAM policy statement combines Effect: "Allow" with NotAction (CloudFormation)

Flags `AWS::IAM::Policy`, `AWS::IAM::ManagedPolicy`, and `AWS::IAM::Role` resources whose policy
document combines `Effect: Allow` with a `NotAction` key. Closes checklist item
`6c-iam-notaction-with-allow` — the CloudFormation counterpart to the existing `iam-notaction-with-
allow` (Terraform) guard, extending the same checklist item rather than duplicating it.

## The threat

`NotAction` used with `Effect: Allow` grants every IAM action AWS has EXCEPT the ones listed — the
opposite of what a reviewer skimming a short list of action names tends to assume. AWS adds new
actions and even whole new services continuously, and every one of them is silently INCLUDED in the
statement's grant the instant it exists, with no change to the template ever required for the blast
radius to grow. This is the same "over-grants as AWS's own API surface grows" failure mode AWS's own
IAM best-practices guide and IAM Access Analyzer both call out explicitly for `NotAction` used with
`Allow`. CWE-269 (Improper Privilege Management), OWASP:A01.

## Exploitability rationale

HIGH. This is a live over-permissioning grant on whatever principal the policy is attached to, not
a defense-in-depth gap — the same severity as its Terraform sibling `iam-notaction-with-allow`.

## What counts as a hit (and what doesn't)

- A resource of type `AWS::IAM::Policy`, `AWS::IAM::ManagedPolicy`, or `AWS::IAM::Role` whose block
  contains BOTH `Effect: Allow` (or `"Effect": "Allow"`) AND a `NotAction` key (`NotAction:` in
  YAML, `"NotAction"` in JSON) anywhere in the same block → fires. This is a pragmatic, text-block
  scope matching the shared `agentsec.cfn` parser's file-level (not statement-level) granularity —
  the same tradeoff the CFN KMS-rotation guard makes.
- **`Effect: Deny` combined with `NotAction` is legitimate and must NOT fire.** "Deny everything
  except these actions" is a common, deliberate guardrail pattern (e.g. a permissions boundary or
  SCP-shaped inline policy) — the opposite risk profile of `Allow` + `NotAction`. This is the
  pattern's own defining precision risk and is exercised directly in the test suite (YAML and JSON).
- A plain `Action` key (no `NotAction` anywhere in the block) → silent.
- An unrelated resource type (e.g. `AWS::S3::Bucket`) → silent, even if it happens to contain
  `Allow`/`NotAction`-looking text elsewhere (e.g. in a bucket name).
- Both YAML and JSON template formats are scanned identically (see `agentsec/cfn.py`'s module
  docstring for how the two formats converge on one `block` text every CFN guard scans the same
  way).

## When NOT to flag (and the pragma)

- `Effect: Deny` + `NotAction` → silent (legitimate guardrail pattern).
- A plain `Action` allow-list → silent (the fix).
- An audited exception → suppress explicitly (YAML templates only — JSON has no comment syntax, so
  a JSON-authored template cannot carry this pragma at all, a known limitation shared by every CFN
  guard in this batch):

```yaml
Resources:
  AuditedPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: audited-broad-grant  # security: allow-cfn-iam-notaction-with-allow
      PolicyDocument:
        Statement:
          - Effect: Allow
            NotAction:
              - iam:*
            Resource: '*'
```

## Known bypasses (honest limits)

- **No dataflow, no cross-statement reasoning.** The check is textual: it fires if `Effect: Allow`
  and `NotAction` both appear anywhere in the resource's block, even if they belong to different
  statements within the same resource (e.g. a role's trust policy uses `Effect: Allow` + `Action`
  while a separate inline policy on the *same* role uses `NotAction` without `Allow` nearby) — a
  known, accepted imprecision inherited from the shared parser's resource-level (not
  statement-level) block granularity.
- **File-level location, not line-level** — like every CFN guard in this batch, the finding reports
  the template file, not a specific line (see `agentsec/cfn.py`'s module docstring for why: a JSON
  block is a `json.dumps` reconstruction with no original line mapping to report).
- **JSON templates cannot carry the suppression pragma** — JSON has no comment syntax.
- **YAML block-scalar values inside a resource are captured as ordinary block text** — a
  documented, not-yet-observed-in-practice residual shared by the whole `agentsec.cfn` parser.
- **`Fn::If`-wrapped resource declarations** at the top of `Resources:` are not specially handled
  (see `agentsec/cfn.py`'s module docstring) — a rare authoring style.

## What this guard does NOT prove

A clean scan means no scanned `AWS::IAM::Policy` / `AWS::IAM::ManagedPolicy` / `AWS::IAM::Role`
resource combines `Allow` with `NotAction` in this template — it says nothing about a policy
attached outside CloudFormation entirely (the AWS Console, a different IaC tool, a nested stack this
scan didn't independently discover), a policy assembled by a CloudFormation macro/transform this
guard's textual scan can't resolve, or whether the resulting effective permissions are appropriate
even when they use a plain `Action` allow-list.

## Canary plant

`cfn_iam_notaction_with_allow.yaml` — an `AWS::IAM::Role` whose trust policy uses a normal
`Effect: Allow` + `Action` statement, and whose inline `Policies` entry combines `Effect: Allow`
with `NotAction`. Expected rule: `cfn-iam-notaction-with-allow/allow-notaction`.

# Citations

[1] agentsec checklist item `6c-iam-notaction-with-allow` (§6c)
[2] OWASP:A01 (Broken Access Control)
[3] CWE-269 (Improper Privilege Management)
[4] cfn_nag (`stelligent/cfn_nag`) — `IamRoleNotActionOnPermissionsPolicyRule.rb`,
    `IamRoleNotActionOnTrustPolicyRule.rb`, `IamPolicyNotActionRule.rb`,
    `IamManagedPolicyNotActionRule.rb` (provenance only; detection logic here is original)
[5] agentsec's Terraform sibling guard `iam-notaction-with-allow` (`wiki/guards/iam-notaction-with-
    allow.md`), modeled on Pike's `AWS005` audit rule
