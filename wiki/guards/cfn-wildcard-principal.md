---
type: Guard
title: "cfn-wildcard-principal"
description: "No CloudFormation resource policy grants an action to Principal: \"*\" without a narrowing Condition."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "cfn-wildcard-principal"
checklist_section: ["6a"]
standards: ["OWASP:A01", "CWE-284"]
---

# Resource policy grants an action to any AWS principal (CloudFormation)

Flags CloudFormation resource-policy statements with `Effect: Allow` and `Principal: "*"` and no
narrowing `Condition`. Closes checklist item `6a-s3-bucket-policy-wildcard-principal` — the
CloudFormation counterpart to the existing `s3-bucket-policy-wildcard-principal` (Terraform) guard,
extending the same checklist item rather than duplicating it. It reuses the shared
`agentsec.cfn` resource-block parser that `cfn-kms-key-rotation-not-enabled` established as this
codebase's first CloudFormation-format guard.

## The threat

A resource policy statement with `"Effect": "Allow"` and `"Principal": "*"` (or
`"Principal": {"AWS": "*"}`) grants the action to every AWS account in existence — and if the
resource isn't otherwise locked down (S3 Block Public Access, a restrictive ACL, key-policy
defaults), to anyone on the internet with no AWS account at all. A `Condition` block can
legitimately narrow a wildcard principal (e.g. `aws:SourceVpce`, `aws:PrincipalOrgID`). CWE-284
(Improper Access Control), OWASP:A01 (Broken Access Control).

## Exploitability rationale

HIGH, the same severity class as its Terraform sibling. An unconditioned wildcard principal on a
resource policy is a direct, standing access-control failure — not a hypothetical chain — once the
resource is otherwise reachable (a public S3 bucket, a KMS key another account's IAM policy can
already see, an SNS/SQS endpoint, or an IAM role any principal can assume).

## What counts as a hit (and what doesn't)

Scans five CFN resource-policy surfaces: `AWS::S3::BucketPolicy`, `AWS::KMS::Key` (its embedded
`KeyPolicy`), `AWS::SNS::TopicPolicy`, `AWS::SQS::QueuePolicy`, and `AWS::IAM::Role` (its
`AssumeRolePolicyDocument` trust policy).

Fires when a scanned resource's block contains BOTH:

- an `Effect: Allow` occurrence (`Effect: Allow` in YAML, `"Effect": "Allow"` in JSON), AND
- a wildcard-principal occurrence — `Principal: "*"` / `"Principal": "*"`, or the nested
  `Principal: {AWS: "*"}` / `{"AWS": "*"}` shape, in either quoting style —

AND the block contains no `Condition` key anywhere.

This is a pragmatic, text-block scope, matching how every `cfn-*` guard in this batch scans (regex
over each resource's `block` text, not a real JSON-path-aware statement walker — see
`agentsec/cfn.py`'s module docstring). The guard does not pair a specific `Effect`/`Principal` to
a specific `Statement` entry within a multi-statement policy; it judges the whole resource block at
once (see "Known bypasses" below).

## When NOT to flag (and the pragma)

- A `Condition` present anywhere in the resource's block → silent (treated as a plausible
  narrowing, the same conservative heuristic the Terraform sibling guard uses).
- `Principal` scoped to a specific account ID, role ARN, or service principal (no literal `"*"`)
  → silent.
- A resource type outside the five scanned surfaces → silent.

Suppress an audited case (e.g. a deliberately public bucket policy, or a `Condition` shape this
heuristic doesn't recognize) with a comment containing `security: allow-cfn-wildcard-principal`
anywhere in the resource's block (YAML templates only — JSON has no comment syntax, so a
JSON-authored template cannot carry this pragma at all, a known limitation shared by every CFN
guard in this batch):

```yaml
Resources:
  PublicReadBucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: my-public-assets-bucket  # security: allow-cfn-wildcard-principal
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal: "*"
            Action: s3:GetObject
            Resource: arn:aws:s3:::my-public-assets-bucket/*
```

## Known bypasses (honest limits)

- **No dataflow, no cross-resource reasoning.** Fires on the Effect/Principal/Condition text
  present anywhere in the resource block.
- **Not statement-aware.** A resource with multiple `Statement` entries is judged as a whole: an
  unrelated `Deny` or narrowly-scoped statement elsewhere in the same policy does not suppress a
  genuine wildcard grant in another statement, and conversely a `Condition` attached to a
  *different* statement than the wildcard-principal one is still treated as narrowing the whole
  resource — a false negative this simple heuristic accepts, the same trade-off the Terraform
  sibling guard documents for its own condition check.
- **File-level location, not line-level** — like every CFN guard in this batch, the finding reports
  the template file, not a specific line (a JSON block is a `json.dumps` reconstruction with no
  original line mapping to report).
- **JSON templates cannot carry the suppression pragma** — JSON has no comment syntax.
- **YAML block-scalar values inside a resource are captured as ordinary block text** — a
  documented, not-yet-observed-in-practice residual shared by the whole `agentsec.cfn` parser.

## What this guard does NOT prove

A clean scan means no resource of the five scanned types in the scanned templates has an
unconditioned wildcard-principal statement in its own textual block — it says nothing about a
policy attached outside CloudFormation entirely (the AWS Console, a different IaC tool, a nested
stack this scan didn't independently discover), a policy whose `Principal` is driven by a
CloudFormation parameter/condition this guard's textual scan can't resolve, or whether the
resource is otherwise reachable at all (a private VPC endpoint, a bucket with Block Public Access
enabled at the account level).

## Canary plant

`cfn_wildcard_principal.yaml` — `AWS::S3::BucketPolicy` with a `Statement` entry granting
`Effect: Allow` to `Principal: "*"` and no `Condition`. Expected rule:
`cfn-wildcard-principal/allow-no-condition`.

# Citations

[1] agentsec checklist item `6a-s3-bucket-policy-wildcard-principal` (§6a)
[2] OWASP:A01 (Broken Access Control)
[3] CWE-284 (Improper Access Control)
[4] cfripper (`Skyscanner/cfripper`) — `wildcard_principals.py` (provenance only;
    detection logic here is original)
