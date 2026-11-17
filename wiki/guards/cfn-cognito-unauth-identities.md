---
type: Guard
title: "cfn-cognito-unauth-identities"
description: "No CloudFormation Cognito Identity Pool that allows unauthenticated identities."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "cfn-cognito-unauth-identities"
checklist_section: ["6c"]
standards: ["OWASP:A01", "CWE-284"]
---

# Cognito Identity Pool allows unauthenticated identities (CloudFormation)

Flags `AWS::Cognito::IdentityPool` resources that set `AllowUnauthenticatedIdentities: true`.
Closes checklist item `6c-cfn-cognito-unauth-identities` — a new item, since no existing agentsec
check covered Cognito Identity Pool unauthenticated access before this guard.

## The threat

An Amazon Cognito Identity Pool with `AllowUnauthenticatedIdentities: true` lets ANY caller — no
login, no credentials, no identity proof of any kind — call `GetId`/`GetCredentialsForIdentity`
against the pool and receive temporary AWS credentials scoped to the pool's *unauthenticated* IAM
role. AWS's own default for this property is `false` (unauthenticated access is opt-in), so a
template that sets it to `true` is a deliberate decision to issue anonymous AWS credentials to the
public internet. CWE-284 (Improper Access Control).

## Exploitability rationale

HIGH. The finding itself doesn't prove data exposure — the blast radius depends entirely on what
the unauthenticated role's IAM policy grants — but the access-control gap is real and directly
reachable by an anonymous caller with no reconnaissance beyond knowing (or guessing) the pool ID.
Teams routinely under-appreciate that this role is reachable with zero authentication, and wire up
broader permissions (S3 read/write, DynamoDB, Lambda invoke) assuming some implicit gate that does
not exist.

## What counts as a hit (and what doesn't)

- `AWS::Cognito::IdentityPool` with `AllowUnauthenticatedIdentities: true` → fires.
- `AllowUnauthenticatedIdentities: false` (explicit) → silent.
- The property omitted entirely → silent. AWS's implicit default is `false` — unauthenticated
  access is opt-in, not opt-out — so a template that never mentions the property carries no
  anonymous-access risk from this guard's perspective. This mirrors the CFN KMS-rotation sibling
  guard's own default-aware design, just with the polarity flipped (there, a missing property is
  the vulnerable default; here, it's the safe one).
- An unrelated resource type (e.g. `AWS::S3::Bucket`) → silent, regardless of its own properties.
- Both YAML and JSON template formats are scanned identically (see `agentsec/cfn.py`'s module
  docstring for how the two formats converge on one `block` text every CFN guard scans the same
  way).

## When NOT to flag (and the pragma)

- `AllowUnauthenticatedIdentities: false` or the property omitted → silent (the safe defaults).
- A public read-only demo/preview identity pool by design, with a tightly scoped unauthenticated
  role → suppress explicitly (YAML templates only — JSON has no comment syntax, so a JSON-authored
  template cannot carry this pragma at all, a known limitation shared by every CFN guard in this
  batch):

```yaml
Resources:
  PublicDemoPool:
    Type: AWS::Cognito::IdentityPool
    Properties:
      IdentityPoolName: public-demo
      AllowUnauthenticatedIdentities: true  # security: allow-cognito-unauth-identities
```

## Known bypasses (honest limits)

- **No dataflow, no cross-resource reasoning.** The guard does not inspect the pool's
  unauthenticated IAM role or its attached policies — it only checks the property on the identity
  pool resource itself. A tightly-scoped unauthenticated role and a wide-open one both fire the
  same finding; severity triage of the actual blast radius is a human step.
- **File-level location, not line-level** — like every CFN guard in this batch, the finding
  reports the template file, not a specific line (see `agentsec/cfn.py`'s module docstring for
  why: a JSON block is a `json.dumps` reconstruction with no original line mapping to report).
- **Textual/regex-only.** A value driven by a CloudFormation parameter or `Fn::If` condition
  (e.g. `AllowUnauthenticatedIdentities: !If [IsDemo, true, false]`) is captured as literal text;
  the guard cannot resolve which branch a real deployment takes, so it may under- or over-fire on
  conditional templates depending on the exact text matched.
- **JSON templates cannot carry the suppression pragma** — JSON has no comment syntax.
- **YAML block-scalar values inside a resource are captured as ordinary block text** — a
  documented, not-yet-observed-in-practice residual shared by the whole `agentsec.cfn` parser.

## What this guard does NOT prove

A clean scan means no `AWS::Cognito::IdentityPool` resource in the scanned templates sets
`AllowUnauthenticatedIdentities: true` literally — it says nothing about a pool created outside
CloudFormation entirely (the AWS Console, a different IaC tool, a nested stack this scan didn't
independently discover), a pool whose setting is driven by a parameter/condition this guard's
textual scan can't resolve, or the actual permissions attached to any pool's unauthenticated role.

## Canary plant

`cfn_cognito_identity_pool.yaml` — `AWS::Cognito::IdentityPool` with
`AllowUnauthenticatedIdentities: true`. Expected rule:
`cfn-cognito-unauth-identities/allow-unauthenticated`.

# Citations

[1] agentsec checklist item `6c-cfn-cognito-unauth-identities` (§6c)
[2] OWASP:A01 (Broken Access Control)
[3] CWE-284 (Improper Access Control)
[4] cfn_nag — `CognitoIdentityPoolAllowUnauthenticatedIdentitiesRule.rb`, rule `W57` (provenance
    only; detection logic here is original)
