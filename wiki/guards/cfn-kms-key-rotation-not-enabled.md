---
type: Guard
title: "cfn-kms-key-rotation-not-enabled"
description: "No customer-managed CloudFormation KMS key without automatic rotation enabled."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "cfn-kms-key-rotation-not-enabled"
checklist_section: ["7"]
standards: ["OWASP:A02"]
---

# Customer-managed KMS key without rotation enabled (CloudFormation)

Flags `AWS::KMS::Key` resources that don't enable automatic key rotation. Closes checklist item
`7-kms-key-rotation-not-enabled` — the CloudFormation counterpart to the existing `kms-key-
rotation-not-enabled` (Terraform) guard, extending the same checklist item rather than duplicating
it. This is agentsec's first CloudFormation-format guard — CFN template detection and
the shared `agentsec.cfn` resource-block parser landed in this same PR to support it.

## The threat

An `AWS::KMS::Key` resource with no `EnableKeyRotation: true` property means the same
cryptographic key protects data indefinitely. The longer a single key is used, the larger the
blast radius if it is ever compromised — a leaked key, an over-broad IAM grant, or a misissued
grant to a compromised principal decrypts everything the key ever touched, not just data encrypted
after the compromise. CWE-320 (Key Management Errors).

## Exploitability rationale

MEDIUM. Not itself an exploit primitive — it widens the blast radius of a *separate* compromise
rather than causing one directly, the same severity class as its Terraform sibling.

## What counts as a hit (and what doesn't)

- `AWS::KMS::Key` with no `EnableKeyRotation` property at all → fires (CFN's implicit default is
  `false`).
- `EnableKeyRotation: false` (explicit) → fires.
- `EnableKeyRotation: true` → silent (the fix).
- A resource whose `KeySpec` is set to anything other than `SYMMETRIC_DEFAULT` (an asymmetric
  `RSA_*`/`ECC_*`/`SM2_*` key, or an `HMAC_*` key) → silent. None of these key types support
  automatic rotation at all — flagging them would be a false positive, the same exclusion the
  Terraform sibling guard applies for the identical reason.
- Both YAML and JSON template formats are scanned identically (see `agentsec/cfn.py`'s module
  docstring for how the two formats converge on one `block` text every CFN guard scans the same
  way).

## When NOT to flag (and the pragma)

- `EnableKeyRotation: true` → silent (the fix).
- An asymmetric or HMAC `KeySpec` → silent (rotation isn't supported at all).
- A short-lived key by design → suppress explicitly (YAML templates only — JSON has no comment
  syntax, so a JSON-authored template cannot carry this pragma at all, a known limitation shared
  by every CFN guard in this batch):

```yaml
Resources:
  ShortLivedKey:
    Type: AWS::KMS::Key
    Properties:
      Description: rotated manually every 90 days  # security: allow-kms-key-rotation
```

## Known bypasses (honest limits)

- **No dataflow, no cross-resource reasoning.** Fires on the property's absence/value directly.
- **File-level location, not line-level** — like every CFN guard in this batch, the finding
  reports the template file, not a specific line (see `agentsec/cfn.py`'s module docstring for
  why: a JSON block is a `json.dumps` reconstruction with no original line mapping to report).
- **JSON templates cannot carry the suppression pragma** — JSON has no comment syntax.
- **YAML block-scalar values inside a resource are captured as ordinary block text** — a
  documented, not-yet-observed-in-practice residual shared by the whole `agentsec.cfn` parser.

## What this guard does NOT prove

A clean scan means no `AWS::KMS::Key` resource in the scanned templates is missing rotation — it
says nothing about a key created outside CloudFormation entirely (the AWS Console, a different
IaC tool, a nested stack this scan didn't independently discover) or a key whose rotation setting
is driven by a CloudFormation parameter/condition this guard's textual scan can't resolve.

## Canary plant

`cfn_kms_key.yaml` — `AWS::KMS::Key` with a `Description` property and no `EnableKeyRotation`
property. Expected rule: `cfn-kms-key-rotation-not-enabled/missing-rotation`.

# Citations

[1] agentsec checklist item `7-kms-key-rotation-not-enabled` (§7)
[2] OWASP:A02 (Cryptographic Failures)
[3] CWE-320 (Key Management Errors)
[4] cfripper (`Skyscanner/cfripper`) — `kms_key_rotation_enabled.py` (provenance only; detection
    logic here is original)
