---
type: Guard
title: "cfn-ecr-scan-on-push"
description: "No CloudFormation ECR repository without ScanOnPush vulnerability scanning enabled."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "cfn-ecr-scan-on-push"
checklist_section: ["7"]
standards: ["OWASP:A05", "OWASP:A06", "OWASP:A08"]
---

# ECR repository missing vulnerability scanning on push (CloudFormation)

Flags `AWS::ECR::Repository` resources that don't enable `ImageScanningConfiguration.ScanOnPush`.
Closes one specific check inside checklist item `7-ecr-repository-hygiene` — the CloudFormation
counterpart to one check bundled inside the existing `ecr-repository-hygiene` (Terraform) guard,
extending the same checklist item rather than duplicating it.

## The threat

An `AWS::ECR::Repository` with no automated vulnerability scan on push lets an image with known
CVEs reach the registry — and from there, a deployment — with no automated check at all. A
compromised or careless build pipeline can push a vulnerable base image or a dependency with a
known exploit, and nothing in the registry itself notices. CWE-1104-adjacent supply-chain gap.

## Exploitability rationale

MEDIUM. Not itself an exploit primitive — it removes an automated detection control rather than
causing a compromise directly, the same severity class as its Terraform sibling's scan-on-push
check.

## Deliberately narrower scope than the Terraform sibling

The Terraform `ecr-repository-hygiene` guard bundles three independent checks against
`aws_ecr_repository`: missing scan-on-push, mutable image tags, and no lifecycle policy. This CFN
guard covers **only** scan-on-push — the one check cfn_nag's own `ECRRepositoryScanOnPushRule.rb`
(rule `W79`) documents for CFN's ECR resource surface. Immutable tags and lifecycle-policy
enforcement are not ported here; they remain Terraform-surface concerns for now. This is a
deliberate, documented scope decision, not an oversight.

## What counts as a hit (and what doesn't)

- `AWS::ECR::Repository` with no `ImageScanningConfiguration` property at all → fires.
- `ImageScanningConfiguration` present but `ScanOnPush` is absent or `false` → fires.
- `ImageScanningConfiguration: {ScanOnPush: true}` → silent (the fix).
- Both YAML and JSON template formats are scanned identically (see `agentsec/cfn.py`'s module
  docstring for how the two formats converge on one `block` text every CFN guard scans the same
  way).

## When NOT to flag (and the pragma)

- `ScanOnPush: true` → silent (the fix).
- An audited exception (e.g. scanning enforced by an external CI/CD pipeline stage instead of the
  registry) → suppress explicitly (YAML templates only — JSON has no comment syntax, so a
  JSON-authored template cannot carry this pragma at all, a known limitation shared by every CFN
  guard in this batch):

```yaml
Resources:
  ScannedElsewhere:
    Type: AWS::ECR::Repository
    Properties:
      RepositoryName: app  # security: allow-ecr-scan-on-push
```

## Known bypasses (honest limits)

- **No dataflow, no cross-resource reasoning.** Fires on the property's absence/value directly —
  textual/regex-only, same as every other `cfn-*` guard.
- **File-level location, not line-level** — like every CFN guard in this batch, the finding
  reports the template file, not a specific line (see `agentsec/cfn.py`'s module docstring for
  why: a JSON block is a `json.dumps` reconstruction with no original line mapping to report).
- **JSON templates cannot carry the suppression pragma** — JSON has no comment syntax.
- **Does not cover immutable tags or lifecycle policy** — see "Deliberately narrower scope" above.
- **YAML block-scalar values inside a resource are captured as ordinary block text** — a
  documented, not-yet-observed-in-practice residual shared by the whole `agentsec.cfn` parser.

## What this guard does NOT prove

A clean scan means no `AWS::ECR::Repository` resource in the scanned templates is missing
scan-on-push — it says nothing about a repository created outside CloudFormation entirely (the AWS
Console, a different IaC tool, a nested stack this scan didn't independently discover), an image
tag mutability posture, whether a lifecycle policy prunes stale images, or whether the scan
findings themselves are ever acted on once produced.

## Canary plant

`cfn_ecr_repo.yaml` — `AWS::ECR::Repository` with a `RepositoryName` property and no
`ImageScanningConfiguration` property. Expected rule: `cfn-ecr-scan-on-push/scan-on-push-disabled`.

# Citations

[1] agentsec checklist item `7-ecr-repository-hygiene` (§7)
[2] OWASP:A05 (Security Misconfiguration), OWASP:A06 (Vulnerable and Outdated Components),
    OWASP:A08 (Software and Data Integrity Failures)
[3] cfn_nag (`stelligent/cfn_nag`) — `ECRRepositoryScanOnPushRule.rb`, rule `W79` (provenance
    only; detection logic here is original)
