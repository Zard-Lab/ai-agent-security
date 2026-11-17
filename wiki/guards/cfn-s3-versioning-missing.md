---
type: Guard
title: "cfn-s3-versioning-missing"
description: "No CloudFormation S3 bucket without VersioningConfiguration Status: Enabled."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "cfn-s3-versioning-missing"
checklist_section: ["7"]
standards: ["OWASP:A05", "CWE-693"]
---

# S3 bucket without versioning enabled (CloudFormation)

Flags `AWS::S3::Bucket` resources that don't set `VersioningConfiguration` with `Status: Enabled`.
Closes checklist item `7-s3-versioning-missing` — the CloudFormation counterpart to the existing
`aws-observability-hygiene` (Terraform) guard's S3-versioning check, extending the same checklist
item rather than duplicating it.

## The threat

An `AWS::S3::Bucket` resource with no versioning enabled means an accidental delete, an accidental
overwrite, or a ransomware-style mass-encrypt of the bucket's objects has no rollback path — the
previous object version is simply gone. CWE-693 (Protection Mechanism Failure).

## Exploitability rationale

MEDIUM. Not itself an exploit primitive — like its Terraform sibling, it removes a recovery
mechanism rather than directly causing a compromise, so its impact is realized only when a separate
deletion/overwrite/ransomware event occurs.

## What counts as a hit (and what doesn't)

- `AWS::S3::Bucket` with no `VersioningConfiguration` property at all → fires.
- `VersioningConfiguration` present but `Status: Suspended` → fires.
- `VersioningConfiguration` present but no `Status` sub-property → fires.
- `VersioningConfiguration: {Status: Enabled}` → silent (the fix).
- The match is on the exact string `Status: Enabled` (YAML) / `"Status": "Enabled"` (JSON), case-
  sensitive per CFN's own `Status` enum (`Enabled` / `Suspended`), with reasonable whitespace
  flexibility around the colon.
- Both YAML and JSON template formats are scanned identically (see `agentsec/cfn.py`'s module
  docstring for how the two formats converge on one `block` text every CFN guard scans the same
  way).

## When NOT to flag (and the pragma)

- `Status: Enabled` present anywhere in the resource block → silent (the fix).
- A deliberately unversioned bucket by design (e.g. a genuinely disposable scratch bucket) →
  suppress explicitly (YAML templates only — JSON has no comment syntax, so a JSON-authored
  template cannot carry this pragma at all, a known limitation shared by every CFN guard in this
  batch):

```yaml
Resources:
  ScratchBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: scratch-data  # security: allow-s3-versioning-missing
```

## Known bypasses (honest limits)

- **No dataflow, no cross-resource reasoning.** The guard checks a single resource block's text for
  the presence of `Status: Enabled` — it does not evaluate a `Fn::If`/parameter-driven `Status`
  value, so a template that sets `Status` via an intrinsic function that ultimately resolves to
  `Enabled` at deploy time is not recognized as safe (an accepted false positive) and, conversely, a
  literal `Status: Enabled` string appearing inside an unrelated value is not observed as a
  practical false-negative source but is not proven impossible.
- **File-level location, not line-level** — like every CFN guard in this batch, the finding reports
  the template file, not a specific line (see `agentsec/cfn.py`'s module docstring for why: a JSON
  block is a `json.dumps` reconstruction with no original line mapping to report).
- **JSON templates cannot carry the suppression pragma** — JSON has no comment syntax.
- **YAML block-scalar values inside a resource are captured as ordinary block text** — a
  documented, not-yet-observed-in-practice residual shared by the whole `agentsec.cfn` parser.

## What this guard does NOT prove

A clean scan means no `AWS::S3::Bucket` resource in the scanned templates is missing an enabled
`VersioningConfiguration` — it says nothing about a bucket created outside CloudFormation entirely
(the AWS Console, a different IaC tool, a nested stack this scan didn't independently discover), a
bucket whose versioning is toggled off later through the console or a separate automation, or MFA
Delete (a related but distinct control this guard does not check).

## Canary plant

`cfn_s3_bucket.yaml` — `AWS::S3::Bucket` with a `BucketName` property and no
`VersioningConfiguration` property. Expected rule: `cfn-s3-versioning-missing/no-versioning`.

# Citations

[1] agentsec checklist item `7-s3-versioning-missing` (§7)
[2] OWASP:A05 (Security Misconfiguration)
[3] CWE-693 (Protection Mechanism Failure)
[4] cfripper (`Skyscanner/cfripper`) — `s3_object_versioning.py` (provenance only; detection logic
    here is original)
