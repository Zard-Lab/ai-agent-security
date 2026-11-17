---
type: Guard
title: "cfn-batch-privileged-container"
description: "No AWS Batch job definition container running in privileged mode."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "cfn-batch-privileged-container"
checklist_section: ["6c"]
standards: ["OWASP:A05"]
---

# AWS Batch job definition container runs in privileged mode (CloudFormation)

Flags `AWS::Batch::JobDefinition` resources whose `ContainerProperties.Privileged` property is
`true`. Closes checklist item `6c-cfn-batch-privileged-container`. This is adjacent to the existing
`6c-k8s-privileged-container` item conceptually (same underlying container-escape risk) but a
different resource type entirely (AWS Batch job containers, not Kubernetes pods), so it ships as
its own new checklist item rather than extending the K8s one.

## The threat

`ContainerProperties.Privileged: true` on an AWS Batch job definition disables nearly all container
isolation for that job's container — it gets full access to the host's devices and kernel
capabilities, the same escape surface a privileged Kubernetes pod gets. A container breakout to
full host/instance compromise is straightforward if the container is ever compromised: a
supply-chain-compromised base image, an app-level RCE in the job's own code, or a poisoned job
input feeding into a vulnerable dependency. OWASP:A05 (Security Misconfiguration).

## Exploitability rationale

CRITICAL, matching the severity of its Kubernetes analogue `k8s-privileged-container`: privileged
mode is a full container-isolation bypass, not a narrower misconfiguration — once the container is
compromised, the isolation boundary that would otherwise contain the blast radius is simply absent.

## What counts as a hit (and what doesn't)

- `AWS::Batch::JobDefinition` with `ContainerProperties.Privileged: true` (YAML or JSON) → fires.
- `ContainerProperties.Privileged: false` → silent.
- The `Privileged` property omitted entirely → silent (AWS's own default is `false`; this guard
  only flags the explicit opt-in).
- An unrelated resource type (e.g. `AWS::KMS::Key`, `AWS::S3::Bucket`) → silent, regardless of what
  text happens to appear in its own block.
- Both YAML and JSON template formats are scanned identically (see `agentsec/cfn.py`'s module
  docstring for how the two formats converge on one `block` text every CFN guard scans the same
  way).

## Detection scope

The guard matches `Privileged: true` / `"Privileged": true` anywhere within the resource's own
block text, rather than requiring a strict `ContainerProperties` nesting path (this codebase's CFN
parser hands guards a resource's whole block, not a structural property tree). A resource is
unlikely to carry any OTHER unrelated `Privileged: true` key, so this is a pragmatic, low-FP-risk
scope — the same precision/scope tradeoff every other guard in this CFN batch makes.

## When NOT to flag (and the pragma)

- `ContainerProperties.Privileged: false` or omitted → silent (the fix / the default).
- A reviewed, intentional case (e.g. a job that genuinely needs host device access) → suppress
  explicitly (YAML templates only — JSON has no comment syntax, so a JSON-authored template cannot
  carry this pragma at all, a known limitation shared by every CFN guard in this batch):

```yaml
Resources:
  TrustedHardwareJob:
    Type: AWS::Batch::JobDefinition
    Properties:
      Type: container
      ContainerProperties:
        Image: trusted-hardware-tool:latest
        Privileged: true  # security: allow-cfn-batch-privileged-container
```

## Known bypasses (honest limits)

- **No dataflow, no cross-resource reasoning.** Fires on the property's literal value directly;
  a `Privileged` value driven by a CloudFormation parameter or condition this guard's textual scan
  can't resolve is not evaluated.
- **File-level location, not line-level** — like every CFN guard in this batch, the finding
  reports the template file, not a specific line (see `agentsec/cfn.py`'s module docstring for why:
  a JSON block is a `json.dumps` reconstruction with no original line mapping to report).
- **JSON templates cannot carry the suppression pragma** — JSON has no comment syntax.
- **Block-scoped, not structurally path-scoped** — the regex matches `Privileged: true` anywhere in
  the resource's block, not strictly under `ContainerProperties`. Not observed as a practical FP
  source (no other AWS Batch job definition property is named `Privileged`), but not structurally
  enforced either.
- **YAML block-scalar values inside a resource are captured as ordinary block text** — a
  documented, not-yet-observed-in-practice residual shared by the whole `agentsec.cfn` parser.

## What this guard does NOT prove

A clean scan means no `AWS::Batch::JobDefinition` resource in the scanned templates sets
`Privileged: true` — it says nothing about a job definition created outside CloudFormation entirely
(the AWS Console, a different IaC tool, a nested stack this scan didn't independently discover), a
job definition whose `Privileged` setting is driven by a CloudFormation parameter/condition this
guard's textual scan can't resolve, or a `LinuxParameters.Capabilities` grant that achieves a
similar effective privilege escalation through a different property this guard doesn't inspect.

## Canary plant

`cfn_batch_job.yaml` — `AWS::Batch::JobDefinition` with `ContainerProperties.Privileged: true`.
Expected rule: `cfn-batch-privileged-container/privileged-true`.

# Citations

[1] agentsec checklist item `6c-cfn-batch-privileged-container` (§6c)
[2] OWASP:A05 (Security Misconfiguration)
[3] cfripper (`Skyscanner/cfripper`) — `BatchJobDefinitionContainerPropertiesPrivilegedRule.rb`,
    rule `W34` (provenance only; detection logic here is original)
[4] `k8s-privileged-container` — the conceptually adjacent Kubernetes guard this item's threat
    framing is drawn from (different resource type, kept as separate checklist items)
