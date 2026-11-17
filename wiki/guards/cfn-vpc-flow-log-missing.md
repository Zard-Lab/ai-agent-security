---
type: Guard
title: "cfn-vpc-flow-log-missing"
description: "Flags a CloudFormation template that defines a VPC but declares no AWS::EC2::FlowLog resource anywhere in the same file."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "cfn-vpc-flow-log-missing"
checklist_section: ["7"]
standards: ["OWASP:A09", "CWE-778"]
---

# VPC has no AWS::EC2::FlowLog resource (CloudFormation)

Flags a CloudFormation template that defines an `AWS::EC2::VPC` resource but has no
`AWS::EC2::FlowLog` resource declared anywhere in the same file. This closes a **new** checklist
item, `7-cfn-vpc-flow-log-missing` — no existing agentsec item covered VPC flow logging before this
guard, CloudFormation or otherwise.

## The threat

VPC Flow Logs record accepted/rejected IP traffic to and from network interfaces in a VPC. Without
them, there is no audit trail for network activity inside the VPC — an attacker's lateral movement
between instances, data exfiltration to an external IP, or internal reconnaissance leaves no
record an incident responder can later reconstruct. CWE-778 (Insufficient Logging); OWASP:A09
(Security Logging and Monitoring Failures).

## Exploitability rationale

MEDIUM. This is an observability gap, not a direct exploit primitive — the same severity tier as
the sibling `cfn-kms-key-rotation-not-enabled` guard. It doesn't hand an attacker anything by
itself; it removes the evidence trail that would otherwise expose a *separate* compromise.

## What counts as a hit (and what doesn't)

This is a **template-wide presence check**, not per-VPC resolution. The guard fires **once per
template file** when that file's parsed resource list contains at least one `AWS::EC2::VPC`
resource and zero `AWS::EC2::FlowLog` resources anywhere in the file — it does not attempt to
match a specific `FlowLog`'s `ResourceId`/`Ref` back to a specific VPC's logical id.

That scoping choice is deliberate: a `FlowLog` resource's `ResourceId` can reference a VPC, a
subnet, or an ENI (via `!Ref`, `Fn::GetAtt`, or a hardcoded ID), and resolving that reference back
to "does *this* VPC have *its own* FlowLog" would require real cross-resource reference reasoning.
`agentsec.cfn` deliberately does not do that (see its module docstring) — the same limitation the
`cfn-kms-key-rotation-not-enabled` guard document already discloses for its own domain. A
template-level "is there a VPC with no FlowLog declared anywhere in this file" check is the
defensible, honestly-scoped v1.

- A template with an `AWS::EC2::VPC` resource and no `AWS::EC2::FlowLog` resource → fires.
- A template with an `AWS::EC2::VPC` resource and an `AWS::EC2::FlowLog` resource (regardless of
  what the FlowLog's `ResourceId` actually points at) → silent.
- A template with no `AWS::EC2::VPC` resource at all → silent (nothing to flag).
- Multiple VPC resources in one file all get named in the single file-level finding message; the
  guard still emits only one finding per file, not one per VPC.
- Both YAML and JSON template formats are scanned identically, via the shared
  `agentsec.cfn.cfn_resources()` parser (see `agentsec/cfn.py`'s module docstring for how the two
  formats converge on one `block` text every CFN guard scans the same way).

## When NOT to flag (and the pragma)

- A `FlowLog` resource present anywhere in the file → silent.
- No VPC in the file → silent.
- Flow logging genuinely handled elsewhere for this VPC (see "Known bypasses" below for the honest
  caveat about *why* that's already a silent case in practice) → suppress explicitly with a
  comment anywhere in the file (YAML templates only — JSON has no comment syntax, so a JSON
  template cannot carry this pragma at all, a known limitation shared by every CFN guard in this
  batch):

```yaml
Resources:
  SandboxVpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/16  # security: allow-vpc-flow-log-missing
```

Unlike the per-resource-block pragma convention `cfn-kms-key-rotation-not-enabled` uses, this
guard's pragma is checked against the **whole file's text**, not one resource's block — the finding
itself is file-level (there is no single resource whose block would meaningfully carry the
suppression), so the pragma is scoped the same way the finding is.

## Known bypasses (honest limits)

- **A multi-VPC template where only some VPCs lack a FlowLog stays silent.** Because this is a
  template-wide "any FlowLog present" check, a template declaring three VPCs where only one has a
  `FlowLog` resource produces no finding at all — the other two unmonitored VPCs are invisible to
  this guard. This is the direct cost of not doing cross-resource `ResourceId` resolution.
- **A VPC whose FlowLog lives in a separate template or nested stack false-positives.** `agentsec.cfn`
  scans each template file independently and does not follow `AWS::CloudFormation::Stack`
  references (see its module docstring) — if a VPC template and its FlowLog are split across a
  parent/child stack pair, or across two independently-authored templates, this guard flags the VPC
  template even though flow logging is actually configured, just not in the same file.
- **No dataflow, no cross-resource reasoning** — the check is a pure presence/absence test over the
  file's parsed resource list, not a proof that a specific VPC's traffic is actually being
  captured.
- **File-level location, not line-level** — like every CFN guard in this batch, the finding reports
  the template file, not a specific line (see `agentsec/cfn.py`'s module docstring for why: a JSON
  block is a `json.dumps` reconstruction with no original line mapping to report, and this guard's
  finding isn't anchored to one resource in the first place).
- **JSON templates cannot carry the suppression pragma** — JSON has no comment syntax.

## What this guard does NOT prove

A clean scan means every template file that declares a VPC also declares at least one FlowLog
resource somewhere in that same file — it does not prove that FlowLog actually targets that VPC
(vs. a different VPC, a subnet, or an ENI in the same file), that the FlowLog's destination
(CloudWatch Logs / S3) is itself correctly configured and retained, or that flow logging is enabled
for a VPC created outside CloudFormation entirely (the AWS Console, a different IaC tool, or a
nested/sibling stack this scan didn't independently discover).

## Canary plant

`cfn_vpc_no_flow_log.yaml` — `AWS::EC2::VPC` with a `CidrBlock` property and no
`AWS::EC2::FlowLog` resource anywhere in the file. Expected rule:
`cfn-vpc-flow-log-missing/no-flow-log`.

# Citations

[1] agentsec checklist item `7-cfn-vpc-flow-log-missing` (§7) — new item, first covered by this guard
[2] OWASP:A09 (Security Logging and Monitoring Failures)
[3] CWE-778 (Insufficient Logging)
[4] cfn_nag (`stelligent/cfn_nag`) — `VpcHasFlowLogRule.rb`, rule `W60` (provenance only;
    detection logic here is original)
