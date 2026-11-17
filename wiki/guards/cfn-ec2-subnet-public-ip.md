---
type: Guard
title: "cfn-ec2-subnet-public-ip"
description: "No CloudFormation EC2 subnet that auto-assigns public IPs to every instance launched into it."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "cfn-ec2-subnet-public-ip"
checklist_section: ["7"]
standards: ["OWASP:A05"]
---

# EC2 subnet auto-assigns public IPs on instance launch (CloudFormation)

Flags `AWS::EC2::Subnet` resources with `MapPublicIpOnLaunch: true`. Closes checklist item
`7-cfn-ec2-subnet-public-ip` (§7) — a new item, since no existing agentsec check covered this
CloudFormation subnet-level exposure setting. Built on the same `agentsec.cfn` shared parser as
`cfn-kms-key-rotation-not-enabled` (this batch's second CFN guard).

## The threat

`MapPublicIpOnLaunch` is a subnet-level setting: when `true`, every EC2 instance launched into that
subnet automatically receives a public IP address, whether or not the instance's own launch config
(or the ASG/launch template driving it) ever asked for one. That silently widens the network
exposure of anything deployed there — independent of what the instance's own security groups or
NACLs say — because the subnet setting is applied at launch time, ahead of and regardless of the
instance author's intent. This is cfn_nag's rule `W33`.

## Exploitability rationale

MEDIUM. Not itself a direct exploit primitive — an instance still needs a routable path and an
open security group for a public IP to be reachable — but it's a misconfiguration that widens
blast radius by removing a layer of intentionality: a future instance launched into this subnet
gets a public IP by default, without anyone at launch time deciding that on purpose. The actual
risk depends on what gets launched into the subnet, which this guard cannot know.

## What counts as a hit (and what doesn't)

- `AWS::EC2::Subnet` with `MapPublicIpOnLaunch: true` (or `"MapPublicIpOnLaunch": true` in JSON)
  anywhere in the resource's block → fires.
- `MapPublicIpOnLaunch: false` (explicit) → silent (the fix).
- The property **missing entirely** → silent, deliberately. AWS's real default for a subnet's
  auto-assign-public-IP behavior is not a fixed CFN default — it depends on how the subnet's VPC
  itself was created: a *default* VPC's default subnets have it on by default, while a
  *non-default* VPC's subnets default it to off. Because the template alone doesn't say which case
  applies, an absent property is not verifiable evidence of the vulnerable behavior, so flagging it
  would be a guess, not a finding. Only an explicit `true` is an unambiguous, textually-verifiable
  hit.
- An unrelated resource type (e.g. `AWS::S3::Bucket`) → silent, even if it happens to contain a
  `MapPublicIpOnLaunch`-shaped key somewhere (not a realistic case, but the resource-type filter
  guards it regardless).
- Both YAML and JSON template formats are scanned identically (see `agentsec/cfn.py`'s module
  docstring for how the two formats converge on one `block` text every CFN guard scans the same
  way).

## When NOT to flag (and the pragma)

- `MapPublicIpOnLaunch: false` or omitted → silent.
- A deliberately public-facing subnet (e.g. a subnet dedicated to a public load balancer, where
  every instance in it is meant to be internet-reachable by design) → suppress explicitly (YAML
  templates only — JSON has no comment syntax, so a JSON-authored template cannot carry this
  pragma at all, a known limitation shared by every CFN guard in this batch):

```yaml
Resources:
  PublicLoadBalancerSubnet:
    Type: AWS::EC2::Subnet
    Properties:
      CidrBlock: 10.0.1.0/24
      VpcId: !Ref MyVpc
      MapPublicIpOnLaunch: true  # security: allow-ec2-subnet-public-ip
```

## Known bypasses (honest limits)

- **No dataflow, no cross-resource reasoning.** Fires on the property's literal value in the
  resource block; a value driven by a CloudFormation Parameter or Condition (e.g.
  `MapPublicIpOnLaunch: !If [IsPublic, true, false]`) is not resolved — it won't match the literal
  `true` pattern, so a parameterized subnet that evaluates to `true` at deploy time is a silent
  false negative.
- **File-level location, not line-level** — like every CFN guard in this batch, the finding
  reports the template file, not a specific line (see `agentsec/cfn.py`'s module docstring for
  why: a JSON block is a `json.dumps` reconstruction with no original line mapping to report).
- **JSON templates cannot carry the suppression pragma** — JSON has no comment syntax.
- **YAML block-scalar values inside a resource are captured as ordinary block text** — a
  documented, not-yet-observed-in-practice residual shared by the whole `agentsec.cfn` parser.
- **No VPC-default reasoning.** The guard cannot see the referenced VPC's own configuration, so it
  only ever judges what's written on the subnet resource itself — it does not (and cannot) infer
  the "default VPC" case where auto-assign-public-IP might be true even without this property set.

## What this guard does NOT prove

A clean scan means no `AWS::EC2::Subnet` resource in the scanned templates *explicitly* sets
`MapPublicIpOnLaunch: true` — it says nothing about a subnet created outside CloudFormation
entirely (the AWS Console, a different IaC tool, a nested stack this scan didn't independently
discover), a subnet in a default VPC whose implicit public-IP behavior this guard cannot observe,
or a value resolved only at deploy time through a Parameter/Condition this guard's textual scan
can't evaluate.

## Canary plant

`cfn_subnet.yaml` — `AWS::EC2::Subnet` with `CidrBlock`, `VpcId`, and
`MapPublicIpOnLaunch: true`. Expected rule: `cfn-ec2-subnet-public-ip/map-public-ip-true`.

# Citations

[1] agentsec checklist item `7-cfn-ec2-subnet-public-ip` (§7)
[2] OWASP:A05 (Security Misconfiguration)
[3] cfn_nag (`stelligent/cfn_nag`) — `EC2SubnetMapPublicIpOnLaunchRule.rb`, rule `W33` (provenance
    only; detection logic here is original)
