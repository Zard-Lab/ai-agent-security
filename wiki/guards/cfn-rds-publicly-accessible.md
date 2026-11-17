---
type: Guard
title: "cfn-rds-publicly-accessible"
description: "CloudFormation RDS instance directly reachable from the internet."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "cfn-rds-publicly-accessible"
checklist_section: ["7"]
standards: ["OWASP:A05", "CWE-284"]
---

# RDS instance directly reachable from the internet (CloudFormation)

Flags `AWS::RDS::DBInstance` resources that set `PubliclyAccessible: true`. Closes checklist item
`7-rds-not-publicly-accessible` — the CloudFormation counterpart to the existing
`rds-publicly-accessible` (Terraform) guard, extending the same checklist item rather than
duplicating it.

## The threat

`PubliclyAccessible: true` on an `AWS::RDS::DBInstance` assigns the database instance a public IP
address and opens its port to any address that can also pass the attached security group.
Combined with a permissive security group (or simply the default AWS behavior of the port being
reachable once the instance is public), this is one of the most common real-world causes of an
internet-exposed production database. CWE-284 (Improper Access Control), OWASP:A05.

## Exploitability rationale

HIGH. An internet-reachable database port is a direct attack surface — credential-stuffing,
default-credential brute force, and unpatched-engine exploitation all become possible the moment
the instance has a public IP, no separate compromise required. Same severity as the Terraform
sibling.

## What counts as a hit (and what doesn't)

- `AWS::RDS::DBInstance` with `PubliclyAccessible: true` (or `"PubliclyAccessible": true` in JSON)
  → fires.
- `PubliclyAccessible: false` (explicit) → silent.
- No `PubliclyAccessible` property at all → **silent** (a deliberate default-handling decision, not
  a claim about AWS's real behavior — see below).
- Both YAML and JSON template formats are scanned identically (see `agentsec/cfn.py`'s module
  docstring for how the two formats converge on one `block` text every CFN guard scans the same
  way).

### The missing-property decision, and why

RDS's actual default `PubliclyAccessible` value is not a fixed constant — it depends on whether the
DB instance's subnet group sits in a public or private VPC subnet, something this guard cannot
determine from the template text alone (that requires resolving the referenced
`DBSubnetGroupName`/subnet resources and their route tables, out of scope for a textual, per-
resource scan). Given that ambiguity, this guard follows the same convention its Terraform sibling
already uses for the identical checklist item: `rds_publicly_accessible.py`'s own docstring states
"the Terraform AWS provider defaults `publicly_accessible` to `false`, so silence is the safe
state" and its guard logic does not fire on an omitted attribute. This CFN guard mirrors that
choice — omission is treated as silent, not as a hit — for consistency between the two guards
covering the same checklist item, at the cost of a known false-negative risk: a `DBInstance`
launched into a public subnet with no explicit `PubliclyAccessible` property is picked up nowhere
by this guard.

## When NOT to flag (and the pragma)

- `PubliclyAccessible: false` or omitted → silent.
- A deliberately public instance by design (e.g. a public read-replica behind its own firewalling)
  → suppress explicitly (YAML templates only — JSON has no comment syntax, so a JSON-authored
  template cannot carry this pragma at all, a known limitation shared by every CFN guard in this
  batch):

```yaml
Resources:
  PublicReadReplica:
    Type: AWS::RDS::DBInstance
    Properties:
      PubliclyAccessible: true  # security: allow-rds-public
```

## Known bypasses (honest limits)

- **No dataflow, no cross-resource reasoning.** The guard reads `PubliclyAccessible` directly off
  the resource's own block; it does not resolve subnet groups, route tables, or security-group
  rules to determine actual internet reachability.
- **The missing-property case is a known false negative**, by design — see above.
- **File-level location, not line-level** — like every CFN guard in this batch, the finding reports
  the template file, not a specific line (see `agentsec/cfn.py`'s module docstring for why: a JSON
  block is a `json.dumps` reconstruction with no original line mapping to report).
- **JSON templates cannot carry the suppression pragma** — JSON has no comment syntax.
- **YAML block-scalar values inside a resource are captured as ordinary block text** — a
  documented, not-yet-observed-in-practice residual shared by the whole `agentsec.cfn` parser.

## What this guard does NOT prove

A clean scan means no scanned `AWS::RDS::DBInstance` resource explicitly sets
`PubliclyAccessible: true` — it says nothing about an instance created outside CloudFormation
entirely (the AWS Console, a different IaC tool, a nested stack this scan didn't independently
discover), an instance whose actual public reachability is instead driven by its subnet placement
with the property left unset, or the attached security group's own rules.

## Canary plant

`cfn_rds_public.yaml` — `AWS::RDS::DBInstance` with `Engine: postgres` and
`PubliclyAccessible: true`. Expected rule: `cfn-rds-publicly-accessible/publicly-accessible-true`.

# Citations

[1] agentsec checklist item `7-rds-not-publicly-accessible` (§7)
[2] OWASP:A05 (Security Misconfiguration)
[3] CWE-284 (Improper Access Control)
[4] cfn_nag (`stelligent/cfn_nag`) — `RDSInstancePubliclyAccessibleRule.rb`, rule `F22`
    (provenance only; detection logic here is original)
