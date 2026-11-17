---
type: Guard
title: "cfn-nacl-ineffective-deny"
description: "Surfaces a CloudFormation Network ACL deny entry whose CIDR block is not the full-range 0.0.0.0/0 or ::/0, for manual review."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "cfn-nacl-ineffective-deny"
checklist_section: ["7"]
standards: ["OWASP:A05"]
---

# Network ACL deny entry's CIDR block is not the full-range 0.0.0.0/0 or ::/0

Flags `AWS::EC2::NetworkAclEntry` resources with `RuleAction: deny` whose `CidrBlock` (or
`Ipv6CidrBlock`) is present but is not exactly the full-range value (`0.0.0.0/0` for IPv4, `::/0`
for IPv6). Closes checklist item `7-cfn-nacl-ineffective-deny` (new — no existing agentsec item
covered this pattern before this guard).

## The threat

A Network ACL `deny` rule's *effectiveness* depends on what range it actually blocks. If an author
intends a rule to block all traffic on a given protocol/port from a subnet and writes a narrower
CIDR than they meant (a typo, a copy-paste from an `allow` rule, a misunderstanding of NACL
evaluation semantics), the rule silently permits everything outside that narrow range — the
opposite of what was intended. cfn_nag's real detector for this
(`EC2NetworkAclEntryIneffectiveDenyRule.rb`, rule `W71`) treats any non-full-range CIDR on a deny
rule as worth a second look.

## Exploitability rationale — why this is a SURFACING finding, not a proven bug

LOW severity, review-signal (`surfacing_rule_prefixes = ("cfn-nacl-ineffective-deny/narrow-cidr-
deny",)` — per-rule surfacing, since this guard emits exactly one rule; see
`agentsec/guards/compose_no_network_segmentation.py` for the declaration convention this follows).
A narrow CIDR on a `deny` rule is not a bug by itself — it is also the textbook way to write a
*legitimate*, deliberate NACL entry: "block this one known-bad `/24`," "deny this partner's old IP
range now that they've rotated," etc. This guard cannot tell the difference between "the author
meant to block everything and mistyped the CIDR" and "the author meant to block exactly this
range." So it surfaces the pattern for a human to confirm rather than asserting a proven
vulnerability.

## What counts as a hit (and what doesn't)

- `AWS::EC2::NetworkAclEntry` with `RuleAction: deny` and `CidrBlock` set to anything other than
  `0.0.0.0/0` (e.g. `10.0.0.0/24`) → fires.
- The same, but `Ipv6CidrBlock` set to anything other than `::/0` → fires.
- `RuleAction: deny` with `CidrBlock: 0.0.0.0/0` (the full range — the "deny everything" case) →
  silent. This is the correct, unambiguous form.
- `RuleAction: deny` with `Ipv6CidrBlock: '::/0'` → silent, same reasoning.
- `RuleAction: allow` with any CIDR → silent (not a deny rule at all — this guard only reasons
  about deny entries, per cfn_nag's own scope for this rule).
- Any other resource type (`AWS::EC2::NetworkAcl`, `AWS::EC2::SecurityGroup`, etc.) → silent.
- Both YAML and JSON template formats are scanned identically via the shared `agentsec.cfn`
  resource-block parser.

## When NOT to flag (and the pragma)

A narrow-CIDR deny that is genuinely intentional (blocking one specific known-bad range while
other rules/route tables handle the rest) is not a finding worth repeating on every scan.
Suppress it with a comment containing `security: allow-nacl-ineffective-deny` anywhere in the
resource's block (YAML templates only — JSON has no comment syntax, so a JSON-authored template
cannot carry this pragma at all, the same known limitation shared by every CFN guard in this
batch):

```yaml
Resources:
  BlockKnownBadRange:
    Type: AWS::EC2::NetworkAclEntry
    Properties:
      RuleAction: deny
      CidrBlock: 198.51.100.0/24  # security: allow-nacl-ineffective-deny
```

## Known bypasses (honest limits — the narrowest-scoped guard in this batch)

This guard is deliberately narrower than cfn_nag's real `W71` rule and does NOT attempt:

- **No CIDR-containment or subnet-overlap math.** It does a literal string comparison against
  `0.0.0.0/0`/`::/0` only. It cannot tell whether a narrow CIDR is a strict subset, superset, or
  disjoint from any other rule's range, and it does not reason about IPv6 CIDR normalization
  (e.g. `::0/0` vs `::/0` would not be recognized as equivalent — only the exact canonical
  `::/0` string is treated as full-range).
- **No NACL rule-number evaluation-order reasoning.** Real NACLs evaluate rules in `RuleNumber`
  order and stop at the first match; a narrow deny at rule 100 followed by a broad allow at rule
  200 behaves very differently from the reverse. This guard does not read `RuleNumber` at all or
  correlate entries within the same `NetworkAclId` — reasoning cfn_nag's real Ruby implementation
  may or may not fully perform either; this guard makes no claim to match it beyond the "is the
  deny CIDR the full range" text check.
- **No cross-file / cross-resource correlation.** Each `NetworkAclEntry` is evaluated in
  isolation; a companion `allow` entry elsewhere in the same or a different template that makes
  a narrow deny redundant (or necessary) is not considered.
- **File-level location, not line-level** — like every CFN guard in this batch, the finding
  reports the template file, not a specific line.
- **JSON templates cannot carry the suppression pragma** — JSON has no comment syntax.
- **YAML block-scalar values inside a resource are captured as ordinary block text** — a
  documented, not-yet-observed-in-practice residual shared by the whole `agentsec.cfn` parser.

## What this guard does NOT prove

A finding here does not prove the NACL rule is broken, and a clean scan does not prove every deny
rule in the account behaves as intended — it only means every `AWS::EC2::NetworkAclEntry` deny
entry found in the scanned templates uses the full-range CIDR (or was suppressed). It says nothing
about NACLs created outside CloudFormation (the AWS Console, a different IaC tool, a nested stack
not independently discovered), rule ordering correctness, or whether a narrow CIDR that fires this
finding is actually a mistake versus a deliberate, correct design choice — that judgment call is
left to the reviewer this guard is surfacing the case for.

## Canary plant

`cfn_nacl_deny.yaml` — `AWS::EC2::NetworkAclEntry` with `RuleAction: deny` and `CidrBlock:
10.0.0.0/24` (not the full range). Expected rule: `cfn-nacl-ineffective-deny/narrow-cidr-deny`.

# Citations

[1] agentsec checklist item `7-cfn-nacl-ineffective-deny` (§7)
[2] OWASP:A05 (Security Misconfiguration)
[3] cfn_nag (`stelligent/cfn_nag`) — `EC2NetworkAclEntryIneffectiveDenyRule.rb`, rule `W71`
    (provenance only; detection logic here is original and deliberately simpler — no
    CIDR-containment math, no rule-order evaluation)
