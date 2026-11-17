---
type: Guard
title: "cloudtrail-logging-disabled"
description: "CloudTrail logging disabled or restricted to a single region."
timestamp: "2026-07-14T14:41:41+08:00"
guard_id: "cloudtrail-logging-disabled"
checklist_section: ["10"]
standards: ["CWE-778", "OWASP:A09", "SOC2:CC7.2"]
---

# CloudTrail logging disabled or restricted to a single region

## What it detects

A Terraform `aws_cloudtrail` resource block that explicitly sets
`enable_logging = false` (the trail records no API activity at all) or
`is_multi_region_trail = false` (the trail misses every API call made outside its
home region).

## Why it matters

CloudTrail is the account's audit log of every API call — the record an incident
response depends on to answer "what happened." A disabled trail leaves zero audit
history; a single-region trail silently misses activity in any other region, exactly
where an attacker pivoting through a compromised credential would operate to stay off
the radar. agentsec had no CloudTrail-specific coverage before this guard — checked
the checklist for any existing `cloudtrail`/audit-logging item and found none (this is
genuinely new ground, not an extension). Checkov's own `CKV_AWS_251` (logging) and
`CKV_AWS_67` (multi-region) checks exist for the same reasons.

## Detection scope

- Language: Terraform (`.tf`)
- Applies when: `"terraform" in profile.features`
- Scanned files: every `.tf` file under the repo root
- Uses `iter_terraform_resources()` to isolate `aws_cloudtrail` resource blocks
- Fires HIGH when a block contains `enable_logging = false`
- Fires MEDIUM when the trail is single-region — either an explicit
  `is_multi_region_trail = false` (anchored on that line) **or the attribute absent
  entirely** (anchored on the resource's opening line). The AWS provider defaults
  `is_multi_region_trail` to `false` (the insecure state), so a trail that omits it is
  single-region by default — the majority real-world shape, and what Checkov's
  `CKV_AWS_67` evaluates the effective default for. Only an explicit
  `is_multi_region_trail = true` silences the MEDIUM.
- `enable_logging` is the opposite: its provider default is `true` (the SAFE state), so an
  **absent** `enable_logging` is NOT flagged — silence is correct there. Only an explicit
  `enable_logging = false` fires HIGH.
- Pragma: `# security: allow-cloudtrail-logging` on the attribute line suppresses an explicit
  finding; for the absent-multi-region case (no attribute line) it goes on the resource's
  opening line.

## Rules

| Rule ID | Severity | Trigger |
|---|---|---|
| `cloudtrail-logging-disabled/logging-disabled` | HIGH | `enable_logging = false` |
| `cloudtrail-logging-disabled/single-region-trail` | MEDIUM | `is_multi_region_trail = false` OR the attribute absent (provider-default false) |

## Opt-out

`# security: allow-cloudtrail-logging` on the attribute line.

## Known bypasses / false negatives

| Bypass | Why missed |
|---|---|
| `enable_logging = var.is_enabled` where the variable defaults to `false` elsewhere | Only a literal `false` on the attribute line is matched, same tradeoff as `rds-publicly-accessible` |
| A trail defined via `aws_cloudtrail` inside a `module` block that sets the attribute at the call site | The helper only sees the resource's own literal body |

## False positive scenarios

None identified — both attributes are boolean-only and unambiguous.

## Checklist mapping

`10-cloudtrail-logging-disabled` (new item, HIGH — no prior CloudTrail/cloud-audit-log
coverage in the checklist before this guard)

## Standards

- OWASP:A09 (Security Logging and Monitoring Failures)
- CWE-778 (Insufficient Logging)

## Related guards

- `agent-tool-audit-log`: application-level agent tool-call logging — a different
  layer (app code vs. cloud infrastructure) of the same "can we investigate an
  incident" concern.

# Citations

[1] agentsec checklist item `10-cloudtrail-logging-disabled` (§10)
[2] CWE-778
[3] OWASP:A09
[4] SOC2:CC7.2
