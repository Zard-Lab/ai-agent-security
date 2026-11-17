---
type: Guard
title: "iac-open-ingress"
description: "World-open ingress in Terraform."
timestamp: "2026-06-17T14:14:57+08:00"
guard_id: "iac-open-ingress"
checklist_section: ["6c"]
standards: ["CIS:AWS", "OWASP:A05", "SOC2:CC6.6"]
---

# World-open ingress in Terraform

The seed of the IaC-misconfig family. Flags a Terraform security-group `ingress` rule whose
`cidr_blocks` is `0.0.0.0/0` (or `::/0`) — world-open inbound. Closes `6c-iac-open-ingress`.
Gated on a new `terraform` feature (any `*.tf` file present). OWASP:A05 / CIS:AWS.

## The threat

`ingress { cidr_blocks = ["0.0.0.0/0"] }` exposes the port to the entire internet. It is the single
most common cloud-deploy mistake — how Postgres (5432), SSH (22), Redis, and admin panels end up
publicly reachable and then trivially scanned/exploited. CWE-284 (improper access control), CIS AWS
Foundations 5.x.

## Exploitability rationale

HIGH. The misconfiguration is the exposure — no further bug needed; the open port is immediately
internet-reachable. Likelihood is high (copy-pasted `0.0.0.0/0` is everywhere). Capped below critical
because impact depends on what listens behind the port.

## What counts as a hit (and what doesn't)

Fires on a `cidr_block(s)`/`ipv6_cidr_blocks` line containing `0.0.0.0/0` or `::/0` while the block
stack has an open `ingress` block. Block context is tracked by a label stack (push on `<label> ... {`,
pop on `}`). The same CIDR inside an `egress` block is **silent** — open egress is normal. Comment lines
(`# ...`) are skipped, so a CIDR in a comment doesn't FP.

## When NOT to flag (and the pragma)

- A world-open CIDR in an `egress` block → silent.
- A restricted CIDR (`10.0.0.0/8`, an office range) → silent.
- An intentionally public rule (e.g. 443 on a public load balancer) → suppress with
  `# security: allow-open-ingress`.

## Known bypasses (honest limits — this is a conservative seed)

- **`aws_security_group_rule` form.** A standalone rule resource with `type = "ingress"` and
  `cidr_blocks = ["0.0.0.0/0"]` is **not** matched (the block label is `resource`, not `ingress`) —
  a deliberate false negative to keep the first IaC guard low-FP. A later iteration can track a
  `type = "ingress"` line within the block.
- **Variables / locals.** `cidr_blocks = [var.open]` where `var.open` defaults to `0.0.0.0/0` elsewhere
  is not resolved.
- **One-line blocks / unusual brace placement.** The label stack assumes the common multi-line HCL
  layout (`ingress {` opening a line).
- **Other IaC dialects.** CloudFormation, Kubernetes NetworkPolicy, and Pulumi are out of scope for
  this seed (future members of the family).

## What this guard does NOT prove

It catches the literal world-open ingress pattern in `*.tf`; it does not evaluate the full resolved
plan, variables, or other IaC tools. Absence of a finding ≠ the network is provably restricted — a
plan-time policy scanner (tfsec/Checkov/OPA) remains the comprehensive control; this is the fast,
dependency-free first line.

# Citations

[1] agentsec checklist item `6c-iac-open-ingress` (§6c)
[2] CIS:AWS
[3] OWASP:A05
[4] SOC2:CC6.6
