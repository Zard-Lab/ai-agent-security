---
type: Guard
title: "msk-cluster-transit-encryption-disabled"
description: "MSK cluster allows plaintext broker traffic."
timestamp: "2026-10-27T09:00:00Z"
guard_id: "msk-cluster-transit-encryption-disabled"
checklist_section: ["7"]
standards: ["OWASP:A02", "CWE-319"]
---

# MSK cluster allows plaintext broker traffic

_Author — Marconi, 2026-10-25. Revised 2026-10-27 (review H1/H6: fixed a wrong provider-default
claim that fired on every unconfigured cluster; see "The threat")._

---

## The threat

A Terraform `aws_msk_cluster` whose `client_broker` is explicitly set to `"PLAINTEXT"` (or the
opportunistic `"TLS_PLAINTEXT"`) lets a client negotiate a plaintext connection to the broker.
Anyone who can observe the network path (a shared VPC, a misconfigured security group, a
compromised node on the same subnet) reads every message produced or consumed on that
connection — no application-level bug required. The same block also carries `in_cluster`, which
governs broker-to-broker replication traffic; disabling it exposes the cluster's own internal
traffic the same way. CWE-319 (Cleartext Transmission of Sensitive Information), OWASP:A02.

**The provider default for `client_broker` is `"TLS"` (safe).** An earlier version of this
guard's detection, and of this doc, wrongly stated the default as `"TLS_PLAINTEXT"` and fired on
every cluster with no `encryption_info` block at all — fixed after an agentic pre-review (H1)
caught it against the actual `hashicorp/terraform-provider-aws` docs. `in_cluster`'s own default
really is `true` (safe), which the guard already had right.

## Why this guard fits the stack

MSK backs the event/queue layer of an agentic app (durable task queues, audit event streams,
cross-service pub/sub) in the FastAPI + LLM/RAG shape this project targets:

```hcl
resource "aws_msk_cluster" "events" {
  cluster_name           = "events"
  kafka_version           = "3.5.1"
  number_of_broker_nodes  = 3
  encryption_info {
    encryption_in_transit {
      client_broker = "PLAINTEXT"  # fires -- the provider default ("TLS") would NOT fire
    }
  }
}
```

The control is nested three levels deep — a top-level `encryption_info { ... }` block,
containing `encryption_in_transit { ... }`, containing `client_broker` and `in_cluster`.

## Detection design

1. `applies()` gate — `"terraform" in profile.features`.
2. Scans every `.tf` file via `iter_files(root, (".tf",))`, skipping non-product paths.
3. Uses `iter_terraform_resources()` to isolate each `aws_msk_cluster` block. Comments are
   blanked into `code_body` before matching.
4. Extracts `encryption_info { ... }`'s own inner text with a brace-balanced regex that
   tolerates one level of nested braces (needed because `encryption_in_transit` nests inside
   it), then extracts `encryption_in_transit { ... }`'s inner text from that.
5. **Rule A (`client-broker-not-tls`)**: fires HIGH only when `client_broker` is the literal
   `"PLAINTEXT"`. **Rule A' (`client-broker-opportunistic-tls`)**: fires MEDIUM when it is the
   literal `"TLS_PLAINTEXT"`. Both stay silent when the attribute, `encryption_in_transit`, or
   `encryption_info` is absent (provider default `"TLS"`, safe), when it is literally `"TLS"`,
   or when the value is a non-literal expression (e.g. a variable) — a non-literal cannot be
   proven unsafe, so it is not treated the same as a known-unsafe literal.
6. **Rule B (`in-cluster-disabled`)**: fires HIGH only when `encryption_in_transit` is PRESENT
   and its `in_cluster` attribute is explicitly `false`. Absence stays silent (provider default
   `true`, safe).
7. Inline opt-out: `# security: allow-msk-plaintext` anywhere in the resource block (checked via
   `pragma_present(..., dialect="hcl")` against the block's own text, so a commented-out
   `# client_broker = "TLS"` can never silence a real finding).
8. Severity: `high` for Rule A and Rule B, `medium` for Rule A'. Standards: `["OWASP:A02", "CWE-319"]`.

## When NOT to flag

- `client_broker` absent, `"TLS"`, or set to a variable/non-literal expression.
- `in_cluster` absent or `true` (the attribute's own default is `true`).
- An audited case (e.g. a cluster deliberately run inside an isolated, trusted network for a
  throwaway dev workload), suppressed with `# security: allow-msk-plaintext`.

## Tests

| Test | What it checks |
|---|---|
| `test_msk_no_encryption_info_block_stays_silent` | FP-bait: no `encryption_info` at all → silent (provider default `"TLS"` is safe). |
| `test_msk_encryption_in_transit_block_absent_stays_silent` | FP-bait: `encryption_info` present, `encryption_in_transit` absent → silent. |
| `test_msk_client_broker_attribute_absent_but_block_present_stays_silent` | FP-bait: `encryption_in_transit` present, `client_broker` itself absent → silent. |
| `test_msk_client_broker_variable_stays_silent` | FP-bait: `client_broker = var.client_broker` → silent (non-literal). |
| `test_msk_client_broker_tls_plaintext_fires_medium` | Positive: `client_broker = "TLS_PLAINTEXT"` fires Rule A' at `medium`. |
| `test_msk_client_broker_plaintext_fires` | Positive: `client_broker = "PLAINTEXT"` fires Rule A at `high` (**verified_by**). |
| `test_msk_client_broker_tls_silent` | FP-bait: `client_broker = "TLS"` → Rule A silent. |
| `test_msk_in_cluster_false_fires` | Positive: `in_cluster = false` (with `client_broker = "TLS"`) fires Rule B only. |
| `test_msk_in_cluster_true_silent` | FP-bait: `in_cluster = true` → Rule B silent. |
| `test_msk_in_cluster_absent_does_not_fire_rule_b` | `encryption_in_transit` present but `in_cluster` absent → Rule B stays silent. |
| `test_msk_pragma_silences` | Suppress pragma → both rules silent. |
| `test_msk_unrelated_resource_silent` | A non-`aws_msk_cluster` resource → silent. |
| `test_msk_applies_gate` / `test_msk_applies_with_terraform` | `applies()` gate. |

## Known bypasses

- **A resource nested inside a `module` block** — only the literal resource body is seen.
- **`client_broker`/`in_cluster` set via a computed/interpolated expression** — not resolved
  (deliberately silent; see Detection design above).

## What this guard does NOT prove

A silent guard does not confirm the applied infrastructure matches the source (drift), that the
attribute wasn't overridden via `-var`/`terraform.tfvars` at apply time, or that a cluster
provisioned outside Terraform carries the same configuration. This is a presence-based,
source-only check.

# Citations

[1] agentsec checklist item `7-msk-cluster-transit-encryption-disabled` (§7)
[2] OWASP:A02
[3] CWE-319
