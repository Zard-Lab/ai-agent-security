---
type: Guard
title: "elasticache-transit-encryption-disabled"
description: "ElastiCache replication group has transit encryption disabled."
timestamp: "2026-10-25T09:00:00Z"
guard_id: "elasticache-transit-encryption-disabled"
checklist_section: ["7"]
standards: ["OWASP:A02", "CWE-319"]
---

# ElastiCache replication group has transit encryption disabled

_Author — Marconi, 2026-10-25_

---

## The threat

A Terraform `aws_elasticache_replication_group` without `transit_encryption_enabled = true`
lets clients talk to the Redis/Valkey cluster over plain TCP. Like
`aws_ebs_volume.encrypted`, the attribute is opt-in and defaults to `false` when never set, so
`terraform apply` succeeds either way and the omission is silent. A cache holding session
tokens, rate-limit counters, or cached query/RAG results sent in the clear is readable by
anyone who can observe the network path to the cluster (a shared VPC, a misconfigured security
group, a compromised node on the same subnet) — no application-level bug required. CWE-319
(Cleartext Transmission of Sensitive Information), OWASP:A02.

The `false` default is AWS's own: the `CreateReplicationGroup` API reference documents
`TransitEncryptionEnabled` as "Default: `false`" [4]. The Terraform provider doc states no default
of its own. For `engine_version` below `7.0.5` the setting can only be chosen at creation; from
`7.0.5` it can be turned on in place through `transit_encryption_mode = "preferred"`.

## Why this guard fits the stack

ElastiCache backs the session/cache layer of a FastAPI + LLM/RAG app (session storage, rate
limiting, response caching) in the stack this project targets:

```hcl
resource "aws_elasticache_replication_group" "sessions" {
  replication_group_id = "sessions"
  engine                = "redis"
  node_type             = "cache.r6g.large"
  # no transit_encryption_enabled attribute at all -> defaults to false
}
```

This is the simple single-attribute shape, the same as `ebs_volume_not_encrypted.py` — no
nested blocks, no sub-attributes to resolve.

## Detection design

1. `applies()` gate — `"terraform" in profile.features`.
2. Scans every `.tf` file via `iter_files(root, (".tf",))`, skipping non-product paths.
3. Uses `iter_terraform_resources()` to isolate each `aws_elasticache_replication_group` block.
   Comments blanked into `code_body`. `_TRANSIT_ENCRYPTION_TRUE` searches for
   `transit_encryption_enabled = true` anywhere in the block. Fires unless found — whether the
   attribute is missing entirely or set to `false`.
4. Inline opt-out: `# security: allow-elasticache-plaintext` anywhere in the block.
5. Severity: `high` (a direct, no-encryption-at-all case). Rule id:
   `elasticache-transit-encryption-disabled/missing-encryption`. Standards:
   `["OWASP:A02", "CWE-319"]`.

## When NOT to flag

- `transit_encryption_enabled = true` present anywhere in the block.
- An audited case (e.g. a genuinely non-sensitive cache confined to an isolated, trusted
  network), suppressed with `# security: allow-elasticache-plaintext`.

## Tests

| Test | What it checks |
|---|---|
| `test_elasticache_missing_attribute_fires` | Positive: no `transit_encryption_enabled` attribute at all fires (**verified_by**). |
| `test_elasticache_explicit_false_fires` | Positive: `transit_encryption_enabled = false` fires. |
| `test_elasticache_enabled_silent` | FP-bait: `transit_encryption_enabled = true` → silent. |
| `test_elasticache_pragma_silences` | Suppress pragma → silent. |
| `test_elasticache_comment_does_not_suppress_finding` | A commented `# transit_encryption_enabled = true` does NOT suppress a genuine finding. |
| `test_elasticache_unrelated_resource_silent` | A non-`aws_elasticache_replication_group` resource → silent. |
| `test_elasticache_applies_gate` / `test_elasticache_applies_with_terraform` | `applies()` gate. |

## Known bypasses

- **Variable indirection**: `transit_encryption_enabled = var.encrypt_transit` where the
  variable defaults to `true` elsewhere — only a literal value is matched.
- **A resource nested inside a `module` block** — only the literal resource body is seen.
- **Not a bypass any more: a same-named `tags` key.** The attribute is read from the resource's
  own top-level attributes (`top_level_attribute_text` of the code view), and
  `literal_bool_state` only matches an attribute that starts its line. A tag such as
  `tags = { transit_encryption_enabled = "true" }`, on one line or several, therefore neither
  satisfies nor triggers the check (PR #1162 round-4 M2). A resource written on one line,
  `resource "aws_elasticache_replication_group" "x" { transit_encryption_enabled = true }`, is
  read the same as its multi-line form: the helper returns the opening line's own attribute
  (PR #1162 round-5 M1; `tests/test_terraform_layout_invariance.py` pins the layout invariant).
- **`aws_elasticache_cluster` is out of scope.** The guard reads
  `aws_elasticache_replication_group` only, so a single-node `aws_elasticache_cluster` with
  transit encryption off is not reported.

## What this guard does NOT prove

A silent guard does not confirm the applied infrastructure matches the source (drift), or that
a replication group provisioned outside Terraform has transit encryption on. This is a
presence-based, source-only check.

# Citations

[1] agentsec checklist item `7-elasticache-transit-encryption-disabled` (§7)
[2] OWASP:A02
[3] CWE-319
[4] AWS, ElastiCache API Reference, `CreateReplicationGroup`, `TransitEncryptionEnabled`:
"Default: `false`".
https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_CreateReplicationGroup.html
