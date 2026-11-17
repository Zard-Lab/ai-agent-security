---
type: Guard
title: "opensearch-domain-encryption-disabled"
description: "OpenSearch/Elasticsearch domain has an encryption control disabled."
timestamp: "2026-10-27T09:00:00Z"
guard_id: "opensearch-domain-encryption-disabled"
checklist_section: ["7"]
standards: ["OWASP:A02", "CWE-311", "CWE-319"]
---

# OpenSearch/Elasticsearch domain has an encryption control disabled

_Author — Marconi, 2026-10-25. Revised 2026-10-27 (review H2/H6: fixed a wrong provider-default
claim on `enforce_https`; see "The threat")._

---

## The threat

A Terraform-managed OpenSearch/Elasticsearch domain has three independent encryption controls,
only two of which are off by default:

1. **`domain_endpoint_options.enforce_https`** — the provider default is actually `true`
   (safe). Only an explicit `enforce_https = false` accepts plain HTTP as well as HTTPS, so
   search queries and results can be sent in the clear. CWE-319 (Cleartext Transmission of
   Sensitive Information), OWASP:A02.
2. **`node_to_node_encryption.enabled`** — this one really does default OFF. Without it,
   traffic between the domain's own data nodes (shard replication, cluster coordination) is
   unencrypted on the wire. Same CWE-319 / OWASP:A02 class, one layer further in.
3. **`encrypt_at_rest.enabled`** — this one also defaults OFF. Without it, indexed documents
   sit unencrypted on the underlying EBS volumes. CWE-311 (Missing Encryption of Sensitive
   Data), OWASP:A02.

An earlier version of this guard, and of this doc, wrongly treated `enforce_https` as
off-by-default too and fired it on every unconfigured domain — fixed after an agentic
pre-review (H2) caught it against the actual `hashicorp/terraform-provider-aws` docs.

## Why this guard fits the stack

OpenSearch/Elasticsearch domains commonly back log aggregation or a RAG-adjacent search index
in the FastAPI + LLM/RAG shape this project targets:

```hcl
resource "aws_opensearch_domain" "logs" {
  domain_name    = "logs"
  engine_version = "OpenSearch_2.11"
  # no node_to_node_encryption or encrypt_at_rest block -> both default OFF, both fire.
  # (domain_endpoint_options / enforce_https defaults ON, so omitting it is safe.)
}
```

AWS renamed `aws_elasticsearch_domain` to `aws_opensearch_domain`, but both resource types
still appear in real configs — older code on the legacy name, newer code on the renamed one —
and both carry identical detection logic.

## Detection design

1. `applies()` gate — `"terraform" in profile.features`.
2. Scans every `.tf` file via `iter_files(root, (".tf",))`, skipping non-product paths.
3. Uses `iter_terraform_resources()` to isolate blocks whose resource type is EITHER
   `aws_opensearch_domain` OR `aws_elasticsearch_domain` — one detection path applied to both
   strings. Each block is matched in the resource's `terraform_code_view()` (`guards/base.py`):
   comments blanked and `${...}` interpolations neutralised, so an interpolation's own `}` (a
   `kms_key_id = "${aws_kms_key.k.arn}"`, a `custom_endpoint = "s.${var.d}.com"`) cannot cut a
   `[^{}]*` block regex short (PR #1162 round-2 M-2). It used to, which turned a compliant
   `encrypt_at_rest` into a HIGH false positive and hid an `enforce_https = false`. The suppress
   pragma is still read from the raw block.
4. Each of the three nested blocks — `domain_endpoint_options { enforce_https = ... }`,
   `node_to_node_encryption { enabled = ... }`, `encrypt_at_rest { enabled = ... }` — is
   extracted independently, then its one boolean attribute is read via the shared
   `literal_bool_state()` helper (`guards/base.py`), which distinguishes a literal `true`,
   literal `false`, non-literal expression (e.g. a variable), or absence.
5. **Rule A (`enforce-https-disabled`)**: fires only on a literal `enforce_https = false`
   (provider default `true` is safe; absence and non-literal values stay silent).
6. **Rule B (`node-to-node-disabled`)**: fires when the block/attribute is absent, or the
   attribute is a literal `false` (provider default is unsafe; a non-literal value stays
   silent — it cannot be proven either way).
7. **Rule C (`encrypt-at-rest-disabled`)**: same shape as Rule B.
8. The three rules are fully independent — a domain can fail 0, 1, 2, or all 3 at once. An
   unconfigured domain fires Rules B and C only (not A, per the corrected default above).
9. Inline opt-out, ONE pragma covers all three rules for the resource:
   `# security: allow-opensearch-unencrypted` anywhere in the resource block.
10. Severity: `high` for all three rules. Standards: `["OWASP:A02", "CWE-319"]` for the two
    transit rules (A, B), `["OWASP:A02", "CWE-311"]` for the at-rest rule (C).

## When NOT to flag

- `domain_endpoint_options` absent, or `enforce_https` absent/`true`/a variable.
- `node_to_node_encryption { enabled = true }` present, or `enabled` set to a variable.
- `encrypt_at_rest { enabled = true }` present, or `enabled` set to a variable.
- An audited case (e.g. a domain deliberately run inside an isolated, trusted network for
  throwaway dev data), suppressed with `# security: allow-opensearch-unencrypted`.

## Tests

| Test | What it checks |
|---|---|
| `test_opensearch_fully_unconfigured_fires_the_off_by_default_two` | Positive: no blocks at all fires Rules B and C only, at `high` (**verified_by**). |
| `test_opensearch_fully_hardened_silent` | FP-bait: all three blocks correctly configured → silent. |
| `test_opensearch_enforce_https_block_absent_stays_silent` / `test_opensearch_enforce_https_attribute_absent_stays_silent` / `test_opensearch_enforce_https_variable_stays_silent` | FP-bait: Rule A's three safe-by-default shapes. |
| `test_opensearch_enforce_https_false_fires` | Positive: Rule A fires on literal `false`. |
| `test_opensearch_enforce_https_true_silent` | FP-bait: Rule A silent when `enforce_https = true`. |
| `test_opensearch_node_to_node_block_absent_fires` / `test_opensearch_node_to_node_enabled_false_fires` | Positive: Rule B's absence/false shapes. |
| `test_opensearch_node_to_node_enabled_true_silent` / `test_opensearch_node_to_node_variable_stays_silent` | FP-bait: Rule B silent on `true` and on a variable. |
| `test_opensearch_encrypt_at_rest_block_absent_fires` / `test_opensearch_encrypt_at_rest_enabled_false_fires` | Positive: Rule C's absence/false shapes. |
| `test_opensearch_encrypt_at_rest_enabled_true_silent` / `test_opensearch_encrypt_at_rest_variable_stays_silent` | FP-bait: Rule C silent on `true` and on a variable. |
| `test_elasticsearch_domain_legacy_type_fires_the_off_by_default_two` / `test_elasticsearch_domain_legacy_type_hardened_silent` | The legacy `aws_elasticsearch_domain` type gets identical treatment. |
| `test_opensearch_pragma_silences` | Suppress pragma → all three rules silent. |
| `test_opensearch_interpolated_kms_key_does_not_hide_enabled_at_rest` | Round-2 M-2: an interpolated `kms_key_id` no longer turns a compliant `encrypt_at_rest` into a finding; `enabled = false` beside it still fires. |
| `test_opensearch_interpolated_custom_endpoint_does_not_hide_enforce_https_false` | Round-2 M-2: `enforce_https = false` after an interpolated `custom_endpoint` fires (was a false negative); `true` stays silent. |
| `test_opensearch_quoted_and_interpolated_booleans` | Quoted `"true"`/`"false"` read as the bool; a quoted `"${var.x}"` is non-literal and silent. |
| `test_opensearch_commented_out_block_is_not_set` | A block written only in a comment enables nothing. |
| `test_opensearch_unrelated_resource_silent` | A non-domain resource → silent. |
| `test_opensearch_applies_gate` / `test_opensearch_applies_with_terraform` | `applies()` gate. |

## Known bypasses

- **A resource nested inside a `module` block** — only the literal resource body is seen.
- **Any attribute set via a computed/interpolated expression** rather than a literal boolean —
  not resolved (deliberately silent; see Detection design above). A quoted `"true"`/`"false"`
  IS read as the bool (Terraform coerces it); a quoted `"${var.x}"` is non-literal.
- **Region/account default-encryption settings do not apply here** (unlike EBS) — these are
  per-domain attributes with no account-level override, so this guard carries no equivalent
  false-positive risk on that axis.

## What this guard does NOT prove

A silent guard does not confirm the applied infrastructure matches the source (drift), that an
attribute wasn't overridden via `-var`/`terraform.tfvars` at apply time, or that a domain
provisioned outside Terraform carries the same configuration. This is a presence-based,
source-only check across three independently-graded conditions.

# Citations

[1] agentsec checklist items `7-opensearch-domain-encryption-disabled` (§7)
[2] OWASP:A02
[3] CWE-311, CWE-319
