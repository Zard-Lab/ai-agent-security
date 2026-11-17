---
type: Guard
title: "arm-redis-ssl-disabled"
description: "ARM-templated Azure Cache for Redis allowing unencrypted (non-SSL) connections."
timestamp: "2026-09-12T00:00:00Z"
guard_id: "arm-redis-ssl-disabled"
checklist_section: ["7"]
standards: ["OWASP:A02"]
---

# ARM template Azure Cache for Redis allows unencrypted (non-SSL) connections

Flags `Microsoft.Cache/redis` resources whose `properties.enableNonSslPort` is `true`. Closes a
new checklist item — no existing agentsec item covers Azure Cache for Redis TLS enforcement for
any format. This is agentsec's first Azure Resource Manager (ARM)-format guard — ARM
template detection and the shared `agentsec.arm` resource parser landed in this same PR to
support it.

## The threat

A Redis cache accepts plaintext connections on its non-TLS port (6379, alongside the default TLS
port 6380) whenever `enableNonSslPort` is set. Redis routinely holds session tokens, rate-limit
counters, and cached application data — a plaintext connection means any network position between
the client and the cache (a shared subnet, a compromised peer VM, a misconfigured NSG) can read or
tamper with that traffic, including whatever credentials or tokens pass through it. CWE-319
(Cleartext Transmission of Sensitive Information).

## Exploitability rationale

MEDIUM. Requires a network position between the client and the cache — not itself remotely
exploitable, but the same severity class as the analogous Terraform Azure Storage
HTTPS-enforcement guard (`azure-storage-account-https-only`), which this guard mirrors for the
Redis case.

## What counts as a hit (and what doesn't)

- `Microsoft.Cache/redis` with `enableNonSslPort: true` → fires.
- `Microsoft.Cache/redis` with `enableNonSslPort: false` (explicit) → silent (the fix).
- `Microsoft.Cache/redis` with no `enableNonSslPort` property at all → silent (ARM's own default
  is `false` — the non-SSL port is disabled unless explicitly enabled).
- Any other resource type, including one that happens to carry a similarly-named property →
  silent (the guard only ever looks inside a `Microsoft.Cache/redis` resource's own `block`).

## When NOT to flag (and the pragma)

- `enableNonSslPort` absent or explicitly `false` → silent (the fix).
- **No suppression pragma exists for this guard.** ARM templates are pure JSON, which has no
  comment syntax — a known, documented limitation shared by every guard built on
  `agentsec.arm` (see that module's docstring). There is no equivalent to the CFN guards'
  YAML-only `# security: allow-...` pragma here.

## Tests

| Test | What it checks |
|---|---|
| `test_arm_redis_ssl_flags_enable_non_ssl_port_true` | `enableNonSslPort: true` fires. |
| `test_arm_redis_ssl_silent_when_explicitly_false` | `enableNonSslPort: false` stays silent. |
| `test_arm_redis_ssl_silent_when_property_absent` | Property absent stays silent (the secure Azure default). |
| `test_arm_redis_ssl_multiple_resources_only_redis_flagged` | Only the non-SSL cache is flagged among several resources. |
| `test_arm_redis_ssl_silent_on_non_redis_resource` | FP bait: unrelated resource type carrying the same property name. |
| `test_arm_redis_ssl_not_applicable_without_arm` | `applies()` is `False` without the `arm` feature. |

## Known bypasses (honest limits)

- **No dataflow, no cross-resource reasoning.** Fires on the property's value directly.
- **File-level location, not line-level** — like every guard built on `agentsec.arm`, the finding
  reports the template file, not a specific line (a `block` is a `json.dumps` reconstruction with
  no original line mapping to report).
- **Template expressions are not evaluated.** If a future variant of this pattern set
  `enableNonSslPort` via `"[parameters('allowNonSsl')]"` rather than a literal `true`/`false`,
  this guard would not recognize it either way (it looks for the literal JSON value) — see
  `agentsec.arm`'s module docstring for the same posture on resource `name`.
- **Nested/linked templates** (`Microsoft.Resources/deployments` referencing a separate template
  file or URI) are not followed — each template file is scanned independently.

## What this guard does NOT prove

A clean scan means no `Microsoft.Cache/redis` resource in the scanned templates has
`enableNonSslPort` set to `true` — it says nothing about a cache created outside this template
entirely (the Azure Portal, a different IaC tool, a linked template this scan didn't
independently discover), nor about the cache's actual runtime TLS configuration if it was changed
out-of-band after deployment.

## Canary plant

`arm_redis.json` — a `Microsoft.Cache/redis` resource with `enableNonSslPort: true`. Expected
rule: `arm-redis-ssl-disabled/non-ssl-port-enabled`.

# Citations

[1] OWASP:A02 (Cryptographic Failures)
[2] CWE-319 (Cleartext Transmission of Sensitive Information)
[3] Azure/template-analyzer — `Redis.EnableSSL` (`TA-000022`, provenance only; detection logic
    here is original)
