---
type: Guard
title: "compose-resource-limits-absent"
description: "Docker-compose service with no memory or CPU resource limit."
timestamp: "2026-08-16T10:56:38+08:00"
guard_id: "compose-resource-limits-absent"
checklist_section: ["6c"]
standards: ["CWE-770", "OWASP:A05"]
---

# Docker-compose service with no memory or CPU resource limit

_Author — Marconi, 2026-08-16_

---

## The threat

A service with no memory or CPU limit can exhaust the host's resources — Docker imposes
neither by default, so a single compromised or runaway service degrades every other
container on the same host. CWE-770 (Allocation of Resources Without Limits or
Throttling), OWASP:A05.

## Why this guard fits the stack

An LLM/RAG worker or a background job processor is exactly the kind of service that can
run away (an unbounded retry loop, a memory leak in a long-lived process, an adversarial
input driving unbounded work) — without a limit, one such service takes the whole host
down:

```yaml
services:
  app:
    image: myapp
    # no mem_limit, no deploy.resources.limits, no cpus -> unbounded
```

Sourced from compose-lint's `ResourceLimitsRule` (`CL-0026`), simplified to a flat
service-body text search rather than a structural walk of `deploy.resources.limits`
specifically — acceptable because `memory:`/`cpus:` under any other key in a service
block is not a real compose shape.

## Detection design

1. `applies()` gate — `"docker" in profile.features`.
2. Scans every `docker-compose*.yml`/`.yaml` file via `iter_files_named`, skipping
   `is_dev_compose_file` files.
3. Uses `iter_compose_services()` to get each service's full body text, comment-blanks it,
   and searches flatly (not indent/nesting-aware) for a memory bound
   (`mem_limit:`/`memory:`) and a CPU bound (`cpus:`/`cpu_quota:`) — covering both the
   compose-v2 top-level spellings and the Swarm-style `deploy.resources.limits.*` nesting
   in one pass, since both keyword sets only legitimately appear inside a service's own
   resource-limit configuration.
4. Fires if either bound is missing (message names which one).
5. Inline opt-out: `# security: allow-compose-resource-limits` anywhere in the file.
6. Severity: `low`. Rule id: `compose-resource-limits-absent/no-limits`.
   Standards: `["OWASP:A05", "CWE-770"]`.

## Severity note (2026-08-21, #663 review M2)

Shipped initially at `medium`. A code review measured 27 findings across 6 real repos with
no proven exploit path — an absent limit alone doesn't show a workload can be driven to
exhaust one. That places the guard squarely in the project's own auto-exclude noise
category: "DoS, rate-limiting, memory/CPU exhaustion" is named explicitly in
`wiki/methodology/fable-security-fundamentals.md` (F2), `security-audit-behaviors.md`
(B8), and `wiki/research/llm-audit-methodology.md`. Shipping at `medium` would have
implicitly decided an open doctrinal question — the sibling `redos` case (#91, the
maintainers' noise-category doctrine) covers the same DoS/exhaustion
category, is still open, and leans toward demote/remove rather than a carve-out.
Demoted to `low`: the coverage and remediation guidance stay (resource limits are real
hardening), but the finding no longer competes with proven-impact HIGH/MEDIUM findings
for "fix these first" attention, consistent with B8 (calibration over alarm).

## When NOT to flag

- Both a memory bound and a CPU bound are present (any recognized spelling of either).
- An audited case (e.g. a genuinely unbounded local-only sidecar), suppressed with
  `# security: allow-compose-resource-limits`.

## Tests

| Test | What it checks |
|---|---|
| `test_no_limits_at_all_fires` | Positive: neither bound present fires (**verified_by**). |
| `test_memory_only_fires` | Positive: memory bound present, CPU absent, still fires. |
| `test_deploy_resources_limits_both_set_silent` | FP-bait: `deploy.resources.limits.memory`/`.cpus` both set → silent. |
| `test_mem_limit_and_cpus_both_set_silent` | FP-bait: v2 top-level spelling, both set → silent. |
| `test_cpu_quota_counts_as_cpu_bound` | FP-bait: `cpu_quota` (the older spelling) counts as a CPU bound → silent. |
| `test_pragma_silences` | Suppress pragma → silent. |
| `test_applies_gate` / `test_applies_with_docker` | `applies()` gate. |

## Known bypasses

- **Does not reproduce the real source's `0`-means-unbounded nuance** — `mem_limit: 0` is
  read by this simplified guard as "a memory bound is present" even though Docker treats
  a non-positive limit as unlimited. A real gap versus upstream, documented rather than
  silently accepted.
- **Does not resolve defaulted interpolation** (`${MEM:-0}`) to its literal fallback.
- **A reservation, not a limit** (`mem_reservation`, `cpu_shares`) is not matched by this
  guard's keyword set, correctly, since those express priority under contention, not a
  hard ceiling — but a compose file relying only on reservations gets no signal either
  way from either keyword class.

## What this guard does NOT prove

A silent guard does not confirm the limit value is actually sane for the workload (a
1-byte memory limit satisfies this check), or that the applied deployment matches the
source. This is a presence-based, source-only check.

# Citations

[1] agentsec checklist item `6c-compose-resource-limits` (§6c)
[2] CWE-770
[3] OWASP:A05
