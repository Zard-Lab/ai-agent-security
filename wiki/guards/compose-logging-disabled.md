---
type: Guard
title: "compose-logging-disabled"
description: "Docker-compose service with logging driver explicitly disabled."
timestamp: "2026-08-16T10:56:38+08:00"
guard_id: "compose-logging-disabled"
checklist_section: ["6c"]
standards: ["CWE-778", "OWASP:A09"]
---

# Docker-compose service with logging driver explicitly disabled

_Author — Marconi, 2026-08-16_

---

## The threat

Setting the logging driver to `none` disables all log collection for the service — no
stdout/stderr capture, nothing for `docker logs` or a log-shipping sidecar to read. An
incident on a service with logging disabled leaves no forensic trail: no request history,
no error output, no evidence of what an attacker did once inside. CWE-778 (Insufficient
Logging), OWASP:A09.

## Why this guard fits the stack

Complements this project's existing logging/monitoring section (§10) at the
container-runtime layer — a service can have every application-level log statement
correct and still produce nothing, if its compose-level logging driver is disabled:

```yaml
services:
  app:
    logging:
      driver: none
```

Sourced from compose-lint's `LoggingDisabledRule` (`CL-0014`).

## Detection design

1. `applies()` gate — `"docker" in profile.features`.
2. Scans every `docker-compose*.yml`/`.yaml` file via `iter_files_named`, skipping
   `is_dev_compose_file` files.
3. Uses `iter_compose_services()`, then a nested `logging:` block scan for
   `driver: none` (quoted or bare), indent-tracked the same way as the other block-keyed
   guards in this batch.
4. Inline opt-out: `# security: allow-compose-logging-disabled` anywhere in the file.
5. Severity: `low`. Rule id: `compose-logging-disabled/driver-none`.
   Standards: `["OWASP:A09", "CWE-778"]`.

## When NOT to flag

- Any other driver (`json-file`, `syslog`, `awslogs`, …), or no `logging:` block at all
  (the platform default driver, which is not `none`).
- An audited case (e.g. a genuinely log-free throwaway sidecar), suppressed with
  `# security: allow-compose-logging-disabled`.

## Tests

| Test | What it checks |
|---|---|
| `test_driver_none_fires` | Positive: `driver: none` fires (**verified_by**). |
| `test_quoted_driver_none_fires` | Positive: `driver: 'none'` (quoted) fires. |
| `test_json_file_driver_silent` | FP-bait: `driver: json-file` → silent. |
| `test_no_logging_block_silent` | FP-bait: no `logging:` block at all → silent. |
| `test_pragma_silences` | Suppress pragma → silent. |
| `test_applies_gate` / `test_applies_with_docker` | `applies()` gate. |

## Known bypasses

- **Variable indirection**: `driver: ${LOG_DRIVER}` where the variable resolves to `none`
  — only a literal value is matched.

## What this guard does NOT prove

A silent guard does not confirm logs are actually being collected and retained downstream
(a configured driver that fails silently at runtime is invisible to a static check), or
that the applied deployment matches the source. This is a presence-based, source-only
check.

# Citations

[1] agentsec checklist item `6c-compose-logging-disabled` (§6c)
[2] CWE-778
[3] OWASP:A09
