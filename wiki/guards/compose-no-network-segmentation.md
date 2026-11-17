---
type: Guard
title: "compose-no-network-segmentation"
description: "All compose services share the implicit default network with no explicit segmentation."
timestamp: "2026-09-05T00:00:00Z"
guard_id: "compose-no-network-segmentation"
checklist_section: ["6c"]
standards: ["OWASP:A05", "CIS:Docker"]
---

# All compose services share the implicit default network with no explicit segmentation

_Author — 2026-09-05_

---

## The threat

When a docker-compose file declares no `networks:` anywhere, every service is attached to one
implicit default bridge network and can reach every other service on any port — the public web
frontend, an internal admin API, the database, a message broker, all flat. A compromised low-value
service (the public-facing app, reachable from the internet) then has an unobstructed lateral path
straight to the database or an internal-only service, with no network boundary to cross. Findings
carry `OWASP:A05` (security misconfiguration) and `CIS:Docker`.

## Why it's often introduced / Why this guard fits the stack

Compose's implicit default network is convenient — every service can reach every other one by
service name with zero configuration — so most tutorials and starter templates never introduce
`networks:` at all. In the 9_Agent_SaaS shape this is especially relevant: an LLM/agent app
typically has a public-facing API service, an internal worker/agent process, and a database, where
only the worker genuinely needs to reach the database directly.

```yaml
services:
  web:
    image: myapp:1.0
  worker:
    image: myapp-worker:1.0
  db:
    image: postgres:16
# no `networks:` anywhere -> all three share one flat default bridge network
```

## Detection design

This is the one **cross-service, whole-file** guard in the batch — the others in this set are all
per-service. A single service block can never answer "is this file segmented"; segmentation is a
property of the file's service topology as a whole. `run()` therefore collects every service in
one pass (via `iter_compose_services()`) before deciding on a single finding for the file, rather
than emitting per-service.

1. **applies() gate** — `"docker" in profile.features`.
2. **Files scanned** — `iter_files_named(root, "docker-compose*.yml", "docker-compose*.yaml")`,
   skipping `is_dev_compose_file()` names.
3. **Parse** — `iter_compose_services()` collects every service in the file. If there are fewer
   than 2 services, the file is skipped (no peer to laterally move to). Each service's OWN block
   is checked for a `networks:` key (block-list or inline `[...]`/`{...}` form) — a TOP-LEVEL
   `networks:` block (declaring custom networks nobody actually joins) does not count, since
   nothing changes about the default-bridge blast radius until a service attaches to one via its
   own `networks:` key. If ANY service declares its own `networks:`, the file is treated as
   segmented and stays silent.
4. **Pragma opt-out** — `# security: allow-no-network-segmentation` anywhere in the file.
5. **Severity / rule / standards** — `medium`, rule
   `compose-no-network-segmentation/default-network-only`, standards
   `["OWASP:A05", "CIS:Docker"]`. Declared `surfacing_rule_prefixes = ("compose-no-network-segmentation/default-network-only",)`
   (the guard's one and only rule, so every real finding it emits is classified as a review
   signal): an unsegmented compose file is an architecture worth confirming by hand (is this
   genuinely a single-trust-boundary app, or does it need segmentation?), not a proven exploit by
   itself. Per-rule rather than a flat `surfacing = True`, matching `actions_script_injection.py`'s
   established pattern for a guard added after the BB4 migration — a flat `surfacing = True` on a
   brand-new check id collides with `tests/test_checkmeta.py`'s frozen pre-migration equivalence
   snapshot, which only knows the 5 guards that existed when it was written.

## When NOT to flag

- A single-service compose file — no lateral-movement peer exists.
- At least one service declaring its own `networks:` — the file is treated as segmented, even if
  other services in the same file declare none (the given candidate's own FP-bait case).
- An audited exception (a genuinely single-trust-boundary app where every service is meant to
  reach every other one) — suppress with the pragma.

No existing compose guard operates at this whole-file/cross-service level; every other guard in
the `compose-*` family (including the other three built in this batch) evaluates one service block
at a time.

## Tests

| Test | What it checks |
|---|---|
| `test_no_service_declares_networks_fires_once` | 3 unsegmented services fire exactly ONE finding for the whole file |
| `test_top_level_networks_block_unattached_still_fires` | a top-level `networks:` block nobody joins still fires |
| `test_two_services_minimum_fires` | the 2-service floor for firing |
| `test_one_service_with_explicit_networks_silences_whole_file` | one segmented service silences the whole file (FP-bait) |
| `test_single_service_file_silent` | a single-service file has no peer, stays silent |
| `test_inline_networks_list_counts_as_segmented` | inline `networks: [internal]` counts as segmentation |
| `test_pragma_silences` | the pragma suppresses the finding |
| `test_dev_compose_out_of_scope` | a `*.dev.yml` compose file is skipped |
| `test_applies_gate` / `test_applies_with_docker` | gated on the `docker` feature |
| `test_no_compose_silent` | no compose file -> no findings |

## Known bypasses

- **`network_mode: host`/`network_mode: "service:other"`** on a service is not specifically
  recognized as an alternative segmentation signal — a service using it alongside no `networks:`
  key is still counted as unsegmented (a documented false-positive-leaning gap, not a miss).
- Multiple compose files combined via `docker compose -f a.yml -f b.yml` (an override file adding
  `networks:` to a service defined in the base file) are evaluated independently — a network
  attached only in the override file would not be seen when scanning the base file alone.

## What this guard does NOT prove

Silence means at least one service in the committed compose file declares its own `networks:` key.
It does NOT prove the network topology is actually well-segmented (a single shared network with
every service still attached counts as "segmented" here, even if it provides no real boundary), or
that any named network's own configuration (`internal: true`, driver options) is itself secure.
This is a `surfacing` check by design — a signal to review the architecture by hand, not a proof of
either a bug or its absence.

# Citations

[1] OWASP DockSec `compose_scanner.py`, top-level check id `compose-no-network-segmentation`
    (source-verified, id reused verbatim; see the project's private `docksec.md` research digest,
    candidate #5).
[2] OWASP:A05
[3] CIS:Docker
