---
type: Guard
title: "compose-dns-bypass"
description: "docker-compose service bypasses the DNS-egress-allowlist resolver."
timestamp: "2026-07-12T15:57:43+02:00"
guard_id: "compose-dns-bypass"
checklist_section: ["6d"]
standards: ["OWASP-LLM:LLM02", "OWASP:A05"]
---

# docker-compose service bypasses the DNS-egress-allowlist resolver

_Author — 2026-07-11_

---

## The threat

A default-deny DNS resolver (the HWH `ai-agent-mastery` Unbound allowlist) is an anti-exfiltration
chokepoint: it refuses any lookup not on the allowlist, so a compromised dependency or a
prompt-injected agent cannot resolve `attacker.example.com` to phone home. But that control only
binds the containers that actually resolve THROUGH the resolver. Docker gives every container an
embedded resolver by default; a service that does not set `dns: [<resolver-ip>]` in
`docker-compose.yml` uses that default instead and can resolve any domain — the egress allowlist is
silently bypassed for it. One app container missing its `dns:` line re-opens the exfiltration path
the resolver was deployed to close. Findings carry `OWASP:A05` (security misconfiguration) and
`OWASP-LLM:LLM02` (sensitive information disclosure).

## Why it's often introduced  /  Why this guard fits the stack

Routing DNS through an internal resolver is per-service opt-in: each container must repeat the
`dns:` block. In a multi-service compose (the 9_Agent_SaaS shape — agent-api, rag-pipeline, caddy,
workers, …) it is easy to add a new service and forget the `dns:` line, or to assume the resolver
covers everything on the network. The correct pattern is what the flagship does — every app
container pins `dns: [172.20.0.53]` to the fixed resolver IP:

```yaml
services:
  unbound:                       # the allowlist resolver, pinned to a fixed compose-network IP
    networks: { appnet: { ipv4_address: 172.20.0.53 } }
  agent-api:
    dns: ["172.20.0.53"]         # routed through the resolver — correct
  worker:                        # <-- no dns: → uses Docker's embedded resolver → BYPASSES the allowlist
    networks: { appnet: { ipv4_address: 172.20.0.12 } }
```

## Detection design

1. **applies() gate** — `"docker" in profile.features` (set by `detect.py` for any Dockerfile /
   `docker-compose*` file), like the sibling `compose-db-port-exposed`.
2. **Files scanned** — `iter_files_named(root, "docker-compose*.yml", "docker-compose*.yaml")`.
3. **Parse** — `_parse_services()`, an indentation-aware scan of the `services:` map (no PyYAML —
   the house pattern, mirrors `compose_db_port_exposed._scan`). Inline `#` comments are stripped
   first (`strip_hash_comments`). Per service it records: `dns:` presence + the IPv4s it lists
   (block list, `dns: [..]` flow, or scalar), the service's `ipv4_address` pins, the image, and the
   name/line for the finding.
4. **Resolver identification (the shared-routing pattern)** — a candidate resolver is a **private**
   `ipv4_address` pinned by some service; `resolver_ips` = the candidates that **two or more distinct
   services** route `dns:` through. A service's OWN pinned IP is excluded from its vote
   (`(dns_ips & candidates) - ipv4`), so a resolver that self-lists its `dns:` (common when a shared
   `dns:` fragment is applied to every service) cannot supply one of its own quorum votes — otherwise
   a single genuine router would re-establish the "resolver" (review #378 second pass). The ≥2-router
   floor is the precision guard: a single incidental `dns:` pointer (one service using an internal
   service-discovery sidecar) must not designate a "resolver" and flood the file with false positives
   (review #378 High). If `resolver_ips` is empty → **silent** (no shared-resolver pattern).
5. **Fire** — MEDIUM, once per service that is **not** the resolver (`ipv4 ∩ resolver_ips` empty)
   AND does not route through it (`dns_ips ∩ resolver_ips` empty). Rule
   `compose-dns-bypass/service-skips-resolver`, standards `["OWASP:A05", "OWASP-LLM:LLM02"]`.
6. **Pragma opt-out** — `# security: allow-dns-bypass` anywhere in the file suppresses it.

This checks compose DNS **wiring** only. Whether the resolver is genuinely default-deny is the
sibling `dns-egress-allowlist`'s job (it reads `unbound.conf`); the two are complementary.

## When NOT to flag

- **Every service routes through the resolver** (the correct HWH shape) — silent.
- **The resolver service itself** — it holds the resolver IP (`ipv4 ∩ resolver_ips`), so it is
  excluded and never flagged for lacking its own `dns:`.
- **No shared-resolver pattern** — fewer than two services route `dns:` at a private in-compose
  `ipv4_address` (e.g. all services use a public DNS, none set `dns:`, or only *one* service points
  at an internal sidecar). Silent — the guard makes no claim without ≥2 services sharing a resolver.
- **A service that legitimately needs no egress, or uses a different resolver by design** — suppress
  with the pragma.

## Tests

| Test | What it checks |
|---|---|
| `test_compose_dns_bypass_missing_dns_fires` | a `dns:`-less service among routed peers → one MEDIUM finding; severity/check_id/standards |
| `test_compose_dns_bypass_dns_elsewhere_fires` | a service pointing `dns:` at a public IP still bypasses → fires |
| `test_compose_dns_bypass_dns_elsewhere_message_says_change` | the points-elsewhere finding says CHANGE (not add) `dns:` and omits the embedded-resolver claim (#378 Medium) |
| `test_compose_dns_bypass_single_incidental_pointer_silent` | one service routing at an in-compose sidecar (1 router) does not flood siblings (#378 High) |
| `test_compose_dns_bypass_resolver_self_vote_silent` | a resolver self-listing its `dns:` doesn't supply its own quorum vote (#378 2nd-pass Medium) |
| `test_compose_dns_bypass_self_listing_resolver_still_fires_with_two_routers` | FN-guard: self-vote exclusion doesn't over-suppress when two genuine routers exist |
| `test_compose_dns_bypass_flow_list_routed_silent_but_bypass_fires` | `dns: [ip]` flow syntax counts as routed; the bare service still fires |
| `test_compose_dns_bypass_all_routed_silent` | every service routed (HWH shape) → silent |
| `test_compose_dns_bypass_resolver_service_not_flagged` | the resolver service is not flagged for lacking `dns:` |
| `test_compose_dns_bypass_no_routing_pattern_silent` | no in-compose resolver-routing pattern → silent |
| `test_compose_dns_bypass_public_shared_dns_silent` | a shared PUBLIC DNS (8.8.8.8) is not an allowlist → silent |
| `test_compose_dns_bypass_pragma_silences` | the pragma suppresses all findings |
| `test_compose_dns_bypass_no_compose_silent` | no compose file → silent |
| `test_compose_dns_bypass_inline_comment_ip_not_absorbed` | an IP in a comment does not conjure a resolver pattern |
| `test_compose_dns_bypass_applies_gate` | gated on the `docker` feature |

## Known bypasses

- **Templated / env-interpolated addresses** (`ipv4_address: ${DNS_IP}`, `dns: [${RESOLVER}]`) are
  opaque — the ipv4↔dns cross-reference can't match, so the guard stays silent (conservative, not a
  false positive).
- **Split compose** — a resolver defined in one file and an app service in a `-f` override / a
  separate `docker-compose.*.yml` are analyzed independently, so a cross-file bypass is missed.
- **Anchors / aliases / merge keys** (`&x`, `*x`, `<<:`) are not resolved by the line scanner.
- **Out-of-compose routing** — DNS forced via the Docker daemon config, `network_mode: host`, or an
  entrypoint that rewrites `/etc/resolv.conf` is invisible here.
- **Single-router allowlist (residual FN)** — the ≥2-router precision floor means a legitimate but
  tiny allowlist where only *one* service routes through the resolver (a resolver + a single client)
  does not reach the threshold, so a sibling bypass there is missed. Deliberate: a one-service
  pattern is indistinguishable from an incidental sidecar pointer, and false positives are the worse
  failure for a guard.

## What this guard does NOT prove

Silence does not prove egress is restricted. It does not verify the resolver is default-deny (that is
`dns-egress-allowlist`), that the allowlist is tight, that L3/L4 egress is filtered, or that a
container can't bypass DNS entirely by holding a raw IP. It proves only that, within a single
committed compose file, every non-resolver service is wired to an in-compose resolver that its peers
also use. Whether egress is truly constrained on the running host is a Phase B (`agentsec
harden-host`) concern.

# Citations

[1] agentsec checklist item `6d-egress-dns-wiring` (§6d)
[2] OWASP-LLM:LLM02
[3] OWASP:A05
