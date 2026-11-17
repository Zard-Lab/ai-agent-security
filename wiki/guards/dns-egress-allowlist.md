---
type: Guard
title: "dns-egress-allowlist"
description: "DNS resolver not configured as a default-deny egress allowlist."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "dns-egress-allowlist"
checklist_section: ["4", "6d"]
standards: ["OWASP-LLM:LLM02", "OWASP:A05", "OWASP:A10", "SOC2:CC6.6"]
---

# DNS resolver not configured as a default-deny egress allowlist

_Author — 2026-06-30_

---

## The threat

Exfiltration and command-and-control both need to reach an attacker-controlled host, and reaching a host
almost always starts with a DNS lookup. If app containers resolve through a local Unbound resolver that
forwards everything, a compromised dependency (supply-chain), a prompt-injected agent, or any RCE can
resolve `attacker.example.com` and stream stolen data out. A **default-deny** resolver (`local-zone: "."
refuse` plus an explicit allowlist of the few domains the app legitimately needs) refuses unknown lookups
before any TCP connection — turning DNS into an egress chokepoint (the HWH `ai-agent-mastery` model, with
a `dns-monitor` timer alerting on every refused query). Findings carry `OWASP:A05` and `OWASP-LLM:LLM02`
(sensitive information disclosure).

## Why it's often introduced  /  Why this guard fits the stack

Unbound is frequently deployed purely as a caching resolver, with the egress-allowlist step omitted (it
is extra config that requires enumerating every domain the app talks to). In the 9_Agent_SaaS shape, the
LLM/RAG agent reaches many external APIs, which makes a deny-by-default DNS allowlist one of the few
practical anti-exfiltration controls — and the committed `unbound.conf` is where it lives.

## Detection design

1. **applies() gate** — `"host-config" in profile.features` (`unbound.conf` sets it).
2. **Files scanned** — a single `walk_files(root)`; Unbound configs are `unbound.conf` or a `*.conf`
   under an `unbound/` / `unbound.conf.d/` dir (`_is_unbound`). No Unbound config -> no finding.
3. **Logic** — if Unbound config exists and **no** *live* `_DEFAULT_DENY` (a `local-zone: "." <refuse|deny|
   static|always_nxdomain|always_nodata|...>`) is present in **any** of the Unbound files, emit **one** MEDIUM
   finding anchored at the first config. The check is **line-by-line and skips comment lines**, so a
   commented-out `# local-zone: "." refuse` does not read as present (review #250). The default-deny may live
   in a split config file (collective check).
4. **Pragma opt-out** — `# security: allow-open-dns-egress` (a caching-only resolver not meant as an
   egress filter), counted only as a real `#` comment (the `hash` comment view, so the phrase inside a quoted string does not count, #1040).
5. **Severity / rule / standards** — `medium`, rule `dns-egress-allowlist/no-default-deny`,
   standards `["OWASP:A05", "OWASP-LLM:LLM02"]`. Matches the §6d `6d-egress-allowlist` checklist item
   (also `medium`) and the sibling absence-guards (`fail2ban-absent` / `auto-updates-absent`); the pragma is
   the escape hatch for a legitimately caching-only resolver.

## When NOT to flag

- The root zone is already refused/denied (`local-zone: "." refuse` etc.) — it IS an allowlist — silent.
- No Unbound config committed — silent; the guard makes no claim about egress restriction done by a
  firewall / cloud egress policy / a different resolver.
- A deliberate caching-only Unbound — suppress with the pragma (the legitimate-exception escape hatch, same
  as the sibling absence-guards).

## Tests

| Test | What it checks |
|---|---|
| `test_dns_egress_open_unbound_fires` | open forward-all Unbound -> MEDIUM finding; standards correct |
| `test_dns_egress_under_unbound_dir_fires` | a `unbound/*.conf` is scanned |
| `test_dns_egress_default_deny_silent` | `local-zone: "." refuse` (HWH shape) stays silent |
| `test_dns_egress_always_nxdomain_silent` | `always_nxdomain` deny action stays silent |
| `test_dns_egress_deny_in_split_file_silent` | default-deny in a sibling file still counts |
| `test_dns_egress_no_unbound_silent` | host-config but no Unbound -> silent |
| `test_dns_egress_pragma_silences` | the pragma suppresses it |
| `test_dns_egress_applies_gate` | gated on the `host-config` feature |

## Known bypasses

- **Non-Unbound resolver:** an egress allowlist enforced by dnsmasq, a firewall, or a cloud DNS policy is
  invisible to this guard (it only understands Unbound's `local-zone` syntax).
- **Allowlist too broad:** a config that refuses `"."` but then `transparent`-allows an over-broad set
  (or a wildcard) reads as default-deny and stays silent — the guard checks for the deny, not the
  tightness of the allowlist.
- **Variable/templated config** assembled at deploy time is not resolved.

## What this guard does NOT prove

This is a **partial** check on `6d-egress-allowlist`: it verifies the DNS-allowlist mechanism only, and
only when Unbound config is committed. Silence does NOT prove outbound is restricted (a firewall/cloud
policy may or may not exist), that the allowlist is tight, or that the resolver is actually the one the
containers use. Whether egress is truly restricted on the running host is a Phase B (`agentsec
harden-host`) concern.

# Citations

[1] agentsec checklist item `4-egress-allowlisting` (§4)
[2] agentsec checklist item `6d-egress-allowlist` (§6d)
[3] OWASP-LLM:LLM02
[4] OWASP:A05
[5] OWASP:A10
[6] SOC2:CC6.6
