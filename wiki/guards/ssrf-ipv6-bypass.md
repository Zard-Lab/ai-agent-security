---
type: Guard
title: "ssrf-ipv6-bypass"
description: "SSRF IPv6-mapped bypass — ipv4_mapped not checked alongside is_private/is_loopback."
timestamp: "2026-06-28T11:57:06+08:00"
guard_id: "ssrf-ipv6-bypass"
checklist_section: ["3a"]
standards: ["OWASP-LLM:LLM02", "OWASP:A10"]
---

# SSRF IPv6-mapped bypass — ipv4_mapped not checked alongside is_private/is_loopback

## Threat

**CWE-918 / SSRF via IPv6-mapped bypass.**

An SSRF IP blocklist that checks `is_loopback` / `is_link_local` can be bypassed with an
IPv6-mapped IPv4 address: `::ffff:127.0.0.1`. The OS network layer resolves it to the loopback
interface, but Python's `ipaddress` module reports `is_loopback == False` and
`is_link_local == False` for the IPv6-mapped form — unless you first unwrap `.ipv4_mapped` and
re-apply the checks.

**Note on `is_private` (do NOT key on it):** since the CVE-2024-4032 fix (CPython 3.9.19 / 3.10.14 /
3.11.9 / 3.12.3+), `IPv6Address.is_private` *delegates* to `ipv4_mapped.is_private`, so
`ipaddress.ip_address("::ffff:127.0.0.1").is_private == True` — a blocklist using `is_private`
already catches the mapped form on its own. Firing on an `is_private` check would therefore be a
false positive on every supported runtime. The guard keys only on `is_loopback` / `is_link_local`,
which do NOT delegate. (`is_reserved` / `is_multicast` are not SSRF-blocklist properties and are
likewise excluded.) This was corrected in the PR #206 review.

**Attack scenario:** Developer adds an SSRF guard checking `ip.is_loopback or ip.is_link_local`.
Attacker supplies `::ffff:127.0.0.1` (loopback) or `::ffff:169.254.169.254` (AWS metadata / link
local). The check passes, the request goes through, and the attacker reaches the internal service.

## Detection design

**Two-stage file-level check:**

1. File must import `ipaddress` (import gate prevents FP on unrelated files).
2. File must use `is_loopback` or `is_link_local` — the two properties that do NOT delegate to the
   mapped address — indicating an SSRF host-validation blocklist is happening. (`is_private` is
   deliberately excluded: it already catches `::ffff:` forms on supported CPython, so keying on it
   would be a false positive. See the Threat note.)
3. File must NOT reference `ipv4_mapped` anywhere — the fix. The match is name-based (`\bipv4_mapped\b`),
   so it recognizes both the attribute form `ip.ipv4_mapped` and the IPv4-safe `getattr(ip,
   "ipv4_mapped", None)` form.

If conditions 1 and 2 are met but 3 is not: flag the first occurrence of the block check as the
finding location.

**Why file-level, not line-level:** The `.ipv4_mapped` check and the blocklist check don't have to
be on the same line — they'd typically appear in the same validation function but potentially
separated by several lines. A file-level gate with a single finding is more actionable than per-line
noise.

## Tests

| Test | Expected |
|---|---|
| `is_loopback` without `ipv4_mapped` | 1 finding, HIGH |
| `is_link_local` without `ipv4_mapped` | 1 finding, HIGH |
| `is_private` ALONE (no loopback/link-local) | silent — `is_private` already catches the mapped form |
| `getattr(ip, "ipv4_mapped", None)` unwrap present | silent — name-based match recognizes the IPv4-safe form |
| `ip.ipv4_mapped` present alongside block checks | silent |
| `ipaddress` import only (no block check) | silent |
| Block check without `ipaddress` import | silent |
| `# security: allow-ssrf-ipv6-bypass` pragma | silent |
| No `python` in profile features | `applies()` returns False |

## Known bypasses / limitations

- Validation code split across files (import in one, check in another): will not fire.
- Block check inside a nested helper function in a separate module: will not fire.
- **`ip_network` containment blocklists** (`if ip in ipaddress.ip_network("127.0.0.0/8")`) have the
  same IPv6-mapped bypass but use no `is_*` property, so the block-check gate never trips → false
  negative. Detecting membership-style blocklists is future work (would need a separate signal).
- Does not detect string-based IPv6-mapped checks (`if "::ffff:" in host`) — these are less
  common and harder to distinguish from legitimate logging.

## What this guard does NOT prove

- That the resolved IP (after DNS) is safe — DNS rebinding is a separate attack.
- That the IPv4 blocklist itself is correct (that's `ssrf-general` territory).
- That the SSRF check runs before the request is made (ordering must be verified manually).

# Citations

[1] agentsec checklist item `3a-ssrf-ipv6-mapped-bypass` (§3a)
[2] OWASP-LLM:LLM02
[3] OWASP:A10
