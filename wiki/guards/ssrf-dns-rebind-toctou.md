---
type: Guard
title: "ssrf-dns-rebind-toctou"
description: "An SSRF allow-list resolves a hostname once to validate it, then a separate fetch call re-resolves the same hostname."
timestamp: "2026-10-06T00:00:00Z"
guard_id: "ssrf-dns-rebind-toctou"
checklist_section: ["3a"]
standards: ["OWASP-ASI:ASI06", "CWE-918", "CWE-367"]
---

# SSRF allow-list is defeated by a DNS-rebind between validation and fetch

_Author — 2026-09-26_

---

## The threat

CVE-2026-41488 (`langchain-openai`'s `_url_to_size`): an SSRF guard resolves a hostname
and range-checks the IP (rejecting private/loopback/reserved ranges), then a SEPARATE
fetch call resolves the SAME hostname again. Between the two resolutions, a malicious
DNS record can rotate from a public IP (which passes the guard) to a private one (which
the actual request then connects to) — CWE-367 (Time-of-Check Time-of-Use), CWE-918
(SSRF). CVE-2026-53708 (`mcp-contextforge-gateway` < 1.0.3) shipped the identical bug
under a differently-named guard (`validate_gateway_test_url`), which is why this guard
recognizes a callee as a guard by either its name OR its body. Sourced from
`agent-audit-kit`'s `ssrf_toctou.py` (AAK-SSRF-TOCTOU-001), verified against the real repo
source.

## Why it's often introduced

An SSRF guard that resolves and checks the hostname LOOKS complete — it correctly rejects
`http://169.254.169.254/`. The bug is invisible from reading the guard function alone: it
only exists in the gap between the guard's own resolution and the separate HTTP client's
independent resolution, which is a property of the CALLER's control flow, not the guard's
logic.

## Detection design

1. `applies()` gates on `"python" in profile.features` — this guard is AST-based, Python
   source only (no JS/TS variant, unlike its sibling `ssrf-redirect-bypass`).
2. Scans every `.py` file under `python_scan_dirs`, through the shared walker (`iter_files`):
   vendored dirs (`.venv`, `site-packages`, `node_modules`), nested worktrees and `.gitignore`d
   files are skipped, like every sibling Python guard. A bare `rglob` here once parsed a whole
   site-packages tree and was killed over its time budget (#1042).
3. Within each function, via `ast`, walks `Call` nodes in source order. A callee counts as
   a guard if either: (a) its name matches a closed vocabulary (`validate_safe_url`,
   `is_safe_url`, ...) or a name-shape pattern (`*_url_valid`, `*ssrf*`, `validate_*host*`,
   ...); or (b) it is a function DEFINED IN THE SAME FILE whose body both resolves a
   hostname (`socket.gethostbyname`, `socket.getaddrinfo`, `dns.resolver`, ...) and
   range-checks the result (`is_private`, `is_loopback`, `ip_address(`, `BLOCKED_*`, ...) —
   this second track is what catches `validate_gateway_test_url`'s real, unusually-named
   shape.
4. Once a guard call is seen, the next HTTP fetch fires (fetch-shaped method on a
   client-shaped receiver, or a name bound to a client constructor, with a non-literal
   target: the shared classifier `agentsec/ssrf_fetch.py`, so a `config.get("key")` or
   `response.headers.get(...)` dict read is not one) UNLESS the function's own
   source contains an IP-pinning marker (`socket.getaddrinfo`, `HTTPAdapter`,
   `session.mount`, `resolved_ip`, `pinned_ip`, `dns_pin`, ...).
5. Inline opt-out: a `# security: allow-ssrf-dns-rebind-toctou` comment anywhere in the file
   silences the file (a string literal or docstring quoting the phrase does not count, #424).
6. Severity HIGH, rule `ssrf-dns-rebind-toctou/no-ip-pinning`, standards
   `["OWASP-ASI:ASI06", "CWE-918", "CWE-367"]`.
7. Two version-floor entries cover repos that depend on the vulnerable libraries directly:
   `langchain-openai` >= 1.1.14 (CVE-2026-41488) and `mcp-contextforge-gateway` >= 1.0.3
   (CVE-2026-53708).

## When NOT to flag

- The resolved IP is pinned (an `HTTPAdapter`/`session.mount`/equivalent marker present)
  and reused for the actual request.
- No guard call precedes the fetch in the same function at all — that is `ssrf-general`'s
  scope, not this guard's.
- A function whose name doesn't match the guard vocabulary AND whose body neither resolves
  nor range-checks anything is never mistaken for a guard.

## Tests

| Test | What it checks |
|---|---|
| `test_validate_then_fetch_no_ip_pin_fires` | The CVE-2026-41488 shape — fires |
| `test_body_recognized_guard_with_unusual_name_fires` | CVE-2026-53708's unusually-named guard — fires via body recognition |
| `test_ip_pinned_via_http_adapter_is_safe` | `HTTPAdapter` pin — silent |
| `test_no_validator_call_is_safe` | No preceding guard at all — out of scope, silent |
| `test_unrelated_function_name_with_no_resolve_body_is_safe` | Neither name nor body matches — silent |
| `test_dict_get_after_validator_is_not_a_fetch`, `test_response_header_and_metadata_reads_are_not_fetches` | Dict reads after a validator — silent |
| `test_requests_get_variable_still_fires`, `test_client_shaped_and_bound_receivers_still_fire` | Real fetches — fire |
| `test_body_scan_stays_linear_in_function_count` | Growth-ratio pin: the per-function source re-split (11.6 s on a 6.8k-line file) stays fixed |
| `test_pragma_suppresses_finding` | Inline pragma silences it |
| `test_ssrf_dns_rebind_toctou_pragma_quoted_in_a_string_does_not_suppress` | A pragma quoted in a string literal or quoted scalar does not suppress; a real comment still opts the file out (#424 E6) |
| `test_guard_not_applicable_without_python_feature` | `applies()` gates correctly |

## Known bypasses

- Single-function scope: a guard call and its fetch split across a helper-function
  boundary are not correlated. The validator scan is not branch-aware either: a validator call
  in an `if` arm sets `validator_seen` for the REST of the function, including a
  mutually-exclusive `else` arm's own, unrelated, unvalidated fetch (confirmed on fastmcp's
  `jwt.py::_fetch_jwks`, whose `if self.ssrf_safe: ssrf_safe_fetch(...) else: client.get(...)`
  reads the `if` arm's safe fetch as covering the `else` arm's plain one). Tracking validator
  calls per-`ast.If`-body rather than as one flat, ordered list would close this; not attempted.
- The pin-marker vocabulary is a fixed list; a bespoke pinning mechanism this guard
  doesn't recognize would cause a false positive on an already-fixed function.
- JS/TS is out of scope for this guard (see `ssrf-redirect-bypass` for the analogous
  TS/JS-side check on a different SSRF-bypass mechanism).

## What this guard does NOT prove

Silence does not prove the guard's own range-check is complete (e.g. covers IPv6
link-local, or every RFC 1918 range) — only that no re-resolution TOCTOU window exists
between it and the fetch that follows it.

# Citations

[1] agentsec checklist item `3a-ssrf-dns-rebind-toctou` (§3a)
[2] CVE-2026-41488 (langchain-openai < 1.1.14), GHSA-r7w7-9xr2-qq2r
[3] CVE-2026-53708 (mcp-contextforge-gateway < 1.0.3), GHSA-9hgc-g3w5-67cm
[4] CWE-918, CWE-367, OWASP-ASI:ASI06
[5] agent-audit-kit `ssrf_toctou.py`, rule AAK-SSRF-TOCTOU-001
