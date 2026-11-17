---
type: Guard
title: "forwarded-header-blind-trust"
description: "X-Forwarded-For / X-Real-IP trusted in a security decision without proxy validation."
timestamp: "2026-06-21T19:50:18+08:00"
guard_id: "forwarded-header-blind-trust"
checklist_section: ["2b"]
standards: ["ASVS:15.3.4", "ASVS:4.1.3", "OWASP:A04", "OWASP:A07"]
---

# X-Forwarded-For / X-Real-IP trusted in a security decision without proxy validation

_Author — 2026-06-21_

---

## The threat

**IP spoofing via `X-Forwarded-For` / `X-Real-IP` in security decisions.**  These headers are
set by reverse proxies to carry the original client IP.  When an application sits behind no proxy,
or behind a proxy that does not strip/validate the incoming header, the value is **fully
client-controlled**.  An attacker can set `X-Forwarded-For: 127.0.0.1` and bypass IP-based rate
limiting, IP allowlisting, ban enforcement, or geo-blocking trivially.

- **Who reaches it:** any HTTP client.
- **Privilege required:** none.
- **Effect:** IP-based security controls (rate limits, allowlists, bans) become ineffective.

Standards: **OWASP:A04** (Insecure Design).

---

## Detection design

1. **`applies()`** — `"python" in profile.features`.
2. **Files scanned** — all `.py` files in `python_scan_dirs`.
3. **Per-file logic:**
   - Skip if `# security: allow-forwarded-header-trust` in file.
   - Skip if `ProxyHeadersMiddleware`, `forwarded_allow_ips`, or `TrustedHostMiddleware` in file
     (proxy-aware signal).
   - Scan lines for `_XFF` (headers access for `X-Forwarded-For` or `X-Real-IP`).
   - For each XFF match, the search scope is the header access's **enclosing function**
     (`enclosing_function_span()`) — not a fixed line window. Module-level code with
     no enclosing `def` falls back to a ±5-line window (`_CTX_WINDOW`).
   - If the header value is assigned to a variable (`ip = headers.get(...)`), that SAME
     variable — or a **one-hop binding derived from it** — must be referenced on the line
     carrying an `_SEC_CTX` keyword, anywhere in the search scope. A keyword attached to an
     unrelated variable is proximity coincidence, not real flow, and stays silent. If the
     header value is used inline (no variable captured), the keyword must appear on the same
     line/statement.
   - **The one-hop alias set is resolved from the AST, not a line regex (#772).** A binding is
     a derivation when its value is a *receiver-rooted chain* on the header variable
     (`ip = raw.split(",")[0].strip()`, an annotated `ip: str = raw`, a parenthesised or
     multi-line RHS, a trailing `# comment`), so the rename's spelling is not a detection
     boundary; a kwarg on its own line, a `def` default, and text inside a triple-quoted prompt
     are not `ast.Assign` targets and cannot alias the header. The resolution is:
     - **scoped** — only assignments in the header read's OWN function scope alias it. A name
       local to a nested `def`/`lambda` (its parameter, or a name that scope assigns) is masked
       from the sink check on lines inside that scope, because Python makes it a local there, not
       the header value; a *closure* over the header name (bound by neither) still counts, which
       is why this is name-level masking, not whole-span exclusion. A comprehension
       (`denied = [ip for ip in ...]`) is not a receiver-rooted chain so it cannot alias the
       header var it shadows;
     - **ordered** — only aliases and sinks AFTER the header read count;
     - **liveness-aware** — reassigning a tracked name to a non-header value (a sanitizer such as
       `client = trusted_client_ip(request, client)`, including via a walrus `ip := sanitize(ip)`,
       or the safe branch of a hand-rolled proxy check) kills the taint: the guard must not fire
       on remediated code. Only the reassigned name is dropped from that line's sink check, so a
       real sink of a different still-live name on the same physical line is not masked.

     Membership is tested against the header's OWN binding, never against names already added, so
     a **second** rename (`ip2 = ip`) is a disclosed, accepted gap and the hop count cannot grow.
     A source-order sweep (not control-flow) is a disclosed limitation of the liveness pass. An
     unparseable module degrades to the bare one-hop-rename text scan.
   - Emit MEDIUM, rule `forwarded-header-blind-trust/xff-in-security-context`.
4. **Severity:** `medium`; **Standards:** `["OWASP:A04"]`.

---

## Tests

| Test | What it checks |
|---|---|
| `test_forwarded_header_blind_trust_fires` | XFF header in rate-limit context → MEDIUM finding. |
| `test_forwarded_header_blind_trust_proxy_aware_silent` | `ProxyHeadersMiddleware` present → silent. |
| `test_forwarded_header_blind_trust_get_with_default_no_sec_ctx_silent` | XFF read but no security keyword in scope → silent. |
| `test_forwarded_header_blind_trust_pragma_silences` | Pragma in file → silent. |
| `test_forwarded_header_blind_trust_fires_through_derived_split_idiom` | Canonical `raw.split(",")[0].strip()` → fires (AST derivation, #772). |
| `test_forwarded_header_blind_trust_fires_through_every_one_hop_spelling` | Annotated / parenthesised / commented / multi-line rename → fires. |
| `test_forwarded_header_blind_trust_assignment_sink_still_fires` | `blocked = is_rate_limited(ip)` still fires (liveness kill is surgical). |
| `test_forwarded_header_blind_trust_kwarg_in_multiline_call_is_not_an_alias` | Kwarg on its own line is not an assignment → silent. |
| `test_forwarded_header_blind_trust_assignment_inside_string_literal_is_not_an_alias` | Rename inside a triple-quoted prompt → silent. |
| `test_forwarded_header_blind_trust_nested_def_param_shadow_is_not_an_alias` | Nested-`def` parameter shadow → silent (scope, #772 High 1). |
| `test_forwarded_header_blind_trust_nested_def_sink_on_shadowed_param_is_silent` | Sink inside nested scope on the shadowed param → silent. |
| `test_forwarded_header_blind_trust_comprehension_shadow_is_not_an_alias` | `denied = [ip for ip in ...]` comprehension shadow → silent. |
| `test_forwarded_header_blind_trust_sanitized_reassignment_kills_the_taint` | Sanitizer reassignment → silent (liveness, #772 High 2). |
| `test_forwarded_header_blind_trust_hand_rolled_proxy_check_is_silent` | Hand-rolled trusted-proxy check → silent. |
| `test_forwarded_header_blind_trust_alias_and_sink_before_header_read_is_silent` | Alias + sink before the header read → silent (ordering, #772 Medium 1). |
| `test_forwarded_header_blind_trust_unparseable_module_degrades_to_bare_rename` | Unparseable module → bare-rename fallback, both directions (#772 Low). |
| `test_forwarded_header_blind_trust_lambda_param_shadow_is_not_a_sink` | Lambda parameter shadow → silent (review Issue 1). |
| `test_forwarded_header_blind_trust_closure_over_header_still_fires` | Lambda / nested-def closure over the header value → fires (both, name-level masking). |
| `test_forwarded_header_blind_trust_nested_def_local_rebind_is_silent` | Nested def reassigning the header name to a local → silent. |
| `test_forwarded_header_blind_trust_same_line_kill_does_not_mask_other_sink` | Semicolon line: unrelated kill does not mask a real same-line sink (review Issue 2). |
| `test_forwarded_header_blind_trust_walrus_sanitizer_kills_taint` | Walrus sanitizer `ip := sanitize(ip)` → silent (review Issue 3). |
| `test_forwarded_header_blind_trust_walrus_derivation_of_raw_header_fires` | Walrus capturing the raw header `x := ip` → fires. |

# Citations

[1] agentsec checklist item `2b-forwarded-header-trust` (§2b)
[2] ASVS:15.3.4
[3] ASVS:4.1.3
[4] OWASP:A04
[5] OWASP:A07
