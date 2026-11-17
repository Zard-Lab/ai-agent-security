---
type: Guard
title: "ssrf-bracketed-ipv6-bypass"
description: "A JS/TS SSRF guard classifies a hostname without normalizing the brackets WHATWG keeps on an IPv6 literal."
timestamp: "2026-10-06T00:00:00Z"
guard_id: "ssrf-bracketed-ipv6-bypass"
checklist_section: ["3a"]
standards: ["OWASP-ASI:ASI06", "CWE-918"]
---

# SSRF guard classifies a bracketed IPv6 hostname and never normalizes it

_Author — 2026-09-26_

---

## The threat

CVE-2026-80347 (mcp-fetch): a real SSRF guard is present and is the whole problem.
`URL.hostname` in WHATWG (Node, browsers) keeps the brackets on an IPv6 literal
(`"[::1]"`), but `net.isIP()` does not accept bracketed input — it returns `0`, so the
entire private-address branch never runs, and the guard's own default-allow tail lets the
request through. `http://[::1]/` reaches loopback through a check written specifically to
stop it. CWE-918 (SSRF), OWASP-ASI:ASI06 (agentic outbound-request risk). Sourced from
`agent-audit-kit`'s `ssrf_bracketed_host.py` (AAK-SSRF-BRACKETED-HOST-001), verified
against the real repo source.

## Why it's often introduced

A developer writes and tests an SSRF guard against the common cases (`127.0.0.1`,
`10.0.0.1`, `169.254.169.254`) — plain dotted-quad literals `net.isIP` handles correctly.
IPv6 loopback is a less-obvious test case, and WHATWG's bracket-retention behavior on
`.hostname` (as opposed to stripping it, which `urlsplit` does in Python) is a
platform-specific quirk few reviewers think to check for.

## Detection design

1. `applies()` gates on the `javascript` or `typescript` feature (matching the checklist
   item's `applies_when`): the guard only scans JS/TS, so on a Python- or Go-only repo it
   is N/A rather than "ran clean". It is independent of the detected backend stack.
2. Scans `.ts`/`.tsx`/`.js`/`.mjs`/`.cjs` files (`iter_files`), with TS/JS comments
   stripped before matching. **JS/TS only, deliberately** — Python's `urlsplit().hostname`
   strips the brackets before the caller ever sees them, so the same code shape in Python
   is not vulnerable.
3. Fires when, in one file, ALL of: a hostname is read off a parsed URL
   (`new URL(...).hostname`, or `.hostname` on a `parsed`/`url`/`u`/`target`/`dest`-named
   variable); an IP-classification call is applied (`net.isIP(`, `isIPv6(`,
   `ipaddress.ip_address(`); an outbound fetch exists in the same file (`fetch(`,
   `axios.`, `got(`, `request(`, `https?.get(`); and the surrounding code reads like an
   SSRF/allow-list guard (`isSafe`, `isAllowed`, `validateUrl`, `ssrf`,
   `block(ed|list)`/`allow(ed)?list`, `guard`, `private-address`) — this last condition is
   what keeps the FP rate low: incidental URL parsing with no guard context does not fire.
4. Suppressed when any bracket-stripping normalization appears anywhere in the file
   (`.replace(/^\[|\]$/g, "")`, `.replaceAll('[', ...)`, `.slice(1, -1)`,
   `.startsWith('[')`, `stripBrackets`, ...).
4a. Not reported when the function around the classification call ends default-DENY: its last
   `return` is a lookup or a comparison (`return isAllowedDomain(host);`, `return false;`), so
   `[::1]` reaches that check and is refused and nothing "falls through to allow". A literal
   `true` tail, `false` from an `isBlocked`/`isPrivate`-style predicate, and a tail the scan
   cannot locate (an arrow expression body, top-level code) are still reported. The finding
   is located at the classification call's line (`file.ts:<line>`).
5. Inline opt-out: a `// security: allow-ssrf-bracketed-ipv6-bypass` comment anywhere in the file
   silences the file (a string literal quoting the phrase does not count, #424).
6. Severity HIGH, rule `ssrf-bracketed-ipv6-bypass/no-bracket-normalization`, standards
   `["OWASP-ASI:ASI06", "CWE-918"]`.

## When NOT to flag

- The same code shape in Python — `urlsplit().hostname` already strips brackets, so
  flagging it there would be a fabricated finding, not a real gap.
- Any file with the classification shape but no outbound fetch in the same file — that is
  incidental URL parsing, not an SSRF guard.
- A file with the full shape but no recognizable guard-context vocabulary — favors
  precision over recall for code that merely happens to parse and classify a URL for an
  unrelated reason.

## Tests

| Test | What it checks |
|---|---|
| `test_bracketed_ipv6_bypass_fires` | The full CVE-2026-80347 shape — fires |
| `test_bracket_stripped_before_classification_is_safe` | A real strip before `isIP()` — silent |
| `test_no_fetch_call_is_safe` | No outbound fetch in the file — silent |
| `test_no_guard_context_is_safe` | No SSRF-guard vocabulary present — silent |
| `test_python_equivalent_shape_is_not_flagged` | Python's `urlsplit` shape — out of scope, silent |
| `test_default_deny_tail_is_not_reported` (and the literal-`false` sibling) | Default-deny tail — silent |
| `test_literal_true_tail_still_fires_and_carries_the_line`, `test_arrow_function_with_a_true_tail_still_fires`, `test_blocking_predicate_returning_false_at_the_tail_still_fires`, `test_unlocatable_tail_still_fires` | Allow / unlocatable tails — fire |
| `test_line_survives_a_block_comment_above` | Comment stripping keeps line numbers |
| `test_applies_only_to_js_ts_repos` | `applies()` gates on the JS/TS features |
| `test_pragma_suppresses_finding` | Inline pragma silences it |
| `test_ssrf_bracketed_ipv6_bypass_pragma_quoted_in_a_string_does_not_suppress` | A pragma quoted in a string literal or quoted scalar does not suppress; a real comment still opts the file out (#424 E6) |

## Known bypasses

- The tail check reads the LAST `return` of the enclosing function, found by brace matching
  that is not string- or regex-literal aware; a function whose final `return` is unrelated
  to the classification result can read as default-deny.
- A NEGATED call in the tail (`return !isBlocked(host);`) is treated as default-deny (silent),
  the same as any other non-recognized-allow tail. This is consistent with the guard's own
  false-negative bias (a lookup or comparison "is refused" by default), but a negated call is
  neither a lookup nor a comparison, and whether the negated function itself handles bracketed
  IPv6 correctly is exactly what this single-file, regex-based guard cannot see. Accepted
  residual, not a regression: round 2's deny-tail recognition only added the LITERAL-`true`/
  literal-`false` cases; this gap predates it.

- The guard-context vocabulary is a fixed word list; a guard function named something
  entirely unrelated to those words would not be recognized as a guard, so a real bug
  there stays silent (favors precision).
- A hostname read through a helper function this guard doesn't trace (rather than a direct
  `.hostname` access) is invisible.
- Non-standard bracket-stripping code this guard's suppressor list doesn't recognize would
  cause a false positive on an already-fixed file.

## What this guard does NOT prove

Silence does not prove the SSRF guard is otherwise correct — only that this one specific
bracket-normalization defect is absent. A DNS-rebind, redirect-following, or other SSRF
bypass class in the same guard function is outside this guard's detection surface (see the
sibling `ssrf-dns-rebind-toctou` and `ssrf-redirect-bypass` guards for those).

# Citations

[1] agentsec checklist item `3a-ssrf-bracketed-ipv6-bypass` (§3a)
[2] CVE-2026-80347 (mcp-fetch), GHSA-mqq2-4r9w-4h99
[3] CWE-918, OWASP-ASI:ASI06
[4] agent-audit-kit `ssrf_bracketed_host.py`, rule AAK-SSRF-BRACKETED-HOST-001
