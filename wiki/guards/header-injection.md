---
type: Guard
title: "header-injection"
description: "Request value written into a response header (HTTP header injection)."
timestamp: "2026-07-11T20:15:31+08:00"
guard_id: "header-injection"
checklist_section: ["6a"]
standards: ["OWASP:A03"]
---

# Request value written into a response header (HTTP header injection)

_Marconi (research-cycle: codeql-security-queries) — 2026-07-11_

---

## The threat

A response-header write (`response.headers[name] = value`) where the header name or value
contains an unescaped newline lets an attacker who controls that input inject additional headers
or split the HTTP response — response splitting / header injection (CWE-113). Depending on what
gets injected this can plant a forged `Set-Cookie`, poison a downstream cache, or smuggle a
second response inside the first.

This is the OUTGOING direction of the same taint sources `log-injection` already covers for the
logging sink — a distinct sink, not a duplicate. OWASP A03:2021 — Injection.

## Why this guard fits the stack

Mined from CodeQL's `python/ql/src/Security/CWE-113/HeaderInjection.ql`, verified against the real
`HttpHeaderInjectionCustomizations.qll` (not just the thin `.ql` wrapper, which imports its actual
sink/source/sanitizer definitions from this file): the sink is any header write whose name or
value "allows newline"; the only recognized sanitizer is a `.replace("\n", ...)` call on the
value. Confirmed via `grep -n "header" agentsec/guards/log_injection.py` that the existing
log-injection guard only covers the read-into-a-log direction, not this write-into-a-header
direction — a genuine, distinct gap, not a duplicate of existing coverage.

## Detection design

1. `applies()` gates on `"python" in profile.features`, matching `log-injection`.
2. Scans `.py` files via `python_scan_dirs` + `iter_files`.
3. `_HEADER_WRITE` matches a `.headers[...] =` subscript ASSIGNMENT (the `(?!=)` lookahead
   excludes `==` comparisons).
4. The tainted-source check (`_USER_INPUT`, the same vocabulary as `log_injection.py`:
   `request.`/`headers[`/`body`/`query_params`/`form[`) is applied **only to the text after the
   sink match** — not the whole line. Caught during this guard's own adversarial self-test: since
   the sink itself contains the literal substring `headers[`, checking the whole line made every
   header-write false-match its own left-hand side as a "tainted source," regardless of what was
   actually assigned. Fixed by slicing `line[write_match.end():]` before the source check.
5. `_REPLACE_SANITIZER` (`.replace('\n', ...)` on the line) suppresses — the one sanitizer the
   real CodeQL query recognizes.
6. Severity MEDIUM (`standards=["OWASP:A03", "CWE-113"]`). Suppress with
   `# security: allow-header-injection` anywhere in the file.

## When NOT to flag

- A static string value (`response.headers['X-Custom'] = 'static-value'`) — not tainted.
- The READ direction (`value = request.headers['X-User']`) — not a header write at all, so
  `_HEADER_WRITE` never matches.
- A value with `.replace('\n', ...)` applied on the same line.

## Tests

| Test | What it checks |
|---|---|
| `test_flags_direct_header_from_request_header` | `response.headers[x] = request.headers[y]` → MEDIUM |
| `test_flags_header_from_query_params` | value from `request.query_params[...]` → fires |
| `test_silent_when_newlines_stripped` | `.replace('\n', '')` on the line → silent |
| `test_silent_on_static_value` | Static string assigned → silent |
| `test_silent_on_read_direction` | Reading `request.headers[...]` (no write) → silent |
| `test_pragma_suppresses` | `# security: allow-header-injection` → silent |
| `test_na_without_python` | `applies()` returns False without `python` |

## Known bypasses (honest limits)

- **No interprocedural tracking**, same class of limitation as `log-injection`: `val =
  request.headers['X-Injected']` on one line, then `response.headers['X-Custom'] = val` on the
  next, is NOT flagged — the source reference has to appear on the same line as the write.
- A sanitizer other than the literal string `.replace('\n', ...)` (e.g. a custom `strip_crlf()`
  helper, or `.replace('\r\n', ...)`) is not recognized and would cause a false positive.
- Only covers subscript-style header writes (`.headers[name] = value`); a header set via a
  framework's response-constructor kwarg (`Response(headers={"X-Custom": tainted})`) is not
  matched by this pattern.

**Known limitation (fixed, review #395):** `request.state`/`request.app` are trusted, server-set
attributes and are now excluded from the taint source; before this fix, `response.headers[...] =
request.state.trace_id` false-positived.

## What this guard does NOT prove

It flags a plausible same-line sink reachable from a same-line source; it does not prove the
value is actually attacker-reachable at runtime, nor does it prove the absence of header
injection reached via a longer call chain or a framework-level auto-escaping mechanism this
guard doesn't know about.

# Citations

[1] agentsec checklist item `6a-no-header-injection` (§6a)
[2] OWASP:A03
