---
type: Guard
title: "async-blocking-io"
description: "Blocking I/O call inside async def stalls the event loop."
timestamp: "2026-06-21T18:50:26+08:00"
guard_id: "async-blocking-io"
checklist_section: ["8"]
standards: ["OWASP:A04"]
---

# Blocking I/O call inside async def stalls the event loop

## Threat

FastAPI and other asyncio-based Python frameworks multiplex all requests on a single event loop
thread. A synchronous, blocking call inside an `async def` route handler holds the GIL and blocks
the event loop for the duration of the call. All other in-flight requests must wait. An attacker
who can trigger the affected endpoint and control response latency (e.g. a `requests.get` to a
server they own, or a `time.sleep` via a path parameter) can render the API completely
unresponsive. This is an availability attack that requires no authentication and leaves no
persistent artifact — it fires on every new connection.

OWASP category: **A05 — Security Misconfiguration** (event-loop misconfiguration in async
framework).

## Detection design

Scan every `.py` file under `python_scan_dirs`. Track whether the scanner is currently inside an
`async def` body by monitoring indentation: the body begins on the line after `async def ...` and
ends when a non-blank line returns to or past the indentation level of the `async def` keyword
itself.

Within an active `async def` body, flag any line matching:

```
requests\.(?:get|post|put|delete|patch|head)\(
|time\.sleep\(
|urllib\.request\.urlopen\(
```

Report the **blocking call line**, not the `async def` line, so the location points directly to the
problem.

**Pragma skip:** if a `# security: allow-blocking-io` comment appears anywhere in a file (a string
literal quoting the phrase does not count, #424), the entire file is skipped (per the shared pragma
convention used across the codebase).

## Severity rationale

**Medium.** A single `requests.get()` inside a FastAPI route is a near-certain DoS vector in
production — it just requires a slow upstream or a controlled target. The severity is MEDIUM rather
than HIGH because static analysis cannot prove that the code path is reachable from an
unauthenticated request, nor that the upstream is attacker-controlled. If either is known to be
true in review, the severity should be escalated manually.

## Known bypasses / false negatives

| Bypass | Why not caught |
|--------|---------------|
| Calling a helper function that internally calls `requests.get` | Requires call-graph / dataflow analysis; line-level detection only |
| Aliased or monkey-patched `requests` (e.g. `import requests as r`) | Regex matches the literal `requests.` prefix only |
| `httpx` in sync mode (`httpx.get(...)`) called from async def | Not in the pattern list; `httpx` sync is less common but still blocks |
| Blocking DB drivers (e.g. `psycopg2` without async) | Different blocking category; out of scope for this guard |
| `subprocess.run(...)` or `os.system(...)` | Blocking but different category; separate guard opportunity |

## False positive scenarios

| Scenario | Why it fires | How to suppress |
|----------|-------------|-----------------|
| Startup script with `async def main()` that calls `requests` for a one-off fetch | Technically a false positive — startup code is not a request handler | Add `# security: allow-blocking-io` to the file |
| Test helpers with `async def` using `requests` against a local test server | Not a real DoS risk in test code | Add pragma to the test file |
| Management CLI with `async def` calling `time.sleep` for a progress loop | Intentional and safe in a non-server context | Add pragma to the file |

## Checklist items flipped

| ID | Before | After | Reason |
|----|--------|-------|--------|
| 8-async-route-no-blocking-io | `manual` | `covered` | Guard detects `requests.*`, `time.sleep`, and `urllib.request.urlopen` calls inside async def bodies in Python files |

## Tests

| Test | Validates |
|------|-----------|
| `test_async_blocking_io_flags_requests_get` | True positive: `requests.get` inside `async def` fires one finding |
| `test_async_blocking_io_flags_time_sleep` | True positive: `time.sleep` inside `async def` fires |
| `test_async_blocking_io_flags_urllib_urlopen` | True positive: `urllib.request.urlopen` inside `async def` fires |
| `test_async_blocking_io_silent_httpx` | False positive guard: `await httpx.AsyncClient().get()` does not fire |
| `test_async_blocking_io_silent_sync_func` | False positive guard: `requests.get` inside a plain `def` does not fire |
| `test_async_blocking_io_pragma_silences` | Pragma: a file containing the suppress string is skipped entirely |
| `test_async_blocking_io_applies_gate` | Feature gate: guard does not apply when features lack `python` and `fastapi` |

# Citations

[1] agentsec checklist item `8-async-route-no-blocking-io` (§8)
[2] OWASP:A04
