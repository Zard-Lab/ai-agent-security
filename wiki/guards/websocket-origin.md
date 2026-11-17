---
type: Guard
title: "websocket-origin"
description: "WebSocket accept() without cross-origin validation (CSWSH risk)."
timestamp: "2026-06-21T18:50:26+08:00"
guard_id: "websocket-origin"
checklist_section: ["2b"]
standards: ["ASVS:4.4.2", "OWASP:A01", "OWASP:CheatSheet"]
---

# WebSocket accept() without cross-origin validation (CSWSH risk)

## Threat

Cross-Site WebSocket Hijacking (CSWSH) exploits the fact that browser WebSocket connections
are not subject to the Same-Origin Policy. When a victim visits an attacker-controlled page,
that page can silently open `new WebSocket("wss://victim-backend.com/ws")`. The browser sends
the request including session cookies — exactly as it would for the legitimate app. If the
server does not validate the `Origin` header and reject disallowed origins before calling
`websocket.accept()`, the attacker's page receives the full authenticated WebSocket session.

Impact: read all server-sent data (streaming AI output, PII, live notifications), inject
frames as the authenticated user, and trigger state-changing actions — all without XSS.

Standards: OWASP:A01 (Broken Access Control), CWE:346 (Origin Validation Error).

## Detection design

The guard scans Python files for calls to `websocket.accept()` (with or without `await`).
For each such call, it looks backward to the START of the enclosing function (
`enclosing_function_span()` in `guards/base.py` — not a fixed window) for any reference to
origin validation. A call with no enclosing function (module-level code) falls back to a
10-line look-back window. If none is found, a HIGH finding is emitted. The search is
look-BACK only, never forward: an origin check performed AFTER `accept()` has already run is
too late — the connection is already open.

**Regex for accept call:**

```python
_ACCEPT = re.compile(r"\bwebsocket\.accept\s*\(", re.IGNORECASE)
```

**Regex for origin check (lookback window):**

```python
_ORIGIN_CHECK = re.compile(
    r"""origin(?![a-rt-z])|headers\.get\s*\(\s*["']origin["']|headers\s*\[\s*["']origin["']""",
    re.IGNORECASE,
)
```

The `origin(?![a-rt-z])` keyword match is intentionally broad but word-shape aware: it catches
`ws.headers.get("origin")`, plain `origin = ...`, `if origin not in ALLOWED`, and the common
snake_case / constant forms (`validate_origin(...)`, `check_origin(...)`, `origin_header`,
`ALLOWED_ORIGINS`, plural `origins`). The negative lookahead rejects `origin` when a following
letter other than `s` continues a different word (`original`, `originally`), which is why a
bare `\borigin\b` was wrong: `\b` treats `_` as a word char and would reject the snake_case
forms above (the dominant Python convention). Scoping the search to the enclosing function
(rather than a raw file-wide search) avoids misattributing an origin check in a previous
unrelated handler, since a different top-level function is never part of the enclosing span.

**Feature gate:** `applies()` returns True when `"fastapi"` or `"python"` is in
`profile.features`. Any Python WebSocket server (Starlette, raw websockets lib, FastAPI)
is in scope.

**Pragma:** A file containing `# security: allow-websocket-no-origin` is skipped entirely.

## Severity rationale

HIGH. CSWSH requires no XSS and no social engineering beyond a single page visit. It gives
an attacker a full authenticated WebSocket session, enabling data exfiltration and state
mutation. In LLM/agent stacks the damage is amplified: streaming AI responses — which may
include private context, tool outputs, or memory — are read in real time by the attacker.

## Known bypasses

| Bypass | Guard behaviour |
|---|---|
| Origin check in a FastAPI middleware (not in the handler) | Miss — guard only sees the handler file |
| Origin check in a DIFFERENT function the handler calls (not inlined into the handler's own body) | Miss — same-function case only |
| Origin allow-list derived at runtime from a DB query | Miss — syntactically invisible |
| `# security: allow-websocket-no-origin` in file | Correctly silenced (pragma) |
| `websocket.accept()` inside a helper called from the handler | Fires on the helper — correct |

## FP scenarios

| Scenario | Guard behaviour |
|---|---|
| `origin = ws.headers.get("origin")` then `await ws.accept()` anywhere in the same function | Correctly silent — origin check detected |
| `if origin not in ALLOWED: await ws.close(); return` before accept | Correctly silent |
| Middleware validates origin before handler is invoked | FP possible — use pragma to suppress |
| Test fixtures that call `websocket.accept()` with `# security: allow-websocket-no-origin` | Correctly silent |

## Checklist items flipped

| Checklist item | Section | State |
|---|---|---|
| `2b-websocket-origin-validated` | §2b — Authorization | covered by this guard |

## Tests

| Test function | Purpose |
|---|---|
| `test_websocket_origin_fires_no_check` | True positive: bare `await ws.accept()` with no origin check |
| `test_websocket_origin_silent_with_origin_check` | True negative: `origin` variable present before accept |
| `test_websocket_origin_silent_with_headers_get` | True negative: `headers.get("origin")` before accept |
| `test_websocket_origin_pragma_silences` | Pragma suppresses the file |
| `test_websocket_origin_applies_python` | Feature gate: fires for `"python"` feature |
| `test_websocket_origin_not_applies_no_python` | Feature gate: silent when neither fastapi nor python |
| `test_websocket_origin_silent_when_check_outside_old_fixed_window` | silent when the origin check sits past the old 10-line window but is still in the enclosing function |
| `test_websocket_origin_module_level_call_still_uses_window_fallback` | module-level call with no enclosing function still uses the fixed-window fallback |
| `test_websocket_origin_still_fires_when_check_is_after_accept` | directionality: a check written after `accept()` still fires (look-back only, never forward) |

# Citations

[1] agentsec checklist item `2b-websocket-origin-validated` (§2b)
[2] ASVS:4.4.2
[3] OWASP:A01
[4] OWASP:CheatSheet
