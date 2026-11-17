---
type: Guard
title: "agent-tool-audit-log"
description: "@agent.tool function has no logging — silent tool invocation."
timestamp: "2026-06-22T12:29:09+08:00"
guard_id: "agent-tool-audit-log"
checklist_section: ["4"]
standards: ["NIST-AI-RMF:MS-2.5", "OWASP-LLM:LLM06", "OWASP:A09"]
---

# @agent.tool function has no logging — silent tool invocation

## What it detects

Python files containing `@<agent>.tool` or `@tool` decorated functions where no logging call
appears anywhere in the function's full body (`enclosing_function_span()` — not a
fixed window; a decorator with no enclosing function found falls back to a 30-line window).

## Why it matters

Agent tools (`@agent.tool` in pydantic-ai, `@tool` in LangChain) are the primary action surface
of an autonomous agent: web search, file I/O, database queries, API calls, code execution. When
a tool fires silently — no structured log entry inside the function body — the audit trail is
incomplete.

If a prompt-injection attack hijacks a tool to exfiltrate data or execute a privileged action,
there is no record of:
- What the agent was instructed to do
- What arguments were passed to the tool
- What identity/session context was active at invocation time

Without this trail, the attack is undetectable after the fact.

## Detection scope

- Language: Python
- Applies when: `"llm" in profile.features`
- Scanned files: all `.py` files under `python_scan_dirs`, excluding test/fixture paths
- Strategy: full enclosing-function-body search (`enclosing_function_span()`) from
  each `@<name>.tool` or `@tool` decorator line through the end of the function — look-AHEAD
  only, never backward into unrelated code above the decorator. Falls back to a 30-line window
  when no enclosing function is found.
- Audit signals (any one suppresses the finding): `logger.`, `logging.`, `log.`, plus the
  OpenTelemetry-style `tracer.` / `span.` calls and a tracing decorator stacked on the function
  whose name contains `trace_tool`, `traced`, `instrument`, `monitor`, or `observe` (case-insensitive).
  This recognises OTel-instrumented agent frameworks where tool calls are traced rather than logged.
- Docstring skip: `@agent.tool` shown inside a triple-quoted docstring example does not trigger the
  guard. Docstring boundaries are tracked by a per-line `"""`/`'''` toggle (`count % 2`).

## Rules

| Rule ID | Severity | Trigger |
|---|---|---|
| `agent-tool-audit-log/missing-tool-log` | MEDIUM | `@agent.tool` function with no logging anywhere in its body |

MEDIUM severity because: (a) a runtime audit signal (e.g. framework middleware tracing every
call automatically) is invisible to static analysis; (b) some frameworks log all tool
invocations at the middleware layer automatically.

## Opt-out

`# security: allow-unlogged-tool` anywhere in a file silences all findings for that file.
Use when the agent framework's middleware (e.g. pydantic-ai instrumentation, LangSmith tracing)
automatically records all tool invocations with full argument capture.

## False-negative scope

- Logging in a DIFFERENT function the tool calls (not inlined into the tool's own body) — not
  detected, only the same-function case is covered.
- Custom logging/observability abstraction whose object name isn't `logger`/`logging`/`log`/`tracer`/
  `span` and whose decorator name isn't one of the recognised tracing names — not detected.
- **Docstring state-machine desync (known limitation).** The docstring skip tracks `"""` and `'''`
  independently with a per-line `count % 2` toggle, so an *unbalanced* `'''` marker shown inside a
  `"""` docstring (or vice-versa) leaves the other quote state stuck "open" and over-skips real code
  after the docstring — a genuinely-unlogged tool below it is then missed. This is a false **negative**
  (miss), never a false positive: the heuristic always errs toward not firing. Pinned by
  `test_agent_tool_audit_log_mixed_quote_desync_is_known_limitation`. A future hardening (ignore `'''`
  toggles while inside a `"""` block and vice-versa, since Python can't nest them) would remove it.

## Checklist mapping

`4-agent-action-audit-log` (MANUAL → partial via this guard)

## Standards

- OWASP-LLM:LLM06 (Sensitive Information Disclosure)
- NIST-AI-RMF:MS-2.5 (AI system behavior monitoring)

## Related guards

- `agent-tool-overpermission`: tool performs privileged actions without scope restriction
- `agent-loop-circuit-breaker`: runaway agent loops without exit condition
- `agent-memory-user-scope`: agent memory not scoped to the requesting user

# Citations

[1] agentsec checklist item `4-agent-action-audit-log` (§4)
[2] NIST-AI-RMF:MS-2.5
[3] OWASP-LLM:LLM06
[4] OWASP:A09
