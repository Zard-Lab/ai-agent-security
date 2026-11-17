---
type: Guard
title: "log-injection"
description: "User-supplied request value interpolated into a log call (CRLF injection risk)."
timestamp: "2026-06-21T18:50:26+08:00"
guard_id: "log-injection"
checklist_section: ["10"]
standards: ["ASVS:16.4.1", "OWASP:A09"]
---

# User-supplied request value interpolated into a log call (CRLF injection risk)

## Threat

**CRLF injection via unescaped user input in log statements.**

When a web application logs a request-supplied value (header, query parameter, body, form field)
without sanitizing it first, an attacker who controls that value can embed carriage return and
linefeed characters (`\r`, `\n`). Because most log destinations write one event per line, a
crafted value such as:

```
alice\nINFO 2026-06-21 admin: privileged action completed successfully
```

produces two lines in the log stream. The second line is fabricated by the attacker. This lets
adversaries:

- Forge log entries to create an alibi or hide their real activity.
- Poison SIEM/alerting pipelines that parse log text as trusted input.
- Confuse log-correlation tooling by inserting events out of band.

The canonical Python pattern flagged by this guard:

```python
logger.info(f"User {request.headers['X-User']} logged in")
logging.debug(f"Query: {request.query_params}")
```

Standards: **OWASP:A09** (Security Logging and Monitoring Failures), **CWE:117** (Improper Output
Neutralization for Logs).

## Detection design

The guard performs same-line co-occurrence detection across all Python files in the detected source
directories. A line is flagged when all three conditions hold:

1. A logging call is present:

```
(?:logging|logger)\.(debug|info|warning|error|critical)\s*\(
```

2. An f-string is opened on the same line, **or** the message is built via another *eager*
(baked-in-before-the-call) interpolation — string concatenation, `.format()`, or `"..." % value`:

```
\bf['"]                                    # f-string
['"]\s*\+|\+\s*['"]|\.format\s*\(|['"]\s*%\s*[\(\w]   # concat / .format() / eager %
```

Eager `%` formatting (`"User %s" % value`) is distinguished from *lazy* `%`-style logging
(`logger.info("User %s", value)`, the recommended-safe form where the logging module defers
formatting and the value is a separate positional arg) by requiring a quote character immediately
followed by `%` — that sequence only occurs when `%` is the string-formatting operator applied
directly to the preceding literal, not when `%s` appears mid-string ahead of a comma-separated arg.

3. A request-supplied value is referenced within the interpolation:

```
(?:request\.|headers\[|(?<!\w)body(?!\w)|query_params|form\[)
```

The third pattern matches:
- `request.` — any FastAPI / Flask request attribute access
- `headers[` — direct header dictionary subscript
- `body` — raw body attribute (word-boundary anchored to avoid false positives on `embodied` etc.)
- `query_params` — FastAPI `Request.query_params`
- `form[` — form field subscript

All three must appear on a single line. The guard iterates every `.py` file; a file-level pragma
(`# security: allow-log-injection`) skips the entire file.

## Extension — agent-tool parameters (CVE-2026-6494, CWE-117)

The original detection scope was web-request taint sources only (`request.`/`headers[`/`body`/
`query_params`/`form[`) — an agent-framework tool function's own parameter was invisible to it,
even though an LLM decides that call's argument values and so a tool parameter is exactly as
untrusted as a request field. This extension adds a second, AST-scoped source:

1. `safe_ast_parse` resolves every function decorated `@tool` (bare or called, `@tool(...)`) or
   whose decorator is an attribute ending in `.tool` (`@agent.tool`, `@mcp.tool()`) — structural
   resolution, not a name-substring match, so an unrelated decorator that merely mentions "tool"
   elsewhere in its name does not qualify.
2. The function's own parameter names (positional, keyword-only, `*args`, `**kwargs`; `self`/`cls`
   excluded) are collected, along with the function's line range (`lineno`..`end_lineno`).
3. Every line already known to carry a logging call with eager interpolation (the same detector
   above) is additionally checked, IF it falls inside a resolved tool function's range, against
   that function's own parameter names as whole-word identifiers — a same-named variable in an
   unrelated, non-`@tool` function, or an unrelated variable inside a `@tool` function's own body,
   does not match. The search runs only over the parts of the message that can carry a VALUE:
   the `{...}` fields of f-string literals plus everything outside string literals (concatenation
   operands, `.format(...)` / `% ...` arguments). A parameter name that appears only in the
   literal prose (`f"looking up id for record: {other!r}"` with a parameter named `id`) does not
   fire.

Rule: `log-injection/tool-param-in-log`, same MEDIUM severity and same `_STANDARDS` as the
original rule.

```python
@tool
def lookup_user(username: str) -> str:
    logger.info(f"Looking up {username}")   # fires log-injection/tool-param-in-log
    return db.get(username)
```

## Severity rationale

**MEDIUM.** CRLF injection in logs enables audit-trail forgery and can confuse security monitoring,
but it does not grant code execution or direct data exfiltration. The impact is reliability of the
audit trail (a secondary control layer) rather than the primary security boundary. Severity is medium
rather than low because tampered audit trails directly undermine incident detection and response,
which is an OWASP Top 10 failure category in its own right.

## Known bypasses / false negatives

| Bypass | Description |
|---|---|
| Multi-line pattern | Request value stored in a variable on one line, then logged on another — not detected (would require dataflow analysis). |
| Variable alias | `val = request.headers["X-User"]` then `logger.info(f"... {val} ...")` — not detected. |
| Custom log wrapper | A project-level `log_info(msg)` call wrapping `logger.info` is not matched by the `logging`/`logger` prefix pattern. |
| Aliased logger | `log = logging.getLogger(...)` then `log.info(...)` — `log.` does not match the guard pattern (only `logger.` and `logging.` are matched). |

**2026-07-12:** concatenation and eager `%`-formatting are no longer bypasses — both are
now detected alongside f-strings and `.format()`. Lazy `%`-style logging
(`logger.info("User %s", request.headers["X-User"])`) remains correctly silent — it is the
recommended-safe form, not a bypass.

## False positive scenarios

| Scenario | Why it is safe | Guard behavior |
|---|---|---|
| `logger.info(f"User {user_id} logged in")` | `user_id` is a sanitized/trusted identifier, not a raw request attribute. | Silent — `_USER_INPUT` pattern does not match `user_id`. |
| `logger.info("Request received")` | No f-string, no interpolation. | Silent — `_FSTRING_OPEN` does not match. |
| `logger.info(repr(request.headers))` | `repr()` escapes all non-printable characters including `\n` and `\r`. | **False positive** — `repr(request.headers)` contains `request.` so the guard fires. Use the pragma to suppress confirmed-safe cases. |
| Structured logging with `extra=` | `logger.info("event", extra={"hdr": request.headers["X"]})` | Silent — no f-string on the line (extra is not an interpolated string). |

The `repr()` case is the main known false positive. The remediation text and the pragma exist
specifically to handle this case; a team using `repr()` consistently should add the pragma.

## Checklist items flipped

| ID | Before | After | Reason |
|---|---|---|---|
| 10-log-injection-encoded | `uncovered` | `covered` | Guard detects direct f-string interpolation of request values into log calls on a single line. |

## Tests

| Test | Validates |
|---|---|
| `test_log_injection_flags_logger_fstring` | True positive: `logger.info(f"... {request.headers[...]} ...")` fires. |
| `test_log_injection_flags_logging_query_params` | True positive: `logging.debug(f"... {request.query_params} ...")` fires. |
| `test_log_injection_flags_string_concat` | True positive: `logging.info("User " + request.headers[...] + " logged in")` fires. |
| `test_log_injection_flags_dot_format` | True positive: `logging.info("User {}".format(request.headers[...]))` fires. |
| `test_log_injection_flags_eager_percent_format` | True positive: `logging.info("User %s" % request.headers[...])` fires. |
| `test_log_injection_silent_lazy_percent_format` | False positive guard: `logging.info("User %s logged in", request.headers[...])` (lazy, recommended-safe form) produces no finding. |
| `test_log_injection_silent_safe_dot_format` | False positive guard: `.format()` call with no request-derived value produces no finding. |
| `test_log_injection_silent_safe_variable` | False positive guard: safe variable in f-string produces no finding. |
| `test_log_injection_silent_plain_string` | False positive guard: plain string (no f-string) produces no finding. |
| `test_log_injection_pragma_silences` | Pragma behavior: file with pragma produces no finding even with a dangerous line. |
| `test_log_injection_applies_gate` | Feature gate: guard returns no findings (or is skipped) when `python` not in features. |
| `test_log_injection_flags_tool_param_fstring` | Extension true positive: `@tool`-decorated function logging its own f-string-interpolated param fires. |
| `test_log_injection_flags_attribute_tool_decorator` | Extension true positive: `@agent.tool()` (attribute-style, called) decorator resolves too. |
| `test_log_injection_silent_non_tool_function_same_param_name` | Extension FP guard: a same-named parameter in a non-`@tool` function does not fire. |
| `test_log_injection_silent_tool_function_unrelated_variable` | Extension FP guard: an unrelated variable inside a `@tool` function's own body does not fire. |
| `test_log_injection_silent_tool_param_outside_function_range` | Extension FP guard: a same-named variable in a later, unrelated function outside the tool function's line range does not fire. |
| `test_log_injection_silent_tool_param_name_only_in_fstring_prose` | FP-bait: the parameter name appears only in the f-string's literal text. |
| `test_log_injection_silent_tool_param_name_only_in_concat_literal` | FP-bait: same, for a concatenated string literal. |
| `test_log_injection_flags_tool_param_in_fstring_field_with_conversion` | Still fires: the parameter sits in a `{...}` field with a conversion and an expression around it. |
| `test_log_injection_flags_tool_param_in_format_and_percent_args` | Still fires: `.format(id)` and `% id` arguments. |
| `test_log_injection_tool_param_pragma_suppresses` | Extension: the same file-level pragma silences the tool-param rule too. |

# Citations

[1] agentsec checklist item `10-log-injection-encoded` (§10)
[2] ASVS:16.4.1
[3] OWASP:A09
[4] CVE-2026-6494, CWE-117 — the agent-tool-parameter extension
