---
type: Guard
title: "system-prompt-exposure"
description: "System prompt exposed via code-level pattern."
timestamp: "2026-06-21T10:35:43+08:00"
guard_id: "system-prompt-exposure"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM07"]
---

# System prompt exposed via code-level pattern

**Guard ID:** `system-prompt-exposure`
**Module:** `agentsec/guards/system_prompt_exposure.py`
**Severity:** LOW (hardcoded-literal) / MEDIUM (logged-at-debug-info, in-error-response, concat-leakage)
**Standards:** OWASP-LLM:LLM07

## Threat

System prompts in LLM applications often contain sensitive steering instructions, confidentiality
policies, persona definitions, or operational constraints. When a system prompt is placed directly
in source code, written to centralized logs, or returned in an HTTP error response, it is exposed
to unintended audiences before the LLM is ever involved.

These are code-level exposure patterns, distinct from OWASP-LLM:LLM07's main scenario (a user
socially engineering the model into revealing its instructions). Both threat surfaces must be
addressed; this guard handles the code-side.

## Complementarity with `system-prompt-leak`

| Guard | What it detects |
|---|---|
| `system-prompt-leak` | Model output is not filtered for verbatim prompt fragments — a user can coerce the model into revealing the prompt |
| `system-prompt-exposure` | The system prompt is exposed in source code, logs, or error responses before it reaches the model |

The two guards address independent attack surfaces and both must pass for full LLM07 coverage.

## Detection design

Four independent checks, each emitting at most one finding:

### 1. `hardcoded-literal` (LOW)

**Signal:** A `system_prompt` variable name or keyword argument is assigned a string literal.

```python
# Fires:
SYSTEM_PROMPT = "You are a helpful assistant. Keep this confidential."
agent = Agent("gpt-4o", system_prompt="You are the assistant.")

# Silent (dynamic loading):
SYSTEM_PROMPT = os.environ.get("SYSTEM_PROMPT", "default")
SYSTEM_PROMPT = settings.SYSTEM_PROMPT
```

**Silence conditions:**
- The same line contains `os.environ`, `getenv(`, `config.`, `settings.`, `.get(`, `load_`, `from_file`, or `read_` (dynamic loading indicators)
- Any file contains `# security: allow-hardcoded-system-prompt`

### 2. `logged-at-debug-info` (MEDIUM)

**Signal:** A `logging.debug()` / `logging.info()` / `logger.debug()` / `logger.info()` call
on the same line as a reference to `system_prompt` or `SYSTEM_PROMPT`.

```python
# Fires:
logger.debug(SYSTEM_PROMPT)
logging.info(f"Starting with system prompt: {system_prompt}")

# Silent:
logger.debug(context)  # no system_prompt reference
```

**Silence conditions:**
- Any file contains `# security: allow-system-prompt-in-log`

### 3. `in-error-response` (MEDIUM)

**Signal:** `detail=system_prompt` or `detail=SYSTEM_PROMPT` as a keyword argument, matching
the FastAPI `HTTPException`/`JSONResponse` pattern.

```python
# Fires:
raise HTTPException(status_code=500, detail=SYSTEM_PROMPT)
raise HTTPException(detail=system_prompt, status_code=403)

# Silent:
raise HTTPException(status_code=500, detail="Internal error")
```

**Silence conditions:**
- Any file contains `# security: allow-system-prompt-in-response`

### 4. `concat-leakage` (MEDIUM) — PL001

**Signal:** the system prompt variable is the value of an unambiguous **API-response key**
(`"output"` / `"result"` / `"response"`) — returning that dict exposes the full prompt in the
response body.

```python
# Fires:
return {"output": system_prompt}                # API response envelope
return {"result": SYSTEM_PROMPT, "status": "ok"}

# Silent — prompt assembly (-> LLM) or serialization, NOT user-facing leakage:
prompt = system_prompt + context                # concat is unknowable line-locally
return f"{system_prompt}\n{user_q}"             # canonical prompt-assembly f-string
return "(" + name + "," + system_prompt + ")"   # SQL-export serialization
messages = [{"role": "system", "content": system_prompt}]   # correct LLM message dict
system_prompt = header + footer                 # prompt building
```

**Narrowed after review.** The original draft also flagged string concatenation
(`system_prompt + x`) and multi-var f-strings (`f"{system_prompt}{x}"`), but a line-local regex
cannot tell whether the result reaches the user (leak), the LLM (prompt assembly, safe), or a
SQL/serialization string (safe) — those sub-patterns false-fired on prompt assembly and on the
flagship's SQL-export serializer (`agent_export_routes.py`), so they were dropped. The
response-key set excludes `content`/`text`/`message` because they collide with the correct LLM
system-message dict shape (`{"role":"system","content": system_prompt}`).

Returns at most ONE finding (first match across all files).

**Silence conditions:**
- Any file contains `# security: allow-system-prompt-concat`

## Severity rationale

- **Hardcoded (LOW):** The exposure is at rest — an attacker needs repo or wheel access. The
  primary risk is rotation inability and insider threat, not active network exfiltration. LOW
  matches the checklist item `4-system-prompt-not-hardcoded`.
- **Logged (MEDIUM):** Logs are forwarded to centralized stacks (Datadog, CloudWatch) with
  broader access, longer retention, and no fine-grained access control. Active exposure channel.
- **In response (MEDIUM):** The prompt is sent over the wire to any HTTP client. Even non-200
  responses reach browsers, CDN edge logs, and API gateways. Active exposure channel.
- **Concat-leakage (MEDIUM):** The system prompt is mixed into runtime strings that may be
  returned to users, serialized as API responses, or stored in logs that record the composite
  string. The full prompt text is embedded in the output at runtime.

## Known bypasses / false negatives

| Pattern | Caught? | Notes |
|---|---|---|
| `SYSTEM_PROMPT = "..."` (variable assignment) | Yes | Primary case |
| `system_prompt="..."` (keyword arg) | Yes | Matches same regex |
| Multi-line assignment `system_prompt = (\n"...\n")` | No | False negative; first line is `system_prompt = (` which doesn't match |
| Triple-quoted `system_prompt = """..."""` | Yes | `"""` starts with `"` which matches `["']` |
| `logging.warning(SYSTEM_PROMPT)` | No | Only DEBUG/INFO in scope; WARNING is intentional |
| `print(SYSTEM_PROMPT)` | No | Too broad; print() has many legitimate uses |
| FastAPI `detail=` on a separate line from `HTTPException` | Yes | `detail=system_prompt` on its own line still matches |

## Checklist items flipped

| Item ID | Before | After |
|---|---|---|
| `4-system-prompt-not-logged` | `manual` | `covered` |
| `4-system-prompt-not-in-response` | `manual` | `covered` |
| `4-system-prompt-not-hardcoded` | `manual` | `covered` |

## Tests

| Test | Validates |
|---|---|
| `test_system_prompt_exposure_flags_hardcoded_literal` | Primary hardcoded plant fires |
| `test_system_prompt_exposure_flags_logged_at_debug` | Logging plant fires |
| `test_system_prompt_exposure_flags_in_error_response` | Error response plant fires |
| `test_system_prompt_exposure_all_three_in_one_file` | All three rules fire from one file |
| `test_system_prompt_exposure_silent_when_env_loaded` | `os.environ.get()` silences hardcoded |
| `test_system_prompt_exposure_silent_when_settings_loaded` | `settings.X` silences hardcoded |
| `test_system_prompt_exposure_silent_for_logging_without_prompt_ref` | `logger.debug(ctx)` silent |
| `test_system_prompt_exposure_hardcoded_pragma_silences_that_check` | Per-check pragma works |
| `test_system_prompt_exposure_log_pragma_silences_log_check` | Per-check pragma works |
| `test_system_prompt_exposure_response_pragma_silences_response_check` | Per-check pragma works |
| `test_system_prompt_exposure_not_applicable_without_llm_feature` | `applies()` gates on LLM |
| `test_system_prompt_exposure_at_most_one_finding_per_rule` | At most one finding per rule |
| `test_system_prompt_exposure_flags_concat_left` | PL001 left-side `+` concat fires |
| `test_system_prompt_exposure_flags_concat_right` | PL001 right-side `+` concat fires |
| `test_system_prompt_exposure_flags_fstring_multi_var` | PL001 f-string multi-var fires |
| `test_system_prompt_exposure_flags_response_dict` | PL001 response dict key fires |
| `test_system_prompt_exposure_concat_pragma_silences_check` | `allow-system-prompt-concat` pragma works |
| `test_system_prompt_exposure_concat_silent_for_prompt_building` | `system_prompt = a + b` stays silent |
| `test_system_prompt_exposure_concat_silent_for_llm_invocation` | LLM arg usage stays silent |
| `test_system_prompt_exposure_concat_silent_for_logging` | Logging concat not double-fired |

# Citations

[1] agentsec checklist item `4-system-prompt-not-hardcoded` (§4)
[2] agentsec checklist item `4-system-prompt-not-in-response` (§4)
[3] agentsec checklist item `4-system-prompt-not-logged` (§4)
[4] OWASP-LLM:LLM07
