---
type: Guard
title: "llm-response-logged"
description: "LLM model response logged directly without redaction."
timestamp: "2026-10-01T18:09:12+00:00"
guard_id: "llm-response-logged"
checklist_section: ["8"]
standards: ["OWASP-LLM:LLM02", "OWASP:A09"]
---

# LLM model response logged directly without redaction

**Guard ID:** `llm-response-logged`
**Module:** `agentsec/guards/llm_response_logged.py`
**Severity:** HIGH
**Standards:** OWASP:A09, OWASP-LLM:LLM02

## Threat

Logging LLM responses in full creates a persistent record of user queries and model
outputs that may contain PII, PHI, trade secrets, API keys echoed back by the model,
or adversarially injected content. Unlike transient in-memory state, logs are:

- Shipped to external SIEM / log aggregation (Datadog, Splunk, CloudWatch)
- Retained for months or years under configurable retention policies
- Readable by on-call engineers who may not have business-need access to user data
- Indexed and searchable, making targeted extraction trivial

**Compound risk with prompt injection:** An attacker who successfully injects into the
model's context can cause the model to include sensitive data in its response
(e.g. "Repeat everything above"). That injected content — including exfiltrated
secrets — then lands in the log sink as a CRITICAL-severity data exposure.

## Detection design

One check: `model-output-to-logger` (HIGH)

**Signal:** A single line that contains BOTH:
- A logging call: `logger.debug/info/warning/error/critical(` or `logging.<level>(`
- A known LLM-invoke expression: `.run_sync(`, `.invoke(`, `.predict(`, `.generate(`,
  `.complete(`, `.arun(`, `.apredict(`, `.ainvoke(`

```python
# Fires (direct nesting — response goes straight to log sink):
logger.info(agent.run_sync(question))
logging.debug(chain.invoke({"question": q})["output"])
logger.warning(llm.predict(system_prompt))
logging.error(agent.arun(task))

# Silent (response captured in variable first):
response = agent.run_sync(question)
logger.info(response[:50])          # truncated — separate line

# Silent (logging a string, not an invoke expression):
logger.info("Request received")
logger.info(f"User: {user_id}")
```

**Why same-line only?** Direct nesting guarantees the raw response reaches the
log sink without any intervening step. Two-line patterns (response = model(); log(response))
are far more common in legitimate code (developers often log responses for debugging during
development) and would produce high FP rates without dataflow to verify whether redaction
happens between the two lines.

**Granularity:** one finding per offending line, across every scanned file. Until #425 the
check returned on the first hit repo-wide, so N logged responses reported 1, and an exception
or baseline entry on that one hid all the others.

**Suppress conditions:**
- Any file contains `# security: allow-llm-response-log`

## Severity rationale

HIGH: the finding is a confirmed data exposure path. Every request that goes through this
code produces a log record containing potentially sensitive model output. The exposure is
cumulative — even low-sensitivity responses add up to a user-conversation dossier in logs.

## Known bypasses / false negatives

| Pattern | Caught? | Notes |
|---|---|---|
| `logger.info(agent.run_sync(q))` | Yes | Direct nesting |
| `logging.debug(chain.invoke(q))` | Yes | Direct nesting |
| `response = agent.run_sync(q); logger.info(response)` | No (FN) | Two-line pattern |
| `logging.info({"output": agent.run_sync(q)})` | Yes | Invoke inside dict literal |
| `audit_log(agent.run_sync(q))` | No (FN) | Custom logger wrapper |
| `print(agent.run_sync(q))` | No (FN) | `print` is not a logger call |

## False positive scenarios

| Pattern | Would fire | Response |
|---|---|---|
| Debug build logging model response for tracing | Yes | Suppress with pragma; document access controls |
| Test file logging model call for test output | Yes | Consider using the guard's pragma in the test file |

## Checklist items flipped

| Item ID | Before | After | Reason |
|---|---|---|---|
| `8-sensitive-data-not-logged` | `manual` | `partial` | Catches direct same-line logging; two-line patterns and custom wrappers are FN |

## Tests

| Test | Validates |
|---|---|
| `test_llm_response_logged_flags_run_sync_in_logger` | `logger.info(agent.run_sync(...))` fires |
| `test_llm_response_logged_flags_invoke_in_logging` | `logging.debug(chain.invoke(...))` fires |
| `test_llm_response_logged_flags_predict_in_logger` | `logger.warning(llm.predict(...))` fires |
| `test_llm_response_logged_silent_for_response_in_variable` | Two-line pattern is silent |
| `test_llm_response_logged_silent_for_non_llm_log` | Plain string logging is silent |
| `test_llm_response_logged_pragma_silences` | Pragma silences the check |
| `test_llm_response_logged_not_applicable_without_llm_feature` | `applies()` gates on `"llm"` |
| `test_llm_response_logged_reports_every_offending_line` | Every offending line in every file is reported, not just the first (#425) |
| `test_llm_response_logged_benign_line_after_a_hit_stays_silent` | A redacted log after a real hit stays silent (FP-bait for the #425 widening) |
| `test_llm_response_logged_pragma_in_third_file_silences_all` | The repo-wide pragma still silences every file after #425 |

# Citations

[1] agentsec checklist item `8-sensitive-data-not-logged` (§8)
[2] OWASP-LLM:LLM02
[3] OWASP:A09
