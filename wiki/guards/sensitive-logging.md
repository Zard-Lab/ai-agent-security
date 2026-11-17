---
type: Guard
title: "sensitive-logging"
description: "Sensitive data written to the logger."
timestamp: "2026-06-14T19:33:21Z"
guard_id: "sensitive-logging"
checklist_section: ["10"]
standards: ["OWASP:A02", "OWASP:A09"]
---

# Sensitive data written to the logger

_Added 2026-06-14 — gap #1 (§10 sensitive-data-in-logs). A `/guard-factory`-driven build
(`claude-skills/guard-factory/SKILL.md`); the second guard off the factory after `input-delimiters`._

---

## The threat

§10 of the checklist: *"Sensitive data not present in logs — request bodies, financial data, API
keys"*. Logs are the quietest exfiltration channel in a modern stack: they are streamed to
third-party aggregators (Datadog, CloudWatch, Loki), retained for months, and read by on-call
engineers, support, and analytics — none of whom necessarily had rights to the underlying data.
A single `logger.info(await request.json())` or `logger.warning(f"key={api_key}")` therefore
defeats RLS, tenant isolation, secret-management, and PII minimization all at once: the data is
copied, in clear text, into a system with a completely different (and usually weaker) access model.

Findings carry `["OWASP:A09", "OWASP:A02"]` (logging failures / cryptographic-and-secret exposure).

## Scope — no overlap with existing checks

Nothing else in agentsec inspects logging **sinks**. The other §10 items
(`10-structured-json-logging`, `10-security-event-logging`, `10-logs-shipped-external`, the alerting
and retention items) are manual *operational* controls about logging being present and shipped —
this guard is the inverse concern (the *wrong data* being logged) and does not touch them. It is
also unrelated to the LLM/RAG guards; it is a generic Python SAST check gated on `python`.

## Why it's often introduced  /  Why this guard fits the stack

Debugging a FastAPI handler, a developer drops `logger.info(await request.json())` to see the
payload, or `logger.debug(f"token={access_token}")` to chase an auth bug — and it ships. The line
looks innocuous in review (it's "just logging"), so the default state is leaky, which is exactly
what a presence guard should catch at the point of introduction.

## Detection design

1. **`applies()` gate** — `"python" in profile.features`.
2. **Scan** — every `.py` under `python_scan_dirs` (deduped via `seen`); per-occurrence findings
   (the `jwt_alg` shape, not the absence-detection "fire once" shape).
3. **Call-site match** — `_LOG_CALL` matches `logger.<level>(` / `logging.<level>(` / `log.<level>(`
   / `self.logger.<level>(` and aliases ending `log`/`logger`, for levels
   debug/info/warning/warn/error/critical/exception/log.
4. **Argument extraction** — `_call_args` (copied from `jwt_alg`) does a string-literal-aware
   paren-depth walk from the opening `(` to its match, so a multi-line logging call is read whole.
5. **Decision over the argument text:**
   - `_REQUEST_BODY` (`request.body`/`.json`/`.data`/`.form`/`.stream`/`.get_data`, `await
     request.json`, `.body()`) → **high**, `sensitive-logging/request-body-logged`.
   - else `_REQUEST_HEADERS` (`request.headers` or `dict(request.headers)`, whole-object — not a
     single `.get(...)`/`[...]` extraction) → **high**, `sensitive-logging/request-headers-logged`
     (added 2026-07-10, CodeQL `py/clear-text-logging-sensitive-data` cross-check). A separate tier
     from the body check because it closes a real precision gap: `Authorization`/`Cookie` ride
     inside the headers dict without ever spelling the words `authorization`/`bearer`/`secret` that
     `_SENSITIVE_FIELD` below looks for — logging `request.headers` wholesale was previously
     invisible to this guard.
   - else `_SENSITIVE_FIELD` (`password`/`passwd`/`secret`/`api_key`/`access_token`/`refresh_token`/
     `auth_token`/`bearer`/`authorization`/`client_secret`/`private_key`/`card_number`/`credit_card`/
     `cvv`/`ssn`/`credential`) matched against a **code view** of the args → **medium**,
     `sensitive-logging/sensitive-field-logged`. A site that matches an earlier tier reports only
     that one (the `elif` chain).
6. **Opt-out** — `# security: allow-sensitive-log` on the logging line or the line above.

### The code-view (the key false-positive control)

The field markers run against `_code_view(args)`, not the raw args: non-interpolated **string-literal
text is stripped** while f-string `{…}` **interpolations are kept**. So `logger.info("password reset
email sent")` is silent (the sensitive *word* is prose inside a message), while
`logger.warning(f"key={api_key}")`, `logger.info(password)`, and `logger.debug(user.password)` all
fire (the sensitive *value* is code). This is the inverse of the `input-delimiters` lesson (PR #27),
where a marker matched a word in a comment — here we deliberately exclude prose-string matches.

### Two-severity rationale

A logged request body is unambiguous (request bodies carry credentials/PII by construction), so it
is **high** — matching the checklist item's HIGH control importance, no decoupling needed (unlike
`input-delimiters`, where the whole detection was heuristic). The field-name half is the
"can't-enumerate-all-PII" heuristic, so it is **medium** + a pragma — advisory, below the default
`--fail-on high` gate. Mirrors `jwt_alg`'s none=high / unpinned=medium split. Severity is flagged for
maintainer (Marconi) curation.

## When NOT to flag

A log that carries no request body and no recognized sensitive field — `logger.info("user logged
in", extra={"id": uid})`, `logger.error("invalid password attempt")` (prose), `logger.info(f"order
{order_id} shipped")` — is clean and silent. The pragma covers a reviewed exception (e.g. a redacted
field that happens to contain a marker word, or a deliberately-logged value in a dev-only path).

## Tests

| Test | What it checks |
|---|---|
| `test_sensitive_logging_flags_request_body` | `logger.info(await request.json())` → HIGH `request-body-logged` |
| `test_sensitive_logging_flags_sensitive_field` | `logger.warning(f"key={api_key}")` → MEDIUM `sensitive-field-logged` |
| `test_sensitive_logging_pragma_opt_out` | `# security: allow-sensitive-log` → silent |
| `test_sensitive_logging_silent_on_safe_log` | a log with no body / no sensitive field → silent |
| `test_sensitive_logging_silent_on_message_word` | sensitive word inside a plain message string → silent (the code-view control) |
| `test_sensitive_logging_not_applicable_without_python` | `applies()` False without python |
| `test_sensitive_logging_flags_full_request_headers` | `logger.info(request.headers)` → HIGH `request-headers-logged` |
| `test_sensitive_logging_flags_dict_request_headers` | `logger.info(dict(request.headers))` → HIGH `request-headers-logged` |
| `test_sensitive_logging_silent_on_single_header_extraction` | `logger.info(request.headers.get("User-Agent"))` → silent (single-header extraction, not the whole set) |

Liveness: the canary's `stripe_webhook.py` logs `await request.json()` (`agentsec/canary.py`), so
`doctor --canary` proves the HIGH tier fires end-to-end alongside the stripe-payments findings.

## Known bypasses

- **Sensitive word in a logged string literal** — deliberately NOT flagged (the code-view control);
  the trade is precision over recall for the prose case. A genuinely sensitive value hard-coded in a
  string (`logger.info("password is hunter2")`) is missed.
- **`print()`** — logging via `print` is common in containers but far too FP-prone to flag at useful
  precision; excluded (documented FN), a candidate for a future opt-in.
- **Fields outside the marker set** — "can't enumerate all PII"; a field named `dob`/`mothers_maiden`
  /`passport_no` is missed. The marker set covers the common credential/financial leaks.
- **Indirect / aliased logging** — a custom wrapper (`audit_log(msg)`) or a logger whose attribute
  chain doesn't match `_LOG_CALL` evades it; a body assigned to a benign-named variable first
  (`data = await request.json(); logger.info(data)`) is missed (no data-flow).
- **Single-header extraction of a sensitive header** — `request.headers.get("Authorization")` is
  deliberately excluded from `_REQUEST_HEADERS` (it targets the whole-object case) and the literal
  string `"Authorization"` is stripped by the code-view before `_SENSITIVE_FIELD` ever sees it — so
  this specific spelling is missed by both tiers. A future pass could special-case `.get()` with a
  sensitive-named literal argument.

## What this guard does NOT prove

That logs are free of sensitive data — only that these specific sinks (a logged request body, or a
logged recognized-secret/PII *value*) are not present in the scanned source. It is static: it cannot
see data that reaches the logger through a variable, a custom log wrapper, or a field outside the
marker set, and it cannot confirm a downstream log processor redacts. The operational §10 controls
(structured logging, shipping, retention, alerting) remain manual.

# Citations

[1] agentsec checklist item `10-no-sensitive-data-in-logs` (§10)
[2] OWASP:A02
[3] OWASP:A09
