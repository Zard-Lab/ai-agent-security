---
type: Research
title: LLM Guard (ProtectAI) — Agentic Security Patterns
description: Statically-detectable patterns distilled from LLM Guard's input/output scanner catalog, mapped to agentsec coverage and guard candidates.
tags: [research, llm, prompt-injection, pii, structured-output, guardrails]
timestamp: "2026-07-01T00:00:00Z"
---

# LLM Guard (ProtectAI) — Agentic Security Patterns

## What this covers

LLM Guard is an open-source input/output scanning toolkit for LLM applications — 16
input scanners and 22 output scanners, applied via two functions: `scan_prompt(scanners,
prompt)` and `scan_output(scanners, prompt, output)`, each returning
`(sanitized_text, is_valid_per_scanner, risk_scores)`. This document distills the
scanner catalog into patterns that are relevant to statically-analyzable FastAPI +
LLM/RAG apps, separating what a source-code scanner can verify (architecture and
dataflow) from what only a runtime content-classifier can verify (semantic properties
of the text itself).

## The static/semantic split

Most of LLM Guard's scanners classify the *content* of a prompt or response at runtime —
toxicity, sentiment, bias, gibberishness, factual consistency, topic relevance. Those
properties depend on what the text actually says, not on how the code is structured, so
they are out of reach for static analysis by design (the same reason a linter can't tell
you whether a comment is rude). The patterns below are the ones with a genuine
architecture-level signature: not "is this text bad" but "does this code path have a
structural gap regardless of what the text says."

## Guardrail enforcement — presence vs. effect

| Pattern | What it catches | Detection |
|---|---|---|
| No independent guardrail layer | Project makes LLM generation calls with no scanning library imported at all | Import scan across the project (`llm_guard`, `nemo_guardrails`, `guardrails`, `presidio`, etc.) |
| Same model as generator and validator | The model that could be jailbroken is also the one asked to judge its own output | Same client variable invoked twice, second call's context includes the first call's result plus a safety/eval keyword |
| **Scan called, result discarded** | A guardrail scan runs but its return value is thrown away entirely — the unscanned text still proceeds | Bare call to `scan_prompt(...)`/`scan_output(...)` with no assignment |
| **Scan called, result never checked** | The sanitized text is kept and used, but the validity flag from the scan is never referenced again | Tuple-unpack captures the scan's return value, but the validity element never reappears in a conditional |

The last two are the more interesting gap: importing a real guardrail library proves
intent, not enforcement. A scan that runs and is silently ignored gives the same
protection as no scan at all, while looking — in a code review or an audit checklist —
like the box is checked.

## PII in the round trip

| Pattern | What it catches | Detection |
|---|---|---|
| PII sent to the model, response returned unredacted | User PII (email, SSN, credit card, phone, date of birth, bank/routing number) is interpolated into a prompt, and the model's response is returned to the client with no anonymization step anywhere in between | PII-shaped variable in an f-string/concat → flows into a generation call → that call's result flows into a `return`/`Response(`/`JSONResponse(` — with no `anonymize`/`redact`/`scrub`/`mask`/`presidio` call across the whole span |

The risk compounds two ways: the PII is transmitted to the model provider and stored in
conversation history/observability tooling, and — because the model saw it — nothing
prevents the model from echoing it back, verbatim or reformatted, to whichever caller
receives the response.

## Structured output trusted without validation

| Pattern | What it catches | Detection |
|---|---|---|
| LLM JSON output parsed without a schema | `json.loads()` on the model's response text, with the parsed dict's fields used directly in a decision (permission check, payment amount, routing choice) — no Pydantic validation gates the shape | `json.loads(...)` argument references a variable from an LLM generation call, with no `.model_validate(`/`.parse_obj(`/`TypeAdapter(`/`Model(**parsed)` on the same or next line |

A model asked to "return JSON" can still be steered — via prompt injection or plain
non-determinism — toward a shape the calling code doesn't expect. The same trust
boundary that applies to third-party HTTP API responses applies to the model's own text
output once it's parsed as structured data.

## Token/size ceilings — two distinct checks

LLM Guard's `TokenLimit` scanner caps the *incoming* prompt before it's sent to the
model — a distinct concern from capping the model's *generated* response length
(`max_tokens` on the outbound API call, which controls completion cost). Both are
economic-DoS mitigations, but they guard opposite ends of the same call: one keeps an
attacker from stuffing an oversized prompt in, the other keeps the model from generating
an unbounded response out. A guard that only checks for `max_tokens` on the call doesn't
tell you whether unbounded content (a retrieved document, an uploaded file) can still be
concatenated into the prompt with no size limit on the way in.

## What didn't make the cut

Scanners whose entire function is classifying the *content* of a string at runtime —
Toxicity, Bias, Sentiment, EmotionDetection, Gibberish, FactualConsistency, Relevance,
NoRefusal, ReadingTime, Language/LanguageSame — have no static-analysis equivalent.
Detecting them requires the same guardrail-presence check above (is a scanning layer
wired in at all), not a bespoke pattern per classifier. `BanTopics`/`BanSubstrings`/
`BanCompetitors`/`Regex` are configurable blocklist mechanisms rather than fixed
vulnerability patterns — again, their presence is what a static check can verify, not
their configured content.
