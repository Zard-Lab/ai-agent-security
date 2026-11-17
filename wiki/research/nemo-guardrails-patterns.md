---
type: Research
title: NeMo Guardrails (NVIDIA) — Agentic Security Patterns
description: Statically-detectable NeMo Guardrails config.yml misconfiguration patterns, sourced from NVIDIA's own guardrail-catalog docs, mapped to agentsec coverage.
tags: [research, llm, guardrails, nemo, configuration]
timestamp: "2026-07-04T00:00:00Z"
---

# NeMo Guardrails (NVIDIA) — Agentic Security Patterns

## What this covers

NeMo Guardrails is NVIDIA's toolkit for adding programmable guardrails (input, dialog,
retrieval, execution, and output rails) to LLM applications, configured primarily through
a `config.yml` file. Unlike a Python-import-based guardrail check (does the project use a
guardrail library at all), the patterns below are about whether an already-adopted
guardrail layer is *itself* soundly configured — every claim is sourced directly from
NVIDIA's own documentation, not inferred from general security principles.

## The presence/effectiveness gap

Adopting a guardrail framework proves intent, not protection. NeMo's own docs repeatedly
draw a line between a control that's *configured* and one that's *effective in
production* — several rails ship an easy, testing-oriented default alongside an explicitly
recommended, harder-to-reach production mode. A config using only the easy default looks
identical to a correctly-hardened one unless you read the specific block it's missing.

| Pattern | What NVIDIA's own docs say | Detection |
|---|---|---|
| Injection detection never configured | Injection detection is opt-in: "to activate injection detection, you must specify the rules to apply and the action to take" | Active `rails:` config (real input/output flows) with no `injection_detection` block anywhere |
| Self-check as the only safety layer | "The performance of this rail is strongly dependent on the capability of the LLM to follow the instructions... If your LLM does not reliably follow this prompt, consider a purpose-built input safety model instead" | `self check input`/`self check output` flows present, no dedicated content-safety-class model (Llama Guard, Nemotron Content Safety, ShieldGemma, etc.) configured alongside |
| Jailbreak heuristics run in-process | Running the heuristics in-process is documented as "TESTING PURPOSES ONLY" and "NOT RECOMMENDED FOR PRODUCTION DEPLOYMENTS" — production guidance is to deploy the detection server separately | `jailbreak detection heuristics` flow enabled with no `server_endpoint` configured |

## Tool-call validation's silent-fallback trap

Tool-call and tool-result validation rails are gated behind a separate, opt-in engine
(`IORails`) rather than the default `LLMRails`. NVIDIA's docs describe the failure mode
plainly: a misdirected, unknown, or duplicated tool flow name "makes the configuration
ineligible for IORails," and the facade "silently falls back to `LLMRails`... with only a
log warning." A config that declares `tool call validation`/`tool result validation` rails
but never actually wires the app to the IORails engine (or has a single typo in a flow
name) reads, on inspection of the config file alone, as fully protected — the validation
simply never runs, with no error, just a log line most deployments won't be watching for.

This is the same *presence vs. effect* gap agentsec's own `guardrail-architecture` guard
already draws for llm-guard's `scan_prompt()`/`scan_output()` (a scan can run and still be
silently unenforced if its result is discarded) — NeMo's tool-rails have an architecturally
identical failure mode, just triggered by engine misconfiguration instead of an ignored
return value.

## PII masking is directional

NeMo's PII/sensitive-data rails (GLiNER, Presidio, Private AI) are configured per flow
direction — `input`, `output`, and (for RAG stacks) `retrieval` are three independent
flow declarations under the same rail, not one on/off switch. A config that masks PII on
the way in but never configures the matching `output` flow leaves the bot's own response —
or content pulled from a RAG-retrieved chunk — free to echo back exactly the PII class the
input side was built to catch. Masking one direction of a two-way conversation protects
half of it.

## What didn't make the cut

NeMo's action-registration system (`@action()` decorator, `rails.register_action(...)`)
has no documented sandboxing or permission model for what a registered Python action can
do — NVIDIA's own docs simply don't mention input validation or execution restrictions for
custom actions. That's a real design property worth knowing, but it isn't a
*misconfiguration* pattern a repo scan can flag: there's no config knob whose presence or
absence changes the outcome. Registering an action is how the framework fundamentally
works; the security responsibility for what that action does is the same as any other
first-party Python function, not something NeMo's config surface can constrain either way.
