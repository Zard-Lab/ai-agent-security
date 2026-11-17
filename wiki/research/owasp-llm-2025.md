---
type: Research
title: OWASP LLM Top 10 — 2025 Edition
description: The OWASP LLM Top 10 for 2025, what changed from 2023, static detectability per item, and implications for agentsec checklist coverage.
tags: [research, owasp, llm]
timestamp: "2026-06-09T00:00:00Z"
captured: 2026-06-09
source: parallel research agent (OWASP genai.owasp.org + Qualys + Oligo)
---

# OWASP LLM Top 10 — 2025 Edition

## What changed from 2023

| Item | 2023 | 2025 | Change |
|---|---|---|---|
| LLM01 | Prompt Injection | Prompt Injection | Unchanged |
| LLM02 | Insecure Output Handling | Insecure Output Handling | Unchanged |
| LLM03 | Training Data Poisoning | Supply Chain Vulnerabilities | Renamed + expanded |
| LLM04 | Model Denial of Service | Data and Model Poisoning | Renamed |
| LLM05 | Supply Chain Vulnerabilities | Improper Output Handling | Reordered |
| LLM06 | Sensitive Information Disclosure | Sensitive Information Disclosure | Unchanged |
| LLM07 | Insecure Plugin Design | **System Prompt Leakage** | **NEW** |
| LLM08 | Excessive Agency | **Vector and Embedding Weaknesses** | **NEW** |
| LLM09 | Overreliance | Misinformation (expanded from Overreliance) | Expanded |
| LLM10 | Model Theft | Unbounded Consumption (expanded from DoS) | Expanded |

## The 10 items — detail

### LLM01: Prompt Injection
Direct (user injects) and indirect (via tool outputs, retrieved docs, emails). Indirect is harder to
defend because data and instructions share the same token stream. No reliable static defense exists;
mitigations are runtime (instruction boundaries, input classifiers). Static detectable: f-string
interpolation of untrusted input directly into LLM prompts.

### LLM02: Insecure Output Handling
LLM output used without sanitization: rendered as HTML (XSS), passed to `eval()`/`exec()` (RCE),
written to spreadsheet cells without formula-prefix (`csv_injection.py` guard already covers this).
Static detectable: `dangerouslySetInnerHTML` with LLM output (`frontend_xss.py` guard covers this);
also `exec(llm_response)` or `eval(llm_response)` patterns.

### LLM03: Supply Chain Vulnerabilities
Compromised model weights, poisoned training data, malicious fine-tuning datasets, compromised
third-party libraries (LiteLLM backdoor Aug 2025). Static detectable: dependency integrity checks
(`python_supply_chain.py` and `js_supply_chain.py` guards cover the library side).

### LLM04: Data and Model Poisoning
Adversarial data injected into training or RAG knowledge bases to steer model outputs. See
`wiki/research/rag-security.md` for RAG-specific poisoning detail. Mostly a runtime concern; no
reliable static detection.

### LLM05: Improper Output Handling
Distinct from LLM02: focuses on the pipeline after LLM output — output passed to downstream systems
(shell commands, SQL, file writes) without validation. Static detectable: tool functions with
model-controlled parameters (paths, SQL fragments, shell args). See guard-candidates.md #7
(`tool-file-path-injection`).

### LLM06: Sensitive Information Disclosure
PII, credentials, or proprietary data included in training data or RAG context leaking through
responses. Also: Supabase `service_role` key exposure leaking entire DB through prompt injection.
Static detectable: hardcoded secrets in prompts, `service_role` in client code
(`supabase_service_role.py` guard done).

### LLM07: System Prompt Leakage (NEW in 2025)
System prompts extracted via social engineering ("Imagine you are a developer..."), hypothetical
framing, or multi-turn role-framing. Real-world: GitHub Copilot, custom OpenAI GPTs, banking
chatbots all had prompts extracted in 2024-2025. Statically detectable: secrets/API keys hardcoded
inside system prompt strings (`OPENAI_API_KEY` in a prompt literal). Full extraction is a runtime
behavioral risk, not code-level.

### LLM08: Vector and Embedding Weaknesses (NEW in 2025)
Entire new category recognizing RAG as a distinct attack surface. Covers:
- Unauthorized access to vector DBs
- Cross-context/cross-tenant leakage via shared similarity search
- Embedding inversion (50-70% data recovery from raw vectors)
- Corpus poisoning (5 docs → 90% manipulation success)
See `wiki/research/rag-security.md` for full detail. Static detectable: retrieval calls without
per-user filter — covered by `agent-memory-user-scope` guard (Phase 1 sprint; was guard-candidates.md #5).

### LLM09: Misinformation (expanded from Overreliance)
Models generating and propagating false information. Purely semantic/behavioral risk — not detectable
statically.

### LLM10: Unbounded Consumption (expanded from DoS)
Resource exhaustion and cost explosion: loops calling LLM APIs without break conditions, missing
`max_tokens`, no rate limits, context window exhaustion via recursive summarization. Static
detectable: `while True` or unbounded `for` loops containing LLM API calls (`guard-candidates.md
#6 llm-unbounded-loop`).

## Static detectability summary

| Item | Statically detectable? | Guard status |
|---|---|---|
| LLM01 Prompt Injection | PARTIAL (string interp pattern) | `rag-no-instruction-filter` done (Phase 1 sprint); direct injection candidate still open |
| LLM02 Insecure Output | YES (eval/exec, dangerouslySetInnerHTML) | `csv_injection`, `frontend_xss`, `dom-xss-sinks` done; `tool-file-path` candidate |
| LLM03 Supply Chain | YES (dependency integrity) | `python_supply_chain`, `js_supply_chain` done |
| LLM04 Data Poisoning | NO (runtime semantic) | — |
| LLM05 Improper Output | PARTIAL (tool param taint) | `mcp-tool-unverified` done (Phase 1 sprint); `tool-file-path` candidate open |
| LLM06 Info Disclosure | YES (secrets in prompts, service_role) | `supabase_service_role.py` done; `secret-in-url-query`, `token-in-localstorage`, `refresh-token-plaintext` done (Phase 1 sprint) |
| LLM07 System Prompt Leakage | PARTIAL (secrets in prompt literals) | `system-prompt-leak` guard (§4) |
| LLM08 Vector/Embedding | PARTIAL (missing filter in retrieval) | `agent-memory-user-scope` done (Phase 1 sprint) |
| LLM09 Misinformation | NO | — |
| LLM10 Unbounded Consumption | YES (loop + LLM call pattern) | Candidate #6 |

## Sources
- https://genai.owasp.org/llm-top-10/
- https://blog.qualys.com/vulnerabilities-threat-research/2024/11/25/ai-under-the-microscope-whats-changed-in-the-owasp-top-10-for-llms-2025
- https://www.oligo.security/academy/owasp-top-10-llm-updated-2025-examples-and-mitigation-strategies
