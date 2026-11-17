---
type: Research
title: OWASP Top 10 for Agentic Applications — 2026 Edition
description: The OWASP ASI01-ASI10 taxonomy (published 2025-12-09), which existing agentsec guards map to each category, and the disposition of the three categories that are not yet reconciled.
tags: [research, owasp, asi, agentic]
timestamp: "2026-09-16T00:00:00Z"
captured: 2026-09-16
source: OWASP GenAI Security Project — Top 10 for Agentic Applications 2026 (genai.owasp.org), cross-referenced against agentsec/checklist/checklist.json and agentsec/guards/
---

# OWASP Top 10 for Agentic Applications — 2026 Edition

A distinct, newer taxonomy from the existing `OWASP-LLM` tags already in use (the 2025 LLM Top 10,
reconciled in `research/owasp-llm-2025.md`, #259). The Agentic Applications Top 10 targets
the layer above a single LLM call — the agent's objective, its tools, its identity, its memory, and
its communication with other agents — published 2025-12-09. Prior to this reconciliation pass,
agentsec's checklist and guards carried zero `OWASP-ASI` tags anywhere (verified: zero hits for
`ASI0`/`OWASP-ASI` in `wiki/` or `checklist.json`).

## The 10 categories

| ID | Name | Summary |
|---|---|---|
| ASI01 | Agent Goal Hijack | An attacker redirects an agent's objective via content it reads (poisoned config, instruction files, tool output). |
| ASI02 | Tool Misuse & Exploitation | A legitimate tool is bent toward an illegitimate outcome via deceptive input or unsafe chaining. |
| ASI03 | Identity & Privilege Abuse | Agents hold broad, long-lived credentials instead of the end-user's own scope (confused deputy). |
| ASI04 | Agentic Supply Chain Vulnerabilities | Compromised frameworks, MCP servers, or components enter the pipeline. |
| ASI05 | Unexpected Code Execution (RCE) | Content becomes running code via sandbox escapes or eval-style APIs. |
| ASI06 | Memory & Context Poisoning | Malicious or false information the agent later treats as its own trusted knowledge. |
| ASI07 | Insecure Inter-Agent Communication | Unverified agent-to-agent messages enable spoofing or tampering. |
| ASI08 | Cascading Failures | One bad decision propagates uncontained through an interconnected multi-agent workflow. |
| ASI09 | Human-Agent Trust Exploitation | The agent controls what is shown during a human-approval step to obtain a rubber-stamp. |
| ASI10 | Rogue Agents | An agent operates outside policy while still appearing legitimate, persisting undetected. |

## Reconciliation status

**7 of 10 categories are already substantially covered by existing guards** — this pass added the
`OWASP-ASI:ASI0N` tag to the mapped guard(s) and checklist item(s) (mirroring the exact
`OWASP-LLM:LLM0N` tag-string convention already in use). **2 remain open research items** (no guard
built yet). **1 is intentionally out of static-analysis scope.**

### ASI01 — Agent Goal Hijack → covered

- **`ai-instruction-poisoning`** (`agentsec/guards/ai_instruction_poisoning.py`), rule
  `auto-approve-enabled`: `autoApprove: true` in a Claude Code settings file removes the
  confirmation gate, so a prompt injection reachable through any tool call redirects the agent's
  objective straight into unrestricted execution (CVE-2025-53773) — the textbook goal-hijack shape.
- Checklist: `4-human-in-the-loop`.

### ASI02 — Tool Misuse & Exploitation → covered

- **`mcp-tool-description-injection`** (`agentsec/guards/mcp_tool_description_injection.py`): an
  adversarial MCP server embeds injection payloads in a tool's own description/schema, steering the
  model into unintended tool calls via metadata it reads as trusted (research cited in the guard:
  79%+ tool-call compliance even where a plaintext version of the same instruction is refused).
- **`tool-callback-enforcement`** (`agentsec/guards/tool_callback_enforcement.py`), rules
  `no-interrupt-before` / `destructive-tool-no-confirm` / `explicit-approval-disabled`: a tool call
  — including a destructive one — that runs with no confirmation gate, or an approval gate
  explicitly turned off, is a legitimate tool bent toward an illegitimate outcome via unsafe chaining.
- Checklist: `4-mcp-tool-description-injection`, `4-human-in-the-loop`.

### ASI03 — Identity & Privilege Abuse → covered, stays `partial`

- **`plugin-security`** (`agentsec/guards/plugin_security.py`), rules `tool-no-auth-check` (PLG003)
  / `tool-shared-service-identity` (PLG008): an `@tool` function acts on a caller's behalf using a
  shared, static service credential rather than the end-user's own scope — the confused-deputy
  pattern this category names directly.
- Checklist: `4-agent-identity-propagation`. Left `status: partial` deliberately — the same
  genuinely-partial gap the checklist item records (no per-function workload identity across
  agentsec's own tooling either), not a new finding.

### ASI04 — Agentic Supply Chain Vulnerabilities → covered

- **`mcp-config-security`** (`agentsec/guards/mcp_config_security.py`), rules
  `dangerous-exec-command` / `dangerous-env-hijack-var`: a compromised or malicious MCP server
  component achieves code execution the moment it is spawned, purely from its own config entry
  (CVE-2025-54136, CVE-2026-22688, CVE-2026-44995) — no prompt injection required.
- **`mcp-tool-unverified`** (`agentsec/guards/mcp_tool_unverified.py`): an MCP server auto-loaded
  without trust attestation is an unvetted agentic component entering the pipeline.
- Checklist: `4-mcp-tool-trust`, `4-mcp-config-security`.
- Deliberately **not** tagged: `python-supply-chain` / `js-supply-chain`. Those guards are generic
  dependency-integrity hygiene (apply to any Python/JS repo, `llm` feature not required) — already
  `OWASP-LLM:LLM03` — and tagging them ASI04 would misrepresent this taxonomy's specifically
  *agentic* framing (compromised frameworks/MCP servers/components an agent depends on at runtime,
  not a project's ordinary pinned-dependency hygiene).

### ASI05 — Unexpected Code Execution (RCE) → covered

- **`code-injection-eval-exec`** (`agentsec/guards/code_injection_eval_exec.py`): dynamic content
  reaching a bare `eval()`/`exec()` sink is the canonical "content becomes running code" shape.
- **`unsafe-deserialization`** (`agentsec/guards/unsafe_deserialization.py`): deserializing
  untrusted bytes (`pickle`/`yaml.load`/`torch.load`/Haystack `Pipeline.load`) executes arbitrary
  code as a side effect of loading — a sandbox-escape-shaped RCE primitive.
- Checklist: `3b-eval-exec-injection`, `3b-unsafe-deserialization`.

### ASI06 — Memory & Context Poisoning → covered

- **`agent-memory-security`** (`agentsec/guards/agent_memory_security.py`), rules
  `unsanitized-user-write` / `memory-to-system-prompt`: unsanitized content written into durable
  memory, and memory re-injected into a system prompt as trusted content — both the "malicious/false
  info the agent later treats as its own knowledge" shape this category names.
- **`agent-memory-user-scope`** (`agentsec/guards/agent_memory_user_scope.py`): an unscoped write
  lets an attacker poison the shared memory pool every user draws from.
- **`agent-memory-retention`** (`agentsec/guards/agent_memory_retention.py`): no retention TTL lets
  a poisoned or stale entry persist indefinitely and re-contaminate future sessions.
- **`dataset-injection`** (`agentsec/guards/dataset_injection.py`): a poisoned document indexed at
  ingest becomes "trusted" retrieved content on every future query (5 crafted docs among millions
  achieve 90%+ attack success).
- **`rag-isolation`** (`agentsec/guards/rag_isolation.py`), rule `vector-store-no-namespace`: a
  missing tenant/collection namespace lets one tenant's (potentially poisoned) content bleed into
  another tenant's retrieval context.
- Checklist: `4-agent-memory-write-validation`, `4-agent-memory-retention`,
  `4-rag-kb-adversarial-doc-gate`, `4-rag-isolation-controls`.

### ASI07 — Insecure Inter-Agent Communication → covered

- **`multi-agent-prompt-origin`** (`agentsec/guards/multi_agent_prompt_origin.py`), rule
  `unauth-agent-handoff`: an agent-handoff endpoint that accepts a relay parameter and forwards it
  into an LLM call with no source verification (HMAC, auth token, mTLS) lets any caller spoof an
  upstream agent's message.
- Checklist: `4-multi-agent-handoff-authentication`.

### ASI08 — Cascading Failures → open research item

No guard bounds blast radius when Agent A's bad output feeds unchecked into Agent B's action across
a chained, multi-agent pipeline. `agent-loop-circuit-breaker` only bounds one agent's *own*
iteration count — a different failure shape (a single agent looping) from a bad decision propagating
*outward* across agent boundaries with no circuit breaker between them. Needs its own research pass
before a guard shape is proposed; tracked as its own problem row (not silently folded into this
reconciliation) so it is not lost as "already handled."

### ASI09 — Human-Agent Trust Exploitation → open research item

No guard checks whether a target application's own approval UI can be gamed by the agent controlling
what is shown at approval time (the rubber-stamp risk this category names). agentsec's own `fix
--write` diff-preview flow was checked directly during the triage and is safe — `text`,
`diff`, and `write` all derive from the same computed value, so there is no TOCTOU gap for an agent
to exploit there — but that is a self-check, not a general detection guard for third-party
approval-UI code. Needs its own research pass; tracked as its own problem row.

### ASI10 — Rogue Agents → intentionally out of static-analysis scope (WONTFIX)

An agent operating outside policy while still *appearing* legitimate, and persisting undetected, is
runtime behavioral drift — there is no static source-code shape to pattern-match against; it is a
property of what the agent *does* over time in production, not what its code says. Same class of
reasoning agentsec already applies to the poisoned-embeddings residual (LLM08: "runtime/ML,
not statically detectable"). Static analysis can raise the cost of a rogue agent forming in the
first place (least-privilege identity per ASI03, confirmation gates per ASI02, memory hygiene per
ASI06) but cannot detect one that has already formed — that is a runtime observability/anomaly
detection problem, a different tool from agentsec's repo-static posture. Documented here explicitly
so the absence reads as a scoped decision, not an oversight.

## Sources

- https://genai.owasp.org/ — OWASP GenAI Security Project, Top 10 for Agentic Applications 2026
- `agentsec/checklist/checklist.json`, `agentsec/guards/` (this repo) — the mapped guards and
  checklist items cited above, verified by reading each guard's source, not assumed from its name
- `research/owasp-llm-2025.md` — the sibling reconciliation this pass mirrors (#259)
