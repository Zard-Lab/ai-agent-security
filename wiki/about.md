---
type: Overview
title: agentsec Knowledge Base
description: The methodology and threat-research behind the agentsec guards and checklist, explaining the why behind every check.
tags: [agentsec, knowledge-base, overview]
timestamp: "2026-06-10T00:00:00Z"
---

# agentsec Knowledge Base

The methodology and threat-research that the agentsec guards and checklist are designed against.
Load this first when designing a guard, triaging a new threat, or reviewing a finding — it's the
"why" behind the checks.

## Methodology (read-first for any guard / review / trend work)

| Page | What it covers |
|---|---|
| [methodology/security-thinking-model.md](methodology/security-thinking-model.md) | The five thinking patterns (P1–P5), the three contested debates + agentsec's stance, and a 10-question rote-vs-understanding test |
| [methodology/fable-security-fundamentals.md](methodology/fable-security-fundamentals.md) | The five operating fundamentals (F1–F5) — the rule each yields and the component that enforces it |
| [methodology/operating-doctrine.md](methodology/operating-doctrine.md) | The two-clock model, determinism guarantees, the guardrails (G1–G6), and the two-persona human-in-the-loop policy |
| [methodology/security-audit-behaviors.md](methodology/security-audit-behaviors.md) | The repeatable auditor behaviors (B1–B10) — questioning the label, exploitability-first severity, adversarial self-verification, coverage honesty — each mapped to the guard mechanism that encodes it |
| [methodology/tool-adoption-security-doctrine.md](methodology/tool-adoption-security-doctrine.md) | The layered-trust model for adopting external scanners/rule packs (Tier 1 own guards · Tier 2 vendored+pinned rules · Tier 3 pinned advisory tools) — the inbound-dependency counterpart to the guardrails; read before wiring any new runner or rule pack |

Every guard answers the same design rubric: see `wiki/guards/TEMPLATE.md`.

## Threat research (the evidence base + daily intake digests)

| Page | What it covers |
|---|---|
| [research/owasp-llm-2025.md](research/owasp-llm-2025.md) | OWASP LLM Top 10 (2025) — items, what changed, static detectability per item |
| [research/owasp-asi-2026.md](research/owasp-asi-2026.md) | OWASP Top 10 for Agentic Applications (2026) — ASI01-10, guard mapping for 7 categories, 2 open research items, 1 out-of-scope |
| [research/rag-security.md](research/rag-security.md) | RAG attack vectors: corpus poisoning, embedding inversion, multi-tenant leakage |
| [research/fastapi-supabase-vulns.md](research/fastapi-supabase-vulns.md) | FastAPI CVEs, Supabase RLS bypasses, service_role exposure |
| [research/supply-chain-secrets.md](research/supply-chain-secrets.md) | npm/PyPI supply-chain attacks, API-key leakage patterns |
| [research/llm-audit-methodology.md](research/llm-audit-methodology.md) | The evidence behind the fundamentals: claude-code-security-review rules, variant analysis, LLM-vs-SAST stats |
| [research/fable5-security-capabilities.md](research/fable5-security-capabilities.md) | Why a strong model fits the authoring-time work; defensive-vs-offensive routing |
| [research/jev-decision-models.md](research/jev-decision-models.md) | Jev / decision models — what it is, why not a Rust rewrite, JAST vs agentsec, five integration surfaces ranked against the egress + determinism doctrine |

**Daily intake digests** land in `research/intake-YYYY-MM-DD.md` — the dated record of new threats
the maintainers' slow-clock intake surfaced.

_Pages are append-mostly; the methodology pages are stable._
