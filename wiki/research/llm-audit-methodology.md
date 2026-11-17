---
type: Research
title: LLM Audit Methodology
description: Evidence base for the agentsec fundamentals, covering claude-code security review rules, variant analysis, and LLM-versus-SAST comparative effectiveness data.
tags: [research, llm, audit]
timestamp: "2026-06-10T00:00:00Z"
status: active
last_updated: 2026-06-10
captured: 2026-06-10
source: web research (Anthropic, Google Project Zero, arXiv, SAST-vs-LLM studies)
---

# LLM Security-Audit Methodology — the evidence

The published basis for the [fable-security-fundamentals](../methodology/fable-security-fundamentals.md). These are the repeatable mental moves
a strong security model makes, with the numbers that justify each.

## 1. claude-code-security-review (Anthropic's production audit rules)
Anthropic's open-source `/security-review` GitHub Action encodes the methodology we adopt:
- **Semantic over pattern:** "reads code the way a security researcher would" — traces data flow,
  catches logic/access-control flaws pattern tools miss.
- **Confidence threshold:** findings below ~8/10 confidence are filtered out.
- **Auto-exclude noise:** DoS, rate-limiting, memory/CPU exhaustion, open-redirects, generic
  validation without proven impact.
- **Adversarial verification pass:** each finding is re-examined to prove or disprove it.
- **Evidence standard:** explicit `file:line` citations, never inference from naming.
- **HIGH/MEDIUM focus:** "better to miss some theoretical issues than flood the report."
→ Sources F2, F3.

## 2. Confirmation bias — the documented LLM weakness
- Framing code as "bug-free" / "security improvement" **reduces detection 16–93%** across models.
- Stripping PR metadata recovers **~68.75%** of missed detections; explicit "ignore metadata"
  instructions push recovery to **~94%**.
→ Source of F3's metadata-blindness rule and Guardrail G1. (arXiv 2603.18740 and related.)

## 3. Variant analysis — Google Project Zero "Big Sleep" / Naptime
- Agents don't hunt open-ended; they start from a **fixed hypothesis** ("this was a bug here — where
  is the sibling?") and search for the same pattern elsewhere.
- Given real tools (code browser, debugger, sandbox) and a **verification loop**, they confirm with
  concrete crash signals, not theoretical concerns — and *pivot gracefully* when a hypothesis fails.
- First public AI-found exploitable memory-safety bug in real-world software (SQLite).
→ Sources F1 (variant analysis) and F4 (graceful pivot).

## 4. LLM vs SAST — why hybrid wins
- CodeQL false-positive rate ~**68%**; Semgrep ~**75%** on benchmark sets.
- LLM post-filtering / hybrid pipelines cut false positives from ~**92% → ~6%** and improve
  detection by ~**2.5×**.
- LLMs excel at semantic/business-logic/cross-file reasoning and novel-pattern generalization;
  deterministic tools win on mechanical patterns, consistency, and scale.
→ This is the core justification for agentsec's architecture: deterministic engine + model at
authoring time. Neither alone; both, in their right roles.

## 5. Trust built in stages — Anthropic Firefox methodology
- Benchmark on historical vulns → focused exploration of one subsystem → earn trust → bulk scale.
- The model performs best with **task verifiers** that let it check its own work in real time.
→ Source F5; also why the guard factory validates on known-spec guards first.

## Consensus: what LLMs are good / bad at
- **Good:** semantic + business-logic vulns, cross-file/config reasoning, novel patterns,
  exploitability assessment, iterative refinement with a verifier.
- **Bad:** confirmation bias under framing, consistency at scale (prompt/version drift), pure
  mechanical pattern detection (SAST is more reliable), cost on very large codebases.
→ The good list = the model's authoring-time job; the bad list = why run time stays deterministic.

## Sources
projectzero.google (Big Sleep); anthropic.com (security-review, Firefox); arXiv 2603.18740
(confirmation bias), 2412.12039, 2503.03586, 2601.22952 (LLM-vs-SAST, FP filtering); SAST-vs-LLM
CI/CD studies.
