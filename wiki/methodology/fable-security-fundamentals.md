---
type: Methodology
title: Fable Security Fundamentals
description: The five operating fundamentals (F1–F5) that define how a Fable-class model applies security thinking to guard authoring and review.
tags: [methodology, security, load-first]
timestamp: "2026-06-10T00:00:00Z"
status: active
last_updated: 2026-06-10
load_first: true
---

# Fable Security Fundamentals (F1–F5)

**LOAD-FIRST** for guard authoring and review. These are *how a Fable-class model applies* the
[security-thinking-model](security-thinking-model.md) (P1–P5). Each fundamental yields a concrete rule and is enforced by a
specific agentsec component.

The division of labour: Fable does F1–F3 at **authoring time** (research, triage, guard writing,
FP-hunting); the CLI executes deterministically at **run time**. Determinism is F5 in action — a
guard that passed its verifiers once is trustworthy forever, at zero marginal cost, zero drift.

---

## F1 — Semantic detection, not pattern-matching
- **Implements:** P1 (adversarial), P2 (trust boundaries)
- **The rule:** Read code like a researcher. Trace data source→sink *across files*; check configs,
  factories, and helpers, not just the flagged line. Apply *variant analysis*: every known bug is a
  hypothesis — "where else does this sibling pattern live?"
- **Why it matters:** Pure pattern-matching (the SAST failure mode) produces 70–92% false positives
  because it can't see context. Semantic tracing is what cuts that to single digits.
- **Enforced by:** the global-check pattern (e.g. csv-injection checks for `safe_cell` anywhere
  before flagging per-site); lethal_trifecta's cross-file inventory.

## F2 — Exploitability over presence
- **Implements:** P2, P4
- **The rule:** A pattern is not a finding. Ask: can an attacker reach it? With what privilege?
  What data is at risk? **Confidence ≥ 8/10 or discard.** Auto-exclude noise categories: DoS,
  rate-limiting, open-redirect, generic input-validation without proven impact.
- **Why it matters:** Noise destroys trust (see the shift-left debate). One finding that wastes a
  non-expert's attention costs more than a missed nit.
- **Enforced by:** the `confidence` field + ≥8 gate in `checklist.json`; severity routing; N/A
  suppression via `applies_when`.

## F3 — Adversarial self-verification
- **Implements:** P1, P5
- **The rule:** Before shipping, actively try to *disprove* the guard. Generate false-positive bait
  fixtures (commented-out code, test fixtures, the mitigation present in a helper, env-guarded
  variants) and confirm it stays silent. Generate evasion variants (whitespace, aliased imports,
  indirect assignment) and document which evade. Evidence = `file:line`, never inference from
  naming. Be **metadata-blind**: never let comments or descriptions frame the judgment.
- **Why it matters:** The documented LLM weakness is *confirmation bias* — framing code as "safe"
  cuts detection 16–93%. Metadata-blindness recovers ~69–94% of missed detections.
- **Enforced by:** the guard factory's adversarial pass (replaces per-guard human review); the
  four-question guard-design rubric.

## F4 — Minimal, non-blocking remediation
- **Implements:** P3
- **The rule:** Propose the smallest fix that closes the hole. Never half-apply. If a fix needs
  human judgment (e.g. which CORS origins are valid, which JWT algorithm), say so and stay
  report-only rather than guess. Pivot gracefully when a hypothesis fails.
- **Why it matters:** A wrong auto-fix is worse than no fix — it breaks trust and can introduce
  bugs. Honesty about what *can't* be safely auto-fixed is the feature.
- **Enforced by:** the `agentsec fix` fixer contract (`fix() -> str | None`; None = skip); the
  fixable-rules allowlist; diff-first default.

## F5 — Trust is built in stages
- **Implements:** P3, P5
- **The rule:** Benchmark on known-answer cases → focused exploration → earn trust → bulk scale.
  Prefer real-time *verifiers* (tests, planted-violation fixtures, the regression corpus) over
  human spot-checks.
- **Why it matters:** It's why determinism isn't a compromise — a verified guard needs no
  re-checking. It's also why the guard factory is first validated on *known-spec* guards
  (supabase-service-role, jwt-alg-pinning) before novel trend items.
- **Enforced by:** the regression corpus (clean→0, vulnerable→caught); pytest + ruff + mypy gates;
  staged rollout of autonomous intake (manual runs before scheduling).

---

## Sources
`claude-code-security-review` (confidence threshold, adversarial verify, file:line evidence);
Anthropic Firefox campaign (benchmark-then-scale); Big Sleep (variant analysis, graceful pivot);
the confirmation-bias literature. See [llm-audit-methodology](../research/llm-audit-methodology.md).
