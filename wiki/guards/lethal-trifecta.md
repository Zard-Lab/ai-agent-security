---
type: Guard
title: "lethal-trifecta"
description: "Lethal-trifecta architecture review."
timestamp: "2026-06-12T10:08:45Z"
guard_id: "lethal-trifecta"
checklist_section: ["3a", "3b", "4"]
standards: ["OWASP-LLM:LLM01", "OWASP-LLM:LLM02", "OWASP-LLM:LLM05", "OWASP-LLM:LLM06", "OWASP-LLM:LLM07", "OWASP-LLM:LLM08", "OWASP:A01", "OWASP:A03", "OWASP:A10"]
---

# Lethal-trifecta architecture review

_Backfilled 2026-06-12 — documents Dean's guard to the shared guard-design convention._

---

## The threat

Simon Willison's **"lethal trifecta"**: an LLM agent is at risk of data exfiltration when it
simultaneously has all three of —

1. **private data** access (user rows, RAG corpus, secrets),
2. exposure to **untrusted content** (web pages, emails, uploaded docs, tool output), and
3. the ability to **communicate externally** (HTTP calls, sending email, webhooks).

With all three, a prompt-injection payload hidden in the untrusted content can instruct the
agent to read private data and send it out — no code vulnerability required, just the
*composition* of capabilities. This is **OWASP-LLM:LLM01 (Prompt Injection)** at the
architecture level. The point of the guard is **P5 — security is compositional**: the bug lives
*between* correct components, so no single-file check finds it.

## Why this guard fits the stack

`9_Agent_SaaS` is exactly this shape: Supabase private data + a RAG/agent ingesting untrusted
documents + outbound tool calls. The guard is the highest-value LLM-specific check in the tool —
it inventories the three legs and the mitigations and tells a human/the `/security` skill
*where to look*.

## Detection design

The guard is a thin wrapper (`LethalTrifectaGuard`) over the `agentsec/ai/lethal_trifecta.py`
analyzer.

1. **`applies()` gate** — `"llm" in profile.features`.
2. **`assess(root, profile)`** scans files for the three **legs** (`_LEGS`) and the expected
   **mitigations** (`_MITIGATIONS`) — RAG sanitization, system-prompt-leak filter, output
   guardrails, SSRF URL validation, per-user scoping. Leg detection is intentionally **broad**;
   mitigation detection is **specific**. RLS in SQL counts as per-user scoping.
3. **`to_findings()`** emits, by severity:
   - **HIGH** `lethal-trifecta/no-defense` — all three legs present AND no injection defense at
     all (LLM01).
   - **MEDIUM** `lethal-trifecta/missing-<mitigation>` — full trifecta but a specific mitigation
     absent (e.g. `missing-ssrf-validation` LLM02/A10; `missing-per-user-scoping` LLM08/A01).
   - **LOW** `lethal-trifecta/untrusted-no-defense` — incomplete trifecta (untrusted content
     present) but no injection defense — a "watch this" signal.
4. It also prints a reasoning **scaffold** consumed by the `/security` skill.

## When NOT to flag (why it's conservative)

When any leg is genuinely absent, or when the expected mitigations are detected, the high/medium
findings don't fire. The design is deliberately **broad on legs, specific on mitigations**: it
would rather point at an architecture that *might* be exposed than miss one — but it does not
claim exploitation. There's no inline pragma; the human/skill confirms.

## Tests

In `tests/test_ai.py` (the `assess()` logic is tested here, not in the per-guard `tests/guards/` location):

| Test | What it checks |
|---|---|
| `test_trifecta_active_no_defense_is_high` | all three legs, no defense → HIGH |
| `test_trifecta_with_mitigations_no_high_no_defense` | full trifecta but mitigations present → no HIGH |
| `test_incomplete_trifecta_untrusted_only_is_low` | only untrusted-content leg → LOW |
| `test_scaffold_has_sections` | the printed reasoning scaffold has its expected sections |
| `test_guard_applies_only_for_llm` | `applies()` True only when `llm` feature present |

## Known bypasses

- **Heuristic leg detection** — legs are inferred from code patterns; an app that reaches
  private data or external comms through an unrecognized library/indirection can read as
  "leg absent" (false negative).
- **Mitigation by appearance** — a detected mitigation is matched by pattern, not proven
  effective; a present-but-broken sanitizer still suppresses the finding.
- **Cross-service composition** — legs split across microservices/repos the single-repo scan
  doesn't see together.

## What this guard does NOT prove

That the agent *is* (or is not) exploitable. It is an **architectural pointer**: it inventories
capability composition and flags missing defenses to direct human review. It does not trace an
actual injection→read→exfiltrate path, and "silent" means "the trifecta isn't all present, or
expected mitigations were detected" — not "this agent is safe."

## 2026-08-22 — §3b closure clarified: this guard is no longer the sole check_id

`3b-llm-output-sanitized` used to map to this guard alone, so it only fired at HIGH when the
**full** trifecta was active (private data + untrusted content + external comms), and only LOW
("watch this") when solely the untrusted-content leg was present. That misses the much more
common single-endpoint shape — an LLM-backed route handler that hands the raw model response
straight to the client (an `exec`/`eval`/`os.system`/`subprocess` sink, an LLM-derived SQL
`execute()`, or an unescaped `Markup()`/`HTMLResponse()`/`mark_safe()` HTML sink) with **no**
private-data leg and **no** external-comms leg at all, so the trifecta heuristic never engages.

That exact deterministic, line-level detection already existed as two purpose-built, canary-verified
sibling guards — [[llm-output-to-sink]] and [[llm-output-html-sink]] — gated only on `llm` +
an LLM-call-in-file provenance check, with no trifecta dependency. They were already mapped to the
near-duplicate item `4-llm-output-sanitized` (§4) but not to `3b-llm-output-sanitized`, even though
this doc's own citation [3] below named 3b as a target this guard only *partially* closes.
`checklist.json`'s `3b-llm-output-sanitized.check_ids` now lists all three guards (mirroring what
`4-llm-output-sanitized` already had), and its `status` flipped `partial` → `covered`. No new
detection code was added to this guard or the two sinks guards — the fix was checklist wiring, not
a new pattern.

# Citations

[1] agentsec checklist item `3a-ssrf-guard` (§3a)
[2] agentsec checklist item `3a-user-content-sanitized-before-llm` (§3a)
[3] agentsec checklist item `3b-llm-output-sanitized` (§3b)
[4] agentsec checklist item `4-lethal-trifecta-assessment` (§4)
[5] agentsec checklist item `4-llm-output-sanitized` (§4)
[6] agentsec checklist item `4-rag-chunks-treated-untrusted` (§4)
[7] agentsec checklist item `4-rag-scoped-to-user` (§4)
[8] agentsec checklist item `4-system-prompt-leak-filter` (§4)
[9] OWASP-LLM:LLM01
[10] OWASP-LLM:LLM02
[11] OWASP-LLM:LLM05
[12] OWASP-LLM:LLM06
[13] OWASP-LLM:LLM07
[14] OWASP-LLM:LLM08
[15] OWASP:A01
[16] OWASP:A03
[17] OWASP:A10
