---
type: Methodology
title: Security Audit Behaviors
description: Ten repeatable auditor behaviors (B1–B10) encoding expert security reasoning into agentsec, from adversarial questioning through exploitability-first severity to coverage honesty.
tags: [methodology, security, audit]
timestamp: "2026-06-10T00:00:00Z"
---

# Security-Audit Behaviors — what a strong model auditor does, and how the guards encode it

The repeatable reasoning behaviors that make a frontier model a strong *defensive* security auditor,
and the agentsec mechanism that turns each behavior into a deterministic check. This sits one level
below the thinking model ([security-thinking-model](security-thinking-model.md), P1–P5) and the fundamentals
([fable-security-fundamentals](fable-security-fundamentals.md), F1–F5): those say *how to think*; this names the *moves* and where
each one lives in the tool.

## Why a model-class auditor is the right foundation

- **Defensive review is the sweet spot.** Code review, vulnerability detection, and remediation are
  where a frontier model runs at full capability — exactly agentsec's scope (100% defensive).
- **It generalizes.** Large-scale defensive disclosure programs (thousands of real vulns across
  hundreds of OSS projects) show the reasoning goes beyond pattern-matching.
- **Hybrid beats either half.** Deterministic scanners alone carry ~70–92% false positives; a model
  semantic layer cuts that toward single digits and roughly doubles real detection. The winning shape
  is **model-as-author + deterministic-runtime** — which is this project's architecture.

## The foundation (one stance)

A security auditor **models an adversary, not a user.** It never asks "does this work?" — it asks
"what does this let someone do that they shouldn't, and can they *reach* it?" The model's edge is
doing this **semantically and across files** (config + code + tests + docs together), which
pattern-only tools cannot.

---

## The behaviors — and the mechanism that encodes each

### B1 — Don't trust the label; question the framing
Re-derive a judgment instead of accepting the existing one. *Example:* an SSRF control scoped
`applies_when: ["llm"]` silently marks SSRF — a **general** web vulnerability — N/A for every
non-LLM app; the audit move is to question that scoping, not accept it.
→ **Encoded as:** the guard-design rubric's "when should this NOT fire / what does it NOT prove"
sections, and a periodic `applies_when` audit of item scoping.

### B2 — Exploitability-first severity
Severity = exploitability × blast-radius × reachability *on this stack* — never the API name alone.
SSRF that can reach a cloud-metadata endpoint is critical (credential theft → whole account); the
same primitive in unreachable code is not.
→ **Encoded as:** a confidence ≥ 8/10 gate; severity graded by impact-and-reachability, not anchored
to the existing value.

### B3 — Trust-boundary localization
Bugs live where untrusted data crosses into trusted execution; audit the crossings, not the
interiors (user→server, doc→prompt, service→service, dependency→build).
→ **Encoded as:** the lethal-trifecta architectural check; guards target boundary patterns (CORS,
RLS, service-role exposure, prompt-input wrapping).

### B4 — Variant analysis
Every known bug is a hypothesis: "where *else* does this sibling pattern live?"
→ **Encoded as:** the global-check pattern (e.g. a CSV guard checks for the safe-wrapper anywhere
before flagging per-site); the threat-intake loop treats each new advisory as "find the sibling in
this stack."

### B5 — Adversarial self-verification
Before reporting, try to *refute* your own finding; evidence is a file:line citation, never an
inference from a name.
→ **Encoded as:** the guard-factory's false-positive bait fixtures — a guard must stay silent on
code that merely *looks* like a violation. This is the single strongest false-positive defense.

### B6 — Coverage honesty / falsifiability
A clean scan proves nothing about absence. State plainly what a check does **not** prove.
→ **Encoded as:** the `covered`/`partial`/`manual` status, the coverage notes that document each
partial's boundary, and a score card that shows what is *not* checked for a given stack. No
green-dashboard illusion.

### B7 — Cross-modal reasoning
Read code + config + tests + docs *together* — the bug is often in the seam (the code looks safe but
the config says otherwise).
→ **Encoded as:** detect → stack-profile → run only relevant checks; guards, scanner runners, and
ingested external reports all merge into one finding model.

### B8 — Calibration over alarm (noise discipline)
A finding that wastes a user's trust costs more than a missed nit. Low-impact noise (DoS,
rate-limiting, open-redirect, generic input-validation without a proven path) is auto-excluded.
→ **Encoded as:** N/A suppression, a HIGH/MEDIUM focus, and the confidence gate. Low-noise is the
core trust property.

### B9 — Plain-language translation
Explain a finding the way one engineer explains it to another — and, for non-experts, in everyday
terms without losing the threat mechanism.
→ **Encoded as:** a plain-language remediation field and human-in-the-loop rules that only ever ask
a non-expert an *action* question (apply this fix?), never a *judgment* question (is this
exploitable?).

### B10 — Authoring-time intelligence, runtime determinism
The deepest move: do the *thinking* once, when a check is written; ship *frozen, predictable* code
that runs on users' repos. Smart at authoring, deterministic at runtime.
→ **Encoded as:** the two-clock model ([operating-doctrine](operating-doctrine.md)) + the Guard Sandbox Contract
(generated checks are pure — no network, no `eval`), making determinism structural rather than a
promise.

---

## What "best-in-class" means here (the honest bar)

Not "catches every bug" — no tool does. For securing AI-built apps it means the *combination*:
**low-noise · exploitability-calibrated · honest about its own blind spots · deterministic and
reproducible · self-growing with the threat landscape · usable by someone with no security
background.** Each behavior above is one ingredient of that bar, frozen into a check that runs the
same way every time.

## Sources

Anthropic's defensive-security research and the open-source `claude-code-security-review` rules
(confidence threshold, adversarial verification, file:line evidence), Google Project Zero's
variant-analysis work (Big Sleep / Naptime), and the LLM-vs-SAST false-positive literature — see
[llm-audit-methodology](../research/llm-audit-methodology.md) and [fable5-security-capabilities](../research/fable5-security-capabilities.md).
