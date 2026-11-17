---
type: Research
title: Jev (TypeSafe AI) — Decision Models and Where They Fit agentsec
description: What TypeSafe AI's Jev "System One" decision model is, why a Rust rewrite is not what it asks for, how the Jev-based SAST tool JAST differs from agentsec, and the five candidate integration surfaces ranked against agentsec's own egress and determinism doctrine.
tags: [research, llm, agentic, triage, egress, decision-models, jev]
timestamp: "2026-10-05T00:00:00+08:00"
---

# Jev (TypeSafe AI) — Decision Models and Where They Fit agentsec

## What this covers

A community thread asked two things: "have you considered refactoring agentsec in Rust and
function-calling Jev?" and "how could we incorporate Jev?". This page answers both from primary
sources so the next person does not have to re-derive it. It records what Jev is, what the Rust
association actually refers to, how the one Jev-based SAST tool that exists (JAST) differs from
agentsec, and which of five possible integration surfaces survive agentsec's existing doctrine —
the egress tiers (G5 / RFC #135), the fast-clock "no network, no LLM" rule, and the accepted
RFC decision that LLM triage is *pipe-out, not build-in*.

This is a research record, not a plan. Nothing here is scheduled.

## What Jev is

Jev is TypeSafe AI's **decision model** ("System One model"), released 2026-09-15. It is a model,
but not a generative one: it never returns text. The caller supplies a `state` (any text or
semi-structured blob) and one or more **typed questions**; the model returns a probability per
option. Three question types exist:

| Type | Caller supplies | Model returns |
|---|---|---|
| `noul` | a yes/no statement | one number in [0, 1] — the *yes* probability (no separate confidence) |
| `choice` | a closed set of named options with descriptions (`criteria: {key: description}`) | the chosen key, a probability per option, a `confidence` |
| `score` | an ordered rubric (`criteria: [level0, level1, …]`) | a probability-weighted numeric score, the distribution, a legend, a `confidence` |

The hosted API is `POST https://api.typesafe.ai/v1/systemone` with `Authorization: Bearer
$TYPESAFE_API_KEY`; models are `jev-latest` / `jev-1.13.x`. It is also served through OpenRouter
(`POST /api/alpha/decisions`, model `typesafe/jev-1.13`). Official SDKs exist for Python
(`typesafe-sdk`) and JavaScript; the raw HTTP shape is trivially callable from stdlib `urllib`.
Pricing is $0.042 per million input tokens with output unmetered; one independent benchmark
measured ~$0.000017 per call and a client-side p50 of ~380–420 ms.

**Evidence, not vendor claims.** The vendor's launch multipliers (193× faster, 444× cheaper,
"zero hallucinations") are not independently reproduced anywhere we found. The one hands-on
benchmark that matters for security work classified 60 hand-labelled Kubernetes agent tool
calls into `readonly / destructive / privileged / exfiltration`: 91.7 % overall, 100 % on the 34
clear cases, 71.4 % on the 14 ambiguous ones, 91.7 % on 12 adversarial "benign-sounding wrapper"
cases. The operationally useful finding was **calibration**: every wrong answer came with
confidence below 1.000, and all 40 answers at exactly 1.000 were correct. That is what makes a
confidence *threshold* usable as a routing signal (auto-approve / block / human review) — on that
dataset, at n = 60, with no frontier-LLM baseline run.

**Known failure shape.** Jev is a black box that emits floats: there is no rationale for which
signal drove a decision, so bias and drift can only be found experimentally. A schema-valid
answer is not a safe answer — "allow at 0.97" on a malicious input is still a security failure.

## Why "Rust"? — what the association actually is

Rust is **not required** to use Jev and nothing about Jev argues for rewriting agentsec. The
association comes from three things that are easy to conflate:

1. **Language distribution.** Of the ~279 public repos tagged `jev-ai` (2026-10-05), Python has
   106, TypeScript 76, JavaScript 26, **Rust 16**, Go 15. Rust is a minority SDK language; the
   official SDKs are Python and JavaScript.
2. **`jev-rs`.** A Rust crate that is *not* a client for TypeSafe's hosted model — it is a local
   reimplementation that serves a Jev-compatible `POST /v1/systemone` from any LLM by scoring the
   log-probabilities of option-label tokens in one prefill, plus a stdio MCP server so coding
   agents can call it as a tool. Rust is the implementation choice for a latency-first local
   server; it is irrelevant to a *consumer* of the API.
3. **JAST** (`turenlabs/jast`, MIT, self-described "experimental"). A Jev-based SAST desktop app
   whose README says "Rust owns every deterministic mechanic: inventory, region bounds, hashing,
   consent and persistence," and Jev supplies the judgment. This is almost certainly the "SAST +
   Rust + Jev" shape the question had in mind. Rust is JAST's choice for a desktop-app shell; the
   deterministic mechanics it lists are exactly what agentsec already does in zero-dependency
   Python (`detect` → `select` → `run` → `normalize` → `suppress` → `emit`).

The honest reading of "refactor in Rust" is therefore "JAST did it in Rust." agentsec's hot path
is bounded file walks and regex/AST passes over a repo; it is not CPU-bound in a way a rewrite
would change, and a rewrite would forfeit the `pipx` channel, the Claude-skill channel and the
whole guard/test/wiki drift-gate estate for no detection gain. **Not recommended.**

## JAST vs agentsec — different tools, not competitors

| | JAST | agentsec |
|---|---|---|
| Detection source | **No rule library.** Asks Jev typed questions about bounded source regions (≤24 KiB, 30-line overlap, related files embedded as context ≤48 KiB) — e.g. `choice` over extracted call identifiers for `sink_pointer`/`source_pointer`, a 0–3 `score` for impact, a `noul` for "insufficient context" | Rule library: stack-aware guards + wrapped OSS scanners, each with a planted-violation test, an FP-bait test, a design doc and a checklist mapping |
| Egress | **Source code is uploaded** to `api.typesafe.ai`; explicit per-scan consent, immutable snapshot, SHA-256 request cache, keys in the OS keychain | **Offline by default** (Tier 0). Tier 1 fetches public advisories and sends nothing about your code. Tier 2 (scan data to a third party) is defined but never implemented |
| Determinism | Probabilistic; "findings are candidate signals, not verdicts"; "model scores are … not calibrated exploit probabilities" | Byte-identical output for same repo + same pinned checklist version (fast-clock rule) |
| Scope | Single-region; "cross-file taint tracking is not supported yet"; no whole-program dataflow | Cross-file resolvers for router auth / middleware registration; schema-state supersession for SQL; stack fingerprinting drives N/A suppression |
| Claimed accuracy | Youden's J "close to 80 %" on the OWASP Java Benchmark *with correct prompts* — "that is not what the app achieves today" | Measured per guard via corpus-scan FP/gap candidates and the triage ledger |

JAST's consent model is worth noting as the best-in-class **Tier 2 UX** we have seen: preview the
file/region counts and exclusion globs, show the exact snapshot, bind consent to that snapshot,
and never re-upload a request whose hash is cached. If agentsec ever implements Tier 2, this is
the reference shape for RFC #135's still-open consent questions.

## Decision gates as a security control — what the field says

Every security write-up on Jev converges on the same architecture, which agentsec should treat
as the *pattern to recognise and to audit*:

1. The agent proposes an action with its context.
2. Jev classifies risk and returns a confidence.
3. **Policy and permission checks** — not Jev — decide block / review / allow.
4. Only an authorised system executes.
5. Every decision is logged; **a model timeout or error defaults to paused**, never to allow.

The two named anti-patterns are **"judgment ≠ authorization"** (the classifier must never *be*
the permission mechanism; scoped credentials, approval gates and sandboxing stay mandatory) and
the **"confidence trap"** (a high score should route a workflow, not grant authority). Once an
attacker knows a classifier gates the action, its *inputs* become the target: context
manipulation, injected instructions, and chaining individually-benign decisions into an unsafe
whole. The OpenRouter cookbook's gate is the canonical shape — deterministic checks first (does
the order exist, is there refund balance), then three `noul` questions, approve only if all
≥ 0.9, block if any ≤ 0.1, otherwise human review, and "errors stop processing; a broken check
never silently approves."

The `jev-gateway` project shows the *other* use of Jev around agents — not a safety gate but a
**tool-selection router** (which tool should be called; closed-set arguments filled directly;
`JEV_MIN_CONFIDENCE` default 0.7; passthrough on low confidence or on any Jev failure). That is
a latency/cost optimisation with an explicit fail-*open* design, which is correct for routing and
would be wrong for a safety gate — a distinction a guard could check.

## Five candidate surfaces, ranked against agentsec doctrine

The constraints that bind, in order: RFC #135 decision #2 (2026-06-22, accepted) — *"`--llm-triage`
→ pipe-out, not build-in. No in-tool LLM call"*; the operating doctrine's fast clock — *"No
network, no LLM"* for `audit` / `coverage` / `fix`; G2 — guards are sandboxed and cannot import
network modules (`tests/test_net_sandbox.py` allows only `net.py`); and the never-implemented
Tier 2 consent mechanism.

| # | Surface | Egress | Doctrine fit | What it would take |
|---|---|---|---|---|
| 1 | **Offline recognition in target repos.** Teach `guardrail-architecture`, `lethal-trifecta` and `tool-callback-enforcement` that a decision-model tool-call gate (`typesafe_sdk`, `api.typesafe.ai`, OpenRouter `/decisions`, `jev-rs`) is a mitigation, so apps that gate with Jev stop drawing "no guardrail" findings | none | full | Extend `_GUARDRAIL_IMPORTS` / `_GUARDRAIL_CALL`; add a `tool_call_gating` key to the trifecta `_MITIGATIONS` and `has_any_injection_defense`; widen `_CONFIRM_PARAM` / `_APPROVAL_PATTERNS`. Both-direction tests per the review doctrine |
| 2 | **New guard: decision gate as sole authority.** Fire when a Jev/decision-model probability is the *only* thing between the agent and a destructive tool — no permission check in the enclosing span, no fail-closed branch on the API error, a threshold below the field's ≥ 0.9 norm, or a gateway-style fail-open used as a safety gate | none | full | Sibling of `guardrail-architecture` rule 4 (`scan-result-ignored`) and `tool-callback-enforcement` rule 2; `surfacing = True`; maps to `3c-llm-as-judge-output` / `14-guardrail-layer-present`; OWASP-LLM LLM01 / ASI |
| 3 | **Pipe-out triager.** A stdlib script or Claude skill reads `agentsec audit --format json`, asks one `choice` question per finding (`real / fp / guard-improvement`) and writes back via `agentsec triage --fingerprint … --verdict … --triaged-by jev:<model>` | user-run, outside the tool | full (this *is* decision #2) | No core change. Must never auto-write `fp` — that path feeds `--write-exception` and suppresses findings; write `pending` + reason unless confidence = 1.0, and even then a human confirms |
| 4 | **In-tool `triage --suggest`** calling `net.get(tier_required=2, …)` and storing `suggested_verdict` / `suggested_p` on `TriageVerdict` | Tier 2 | conflicts | Reopen RFC #135 decision #2; implement Tier 2 consent (open questions: headless CI consent, where consent is stored, destination/retention disclosure); add the `_EGRESS_CATALOG` row |
| 5 | **Audit-time enrichment stamp** (`Finding.jev_p`, re-rank-only like `kev` / `epss`) | Tier 2 | conflicts hardest | Best mechanical precedent (`epss.py`), worst doctrine fit: sends every finding off-box and makes the deterministic scanner non-deterministic |

Not viable: a `Runner` with `tier_required=2`. Runners require a binary on PATH and produce
findings; Jev produces verdicts about findings.

The one genuinely new idea Jev brings is **calibrated confidence as a routing signal**, which the
field's own benchmark says is only trustworthy at the extremes (1.000 was never wrong; the
ambiguous middle was 71 %). agentsec's triage model today has no confidence field at all —
`TriageVerdict` is `real / fp / guard-improvement / pending` plus free-text reason. If surface 3
or 4 is ever built, the probability should land in the *reason* or a tolerant extra field and the
verdict should stay human-owned, which is also what the RFC already says.

## Sources

- Simon Willison, *Jev introduces a new shape of LLM — System One, aka Decision Models* — <https://simonw.substack.com/p/jev-introduces-a-new-shape-of-llm>
- TypeSafe AI quick start (API shape, SDKs, pricing) — <https://docs.typesafe.ai/introduction/quickstart>
- OpenRouter cookbook, *Gate Agent Tool Calls with Jev* — <https://openrouter.ai/docs/cookbook/building-agents/gate-tool-calls-with-jev>
- Karo Zieminski, *AI Agent Security With Jev* (judgment ≠ authorization; confidence trap) — <https://karozieminski.substack.com/p/jev-ai-agent-security>
- *I Benchmarked Jev on Agent Tool-Call Risk. Calibration Held.* (DEV Community) — <https://dev.to/webofmike/i-benchmarked-jev-on-agent-tool-call-risk-calibration-held-49i3>
- `jev-rs` crate docs — <https://docs.rs/jev-rs/latest/jev_rs/>
- `turenlabs/jast` — <https://github.com/turenlabs/jast>
- `vinilana/jev-gateway` — <https://github.com/vinilana/jev-gateway>
- GitHub topic `jev-ai`, Rust slice — <https://github.com/topics/jev-ai?l=rust>
- Internal: the maintainers' network-egress RFC (decisions, 2026-06-22); `wiki/methodology/operating-doctrine.md` (fast clock, G2, G5); `agentsec/net.py` (the egress chokepoint)

## Coverage summary

| Pattern | agentsec today | Status |
|---|---|---|
| A decision-model tool-call gate recognised as a guardrail / HITL mitigation | `guardrail-architecture`, `lethal-trifecta`, `tool-callback-enforcement` do not know the Jev / OpenRouter-decisions / `jev-rs` shapes; an app gating with Jev can still draw "no guardrail" | **Gap — statically tractable** (surface 1) |
| Decision gate used as sole authority: no permission check, fail-open on error, sub-0.9 threshold on a destructive tool | Nearest rules: `guardrail-architecture/scan-result-ignored`, `tool-callback-enforcement` rule 2, `mcp-toolgate-asymmetry` | **Gap — statically tractable** (surface 2) |
| Fail-open tool-selection router (`jev-gateway` shape) wired in front of a safety-relevant tool | — | Gap — tractable once surface 2 exists |
| LLM/decision-model assisted finding triage | Deliberately pipe-out per RFC #135 decision #2; `3c-llm-as-judge-output` is `partial`; zero-trust crosswalk P4 marks automated triage "out of scope" | **By design** (surface 3 is the sanctioned shape) |
| Tier 2 scan-data egress with recorded consent | Defined in RFC #135, never implemented; JAST's preview → snapshot → bound-consent → hash-cache flow is the reference UX | Deferred — RFC open questions unresolved |
| Rewrite agentsec in Rust | — | **Not recommended**; no detection or performance case, forfeits three delivery channels and the drift-gate estate |
