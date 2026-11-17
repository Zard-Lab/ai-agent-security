---
type: Research
title: Zero Trust for AI Agents (Anthropic) — agentsec Coverage Crosswalk
description: Anthropic's Zero-Trust-for-AI-Agents framework — its named agent threat landscape, three maturity tiers, eight-phase workflow, and Agentic SOAR — mapped control-by-control to what agentsec covers, partially covers, leaves manual, or does not cover, with each gap classified as statically tractable or out of static scope.
tags: [research, zero-trust, agentic, anthropic, coverage, gaps]
timestamp: "2026-07-12T00:00:00Z"
captured: 2026-07-12
source: Primary 36-page ebook PDF, read in full from disk (May 27 2026 ed.); claude.com/blog/zero-trust-for-ai-agents
---

# Zero Trust for AI Agents (Anthropic) — agentsec Coverage Crosswalk

Anthropic's **Zero Trust for AI Agents** (36-page ebook, May 27 2026) adapts Zero Trust —
*"trust nothing, verify everything, assume breach has already occurred"* (its three principles: **never
trust and always verify · assume breach · least privilege**, extended for agents by OWASP's **least
agency** and the **blast radius** concept) — to agentic systems. Its governing design test is
**"impossible, not tedious"**: prefer a control that *removes* a capability over one that merely throttles
it, because an agentic attacker has unlimited patience and near-zero per-attempt cost. The ebook is in
five parts: security considerations for autonomous systems (Part I), the current agent threat landscape
(Part II), a **three-tier** architecture — **Foundation → Enterprise → Advanced** — organized across
**seven capability areas** (Part III), an **eight-phase implementation workflow** (Part IV), and
**defensive operations / Agentic SOAR** (Part V), with compliance alignment for regulated industries
(HIPAA, FINRA, GDPR, FedRAMP, EU AI Act).

This page maps that framework onto agentsec. The one fact that governs the whole mapping is agentsec's
nature — it is a **static, deterministic, authoring-time, app-layer** auditor (see
[Scope — What agentsec Checks (and Doesn't)](../scope-and-boundaries.md)). So it maps *densely* onto
the framework's **code-structural** controls (input/output handling, supply-chain integrity, memory/RAG
isolation, least-agency) and is *deliberately silent* on the framework's **runtime / infrastructure**
controls (cryptographic agent identity, JIT/HSM token issuance, behavioral SOAR, dwell-time telemetry) —
the same boundary the scope page already draws against Promptfoo/Garak.

> Sourcing note: this page is written against the **full text of the primary 36-page ebook**, read
> from the PDF (the Anthropic CDN/blog hosts were egress-blocked in this environment, so the file was
> supplied directly and its text extracted locally). Part/tier/phase/threat/capability names below are
> **verbatim from the ebook**. An earlier draft of this page used the tier names "Foundation / Advanced /
> Optimized" from secondary write-ups — the primary source corrects that to **Foundation / Enterprise /
> Advanced**, and lists **seven** capability areas (including AI Governance Policies), now reflected here.

## Verdict legend

- **Covered** — a deterministic agentsec guard/runner asserts the control's structural condition.
- **Partial** — a guard fires on part of the control's surface (some sinks/patterns, not all).
- **Manual** — tracked as a checklist item but verified by a human/ops, no static check.
- **Gap (out of static scope)** — a runtime/infra control agentsec cannot see at authoring time (by design).

Statuses below are taken verbatim from `agentsec/checklist/checklist.json`; guard ids from
`agentsec/registry.py` / `agentsec/guards/`.

## Anthropic's named agent threat landscape → agentsec

The ebook's Part II names five agent-specific threats (per OWASP) — the most directly-sourced mapping on
this page. agentsec's coverage against each:

| Threat (Anthropic, verbatim) | agentsec coverage | Verdict |
|---|---|---|
| **Prompt injection** | `lethal-trifecta`, `input-delimiters`, `prompt-string-interp`, `string-format-injection`, `langchain-prompt-template-injection`, `rag-trust-boundary`, `rag-no-instruction-filter`, `3a-user-content-sanitized-before-llm`, `invisible-unicode` | **Covered (structural)** — agentsec's densest surface; flags the exploitable conditions, not runtime block-rate |
| **Tool & resource misuse** (tool poisoning, tool chaining, resource exhaustion) | `mcp-tool-description-injection`, `mcp-tool-unverified` (CVE floor), `mcp-config-security`, `agent-tool-overpermission`, `tool-callback-enforcement`, `agent-loop-circuit-breaker` (exhaustion) | **Partial/Covered** — poisoned tool descriptions + over-broad/unverified tools + loop-amplification caught statically; cross-tool *chaining* is a gap |
| **Identity & privilege abuse** | least-agency (`agent-tool-overpermission`, `4-agent-tool-allowlist`), §2b BOLA/authz, §7 RLS/tenant, `4-multi-agent-handoff-authentication` | **Partial** — privilege *shape* covered; runtime identity/token issuance is a gap |
| **Memory poisoning** | `agent-memory-security`, `agent-memory-user-scope`, `4-acp-minja-memory-injection`, `dataset-injection`, `rag-isolation` | **Covered** — write-validation + session isolation + RAG corpus-poisoning gates |
| **Supply chain** | `ml-model-provenance`, `slopsquatting`, `js/python-supply-chain`, `mcp-tool-unverified`, runners `pip-audit`/`node-audit`/`trivy`, SHA-pin/lockfile | **Covered (strong)** — deps, model downloads, connectors, lockfiles |

Four of the five named threats sit squarely in agentsec's wheelhouse; only **identity & privilege abuse**
is a partial — agentsec sees least-agency and authz *patterns*, not the runtime identity fabric.

## Unique agentic considerations → agentsec touchpoints

Anthropic names four considerations unique to agents; agentsec's relevant checks:

- **Tool access** — `agent-tool-overpermission`, `tool-callback-enforcement`, `mcp-*`
- **Autonomous decision-making** — `agent-loop-circuit-breaker`, `4-high-impact-action-confirmation` (manual), `4-human-in-the-loop`
- **Context persistence** — `agent-memory-security`, `agent-memory-user-scope`, `rag-isolation`
- **Multi-agent coordination** — `multi-agent-prompt-origin`, `4-acp-*` (relay tagging, handoff auth, memory-injection)

## Part III capability-area crosswalk (seven areas)

Part III organizes its controls into **seven capability areas**, each with a Foundation → Enterprise →
Advanced tier table. The seven are: agent identity & authentication, access control & privilege
management, observability & auditing, behavioral monitoring & response, input validation & output
controls, integrity & recovery, and **AI governance policies**. Below, each maps to agentsec (framework
control → agentsec check(s) → verdict); the headings are the ebook's verbatim area names.

### P1 — Agent Identity & Authentication
*Framework:* cryptographically-rooted agent identity (proof of what it is, who deployed it, what it may
do); short-lived OAuth tokens (minutes); phishing-resistant 2FA; JIT issuance with auto-expiry;
hardware-anchored identity (HSM) at higher tiers.

| Framework control | agentsec | Verdict |
|---|---|---|
| Cryptographic agent identity, 2FA, JIT/HSM issuance | — (runtime/infra identity broker) | **Gap — out of scope** |
| Inter-agent handoff authenticated | `4-multi-agent-handoff-authentication` (`multi-agent-prompt-origin`) | **Covered** |
| Agent/session tokens not hardcoded literals | `4-acp-org-token-not-literal`, `4-acp-hot-reload-token-invalidation` | **Covered** |
| Agent identity propagated to downstream calls | `4-agent-identity-propagation` (`plugin-security`) | **Partial** |
| User-auth token hygiene (adjacent, not agent identity) | §2a `jwt-alg`, `jwt-exp-too-long`, `jwt-claims-validated` | Covered/partial |

**Net: mostly a gap.** agentsec statically checks token *hygiene* and inter-agent handoff auth, but the
pillar's core — a cryptographic identity fabric with short-lived, JIT/HSM-anchored credentials — is a
deploy/runtime concern outside a static app auditor.

### P2 — Access Control & Privilege Management
*Framework:* permissions scoped **per individual task** (not RBAC), continuous revocation, role
isolation, sandboxing, least agency.

| Framework control | agentsec | Verdict |
|---|---|---|
| Least agency — agents not over-tooled | `agent-tool-overpermission`; `4-agent-tool-allowlist` | **Partial** |
| High-impact actions gated (human/allowlist) | `tool-callback-enforcement`; `4-high-impact-action-confirmation` | Partial / **Manual** |
| Model-generated code sandboxed | `4-codeexec-sandboxed` (`langchain-unsafe-chain`, `ai-docker`) | **Partial** |
| Runaway autonomy bounded | `agent-loop-circuit-breaker` | Partial |
| Tenant/row isolation, endpoint authz | §7 RLS guards, §2b BOLA/authz | Covered/partial |
| Per-task dynamic scoping + continuous revocation | — (runtime authorization) | **Gap** |

**Net: strong partial (static).** agentsec catches the *authoring-time* shape of least-privilege
(over-permissioned tools, ungated high-impact callbacks, unsafe code-exec chains). Dynamic per-task
scoping and continuous revocation are runtime.

### P3 — Observability & Auditing
*Framework:* structured logging of agent behavior/tool-calls/data-access; dwell-time metrics; agent
actions and **decision rationale** made visible.

| Framework control | agentsec | Verdict |
|---|---|---|
| Agent tool calls logged with identity/outcome | `4-agent-action-audit-log` (`agent-tool-audit-log`) | **Partial** |
| Sensitive data NOT logged (negative control) | `system-prompt-not-logged`, `llm-response-logged`, `sensitive-logging` | **Covered** |
| Structured log pipeline, dwell-time, rationale capture | §10 Logging & Monitoring (mostly manual) | **Manual / Gap** |

**Net: gap-leaning.** agentsec asserts the *negative* observability controls (don't log secrets/prompts)
and can check that tool calls are logged; the telemetry pipeline and dwell-time metrics are runtime/ops.

### P4 — Behavioral Monitoring & Response (Agentic SOAR)
*Framework:* anomaly detection, automated triage, security orchestration/automation/response fast enough
to contend with AI-accelerated attackers.

| Framework control | agentsec | Verdict |
|---|---|---|
| Independent guardrail layer exists (not self-check) | `guardrail-architecture`; `14-guardrail-layer-present` | **Partial** |
| Preventive loop/iteration bound (static analog) | `agent-loop-circuit-breaker` | Partial |
| Continuous red-team eval in CI | `14-continuous-eval-gate` | **Manual** |
| Runtime anomaly detection, automated triage, SOAR | — | **Gap — out of scope** |

**Net: gap.** This is the runtime SOC layer by definition. agentsec's static analogs are preventive
(bound the loop, require an independent guardrail); live detection/response is complemented by
Promptfoo/Garak and, in the flagship, the `dns-monitor` REFUSED-alerting loop.

### P5 — Input / Output Control
*Framework:* input isolation, output filtering, constitutional classifiers, prompt-injection
countermeasures.

| Framework control | agentsec | Verdict |
|---|---|---|
| Untrusted input isolated/delimited before prompt | `input-delimiters`, `prompt-string-interp`, `string-format-injection`, `langchain-prompt-template-injection`, `3a-user-content-sanitized-before-llm` (ChatML tokens) | **Covered** |
| Retrieved content treated as untrusted | `rag-trust-boundary`, `rag-no-instruction-filter`, `rag-isolation` | **Covered** |
| LLM output not executed / rendered / used as sink | `llm-output-to-sink`, `llm-output-html-sink`, `markdown-render-xss`, `llm-json-output-unvalidated` | **Covered** |
| System-prompt leakage filtered | `system-prompt-leak` | **Covered** |
| PII redacted around the model | `pii-llm-roundtrip` | Partial |
| Obfuscated-injection scan (Glassworm) | `invisible-unicode` | **Covered** |
| Lethal-trifecta architectural assessment | `lethal-trifecta` | **Covered** |
| Constitutional classifier actually blocks a jailbreak at runtime | — (runtime behavior) | **Gap — Promptfoo/Garak** |

**Net: this is agentsec's densest and strongest surface.** The nuance: agentsec verifies the
*structural conditions* for a defense (unwrapped input, missing filter, an unsafe sink), not that a
runtime classifier blocks a specific payload — that live proof is the Promptfoo/Garak layer.

### P6 — Integrity & Recovery
*Framework:* signature verification, AI-BOM (AI Bill of Materials), supply-chain integrity, memory
protected against poisoning, recovery.

| Framework control | agentsec | Verdict |
|---|---|---|
| Supply-chain integrity (deps, models, connectors) | `ml-model-provenance`, `slopsquatting`, `js/python-supply-chain`, `pip-audit`/`node-audit`/`trivy`, `mcp-tool-unverified`, SHA-pin/lockfile | **Covered** |
| Memory protected against poisoning | `agent-memory-security`, `agent-memory-user-scope`, `4-acp-minja-memory-injection`, `dataset-injection` | **Covered** |
| AI-BOM (AI Bill of Materials) generated | `14-ai-asset-inventory` (model cards) | **Manual / Gap** |
| Model-weight signature verification | — (ROADMAP-excluded) | **Gap — out of scope** |
| Recovery / rollback of a compromised agent | — | **Gap** |

**Net: mixed.** The supply-chain and memory-poisoning legs are strong (a real agentsec strength). AI-BOM
generation (the ebook points at **OWASP's AI-BOM**, a CycloneDX ML-BOM extension), model/config signature
verification, and recovery/rollback are gaps — some consciously excluded (see
the maintainers' ROADMAP out-of-scope list: model-weight protection, fine-tuning/RLHF
poisoning — the ebook cites Anthropic's own "250 malicious documents backdoor an LLM, persists through
RLHF" research for exactly this class).

### P7 — AI Governance Policies
*Framework:* documented acceptable-use + incident-response policies, addressing Shadow AI (Foundation) →
formal governance framework with cross-functional oversight (Enterprise) → continuous policy enforcement
with automated compliance checking wired into deployment pipelines (Advanced).

| Framework control | agentsec | Verdict |
|---|---|---|
| AI asset inventory / model cards | `14-ai-asset-inventory` | **Manual** |
| Independent guardrail layer present | `14-guardrail-layer-present`, `guardrail-architecture` | **Partial** |
| Continuous eval / policy gate in CI | `14-continuous-eval-gate` | **Manual** |
| Incident runbook + human accountability | `14-ai-incident-runbook`, `14-human-oversight-accountability` | **Manual** |
| Automated policy enforcement in pipelines | — (org process) | **Gap** |

**Net: mostly manual.** §14 (NIST AI RMF / CISA) is agentsec's least-automated area — governance is an
org-process concern; agentsec surfaces the checklist items but leaves them to human review.

## Part IV — eight-phase implementation workflow (verbatim) → agentsec

| # | Phase (ebook, verbatim) | agentsec |
|---|---|---|
| 1 | **Identify requirements** (regulatory, operational, constraints) | §14 governance — **manual** |
| 2 | **Manage supply chain risks** (AI-BOM, OpenSSF Scorecard, signing, reachability) | **Strong** (§5, `ml-model-provenance`, supply-chain guards); AI-BOM *generation* itself a **gap** |
| 3 | **Define agent boundaries** (approved/prohibited actions, scope limits, blast radius) | **Partial** (`agent-tool-overpermission`, `4-agent-tool-allowlist`, `tool-callback-enforcement`) |
| 4 | **Defend against prompt injection** (input isolation, constitutional classifiers, spotlighting) | **Strong** (§3b, §4 I/O guards) |
| 5 | **Secure tool access** (allow-listing deny-by-default, parameter validation, sandbox) | **Partial** (`agent-tool-overpermission`, `tool-callback-enforcement`, `mcp-*`) |
| 6 | **Protect agent credentials** (short-lived, hardware-bound, JIT, ABAC, per-agent isolation) | **Gap** (runtime identity/creds); only token-literal-in-config is statically adjacent |
| 7 | **Safeguard agent memory** (session/user isolation, integrity validation, retention TTL) | **Covered/partial** (`agent-memory-user-scope`, `agent-memory-security`, `4-agent-memory-write-validation`) |
| 8 | **Measure what matters** (dwell time, coverage, explainability, detection speed) | **Manual/gap** (§10; `4-agent-action-audit-log` partial) |

Phases **2, 4, 7** are where agentsec is strongest; phases **6 and 8** (credentials, measurement) are
where it is weakest — runtime identity and runtime observability, out of static scope.

## The three tiers — Foundation → Enterprise → Advanced

Each tier *strengthens* the one before, not replaces it. The ebook stresses the **Foundation floor has
been raised** by AI-accelerated offense: short-lived tokens, cryptographically-rooted identity,
identity-based isolation, and automated first-pass triage are now *entry* requirements — friction-only
controls (key rotation, non-standard ports, SMS MFA) no longer qualify.

- **Foundation** (minimum viable / small teams) — crypto agent IDs, RBAC deny-by-default, static
  least-privilege, identity-based isolation, short-lived OAuth tokens, comprehensive action logs,
  version-controlled configs, documented policies.
- **Enterprise** (the target for most orgs) — X.509 cert auth, ABAC, dynamic privilege, sandboxed
  execution (gVisor), immutable audit trails, distributed tracing, signed configs, automated rollback.
- **Advanced** (high-risk / regulated) — HSM/TPM hardware-anchored identity + attestation, continuous
  authorization, JIT/JEA, hardware isolation (AMD SEV / Intel TDX, microVMs), SIEM streaming, self-healing.

agentsec sits at the **Foundation** layer's *code-structural* shape (least-agency, sandboxing signals,
token/config hygiene). It does not verify the identity issuance, dynamic authorization, or hardware
anchoring that define Enterprise/Advanced — those are runtime/infra, out of static scope.

**Compliance.** The ebook names **HIPAA, FINRA, GDPR, FedRAMP, the EU AI Act**, and Anthropic's **ISO
42001** certification. agentsec tags §9 findings with **PCI-DSS** and §14 with **NIST AI RMF**, but has no
HIPAA / SOC2 / FedRAMP mapping — compliance-framework tagging is a documented
the maintainers' ROADMAP scale-gap.

## Gap ledger — named & classified

### Statically tractable (candidate future guards / checklist items)
These are gaps a static app auditor *could* learn to see; they are pointers for
`checklist-proposed-additions` /
`guard-roadmap` (archived) — not authored here.

- **Agent-token short-lifetime** — extend the `jwt-exp-too-long` idea to agent/service tokens (flag long
  or absent expiry on agent credentials in config).
- **Agent-config token literals** — a hardcoded agent/org token in agent or MCP config (adjacent to
  `4-acp-org-token-not-literal`, `mcp-config-security`; could broaden).
- **AI-BOM as a static artifact enumerator** — emit an AI Bill of Materials (models, prompts, tools,
  connectors, datasets) from what the repo declares — turning manual `14-ai-asset-inventory` into an
  assisted artifact.
- **Guardrail-layer-present hardening** — strengthen `guardrail-architecture` / `14-guardrail-layer-present`
  toward the framework's independent-classifier expectation.
- **Agent-action-audit-log completeness** — push `4-agent-action-audit-log` from partial toward covered
  (identity + outcome on every tool call).

### Consciously out of static scope (runtime / infra — the honest boundary)
Aligned with [scope-and-boundaries](../scope-and-boundaries.md) (Promptfoo/Garak complement) and the
the maintainers' ROADMAP exclusions:

- Cryptographic **agent identity**, **JIT/HSM** token issuance, phishing-resistant **2FA** (P1).
- Dynamic **per-task scoping** + **continuous revocation** (P2).
- **Behavioral SOAR** / runtime anomaly detection & response, **dwell-time** telemetry (P3, P4).
- Whether a **constitutional classifier** actually blocks a jailbreak at runtime (P5) — Promptfoo/Garak.
- **Model-weight signature verification**, RLHF/fine-tuning poisoning, recovery/rollback (P6).

## Bottom line

agentsec covers the **code-structural half** of Zero-Trust-for-agents: Input/Output Control (P5) in depth,
the supply-chain and memory-poisoning legs of Integrity & Recovery (P6), and the static least-agency shape
of Access Control (P2). It is, by design, the **static complement** to the **runtime/identity/governance
half** — Agent Identity (P1), the Observability pipeline (P3), Behavioral Monitoring / Agentic SOAR (P4),
and AI Governance (P7) — which belong to a deploy-time identity fabric, a runtime detection/response stack
(Promptfoo/Garak, dns-monitor, an agent SOC), and org process, not to a static app auditor. A team adopting
the framework should read a clean agentsec scan as "the *code-structural* Zero-Trust controls are in
place," and pair it with runtime identity brokering, monitoring, red-team eval, and governance for the rest.

## Sources

**Primary:** the **36-page ebook** *Zero Trust for AI Agents* (Anthropic, May 27 2026), read in full from
the PDF — parts, tiers, capability areas, phases, threats, and principles are quoted verbatim from it. The
Anthropic CDN/blog hosts were egress-blocked in this environment, so the file was supplied directly and
its text extracted locally.

- [Zero Trust for AI agents — Claude by Anthropic (blog summary)](https://claude.com/blog/zero-trust-for-ai-agents)
- Secondary syntheses consulted before the primary was available (note: several **mis-named the middle
  tier** as "Optimized" — the primary source says **Enterprise**): Varonis, Pomerium, pasqualepillitteri,
  Sprinto.
