---
type: Research
title: Fable 5 Security Capabilities
description: Analysis of why a strong LLM fits authoring-time security work, including defensive-versus-offensive routing decisions and capability boundaries.
tags: [research, llm, fable]
timestamp: "2026-06-10T00:00:00Z"
status: active
last_updated: 2026-06-10
captured: 2026-06-10
source: web research (Anthropic announcements, Project Glasswing, security press)
---

# Fable 5 — Security Capabilities

Why a Fable-class model is the right engine for the authoring-time work in the flywheel, and the
one important limit. Underpins [fable-security-fundamentals](../methodology/fable-security-fundamentals.md).

## What Fable 5 is
- Mythos-class model (tier above Opus 4.x), publicly released ~June 2026. Public **Fable 5** ships
  with safety classifiers; an unrestricted **Mythos 5** exists only for approved partners.
- Strong at agentic vulnerability work: reconnaissance, multi-step reasoning, exploit-chain
  construction (in research settings), and — most relevant to us — *defensive* code review and
  vulnerability detection.

## The capability, at scale
- The associated disclosure program reported **1,596 vulnerabilities across 281 open-source
  projects** by ~May 2026 (88 with CVE/GHSA assigned), found by Claude models and validated by
  external security firms before coordinated disclosure (Project Glasswing).
- Earlier, Claude Opus 4.6 found **500+ high-severity OSS vulns** by Feb 2026; the Firefox campaign
  alone produced 22 vulns in a single month across 6,000+ C++ files.

## The one limit that matters for us
- Public Fable 5 **safety-routes *offensive* cyber queries** to a more restricted model (happens in
  <5% of sessions). So for building exploits it won't outperform prior models.
- **agentsec is 100% defensive** — code review, vulnerability *detection*, remediation. That is the
  unrestricted sweet spot. We get full capability for exactly the work the flywheel needs.

## Why this shapes the design
- The model is genuinely strong at the *semantic, cross-file, exploitability* reasoning (F1–F3) that
  deterministic SAST can't do. That justifies the hybrid split: model at authoring time, frozen
  deterministic code at run time.
- The same research shows the model is *trained to follow instructions*, which is the root of the
  confirmation-bias and prompt-injection weaknesses — hence F3 metadata-blindness and Guardrail G1.

## Sources
- Anthropic — Claude Fable 5 / Mythos 5 announcement (anthropic.com/news)
- Anthropic — Coordinated Vulnerability Disclosure dashboard (red.anthropic.com/2026/cvd/)
- Anthropic — "Partnering with Mozilla to improve Firefox's security"
- ArmorCode / Wiz analyses of the Mythos disclosure program
