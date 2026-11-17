---
type: Overview
title: Scope — What agentsec Checks (and Doesn't)
description: What agentsec detects, what it deliberately doesn't, and how it complements runtime tools like Promptfoo and Garak.
tags: [agentsec, scope, positioning, promptfoo, garak]
timestamp: "2026-07-05T00:00:00Z"
---

# Scope — What agentsec Checks (and Doesn't)

agentsec is a **static, deterministic** security audit tool. It reads your source code,
config, and dependency manifests before anything is deployed, and reports what it finds
— the same input always produces the same output, and by default it makes zero network
calls. Knowing exactly where that boundary sits matters more for a security tool than
for almost any other kind of software, so this page states it plainly rather than
leaving it implied.

## What agentsec does

- Detects code patterns that make prompt injection *exploitable* — missing input
  delimiters, unsanitized retrieval content, unfiltered system-prompt leakage paths.
- Detects agent tool registrations with excessive or unchecked permissions.
- Detects unsafe handling of LLM output — code execution, HTML rendering, file paths,
  or SQL built from a model's response.
- Detects secrets, supply-chain issues, and classical web vulnerabilities (auth,
  injection, XSS, SSRF, misconfigured RLS) in the same scan.
- Tells you honestly what it could not check for your stack — every guard that
  doesn't apply is reported as **Skipped (N/A)**, not silently omitted, and a stack it
  recognizes but has no guards for yet is reported as **detected but not covered**
  rather than reading as clean.

## What agentsec does not do

- **Track a value across functions or files (taint analysis).** agentsec matches patterns.
  It reasons about a dangerous call and the arguments it is given on the same line, in the
  same statement, or inside a bounded window of the same file, and about structural facts
  like which router a route is mounted on. It does not follow a value from where it enters
  your application to where it is finally used, so a request parameter that is assigned to a
  variable, passed through two helpers, and only then concatenated into a query is not
  connected up the way a dataflow engine (Sonar, CodeQL, Bearer) connects it. The trade is
  deliberate: pattern matching needs no build, no compilation, and no project graph, which is
  what lets the guards run with zero runtime dependencies and stay usable in a pre-commit
  hook. It also means a same-line detection is a floor on the real exposure, never a ceiling.
  If whole-program taint matters for your codebase, run a dataflow tool alongside agentsec
  rather than instead of it; the "different failure classes" argument below applies here too.
- **Test runtime model behavior.** agentsec reads code; it never calls an LLM to see
  how it actually responds to an attack. That's a fundamentally different kind of
  test — see the comparison below.
- **Confirm that a prompt injection actually succeeds.** It flags the structural
  conditions that make exploitation possible (an unwrapped input, a missing filter),
  not a live proof that a specific payload got through.
- **Cover data/model poisoning or misinformation as behaviors.** These are
  training-time or model-behavior concerns, not something visible in application code
  at deploy time.
- **Scan model weights, fine-tuning datasets, or RLHF data.**
- **Judge business-logic or authorization correctness.** agentsec detects *patterns*
  (a privileged field written straight from a request body, a route with no visible
  auth dependency) — it can't know your actual authorization policy.
- **Replace a human penetration test** for a critical application. It's a fast,
  repeatable first pass, not a substitute for one.

## agentsec vs. runtime testing tools (Promptfoo, Garak)

agentsec, [Promptfoo](https://www.promptfoo.dev/), and [Garak](https://github.com/leondz/garak)
solve genuinely different problems, and agentsec's own CI/live-scan layer wires both
in as optional components rather than treating them as competitors:

| | agentsec | Promptfoo / Garak |
|---|---|---|
| What it examines | Your source code, config, dependencies | Your **deployed, running** model/agent |
| How | Static pattern matching — deterministic, same input → same output | Sends live probes/adversarial prompts and observes the actual response |
| Answers | "Is this code structured in a way that makes an attack possible?" | "Does the model actually fall for this attack, right now?" |
| When it runs | Before deploy — in CI, in a pre-commit hook, on a laptop, fully offline by default | Against a running endpoint — needs the model or agent live |
| Example finding | No input-delimiter wrapping before a retrieval-augmented prompt | The deployed agent revealed its system prompt when asked directly |

Neither layer replaces the other. A clean agentsec scan means the code doesn't contain
the structural mistakes that are visible without running anything — it is not a claim
that the deployed model resists every prompt-injection attempt. Static analysis and
runtime red-teaming catch different failure classes, and a serious LLM-facing
deployment benefits from both: agentsec to catch structural mistakes before they ship,
Promptfoo/Garak to confirm the deployed behavior actually holds up.

## What this means in practice

Run agentsec on every commit — it's fast, offline, and deterministic, so it belongs in
CI. If you're shipping an LLM-facing product, also run Promptfoo and/or Garak against a
real deployment before and after release; agentsec already exposes both as CI
components and as part of `agentsec live` for exactly this reason. Treat a clean
agentsec scan as "the code doesn't contain the mistakes we know how to detect
statically," never as "this application is safe against prompt injection."
