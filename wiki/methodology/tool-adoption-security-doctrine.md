---
type: Methodology
title: Tool Adoption Security Doctrine
description: The three-tier trust model governing adoption of external scanners and rule packs, ensuring agentsec's trusted base cannot be weakened by a compromised dependency.
tags: [methodology, security, runners]
timestamp: "2026-06-10T00:00:00Z"
---

# Tool-Adoption Security Doctrine

How agentsec adopts external scanners and rule packs **without weakening its own trust**. Read this
before wiring any new runner, rule pack, or plugin.

## Why this is different for a security tool

agentsec tells people "your app is safe." So the worst failure is not a false alarm — it is the
opposite: a **false all-clear**, where a real hole is missed and the report says "clean." Anything we
depend on to make a finding is part of our trusted base. If that thing is compromised, broken,
out-of-date, or absent, a critical finding can silently disappear.

**The governing rule:** *agentsec must not depend on anything for a critical finding that it would not
let a user depend on.* We hold ourselves to the supply-chain, determinism, and liveness standards we
ask users to meet.

## The risks of leaning on external tools / rule packs

1. **Supply chain.** Each plugin/tool is a dependency; a compromised version runs code during
   install/scan. (The same risk our own supply-chain guards warn users about.)
2. **Rule poisoning + non-determinism.** Rules fetched from a network registry at run time can change or
   be poisoned, and the same code can scan differently on two days. That breaks "deterministic and
   reproducible per version."
3. **Silent breakage.** A tool that stops firing looks exactly like a clean repo — the dead-lint /
   false-all-clear failure mode the canary exists to catch.
4. **Exfiltration.** Every scanner reads the user's source; a compromised one could leak it.

## The layered trust model

Cover each control at the highest tier that is practical.

- **Tier 1 — our dep-free, sandboxed, deterministic guards (the trust anchor).** Every **critical** and
  every **differentiating** control (e.g. authorization wiring, agentic controls, payments business
  logic) is a guard we own: stdlib-only, Guard-Sandbox-Contract-clean (no network/os/subprocess),
  canary-proven live. A critical control's detection must **never** rest solely on an external source.
- **Tier 2 — vendored, reviewed rules.** For patterns we want from Semgrep/ESLint, **author and pin the
  rules in our own pack** (as with `agentsec/ai/semgrep-rules/`), reviewed and version-controlled — not
  `--config p/<registry>` fetched at run time. Restores determinism and removes the poisoning vector.
- **Tier 3 — optional external tools as pinned accelerators.** For breadth where vendoring is impractical
  (e.g. Supabase Splinter's RLS catalog, an IaC scanner's rule set): pin the version, run it, treat its
  findings as **advisory breadth** — never the sole proof of a critical control.

## The adoption checklist (apply to every new tool / rule pack)

1. **No sole external trust for a critical control.** It also has a Tier-1 guard or is downgraded to
   advisory.
2. **Vendor + pin rules.** No runtime registry fetch.
3. **Pin the tool version** and vet it like any dependency (the cooldown/supply-chain standard we preach).
4. **Curate the rule allowlist.** Enable the precise rules; explicitly disable the noisy ones (e.g. broad
   "object-injection"-style heuristics) so the report stays low-false-positive.
5. **Validate before trusting.** Run against the flagship + the precision/recall benchmark; keep only
   rules that produce zero false positives on the corpus.
6. **Prove liveness.** Extend the canary to any tool we rely on, so a silently-broken tool is reported
   DEAD, not "clean."
7. **Run network-isolated.** External scanners get no egress, so a compromised one cannot exfiltrate the
   user's code.
8. **Record versions.** The exact tool + rule-pack version goes in the report, so a scan is auditable and
   reproducible.

## Build vs vendor vs adopt — the quick decision

- **Build (Tier 1)** when the control is critical, is our differentiator, or the available tool rule is
  too noisy to trust.
- **Vendor (Tier 2)** when a precise pattern exists and we can express it as our own reviewed rule.
- **Adopt (Tier 3)** when a mature tool gives broad coverage we cannot practically reproduce — pinned,
  validated, canary-proven, and never the lone detector of a critical control.

The curation + validation is the value agentsec adds *on top of* the raw tools. Anyone can run a
scanner; the point is running the right rules, proven low-false-positive, mapped to the checklist, with
the critical core owned and provably live.

## Related

This is the **inbound-dependency** counterpart to the execution guardrails in [operating-doctrine](operating-doctrine.md):
Tier-2's "vendor + pin, no runtime registry fetch" and the checklist's "run network-isolated" are the
adoption-time mirror of **G5** (no phone-home) and **G2** (the Guard Sandbox Contract); Tier-3's
"advisory breadth, never the sole detector" is the runners-are-optional posture (missing binary → skip).
The "false all-clear" it guards against is P4 (absence is a control) from [security-thinking-model](security-thinking-model.md),
and the canary-liveness requirement is B6 coverage-honesty from [security-audit-behaviors](security-audit-behaviors.md).
