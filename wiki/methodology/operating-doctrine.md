---
type: Methodology
title: Operating Doctrine
description: The two-clock model, determinism guarantees, guardrails (G1–G6), and two-persona human-in-the-loop policy that keep agentsec safe for non-expert users.
tags: [methodology, security, load-first]
timestamp: "2026-06-27T18:55:16Z"
status: active
last_updated: 2026-06-27
load_first: true
---

# Operating Doctrine

**LOAD-FIRST** alongside [security-thinking-model](security-thinking-model.md). The system rules that keep agentsec
deterministic, autonomous-but-bounded, and safe for non-expert users. Where the thinking model and
[fable-security-fundamentals](fable-security-fundamentals.md) govern *how to find vulnerabilities*, this governs *how the system
runs*.

---

## The Two-Clock Model (resolves "deterministic" vs. "always current")

Two clocks at different speeds. Determinism is a property of each *within its clock*.

- **Slow clock — INTAKE** (non-deterministic, model + web, grows the registry). Trend research
  *proposes* checklist items. Output varies run-to-run because the world changes. That is fine —
  its only output is a versioned artifact a human approves. Bounded by idempotence (G4) and the
  maintainer gate.
- **Fast clock — EXECUTION** (100% deterministic, runs on users' repos). `audit` / `coverage` /
  `fix` run against a **pinned registry version**. Same repo + same version → byte-identical
  output. No network, no LLM, no clock-dependence.

Intake *advances the version* (v1.4.1 → v1.4.2); execution is reproducible *against* a version.
Every report stamps `checklist vX.Y.Z (sha256:…)` so any run reproduces exactly. This is why
"super deterministic" and "autonomously current" don't conflict.

---

## Determinism Guarantees

| Invariant | Enforcement |
|---|---|
| Same repo + registry version → identical findings | Guards are **pure functions** of file bytes (no time, env, or network). Enforced by the Guard Sandbox Contract (G2) |
| Stable output ordering | Findings sorted by `(severity_rank, location, rule)` before emit; `iter_files` returns sorted paths. Two-run byte-identical test |
| Reproducible audit | Report header stamps registry version + `sha256(checklist.json)` + agentsec version; `--registry-version` pins older versions |
| No hidden clock-dependence | Exceptions expiry (`review_by`) is the ONE allowed time input — passed explicitly, stamped in the report |
| Auditable growth | `checklist.json` is semver-versioned with a changelog; every item carries `provenance` (source, advisory id, model id, approver, date) |

---

## Guardrails (G1–G6)

The system reads untrusted repo + web content, generates executable checks, and writes to users'
files. Each surface is guardrailed.

- **G1 — Untrusted input is data, never instructions.** Repo files and fetched advisories are inert
  text. The CLI pattern-matches, never interprets, so it is injection-immune by construction. Skills
  run only on trusted invocation.
- **G2 — Guard Sandbox Contract** *(the critical control)*. A generated guard is Python imported
  into the audit process — a poisoned one would run on every scan. So every `agentsec/guards/*.py`
  must pass an AST scan: allowed imports only (`re`, `pathlib`, `dataclasses`, `typing`,
  `__future__`, `agentsec.*`); banned: `os`, `subprocess`, `socket`, any network, `open(...,'w')`,
  `eval`, `exec`, `__import__`, `pickle`. This makes determinism + injection-immunity *structural*
  against the literal call/import shapes it bans. **Said plainly: G2 is a tripwire
  against careless capability use in first-party reviewed code, not a jail or an isolation
  boundary** — it is a banlist, and a banlist's inherent weakness is that an unlisted bypass slips
  through. Confirmed-open residuals as of the #888 pass: name-rebinding a banned call
  (`_e = eval; _e(...)`), class-hierarchy gadget chains
  (`().__class__.__bases__[0].__subclasses__()`), reflection via `__globals__`/
  `loader.load_module`, and file writes that don't spell `open(` (`pathlib.write_text`,
  `io.FileIO`, `tempfile`). (`builtins`-module reflection was itself closed by the #888 pass —
  verified live against `guard_sandbox.evaluate()` — not a residual.) Closing all of
  them needs a fail-closed import *allowlist*, not more
  banlist patching (see `agentsec/guard_sandbox.py`'s own docstring) — tracked separately, not blocking,
  since it doesn't change what G2 already closes.
- **G3 — Fix write-safety.** Never modifies `.github/`, CI/workflow files, lockfiles, secret-pattern
  files, or paths outside the repo (enforced by `fix._is_safe_target`: in-repo `.py` only). Diff-size
  cap (`fix._MAX_DIFF_LINES`). git is the restore point — a `--write` prints the `git restore` undo.
  Allowlist of fixable rules only (`fix.FIXERS`).
- **G4 — Bounded autonomy.** Intake caps proposals per run (**≤5**, enforced in the deterministic
  core by `intake.cap_proposals` / `MAX_PROPOSALS_PER_RUN` — not just skill prose; overflow is
  deferred, logged, never dropped), dedups against a seen-ledger (idempotent), and writes only to a
  proposals PR branch — never the live registry. The cap lives in code, so a flood is structurally
  impossible.
- **G5 — Egress is off by default, tiered, and disclosed.** Out of the box `agentsec audit` makes
  **zero** network calls (Tier 0; verified by the import scan — all `urllib`/`socket`/`http` use is
  confined to `agentsec/net.py`, the single chokepoint, enforced by `tests/test_net_sandbox.py`).
  Any egress is **opt-in per tier** (1 = public-advisory fetch, *dependency names only* — e.g. `--kev`;
  2 = scan-data to a third party), routed through `net.py`, **disclosed in the manifest** before it
  happens (`agentsec network` shows it), and **overridable by `DO_NOT_TRACK=1`** (forces Tier 0).
  The **external scanners that phone out are tier-gated too** (RFC #135 Phase 2): pip-audit (→ OSV),
  node-audit (→ npm), trivy (DB fetch), and react-doctor (npx tool fetch) carry a `tier_required` and
  are **skipped at Tier 0** — disclosed in the report ("scanners skipped (offline)"), never run — so
  Tier 0 is genuinely offline, not just for first-party calls. react-doctor is local-only at every
  tier: `--no-telemetry` blocks its Score API egress and the runner disables the Socket supply-chain
  PURL lookup, so it sends **no scan data** even at Tier 1+.
  Explicitly-networked subcommands (`live`, `deps-monitor`, `setup`) are inherently Tier 1+ — invoking
  them is the opt-in — but still route through `net.py`. "Absence = skip, never auto-download" still
  holds at Tier 0. There is **no** Tier that sends agentsec *usage* analytics — only the user's chosen
  scan/advisory operations. Full policy: the maintainers' network-egress RFC. The inbound-dependency
  analogue — how we adopt external tools/rule packs without weakening our own trust — is
  [tool-adoption-security-doctrine](tool-adoption-security-doctrine.md) (layered trust: own guards / vendored rules / pinned advisory tools).
- **G6 — Suppression is user-controlled config, never an engine name-rule.** A false positive is
  silenced only through config that lives in the *target* repo and that a user could apply to their
  own: an inline `# security: allow-*` pragma, a `# nosec` / `# nosemgrep`, or the expiring exception
  registry (`agentsec-exceptions.json`). The audit *engine* must never bake in a filename/path
  heuristic (e.g. "always skip `canary.py`") — that ships to every user and would silently hide real
  findings in *their* identically-named file. This is F1/F3 (semantic, not metadata-blind heuristics)
  applied to suppression itself, and the reusable lesson of the dogfood self-audit triage,
  where agentsec's own guard-source + canary false
  positives were suppressed entirely via repo-local config. North star: the durable fix is **guard
  precision** (B5 — adversarial FP-bait), not perpetual suppression.

---

## Human-in-the-Loop — Two Personas, Seven Rules

Two different humans, two different gates.

- **MAINTAINER gate** (grows the tool): approves proposed checklist items (the slow clock's one
  decision) and merges factory-built guard PRs. Reviews *judgment*. This is the project maintainer.
- **END-USER gate** (runs the tool): approves changes to *their own code*. Reviews *actions*, never
  judgment.

Seven rules for the end-user experience:

1. **Never ask a non-expert a security-judgment question.** Only action questions: apply this diff? skip? snooze?
2. **Plain language only** (`remediation_plain`); jargon stays in maintainer docs.
3. **Severity routing:** CRITICAL/HIGH → "fix recommended now" (CI-blocking); MEDIUM → "should fix"; LOW → informational.
4. **Escalation:** a finding neither auto-fixable nor plain-language-explainable → "recommend a human security review", finding bundled. Never dump jargon and leave.
5. **Default report-only;** `--write` is explicit opt-in (`agentsec fix` previews a diff; `--write` applies).
6. **Every applied fix is reversible** (git is the restore point; `--write` prints the `git restore` undo).
7. **Honest coverage always shown** (P5): the report states what was NOT checked for this stack — no green-dashboard false confidence.

---

## Related
[security-thinking-model](security-thinking-model.md) · [fable-security-fundamentals](fable-security-fundamentals.md).
