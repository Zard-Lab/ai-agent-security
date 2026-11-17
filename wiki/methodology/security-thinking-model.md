---
type: Methodology
title: Security Thinking Model
description: The five adversarial thinking patterns (P1–P5) underlying every agentsec guard, plus recorded stances on the three contested security debates.
tags: [methodology, security, load-first]
timestamp: "2026-06-10T00:00:00Z"
status: active
last_updated: 2026-06-10
load_first: true
---

# Security Thinking Model

**LOAD-FIRST** for any guard-design, trend-research, or review session. This is the constitution —
the patterns underneath every concrete check. The Fable operating fundamentals ([fable-security-fundamentals](fable-security-fundamentals.md))
are *how* a model applies these; the [operating-doctrine](operating-doctrine.md) is *how the system stays safe and
deterministic* while doing so.

---

## The five thought patterns (what all experts converge on)

| # | Pattern | Essence | How agentsec embodies it |
|---|---|---|---|
| **P1** | **Adversarial asymmetry** | Defenders think in lists; attackers think in graphs. One path suffices to attack; *all* paths must close to defend. Audit by asking "how do I abuse this?", never "is this correct?" | Guard design starts from the exploit, not the happy path |
| **P2** | **Trust boundary analysis** | Every vulnerability is untrusted data/actor crossing a trust boundary unmediated. Audit the *crossings* (user→server, doc→prompt, service→service), not the interiors | lethal-trifecta, cors-wildcard, public-table-rls, supabase-service-role |
| **P3** | **Assume breach / defense in depth** | No single control is reliable. Design each layer assuming the outer one already failed. A mitigation in exactly one place is a single point of failure, not a defense | Expiring exceptions (no silent forever-ignores); layered audit + fix |
| **P4** | **Absence is the strongest control** | What doesn't exist can't be exploited. Every feature, dependency, permission, and default route is attack surface. The safest permission is the one never granted | api-docs-exposed, supabase-service-role, N/A suppression |
| **P5** | **Security is compositional** | Vulnerabilities emerge *between* correct components (the lethal trifecta is exactly this). The weakest link governs. And: testing proves the *presence* of flaws, never their absence | lethal_trifecta architectural check; honest coverage reporting |

---

## The three contested debates — and agentsec's recorded stance

Experts disagree loudest on these. Recording our stance stops us relitigating them and explains
design choices to contributors.

### Shift-left vs "shift-left failed"
- **Argument A:** Fixing at design time is ~100× cheaper than in production.
- **Argument B:** SAST's 70–92% false-positive rates destroyed developer trust — *noise* killed shift-left, not the idea.
- **Our stance — noise-disciplined shift-left.** Shift-left is right; noise is the failure mode. Hence confidence ≥8 gate, N/A suppression, auto-excluded noise categories, HIGH/MEDIUM focus. A finding that wastes a non-expert's trust costs more than a missed nit.

### Automation vs human expertise
- **Argument A:** ~90% of real compromise is known CVEs and misconfigurations — scale and automation win.
- **Argument B:** Tools only find what they're told to; green dashboards breed false confidence.
- **Our stance — hybrid with honest boundaries.** Deterministic guards for mechanical patterns; the model (authoring-time) for semantic/compositional analysis; the human for risk acceptance. AND the tool must state what it does NOT check (coverage report shows `manual` items — no green-dashboard illusion).

### Disclosure ethics at AI scale
- **Argument A:** Fast disclosure forces fixes.
- **Argument B:** 90-day coordination protects users; and mass AI-found vulns can DoS volunteer maintainers.
- **Our stance — consumer, not discloser.** agentsec consumes *published* advisories via trend intake. If our own research ever uncovers a novel vuln in a real project, follow coordinated disclosure (90-day standard) and never publish exploitation detail in checklist items.

---

## The 10-question understanding test (rote vs. understanding)

Ten litmus questions where a rote learner and a real practitioner give visibly different answers.
Used operationally as: the guard-design doc rubric (Q3/Q5/Q9/Q10), the `remediation_plain` quality
bar, and the trend-triage filter (every proposed item must state its trust boundary + exploitability).

**1. Why is a CSRF token unnecessary for a header-authenticated JSON API?**
- *Rote:* "CSRF tokens are always required."
- *Understanding:* CSRF exploits the browser *automatically* attaching ambient credentials (cookies) to cross-site requests. If auth rides in an `Authorization` header that JavaScript must set explicitly, an attacker's page can neither set it nor read it cross-origin — the browser itself is the control. CSRF tokens matter when a *cookie* carries the session, not a header token. (P2)

**2. A scanner reports 200 SQL-injection findings. First move?**
- *Rote:* "Start fixing all 200."
- *Understanding:* 200 findings rarely means 200 bugs. Find the shared *source* — usually one unsafe query helper or one missing-parameterization pattern reused everywhere. Triage the rule, fix the root, and 200 collapse to one. (F1 variant analysis)

**3. Is `eval(user_input)` always critical?**
- *Rote:* "Yes — eval is always critical."
- *Understanding:* Severity = exploitability × blast radius × decay. `eval` on attacker-reachable input in a privileged server context is critical; in a local dev script no attacker reaches, or on values provably constant upstream, it may be low or N/A. Reachability and context set severity, not the API name. (F2)

**4. A team "fixed" SQL injection by encrypting the database. What's wrong?**
- *Rote:* "Encryption is good, so they're safer now."
- *Understanding:* The control doesn't match the threat. SQLi runs through the app's *own authorized* connection — the DB decrypts for the app, so the attacker reads plaintext. Encryption-at-rest defends a stolen disk, not injection. The right control is parameterized queries.

**5. When is it correct NOT to fix a finding?**
- *Rote:* "Always fix everything."
- *Understanding:* Security is risk management. A finding with negligible exploitability, high fix cost, and a compensating control may be correctly *accepted* — but the acceptance must be explicit, owned, and time-bound (it expires and resurfaces). That is exactly the expiring exception registry. (P3)

**6. A dependency scan shows zero CVEs. Are the dependencies secure?**
- *Rote:* "No known CVEs means they're safe."
- *Understanding:* Scanners see only the *published past*. Zero CVEs means nothing is known-and-disclosed *yet* — not that the code is safe. Supply-chain attacks (typosquats, compromised maintainers) often have no CVE at all. Absence of findings is not evidence of safety. (P5)

**7. Why do authentication bypasses cluster *between* services rather than inside them?**
- *Rote:* "Bugs are random / they're in the auth code."
- *Understanding:* Identity is minted and re-validated at *translation points* — gateway→service, service→service, token re-issue. Each hop re-interprets identity; mismatches in how each side parses and trusts it open gaps. The interior is usually consistent; the seams diverge. (P2)

**8. All user input is validated for prompt injection. Is the app safe from it?**
- *Rote:* "We sanitize user input, so it's handled."
- *Understanding:* Direct user input is one channel. *Indirect* injection rides in via retrieved documents, tool outputs, emails, and web pages the model reads — all of which become the same token stream the model obeys. Validating the typed prompt does nothing about a malicious instruction inside a retrieved doc. (P5; OWASP LLM01/LLM08)

**9. Login is rate-limited, yet accounts get credential-stuffed. How?**
- *Rote:* "Rate limiting stops brute force, so we're protected."
- *Understanding:* Per-account / per-IP limits are evaded by spreading thin — password *spraying* (one guess across millions of accounts), distributed botnet IPs, and sibling endpoints (mobile API, token refresh, password reset) that share the credential store but not the limiter. One control, not a defense. (P3)

**10. The scan found nothing. Is the system secure?**
- *Rote:* "The scan passed, so it's secure."
- *Understanding:* Testing proves the *presence* of flaws, never their absence. "Found nothing" means "these specific checks didn't fire on this version" — bounded by what the checks know. Security is a claim about all possible inputs; a clean scan is a statement about the few you tried. Never conflate them, and always say what you did NOT check. (P5)

---

## Sources

OWASP LLM Top 10 (2025); Anthropic `claude-code-security-review` methodology; Google Project Zero
"Big Sleep"; the LLM confirmation-bias literature. Full detail in [llm-audit-methodology](../research/llm-audit-methodology.md) and
[fable5-security-capabilities](../research/fable5-security-capabilities.md).
