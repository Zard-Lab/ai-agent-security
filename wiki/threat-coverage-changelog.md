---
type: Changelog
title: Threat Coverage Changelog
description: Plain-English record of every threat agentsec protects against and when each protection was added, appended by the weekly threat-intake job.
tags: [changelog, threats, coverage]
timestamp: "2026-06-23T00:00:00Z"
---

# Threat Coverage Changelog

A plain-English record of what agentsec protects against, and when each protection was added. You do
not need to be technical to read this. Newest first.

Each entry answers four things:
- **Threat** — what could go wrong, in everyday terms.
- **What we now check** — the automatic check that catches it.
- **Why it matters** — the real-world impact if it is missed.
- **Source** — where the threat intelligence came from.

The weekly threat-intake job appends a new dated block here whenever it proposes or adds coverage, so
this page grows over time into a readable history of the tool's protection.

---

## 2026-06-21 — 42 new guards added; 100 guards total, 1003 tests pass (sprint: Phase 1 gap-fill)

A focused sprint closed the largest remaining gaps in automated coverage. 42 guards were written and
merged across all major sections: CI/CD pipeline (§1), authentication and authorization (§2a–c),
general input safety (§3a), AI/agent controls (§4), frontend and HTTP security (§6a), database
security (§7), application code (§8), and payments (§9).

**Key metrics after this sprint:**
- Guards: 100 total (was ~58 before the sprint)
- Tests: 1,003 passing
- Coverage: 74 fully covered, 67 partial (review-assist), 113 manual — up from 74/20/160
- Canary: 99/100 guards ALIVE (`webhook-idempotency` is a permanent stub — frozenset()
  placeholder, intentional and documented)
- PR #127 open on `feat/phase1-report-gap`

**Batch 1–3 (35 guards):** async-blocking-io, docker-build-arg-secret, dom-xss-sinks,
fail-safe-exception, git-in-docker, jsx-href-scheme, log-injection, npm-ignore-scripts,
pg-anon-grant, pg-function-search-path, pg-security-definer-view, postmessage-origin,
pydantic-model-construct, secret-in-url-query, target-blank-noopener, token-in-localstorage,
vite-client-secret, vite-sourcemap-prod, websocket-no-auth, zip-slip, jwt-claims-validated,
mass-assignment, mcp-tool-unverified, payments-user-scope, pg-rls-no-policy,
refresh-token-plaintext, staticfiles-broad-mount, supabase-storage-public, webhook-idempotency,
websocket-origin, agent-memory-user-scope, jwt-exp-too-long, rag-no-instruction-filter,
session-no-csrf, upstream-response-unvalidated

**Tier 2 (7 guards):** trusted-host-absent, pg-extension-in-public, ci-secret-env-unscoped,
upload-no-size-limit, forwarded-header-blind-trust, rate-limit-no-user-key, no-cache-on-sensitive

*Why it matters:* this sprint moved 47 checklist items from manual or partial to automatic
detection, closing real gaps in auth/authz (JWT validation, CSRF, session controls), database
security (RLS completeness, pg privilege escalation paths), AI/agent controls (RAG instruction
filtering, memory scoping, MCP tool trust), and frontend hygiene (DOM XSS, postMessage origin,
token storage).

Source: internal guard-roadmap gap analysis; PR #127 (`feat/phase1-report-gap`).

## 2026-06-18 — 51 new items added to the security checklist (v0.9.0 → v0.11.0)

A full cross-walk of our checklist against the authoritative sources we treat as our backbone — CWE,
MITRE ATLAS, OWASP API Top 10, OWASP Agentic Top 10, OWASP ASVS 5.0, OWASP Top 10 (2025 draft), the
relevant OWASP Cheat Sheets, plus deep dives on FastAPI authorization wiring, React, Supabase Row Level
Security, and Stripe payment business logic — surfaced **51 genuine gaps**. They were added as
checklist items (the "things to verify" list, 197 → 248), so the coverage score card now shows them as
**manual** review items — the rules are written, but automatic detection comes later (each is tagged for
the guard roadmap: our-guard / vendored-rule / pinned-tool). Two narrower candidates
(sensitive-business-flow, inter-agent-message-auth) were deliberately held for a later pass.

*Why it matters:* a security checklist is only as good as the threats it knows about; this keeps ours
current with the published state of the art and gives the guard roadmap its next targets. The first
guard off this list — catching always-true "RLS theater" database policies — lands separately.

Source: the named standards above, cross-walked by hand (provenance in the maintainers'
intake staging ledger).

## 2026-06-17 — Proposed, awaiting review (from the first automated weekly scan, PR #45)

The automated scanner found five current threats and proposed adding them. These are awaiting a human
review before they become active checks.

- **A booby-trapped AI library update (LangGrinch).** A flaw in a popular AI building block
  (LangChain) lets a malicious response from the AI run code on your server. We propose requiring the
  patched version and turning off the risky setting. *Why it matters:* full server takeover.
- **A web framework that trusts a faked address header (Starlette/FastAPI).** A malformed request
  header could slip past login checks. We propose requiring the patched version. *Why it matters:*
  bypassing the lock on your front door.
- **Tricking the AI into reading private files.** An old "load a prompt from a file" feature can be
  abused to read files it should not. We propose blocking user input from reaching it.
- **Poisoned tool descriptions.** A connected tool can hide secret instructions in its own
  description to manipulate the AI. We propose scanning tool descriptions before the AI trusts them.
- **Poisoned knowledge base.** A few crafted documents mixed into the AI's reference library can
  hijack its answers. We propose checking documents for hidden instructions before they are stored.

Source: CISA/NVD/GitHub advisory feeds, via the automated weekly scan.

## 2026-06-16 — Eight new automatic checks added

- **Command injection.** Stops the app from running a system command built out of user input, which
  an attacker could rewrite into "delete everything." *Why it matters:* full server takeover.
- **Unsafe data loading.** Flags loading saved data (or AI models) in a format that can carry hidden
  code. *Why it matters:* opening the wrong file runs the attacker's code.
- **Template injection.** Stops user text from being treated as a page template, which can be turned
  into code execution.
- **Path traversal.** Stops a request like "../../secret" from escaping the intended folder and
  reading private files.
- **Build-pipeline command injection.** Stops a pull request's title or branch name from injecting
  commands into the automated build, where the project's secrets live.
- **Unpinned build actions.** Requires build steps to be locked to an exact version so a supplier
  cannot swap in malicious code later.
- **Debug mode left on.** Flags the developer debug switch being on by default, which leaks internal
  details to attackers.
- **Database connection without encryption.** Flags a database link that sends the password and data
  in the clear over the network.

Source: community threat matrices + a live MITRE ATLAS scan, reviewed and accepted.

## 2026-06-16 — Governance checklist added (5 items)

Added a short "are the right processes in place" section based on the US government's AI risk
framework (NIST): keep an inventory of AI models and tools, have a guardrail layer (not just a polite
system prompt), run a security test suite on every change, keep an incident playbook, and document who
is accountable for high-impact AI actions. These are human-reviewed items, not automatic checks.

---

_This page is maintained alongside the maintainers' machine-readable intake ledger (the
dedup memory) and the per-section coverage scorecard (`agentsec coverage`). For the technical detail
of any item, see its design doc under `wiki/guards/<id>.md`._
