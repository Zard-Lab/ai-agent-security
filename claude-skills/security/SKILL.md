---
name: security
description: Security command hub for the agentsec audit tool. Routes to a review, audit, fix, or URL-only scan workflow for FastAPI + React + Postgres + LLM/RAG apps. Use when the user asks for a security review/audit, to scan for vulnerabilities, or to fix security findings.
---

# /security — hub

`agentsec` is a stack-aware security audit tool (detects your stack, runs the
right deterministic scanners + dependency-free static guards + an LLM/agentic
analysis, and produces one prioritized report mapped to OWASP / OWASP-LLM / CIS).

**No repo? No terminal you're comfortable in? Just a deployed URL?** Skip straight to
`/security-scan-url` below — every other mode here assumes you have the source checked out.

Pick the mode that fits the request:

- **`/security-scan-url`** — no repo, no DB credentials, just a live URL. For a Lovable/Bolt/
  Replit/v0-built app (or anyone else who only has a deployed link). Checks the Supabase
  backend for anon-key-reachable exposure from the outside, the same way an attacker would.
- **`/security-prime`** — scope the repo before you audit: review the detected stack and interactively write non-product exclusions to `.agentsec/config.json`, so the audit runs high-signal. Run once per repo.
- **`/security-review`** — fast pre-merge gate on the current changes (~2 min). Use before committing/merging.
- **`/security-audit`** — full sweep + a dated report saved under `docs/security/audit-reports/`, closing with a triage step that waives any false positives into the exception registry. Use for a periodic/quarterly pass.
- **`/security-fix`** — patch the mechanical findings from the latest audit report, re-running after each fix.

First-time setup (any mode):
```bash
agentsec --version || pipx install ai-agent-security
agentsec detect .          # confirm the detected stack looks right (skip for /security-scan-url — no repo needed)
```

If the user didn't specify a mode: ask whether they have the repo. No → `/security-scan-url`.
Yes and no mode named → default to `/security-review` for a quick check.
