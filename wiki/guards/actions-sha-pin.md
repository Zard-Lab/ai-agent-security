---
type: Guard
title: "actions-sha-pin"
description: "GitHub Actions pinned to a commit SHA."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "actions-sha-pin"
checklist_section: ["1", "12"]
standards: ["OWASP-LLM:LLM03", "OWASP:A08", "SOC2:CC8.1"]
---

# GitHub Actions pinned to a commit SHA

Flags GitHub Actions steps under `.github/workflows/` that reference an action by a mutable
tag/branch instead of a full 40-char commit SHA. Closes checklist item `1-actions-pinned-to-sha`.

## The threat

A workflow step like `uses: actions/checkout@v4` trusts whatever code the `v4` tag currently points
at. Tags are mutable: if the upstream action is compromised, or an attacker force-pushes the tag
(the `trivy-action` / `setup-trivy` tag-injection incident, Feb–Mar 2026), your CI silently runs new
code **with your repository's secrets** (tokens, deploy keys). Pinning to a commit SHA freezes the
exact code that runs. OWASP A08 (Software & Data Integrity Failures); supply-chain (OWASP-LLM:LLM03).

## Exploitability rationale

CI runs with privileged secrets and write access. An unpinned third-party action is a direct
supply-chain path to secret exfiltration / repo compromise — no app bug required, just a compromised
or re-pointed upstream tag. HIGH: reachable by anyone who controls (or compromises) the referenced ref.

## When NOT to flag (and the pragma)

- **Already pinned** — the ref is a 40-hex commit SHA → silent.
- **Local actions** (`uses: ./.github/actions/...`) — your own code, no external trust → silent.
- **Pinned Docker digests** (`uses: docker://img@sha256:...`) → silent.
- **First-party action you own and trust by tag** — suppress that line with
  `# security: allow-unpinned-action`, counted only as a real `#` comment (the `hash` comment view, so the phrase inside a quoted string does not count, #1040).
- **Workflow-file subdirectories** — only files DIRECTLY in `.github/workflows/` are scanned. A
  workflow copy under a subdirectory (`backup/`, `disabled/`, `_archive/`) is never run by GitHub, so
  an unpinned `uses:` there is not exploitable and is not flagged (round-2 §C.1).

## Known bypasses (honest limits)

- A `uses:` written across a YAML anchor/alias or composed from an expression (`${{ ... }}`) won't
  match the line regex.
- A 40-hex ref that is *not actually a commit* (e.g. a coincidental hex tag) is treated as pinned —
  the guard checks shape, not that the SHA resolves.
- Only scans `.github/workflows/*.yml|yaml`; actions referenced from other CI systems are out of scope.

## What this guard does NOT prove

It proves a ref is *shaped like* a pinned SHA, not that the SHA is the intended/trusted commit, nor
that the pinned action is itself safe. It does not verify reusable-workflow pinning beyond the same
shape rule, and says nothing about secret scoping (`12-actions-sha-pinned-confirmed` remains the
deploy-time human confirmation).

# Citations

[1] agentsec checklist item `1-actions-pinned-to-sha` (§1)
[2] agentsec checklist item `12-actions-sha-pinned-confirmed` (§12)
[3] OWASP-LLM:LLM03
[4] OWASP:A08
[5] SOC2:CC8.1
