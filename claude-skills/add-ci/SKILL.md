---
name: add-ci
description: Add production-derived, sanitized CI/CD security/quality gates to an ai-agent-mastery–derived repo. Use when the user asks to add a CI check like react-doctor, gitleaks/secret-scan, hadolint/dockerfile lint, or a python/frontend security gate to their pipeline.
---

# /add-ci

`agentsec ci` installs individual, production-proven CI/CD components into a
target repo, adapted to the detected stack (paths, package manager) and
**stripped of all secrets and project-specific URLs/domains** — runners are
always `ubuntu-latest`, actions are SHA-pinned, and secrets appear only as
documented `${{ secrets.NAME }}` references you configure yourself.

**First, route the request.** If the user wants *agentsec itself* in CI (the audit on every PR or
push, a job summary, SARIF), that is the **agentsec GitHub Action**, not a component: point them at
section 16 of `docs/user-guide.md` (a SHA-pinned `uses:` step with `fail-on` / `mode` / `path` inputs).
If they want the fast guards before each commit, that is the **pre-commit hook**: an
`id: agentsec-guards` entry under `repo:` + `rev:` in their `.pre-commit-config.yaml` (same section).
Use the component flow below for the *extra* gates (secret-scan, dast, db-lint, react-doctor, ...).

1. **Verify the tool**: `agentsec --version` (else `pipx install ai-agent-security`).
2. **Confirm the stack + see what's available**:
   ```bash
   agentsec detect .
   agentsec ci list .
   ```
   `✓` = applies to this stack, `–` = N/A.
3. **Map the request to a component id**:

   | User says… | Component |
   |---|---|
   | "react-doctor", "frontend health" | `react-doctor` |
   | "secret scan", "gitleaks", "leaked keys" | `secret-scan` |
   | "hadolint", "dockerfile lint" | `dockerfile-lint` |
   | "python security", "bandit/semgrep/pip-audit gate" | `python-sec` |
   | "frontend security", "eslint", "npm audit" | `frontend-sec` |

4. **Preview, then install**:
   ```bash
   agentsec ci show <id>              # manifest + the files it will write
   agentsec ci add <id> . --dry-run   # show what would be written; writes nothing
   agentsec ci add <id> .             # write the files
   ```
   Show the user the diff of the generated workflow before and after.
5. **Report**: list the files written, and any required GitHub repo secrets to
   configure (`Settings → Secrets and variables → Actions`). Confirm that no
   secrets or project-specific values were embedded.

If the requested component is N/A for the detected stack, say so and why (the
missing feature) rather than forcing it. **Do not auto-commit** — surface the
changes and let the user decide.
