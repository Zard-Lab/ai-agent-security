---
name: harden-python
description: Update a project's Python (uv) dependency config to supply-chain standards — hash-verified uv.lock, a 48h exclude-newer cooldown, pinned deps, a single trusted index, and expiring CVE waivers. Use when the user asks to harden pip/uv dependencies or fix `python-supply-chain` findings.
---

# /harden-python

Bring a project's Python dependency posture up to the standard the
`python-supply-chain` guard enforces. The **CLI does the mechanical work**
(`agentsec harden-python`); you handle the judgment parts and the review.

1. **Verify the tools**:
   ```bash
   agentsec --version   # else: pipx install ai-agent-security
   uv --version         # else: pipx install uv   (needed for the hashed lock)
   ```
2. **Preview, then apply** the deterministic hardening (sets `exclude-newer = "48 hours"` and generates a hash-verified `uv.lock` / `requirements-locked.txt` per detected dep dir):
   ```bash
   agentsec harden-python . --dry-run     # preview the planned changes
   agentsec harden-python .               # apply (nothing is committed)
   ```
   Useful flags: `--cooldown HOURS`, `--no-lock` (config only), `--scaffold-exceptions` (create an empty `pip-audit-exceptions.json`).
3. **Handle the judgment-only gaps the CLI reports but won't auto-change** (changing these can break resolution / private registries):
   - `unpinned` → pin the flagged direct deps to `==` (use the versions `uv` just resolved into the lock).
   - `extra-index-url` / `insecure-index` → consolidate to a single `https://` `index-url` with `index-strategy = "first-index"`.
4. **CVE waivers (be conservative)**: for `exception-no-expiry` / `exception-lapsed` in `pip-audit-exceptions.json`, add or refresh a `review_by` date **only after confirming the vulnerability assessment with the user** (propose +30 days). Never auto-accept a new CVE.
5. **Verify**: `agentsec audit . --guards-only` and confirm the `python-supply-chain` findings cleared; report what changed vs. deferred.
6. Respect any existing `# security: allow-no-cooldown` / `allow-extra-index` opt-outs — don't strip a documented decision.

Review the diff (lockfile + pyproject/uv.toml) before committing. **Do not auto-commit** — surface the changes and let the user decide.
