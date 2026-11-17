---
name: harden-js
description: Update a project's JS/TS (npm/pnpm) dependency config to supply-chain standards — lockfile, a 48h release-age cooldown, lifecycle-script blocking, pinned deps, and a single trusted registry. Use when the user asks to harden npm/pnpm dependencies or fix `js-supply-chain` findings.
---

# /harden-js

Bring a project's JS/TS dependency posture up to the standard the `js-supply-chain`
guard enforces (the consumer-side defense against worms like Shai-Hulud, which run
on install via `postinstall`/`preinstall`). The **CLI does the mechanical config
edits** (`agentsec harden-js`); you handle the judgment parts.

1. **Verify the tool**: `agentsec --version` (else `pipx install ai-agent-security`).
2. **Preview, then apply** the deterministic, offline config hardening (writes a hardened `pnpm-workspace.yaml` for pnpm projects, or `.npmrc` for npm: release-age cooldown, `ignore-scripts`/script-blocking, `trustPolicy: no-downgrade`, exotic-subdep blocking, an empty build allowlist):
   ```bash
   agentsec harden-js . --dry-run     # preview the planned changes
   agentsec harden-js .               # apply (nothing is committed)
   ```
   Flags: `--cooldown HOURS`, `--no-allowlist`.
3. **Handle the judgment-only gaps the CLI reports but won't auto-change** (they need package.json edits / a lockfile / regeneration):
   - `unpinned` → pin floating direct deps to exact versions (`1.2.3`, not `^1.2.3`).
   - `no-packagemanager-pin` → add `"packageManager": "pnpm@<version>"` to package.json (Corepack).
   - `lockfile-missing` → run the install and commit the lockfile (`pnpm install` → `pnpm-lock.yaml`; build with `--frozen-lockfile`).
   - For the strongest default-on protections, consider **migrating npm → pnpm** (`pnpm import` converts the lockfile) — pnpm blocks build scripts by default and ships `minimumReleaseAge`/`blockExoticSubdeps`.
4. **Verify**: `agentsec audit . --guards-only` and confirm the `js-supply-chain` findings cleared; report what changed vs. deferred.
5. Respect any existing `# security: allow-no-cooldown` / `allow-lifecycle-scripts` / `allow-exotic-subdeps` opt-outs — don't strip a documented decision.

Review the diff before committing. **Do not auto-commit** — surface the changes and let the user decide.
