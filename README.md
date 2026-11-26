<div align="center">

# agentsec

**Stack-aware security audit for FastAPI + React + Postgres + LLM/RAG apps — detect the stack, run only the right checks, lead with what to fix.**

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/Zard-Lab/ai-agent-security/blob/main/LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/)
[![guards](https://img.shields.io/badge/guards-496-brightgreen.svg)](#what-it-checks)
[![checklist](https://img.shields.io/badge/checklist-v0.22.3%20(576%20items)-brightgreen.svg)](https://github.com/Zard-Lab/ai-agent-security/blob/main/agentsec/checklist/checklist.json)
![zero runtime deps](https://img.shields.io/badge/runtime%20deps-0-brightgreen.svg)

</div>

`agentsec` fingerprints your repo, runs **only the security checks that apply to your stack**, and emits one
prioritized report that leads with what's actually exploitable. **Dependency-free static guards** (zero
runtime deps, stdlib only) plus **11 optional scanners** it orchestrates when installed — with first-class
coverage of the **LLM / agentic** layer most tools miss (prompt-injection-to-RCE, the lethal trifecta, RAG
trust boundaries, RLS misconfig). Ships as a CLI, drop-in CI/CD gates, and Claude Code skills.

```text
$ agentsec audit .

# Security check — 3 issue(s) found
Needs work before shipping. There are serious problems to fix first.
_(1 critical, 1 high, 1 medium)_

## Fix these first
- **LLM output executed as code** — model output reaches exec()/subprocess; prompt-injection → RCE.
- **RLS policy lets owners write privileged columns** — a self-update policy leaves is_admin/tokens writable.

## Security findings (3: 1 critical, 1 high, 1 medium)
- 🔴 **CRITICAL** [llm-output-to-sink]  `agent/tools.py:88`   — model output passed to exec()      _[OWASP-LLM:LLM01]_
- 🔴 **HIGH**     [rls-update-privileged-column] `sql/0.sql:42` — owner can self-grant is_admin     _[OWASP:A01]_
- 🟠 **MEDIUM**   [cors-wildcard]      `app/main.py:31`     — allow_origins=["*"] with credentials  _[OWASP:A05]_

_Stack:_ fastapi · pydantic-ai · supabase · stripe · vite-react
_Checks run:_ 41   ·   _Skipped (N/A for this stack):_ 6   ·   _Scanners not installed:_ trivy, gitleaks
```

## Quickstart

```bash
pipx install ai-agent-security
agentsec audit /path/to/your/repo          # prioritized report, exits non-zero on high+ (your CI gate)
```

That's the whole loop. The dependency-free guards run immediately; add the optional scanners for full depth
with one command:

```bash
agentsec setup /path/to/your/repo          # stack-aware, installs only what your stack needs, no PATH edits
agentsec audit /path/to/your/repo          # …now runs at full depth
```

### Run it in CI

One step in any GitHub Actions job, after `actions/checkout`. It runs from the action's own checkout, so
there is nothing to install and your code never leaves your runner; you get a job summary, inline PR
annotations, a SARIF artifact and the gate:

```yaml
- uses: Zard-Lab/ai-agent-security@<40-hex-commit-sha>  # v0.22.x, pin by SHA
  with:
    fail-on: high        # critical | high | medium
    mode: gate           # or advisory: report and warn, never fail the job
```

Inputs, outputs, permissions and the private-repo setup:
[user guide §16](https://github.com/Zard-Lab/ai-agent-security/blob/main/docs/user-guide.md#16-wiring-agentsec-into-github-actions).

## Why agentsec

- **Runs only what applies (the N/A rule).** No Stripe → payments checks don't fire; no frontend → React
  checks are N/A. A clean report means "nothing applicable found," not "nothing checked" — and the report
  says exactly what ran and what was skipped.
- **Leads with the exploitable few.** Findings are ranked by severity × **reachability** (product code over
  tests/migrations) × **confidence** (proven over surfacing), so "Fix these first" is the short list that
  matters — the antidote to alert fatigue.
- **Covers the LLM/agentic layer.** Beyond the usual SAST: LLM-output-to-sink, the lethal trifecta, RAG
  trust boundaries, agent tool over-permission, MCP trust, prompt/secret leakage.
- **Zero runtime dependencies.** Pure-Python stdlib; the guards always run. External scanners are optional
  and degrade gracefully (reported as *skipped*, never fatal). The audit CLI makes **no network calls**.
- **Honest by construction.** A liveness canary fails CI if any guard silently stops firing; every
  `covered` checklist item must cite a real planted-violation test; exceptions **expire** (no forever-ignores).
- **One report model → SARIF + markdown.** Guards, scanners, the AI layer, and ingested third-party reports
  all become the same `Finding`, merged into one severity-ordered report.

## What it checks

**496 guards** across the FastAPI + React + Postgres + LLM/RAG stack, plus **11 optional scanners**
(`bandit`, `semgrep`, `pip-audit`, `node-audit`, `eslint`, `react-doctor`, `gitleaks`, `trivy`, `hadolint`,
`scorecard`, `go-osv-hygiene`), mapped to OWASP Top 10 · OWASP LLM Top 10 (2025) · CIS · CWE.

| Stack layer (detected feature) | Example guards |
|---|---|
| **LLM / agentic** (`llm`) | lethal-trifecta · llm-output-to-sink · rag-trust-boundary · agent-tool-overpermission · mcp-tool-unverified · system-prompt-leak |
| **Frontend / browser** (`frontend`) | frontend-xss · dom-xss-sinks · token-in-localstorage · jsx-href-scheme · vite-client-secret |
| **Postgres / RLS** (`sql` / `supabase`) | public-table-rls · rls-permissive-policy · rls-update-privileged-column · pg-function-search-path |
| **Supabase** (`supabase`) | service-role-key · auth-users-not-exposed-via-view · supabase-storage-public |
| **Payments / Stripe** (`payments`) | stripe-payments · checkout-price-from-server · no-pan-stored · webhook-idempotency |
| **Supply chain** (`python` / `frontend`) | python-supply-chain · js-supply-chain · npm-ignore-scripts · dependency-version-floor |
| **Auth / API** (`fastapi`) | jwt-alg · bola · mass-assignment · cors-wildcard · security-headers · rate-limit-no-user-key |

Run `agentsec coverage .` for the full per-section score card (covered / partial / manual / N-A) against
your stack.

## Install

```bash
# CLI (recommended), from PyPI:
pipx install ai-agent-security

# Or from a clone, or a release tag straight from git:
pipx install .
pipx install "git+https://github.com/Zard-Lab/ai-agent-security@vX.Y.Z"

# Development:
pip install -e ".[dev]"        # adds pytest, ruff, mypy, pyright, pyyaml
```

Requires **Python ≥3.12**, **zero runtime dependencies**. Optional scanners install via `agentsec setup`,
or, where that can't run (air-gapped / policy-restricted), [by hand](https://github.com/Zard-Lab/ai-agent-security/blob/main/docs/user-guide.md#bring-your-own-scanners-air-gapped--policy-restricted);
`agentsec doctor` shows what's present.

> **Installing from `@main` is not signature-verified.** `pip`/`pipx` do no signature checking, and
> `main` is a moving, unsigned ref, so an install from it carries no proof of provenance. Release
> **tags** are signed (`v0.21.14` onward), but installing from a tag does not verify it either: pip
> discards the git metadata, so the installed package holds nothing to check. Verification is a
> deliberate, separate step, documented in [SECURITY.md](https://github.com/Zard-Lab/ai-agent-security/blob/main/SECURITY.md).

## Common commands

| command | what it does |
|---|---|
| `agentsec scan <repo>` | one-shot: detect + audit → `agentsec-out/{detect.txt, audit.md, audit.sarif}` |
| `agentsec audit <repo>` | the core scan + CI gate (`--format sarif`, `--fail-on`, `--guards-only`, `--baseline`, `--changed-files-only`) |
| `agentsec drift <repo>` | compare current findings against a saved snapshot — catch regressions in CI, including a superseded SQL finding that comes back live |
| `agentsec detect <repo>` | fingerprint the stack (what everything keys off) |
| `agentsec coverage <repo>` | checklist score card for your stack |
| `agentsec ai-bom <repo>` | AI Bill of Materials — models, providers, MCP servers, vector stores, AI deps (JSON / CycloneDX / markdown) |
| `agentsec suggest-excludes <repo>` | advise non-product dirs to exclude/demote (advisory; `--write` to opt into `.agentsec/config.json`) |
| `agentsec live <repo>` | audit **+** running-target scanners (ZAP DAST, Splinter, Schemathesis, jwt_tool) |
| `agentsec harden-host` | opt-in **live-host** hardening audit (SSH/UFW/fail2ban/auto-updates/listeners; read-only, `sudo` for root-only probes) |
| `agentsec trifecta <repo>` | agentic-AI "lethal trifecta" architecture review |
| `agentsec fix <repo>` | apply allowlisted mechanical fixes (dry-run by default; `--write`) |
| `agentsec doctor` | which optional scanners are installed (`--canary`, `--sandbox`, `--efficacy` self-tests) |
| `agentsec setup <repo>` | install the scanner toolchain (stack-aware, no PATH edits) |
| `agentsec ci add <id> <repo>` | install a production-derived CI gate (13 components) |
| `agentsec harden-python` / `harden-js` | fix dependency config to the supply-chain standard |
| `agentsec report-gap <stack>` | flag a stack we don't cover yet (offline; opens a prefilled issue) |

<details>
<summary><b>Which command should I run?</b></summary>

- **First look / attach to a PR** → `agentsec scan .`
- **CI gate** → `agentsec audit . --fail-on high` (or `--format sarif` for code-scanning)
- **Is my stack detected right?** → `agentsec detect .`
- **What's my coverage / to-do list?** → `agentsec coverage .`
- **Fast PR check (changed files only)** → `agentsec audit . --changed-files-only origin/main`
- **Track regressions over time** → `agentsec drift . --save` (once), then `agentsec drift .` on each run.
  A snapshot saved by an older agentsec does not record which findings were superseded history; re-save
  it so `drift` and the `--baseline-snapshot` ratchet also fail when one of them comes back live
- **Repo-specific false positives** → add them to `.agentsec/suppress.json` (merged with the global baseline)
- **Silence one finding in place** → a `# security: allow-<guard-id>` comment (comments only, never a string — [user guide §14](https://github.com/Zard-Lab/ai-agent-security/blob/main/docs/user-guide.md#14-exceptions--baselines))
- **Which guards are firing vs silent?** → `agentsec doctor --efficacy .`
- **Scan a running deployment (DAST, DB lint, fuzzing)** → `agentsec live . --target-url …`
- **LLM/agent architecture review** → `agentsec trifecta .`

Full reference for every command and flag: **[docs/user-guide.md](https://github.com/Zard-Lab/ai-agent-security/blob/main/docs/user-guide.md)**.
</details>

## How it works

```
detect → select applicable checks → run (guards + scanners + AI layer) → prioritize → one report → gate on severity
```

`detect.py` fingerprints the repo into a `StackProfile`; `registry.py` selects only the checks whose stack
feature is present; every source produces the same `Finding`; the report is one severity-ordered list led by
"Fix these first," gated by `--fail-on` (default `high`).

Two classes of finding are reported but **do not** gate: ones you baselined (`--write-baseline`, until their
`review_by` lapses) and schema-state findings **superseded** by an authoritative schema dump the repo ships —
the old migration's copy of a policy the dump already carries live. A dump counts only when its name looks like
one (`schema.sql`, `schema-snapshot.sql`, `*.dump.sql`, …) **and** its head carries pg_dump's session preamble
or banner, and it governs only the `.sql` files in its own directory subtree; a hand-written `schema.sql`
supersedes nothing. Both classes are counted and named on the CI line
(`agentsec: … , N superseded (non-gating) — PASS`), never dropped from the report. Everything else gates.

## Delivery channels

- **CLI** — `pipx`-installable; the commands above.
- **CI/CD** — a composite **GitHub Action** (`action.yml`) for the audit, an à-la-carte **component
  library** (`agentsec ci add`, 13 components) of production-derived, secret-stripped gates, and a
  **pre-commit hook** (`.pre-commit-hooks.yaml`) for the local guard run. See the
  [user guide](https://github.com/Zard-Lab/ai-agent-security/blob/main/docs/user-guide.md#16-wiring-agentsec-into-github-actions).
- **Claude Code skills** — `/security`, `/security-prime`, `/security-review`, `/security-audit`,
  `/security-fix`, `/security-scan-url` (no repo needed — just a live URL), `/add-ci`,
  `/harden-python`, `/harden-js` (drop `claude-skills/*` into `.claude/skills/`).

## Documentation

- **[User Guide](https://github.com/Zard-Lab/ai-agent-security/blob/main/docs/user-guide.md)** — every command, flag, exception/baseline schema, CI wiring,
  reading the report, troubleshooting.
- **[wiki/](https://github.com/Zard-Lab/ai-agent-security/blob/main/wiki/index.md)** — the methodology + threat research the guards are designed against.
- **[Contributing a guard](https://github.com/Zard-Lab/ai-agent-security/blob/main/CONTRIBUTING-GUARDS.md)** — how to add a guard, the quality gates, conventions.

## Standards covered

OWASP Top 10 · OWASP LLM Top 10 (2025) · CIS Benchmarks · OWASP Agentic AI (Threats & Mitigations) · CWE ·
the "lethal trifecta" model.

## Contributing

Adding a guard is a small, well-defined recipe (module + test + design doc + canary plant + checklist
mapping). See **[CONTRIBUTING-GUARDS.md](https://github.com/Zard-Lab/ai-agent-security/blob/main/CONTRIBUTING-GUARDS.md)**. Quality gates: `ruff` + `mypy --strict` + `pyright` +
`pytest` + `agentsec doctor --canary` must all pass. Outside contributors sign the
[Contributor License Agreement](https://github.com/Zard-Lab/ai-agent-security/blob/main/CLA.md) once, on their first pull request (a bot asks).

## Security

Found a vulnerability **in agentsec itself**? Please report it privately — see
[SECURITY.md](https://github.com/Zard-Lab/ai-agent-security/blob/main/SECURITY.md). Don't open a public issue for a security report.

## License

[Apache-2.0](https://github.com/Zard-Lab/ai-agent-security/blob/main/LICENSE).
