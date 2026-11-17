# agentsec — User Guide

The complete how-to for `agentsec`: install it, point it at a repo, read the report, gate CI, and harden a
pipeline component-by-component. (For the overview + quickstart, see the [README](../README.md).)

**Contents**
- [1. Install](#1-install)
  - [`setup` — install the toolchain (start here)](#setup--install-the-toolchain-start-here)
  - [Bring your own scanners (air-gapped / policy-restricted)](#bring-your-own-scanners-air-gapped--policy-restricted)
- [2. How it works](#2-how-it-works-the-mental-model)
- [3. `detect` — fingerprint the stack](#3-detect--fingerprint-the-stack)
- [4. `audit` — the core scan + CI gate](#4-audit--the-core-scan--ci-gate)
- [5. `scan` — one-shot detect + audit to files](#5-scan--one-shot-detect--audit-to-files)
- [6. `live` — scan a running deployment](#6-live--scan-a-running-deployment)
- [7. `trifecta` — agentic-AI architecture review](#7-trifecta--agentic-ai-architecture-review)
- [8. `coverage` — checklist score card](#8-coverage--checklist-score-card)
- [9. `fix` — apply mechanical fixes](#9-fix--apply-mechanical-fixes)
- [10. `report-gap` — flag an uncovered stack](#10-report-gap--flag-an-uncovered-stack)
- [11. `doctor` — check external tools](#11-doctor--check-external-tools)
- [12. `ci` — the CI/CD component library](#12-ci--the-cicd-component-library)
- [13. `harden-python` / `harden-js` — fix deps to standard](#13-harden-python--harden-js--fix-deps-to-standard)
- [14. Exceptions & baselines](#14-exceptions--baselines)
- [15. Ingesting external reports](#15-ingesting-external-reports)
- [16. Wiring agentsec into GitHub Actions](#16-wiring-agentsec-into-github-actions)
- [17. Claude Code skills](#17-claude-code-skills)
- [18. Reading the report](#18-reading-the-report)
- [19. Exit codes](#19-exit-codes)
- [20. Troubleshooting](#20-troubleshooting)

---

## 1. Install

`agentsec` is pure-Python (≥3.12) with **no runtime dependencies**.

```bash
pipx install ai-agent-security # from PyPI; isolated, recommended for CLI use
pipx install .                 # or from a clone
# or, for development:
pip install -e ".[dev]"        # adds pytest, ruff, mypy, pyright, pyyaml

agentsec --version             # prints the checklist registry version (the single source of truth)
```

The dependency-free **static guards** run immediately. The **deterministic scanners** (bandit, semgrep,
trivy, …) and **live scanners** (ZAP, Splinter, …) are optional external tools — `agentsec` runs whichever
are installed and reports the rest as *skipped*. For most users,
[`setup`](#setup--install-the-toolchain-start-here) (below) installs them in one command, and
[`doctor`](#11-doctor--check-external-tools) shows what's present. If your environment can't run `setup`
(air-gapped, or an automation harness that refuses to execute freshly-downloaded binaries), see
[Bring your own scanners](#bring-your-own-scanners-air-gapped--policy-restricted) below.

#### `setup` — install the toolchain (start here)

**The fastest path for a new user who isn't a security expert.** One command installs every scanner the
audit can use, so your *next* `agentsec audit` runs at full depth automatically:

```bash
agentsec setup <repo>            # stack-aware: installs only what your stack needs
agentsec setup <repo> --dry-run  # preview the plan; install nothing
agentsec setup <repo> --all      # install every scanner, ignoring the stack N/A rule
agentsec setup <repo> --include-live   # also set up live-scan tools (schemathesis; guide docker/psql/jwt_tool)
```

What it does, and why it's safe:

- **Auto-installs the Python scanners** (bandit, semgrep, pip-audit) **+ uv** into an agentsec-owned
  virtualenv, via a fallback chain that survives the real-world friction that breaks naïve installs:
  **no `pipx`, a PEP-668 "externally-managed" pip, and `venv` without `ensurepip`** (prefers `uv` when
  present, else a stdlib venv, else a `--without-pip` venv populated by the host `pip --python`).
- **Auto-installs the native binaries** (gitleaks, trivy, hadolint) from version-pinned release URLs,
  **sha256-verified** — a checksum mismatch aborts that tool and writes nothing. Platforms with no pinned
  checksum are *guided*, never downloaded unverified.
- **Guides (never auto-installs)** the Node tools (eslint, react-doctor, node-audit) and system services
  (docker, psql, jwt_tool) — those need a Node toolchain / OS service that's your call.
- **Everything lands in an agentsec-managed dir** (`$XDG_DATA_HOME/agentsec`, default
  `~/.local/share/agentsec`) that the audit **auto-consults** — tools are found with **zero PATH editing**.
  System copies still win when present.
- **Idempotent and reversible** — re-running skips what's already there; `--dry-run` mutates nothing;
  nothing touches your shell config. To undo, delete the managed dir.
- **It skips on presence, not version** — so re-running does **not** upgrade a tool that has fallen
  behind the version agentsec pins, and `doctor` shows it as present either way. After a dependency
  bump lands, move the stale binary out of `~/.local/share/agentsec/bin` and re-run `setup` to pick
  up the pinned build, then check `<tool> --version` to confirm. Tracked as issue #592; the full
  recipe is in the maintainers' dependency-lifecycle notes.

`setup` only prepares the toolchain — it does **not** run the audit. It ends with a `Next: agentsec audit
<repo>` nudge.

#### Bring your own scanners (air-gapped / policy-restricted)

When `agentsec setup` can't run, install the pip-installable scanners yourself and point agentsec at them.
Two environments need this:

- **Air-gapped hosts** with no network to download the pinned release binaries.
- **Policy-restricted CI / automation harnesses** that refuse to *execute* a freshly-downloaded release
  binary (a common supply-chain control), even though ordinary PyPI installs are still allowed.

The Python scanners (bandit, semgrep, pip-audit) come from ordinary `pip install`. There are two ways to
make the audit find them, both needing **zero changes to agentsec** and no edit to your login profile. Pick
recipe 2 if your harness blocks symlinks: it is strictly less privileged (it writes nothing outside the
sandbox) and works everywhere recipe 1 does.

**Recipe 1: symlink the console scripts into the managed dir.** `setup` itself just symlinks those console
scripts into a managed `bin` dir, so placing any scanner binary there by any means works the same way:

```bash
pip install bandit semgrep pip-audit              # ordinary PyPI installs, allowed in most locked-down envs
mkdir -p ~/.local/share/agentsec/bin              # or $XDG_DATA_HOME/agentsec/bin
ln -s "$(command -v bandit)"    ~/.local/share/agentsec/bin/
ln -s "$(command -v semgrep)"   ~/.local/share/agentsec/bin/
ln -s "$(command -v pip-audit)" ~/.local/share/agentsec/bin/
agentsec doctor                                   # confirm they now show as installed
```

**Recipe 2: no symlink, put the scanners on `PATH`.** Some harnesses classify `ln -s` of a binary as
untrusted-code integration and block it. You do not need it: agentsec always prefers a copy found on your
system `PATH` and consults its managed dir only as a fallback, so exposing the scanner venv on `PATH` is
enough. This writes nothing outside the sandbox.

```bash
python -m venv /path/to/scanners/venv             # or point PATH at an existing scanner venv instead
/path/to/scanners/venv/bin/pip install bandit semgrep pip-audit
export PATH="/path/to/scanners/venv/bin:$PATH"    # that venv's bin dir; the managed dir is consulted AFTER PATH
agentsec doctor                                   # confirm they now show as installed
agentsec audit <repo> --network tier1             # tier1 lets pip-audit run + gives semgrep its full registry packs (see Network tiers below)
```

Both the availability check and the actual scanner invocation put your system `PATH` first and treat the
managed dir only as a fallback, so a `PATH` copy always wins over one in the managed dir.

**One native binary is pip-installable after all: hadolint.** The third-party
[`hadolint-py`](https://pypi.org/project/hadolint-py/) wheel unpacks an executable named exactly
`hadolint`, so either recipe above picks it up with no change to agentsec:

```bash
/path/to/scanners/venv/bin/pip install hadolint-py   # into the recipe-2 venv, which is already on PATH
agentsec doctor                                      # hadolint now shows as installed
```

On recipe 1, `pip install hadolint-py` wherever you installed the others, then symlink
`$(command -v hadolint)` into the managed bin dir the same way, alongside them.

You get the *same* binary `agentsec setup` would fetch, not a rebuild: the wheel bundles the upstream
release asset (at the pinned version, byte-for-byte the sha256 `pins.py` records, verified on Linux
x86_64). Only the delivery channel differs, PyPI instead of a GitHub release download, so judge for
yourself whether that satisfies your harness's control. A hadolint newer than the pin is fine: `doctor`
renders it `✓ <installed> (pinned <pin>)`, ahead rather than stale, and does not warn. Two caveats:

- **Platform coverage.** Wheels are published for Linux x86_64 / arm64, Windows x64, and Apple Silicon.
  On anything else (musl/Alpine, 32-bit, s390x/ppc64le, Windows on ARM) pip falls back to a source build
  that downloads the release binary from GitHub at install time, which is the step you were avoiding.
- **The macOS wheel is tagged `universal2` but carries an arm64-only binary**, so it is an Apple-Silicon
  path, not an Intel-Mac one. On an Intel Mac it installs and then fails to execute, which agentsec
  reports as a scanner *error*, never as a clean scan.

**What this path can't reach:**

- **The other native release binaries** (gitleaks, trivy, scorecard) have no wheel-backed PyPI path.
  They are reachable only by placing the release binary in the managed dir yourself, which is exactly the
  step a policy-restricted harness blocks; on an air-gapped host you would stage them from a trusted mirror.
  The near misses are worth knowing so you don't chase them: Ubuntu packages `gitleaks` in `universe`,
  but far enough behind the pin that `doctor` calls it *stale*; `trivy-py` is on PyPI but ships only an
  sdist, so installing it downloads from GitHub at install time and solves nothing here; Scorecard has
  no PyPI distribution at all (the PyPI name `scorecard` is an unrelated project).
- **Node tools** (node-audit, eslint, react-doctor) need a Node toolchain (`npm` / `npx`), so `pip` can't
  help there either. Without one they degrade to *skipped*, like any other missing scanner.

**Network tiers.** bandit runs fully offline (Tier 0). semgrep also runs at Tier 0, but loads only its
local LLM/agent rule pack: the OSS registry packs (`p/python`, `p/owasp-top-ten`, `p/secrets`) are a
network fetch gated behind `--network tier1`, so a host that can never reach Tier 1 gets no general
Python/OWASP/secrets coverage from semgrep this way (the audit report discloses this whenever semgrep runs
at Tier 0). pip-audit is a live-advisory scanner too: skipped at Tier 0, it needs `--network tier1` to query
OSV. So on a truly air-gapped host, expect full offline SAST from bandit plus semgrep's local pack, with
the registry packs and pip-audit no-ops until they have advisory network. See the Tier-0 note in
the maintainers' onboarding notes for the full offline story.

## 2. How it works (the mental model)

```
detect  →  select applicable checks  →  run them  →  prioritize  →  one unified report  →  gate on severity
 stack       (the N/A rule)            guards +       Fix these       Finding[] sorted       exit non-zero on
 profile                               scanners +     first           critical→info          --fail-on and up
                                       AI layer
```

- **Applicability (the "N/A rule").** A check only runs when the stack feature it guards is present. No
  frontend → the React checks are silently *N/A*; no Stripe → the payments checks don't fire. The report
  tells you what ran and what was skipped as N/A, so a clean report means "nothing applicable found", not
  "nothing checked".
- **One report model.** Every source — static guard, external scanner, the AI layer, or an ingested
  third-party report — produces the same `Finding` (severity, location, message, fix, mapped standards).
- **Prioritization.** On top of severity, findings are ranked by **reachability** (product code outranks
  tests/migrations/scripts) and **confidence** (a proven finding outranks a surfacing/review one), so the
  report leads with a **"Fix these first"** shortlist of what's actually exploitable.
- **Severity gate.** `audit`/`live` exit non-zero when any finding is at or above `--fail-on` (default
  `high`). That exit code is your CI gate.

## 3. `detect` — fingerprint the stack

Start here to confirm `agentsec` sees your stack correctly — everything else keys off this.

```bash
agentsec detect .
```

```
Stack profile for /path/to/repo:
  languages=['python', 'typescript'] backend=fastapi llm=pydantic-ai db=supabase
  frontend=vite-react pkg=['pnpm'] docker=True rls=True payments=True
  features: ['docker', 'fastapi', 'frontend', 'llm', 'payments', 'python', 'rls', 'sql', 'supabase', 'typescript']
  python dirs: ['backend_agent_api']   frontend dir: frontend   sql dir: sql
```

The `features` set drives which checks and CI components apply. If `detect` recognizes a stack it has **no
dedicated guard suite for yet** (e.g. Django, Flask, Express), it lists it under "no dedicated guard suite
yet" so silence never reads as "clean" — flag it with [`report-gap`](#10-report-gap--flag-an-uncovered-stack).

## 4. `audit` — the core scan + CI gate

Runs the applicable static guards, the installed deterministic scanners, and the AI layer; merges
everything; applies your [exception registry](#14-exceptions--baselines); prioritizes; and gates on severity.

```bash
agentsec audit .                                   # human-readable report, gate on high+
agentsec audit . --guards-only                     # instant: dependency-free guards only, no external tools
agentsec audit . --fail-on critical                # only critical fails the build
agentsec audit . --no-fail                         # report only, always exit 0
agentsec audit . --format sarif --out findings.sarif   # SARIF for GitHub code-scanning
```

| flag | meaning |
|---|---|
| `--format {markdown,sarif}` | output format (default `markdown`) |
| `--out FILE` | write report to a file instead of stdout |
| `--fail-on {critical,high,medium,low,info}` | minimum severity that fails the run (default `high`) |
| `--no-fail` | always exit 0 (report only) |
| `--guards-only` | skip external scanners; run only the dependency-free guards (fast, hermetic) |
| `--baseline FILE` | apply an [exception registry](#14-exceptions--baselines) (default: `./agentsec-exceptions.json` if present) |
| `--ingest KIND=PATH` | merge an [external report](#15-ingesting-external-reports) (repeatable) |
| `--write-baseline FILE` | snapshot current findings as accepted exceptions so only NEW ones surface later |

## 5. `scan` — one-shot detect + audit to files

The zero-thought entry point: detect, audit, and write everything to `agentsec-out/` in one command.

```bash
agentsec scan .            # writes agentsec-out/{detect.txt, audit.md, audit.sarif} (+ starter exceptions)
agentsec scan . --setup    # install the scanner toolchain first, then scan at full depth
```

Produces the human-readable report, the SARIF for code-scanning, and a stack profile — handy for a first
run or to attach to a PR. Same severity gate as `audit`.

## 6. `live` — scan a running deployment

`audit` reads files on disk; `live` does everything `audit` does **and** drives scanners that need a
*running* target, merging their findings into the same report. Each live scanner degrades gracefully (a
skip note) when its tool or target is missing.

```bash
# Passive ZAP baseline + Supabase Splinter DB lint:
agentsec live . --target-url http://localhost:8001 \
                --db-url postgresql://postgres:postgres@localhost:54322/postgres

# OpenAPI fuzzing + JWT attacks against an owned, authenticated API:
agentsec live . --schemathesis-url http://localhost:8001 \
                --jwt-url http://localhost:8001/api/me \
                --api-token "$TOKEN" --jwt-canary '"email"'
```

| scanner | flag | needs | notes |
|---|---|---|---|
| OWASP ZAP (passive baseline) | `--target-url URL` | Docker | safe; passive crawl + baseline checks |
| OWASP ZAP (active) | `--zap-active` (+ `--zap-openapi URL`) | Docker | **intrusive — sends real attack payloads; owned stacks only** |
| Supabase Splinter | `--db-url DSN` | `psql` | DB lint; SQL fetched pinned, or `--splinter-sql PATH` / `--no-splinter-fetch` |
| Schemathesis | `--schemathesis-url URL` | `st` | OpenAPI fuzzing; `--max-examples N`, `--schemathesis-skip TOML`, `--origin` |
| jwt_tool | `--jwt-url URL` | `jwt_tool` | JWT attacks; pair with `--jwt-canary TEXT` |

`--api-token TOKEN` is the shared bearer for the authenticated scanners. `live` accepts every `audit` flag.

ZAP runs in a Docker container, so by default it reaches a host-published port as
`http://host.docker.internal:PORT`. On **Linux**, pass `--zap-network-host` to run with `--network=host` —
then `--target-url http://127.0.0.1:PORT` works directly. (No-op on Docker Desktop for macOS/Windows.)

> ⚠️ Only run `live` against systems you own or are authorized to test. `--zap-active` and the fuzzers send
> real, potentially destructive traffic — use a disposable/non-prod environment.

## 7. `trifecta` — agentic-AI architecture review

For LLM/agent apps, prints a "lethal trifecta" assessment: does the agent combine **private data +
untrusted content + external communication** without the expected mitigations? N/A (and exits 0) for
non-LLM stacks.

```bash
agentsec trifecta .
```

## 8. `coverage` — checklist score card

The machine-readable security checklist (573 items, versioned + sha-stamped into every report) rendered as
a per-section score card for your detected stack, plus your remaining manual to-do list.

```bash
agentsec coverage .                  # covered / partial / manual / n-a per section
agentsec coverage . --write-tracker  # regenerate the maintainers' tracker (agentsec dev checkout only)
```

Each item carries its severity, mapped standards (OWASP / OWASP-LLM / CIS, and a `cwe` where applicable),
and — for `covered` items — the guard + the planted-violation test that proves it. Drift-tested both ways:
every guard maps to a checklist item, and every `covered` claim cites a real test.

## 9. `fix` — apply mechanical fixes

Deterministically apply the allowlisted, mechanical source fixes from the latest audit. Dry-run by default.

```bash
agentsec fix .            # preview the diffs; write nothing
agentsec fix . --write    # apply the fixes (nothing is committed; git is your undo)
agentsec fix . --write --fix RULE   # restrict to specific rule id(s); repeatable
```

Only safe, allowlisted rules are auto-fixable; everything else is reported, not rewritten. Pairs with the
`/security-fix` Claude skill.

## 10. `report-gap` — flag an uncovered stack

When `detect` sees a stack agentsec has no guards for yet, help us prioritize building them:

```bash
agentsec report-gap                 # list stacks recorded locally as uncovered
agentsec report-gap django          # print a pre-filled GitHub issue URL for the gap
agentsec report-gap django --open   # also open it in your browser
```

Fully offline — it builds a prefilled GitHub-issue URL and (only with `--open`) opens your browser. No
telemetry, no automatic network calls.

## 11. `doctor` — check external tools

Shows which optional scanners and live-scan prerequisites are installed, with one-line install hints.
`doctor` *reports*; its actionable counterpart [`setup`](#setup--install-the-toolchain-start-here)
*installs* — prefer `setup` unless you want to install tools yourself.

```bash
agentsec doctor
agentsec doctor --canary    # self-test: prove every guard fires its planted violation end-to-end
agentsec doctor --sandbox   # prove every guard imports no os/subprocess/network (the Guard Sandbox Contract)
```

## 12. `ci` — the CI/CD component library

Install production-derived CI gates **one at a time**, each adapted to your detected stack and **stripped of
all secrets and project-specific URLs/domains**: the runner is always `ubuntu-latest`, third-party actions
stay commit-SHA-pinned, pinned binaries keep their `version + sha256`, and secrets appear only as documented
`${{ secrets.NAME }}` references you configure yourself.

```bash
agentsec ci list .                       # components + whether each applies to your stack
agentsec ci show react-doctor            # manifest, required secrets, and the files it writes
agentsec ci add react-doctor . --dry-run # preview (writes nothing)
agentsec ci add react-doctor .           # write the files
agentsec ci add react-doctor . --force   # overwrite existing files / install even if N/A
```

The components (`agentsec ci list` prints the live set for your stack):

| id | what | applies when |
|---|---|---|
| `self-audit` | runs agentsec's own audit + coverage score card in your CI | always |
| `react-doctor` | frontend health gate (score threshold) + `react-doctor.config.json` | frontend |
| `secret-scan` | gitleaks (pinned binary + sha256) + generic `.gitleaks.toml` allowlist | always |
| `dockerfile-lint` | hadolint with pin/tag-hygiene rules promoted to error + `.hadolint.yaml` | docker |
| `python-sec` | a dedicated Python gate wrapping `agentsec audit` (bandit/pip-audit/semgrep + guards) | python |
| `frontend-sec` | eslint-security gate + dependency audit, adapted to npm/pnpm/bun | frontend |
| `dast` | scheduled OWASP ZAP baseline DAST via `agentsec live` (target via `DAST_TARGET_URL`) | fastapi |
| `db-lint` | scheduled Supabase Splinter DB lint via `agentsec live` (`DATABASE_URL` secret) | supabase |
| `container-cve` | scheduled Trivy image CVE scan (pinned binary; images in `.trivy-images.txt`) | docker |
| `type-check` | mypy + pyright over the detected Python dirs | python |
| `garak` | scheduled LLM red-team (NVIDIA garak) against a deployed model endpoint | llm |
| `promptfoo` | LLM prompt-injection / eval gate (promptfoo) | llm |
| `scorecard` | scheduled OpenSSF Scorecard supply-chain health run, gated on a minimum score | always |

`ci add` detects the **target** repo, adapts paths (frontend dir, python dirs) and package manager
(`pnpm`/`bun`/`npm`), writes the workflow into `.github/workflows/` plus any config into the right place,
and prints any GitHub secrets to configure. It refuses to overwrite existing files without `--force`;
nothing is committed.

**How the workflows install agentsec.** `self-audit` installs nothing: it calls agentsec's own
[GitHub Action](#16-wiring-agentsec-into-github-actions) (see below). Every other component that runs agentsec installs it
from the release tag of the agentsec that rendered it (`git+https://github.com/<repo>@v<version>`), never from
`main`, so a security gate does not change under you between runs. To upgrade, upgrade agentsec and
re-run `ci add <id> --force`. (A checkout whose version is bumped but not yet released renders a tag
that the next release creates.) agentsec's repository is public, so no token is needed. If the install
must go through a token anyway (a runner that must authenticate to reach GitHub), add
`--install-secret NAME`. It still installs from agentsec's own repository, never from a fork. The
secret is mapped into the install step's `env:` and handed to git through `GIT_ASKPASS`, and the URL
carries only the non-secret username `x-access-token`. The token never appears in a URL or on a
command line, so it cannot land in pip's git cache or the process list of a persistent runner. Like
any `env:` secret, it is visible to every process the install step starts (pip and its build steps).

**`self-audit` options:**

```bash
agentsec ci add self-audit . --path mod --with-baseline   # scope to a monorepo module + ratchet baseline
agentsec ci add self-audit . --advisory                   # report every finding, never fail the build
agentsec ci add self-audit . --install-secret AGENTSEC_PAT  # check the action out with a token (see above)
agentsec ci add self-audit . --action-sha <40-hex-sha>    # pin a given commit; skips the git ls-remote lookup
```

The `self-audit` workflow is a thin caller of agentsec's
[GitHub Action](#16-wiring-agentsec-into-github-actions), which runs `agentsec audit` **once**. That
single pass writes the findings report (the plain-English summary plus the technical detail for the
`TOP` most-severe findings, default 50) and the checklist coverage score card into the run summary,
annotates the most severe findings inline on the PR, uploads the `agentsec-sarif` artifact, and sets
the gate (`FAIL_ON`+ findings fail the job, default `high`). `--advisory` renders the action's
`mode: advisory` for a non-blocking rollout: the report and artifact are unchanged and the build never
fails on findings. In every mode a scan that did not complete fails the job, because a run that did not
happen must not look green. `TOP`, `FAIL_ON` and `ADVISORY` are manifest params
(`agentsec ci show self-audit`); edit the rendered `with:` block to change any action input.

**How the action is pinned.** The workflow pins the action to the **commit SHA** of the release tag of
the agentsec that rendered it (`uses: <repo>@<sha>  # v<version>`), never a tag or a branch: a tag can be
moved after you review it, and agentsec's own `actions-sha-pin` guard fails the gate on one. agentsec
cannot know that SHA offline, so `ci add self-audit` looks it up once with `git ls-remote`, through your
own git credentials (for a private agentsec repo your git needs HTTPS read access, e.g. `gh auth
setup-git`). It sends nothing about your repo, is disclosed before it runs, and is refused under
`DO_NOT_TRACK=1`. If the lookup fails (offline, no access, or a version that is not released yet) nothing is
written and the error says why; pass `--action-sha <sha>` to supply the commit yourself (the commit
of the same release: the rendered workflow passes the inputs that release's action declares). A run
that writes nothing (every file exists and no `--force`) does no lookup. Dependabot and
Renovate bump the SHA pin through its `# v<version>` comment, or re-run `ci add self-audit --force` with
a newer agentsec. With `--install-secret NAME` the workflow instead checks the agentsec repo out at that
commit into `.agentsec-action/` with the token (`persist-credentials: false`, so the token is not left in
the checkout), ignores that directory for the run, and runs it as a local action.

**Preflight:** `agentsec ci doctor .` reads the generated workflows and flags what would only fail in
CI: a private install with no token, a non-deterministic gate, a missing baseline snapshot, a
code-scanning upload that needs GitHub Advanced Security, an install from a moving branch
(`install-unpinned`: anything but a `vX.Y.Z` tag or a 40-hex SHA; for agentsec's action, anything but a
40-hex SHA) and a token inside an install URL (`install-token-in-url`). The last two are how a workflow
rendered by an older agentsec shows up: re-render it with `--force`. It reads the action form too
(agentsec's repository under any owner, or a local `uses: ./<dir>` that a step checked agentsec out
to; a look-alike name is someone else's action): a private checkout with no token, `scanners: all` in a
gate, and a `baseline-snapshot:` that does not exist. Two notes are information only and never change the
verdict: a remote `uses:` of agentsec works only while the agentsec repo is public, and a `with:` it
cannot read (anything but a block or a one-line `{ key: value }` mapping) was not checked.

> The sanitization guarantee is enforced in CI by a test that scans every component file against a denylist
> (secret values, tokens, DSNs, real domains, `self-hosted`, project-specific paths). A hard contract.

**Notifications:** there's no `slack-notify` component — use the official
[GitHub Slack app](https://github.com/integrations/slack):
`/github subscribe your-org/your-repo workflows:{name:"Security",conclusion:failure}`.

## 13. `harden-python` / `harden-js` — fix deps to standard

The deterministic, scriptable counterparts of the supply-chain guards (detect) and the `/harden-*` skills
(interactive).

```bash
agentsec harden-python . --dry-run    # preview; writes nothing
agentsec harden-python .              # set exclude-newer cooldown + hash-verified uv lock
agentsec harden-js . --dry-run        # preview; writes nothing
agentsec harden-js .                  # write hardened pnpm-workspace.yaml / .npmrc (offline, no tool needed)
```

`harden-python` sets a release-age cooldown (`exclude-newer = "48 hours"`) and generates a hash-verified
lock (needs `uv` for the lock step; degrades gracefully without it). `harden-js` writes
`minimumReleaseAge` / `trustPolicy: no-downgrade` / lifecycle-script blocking (pnpm) or
`ignore-scripts=true` / `min-release-age` (npm). Both make only safe, reversible edits; pinning and
migrations are *reported, not auto-performed*. Common flags: `--cooldown HOURS`, `--dry-run`.

## 14. Exceptions & baselines

Accept a finding with an **expiring** decision — no silent forever-ignores. Create `agentsec-exceptions.json`
(auto-loaded if present, or pass `--baseline FILE`):

```json
{
  "exceptions": [
    {
      "rule": "frontend-xss/dangerously-set-inner-html",
      "location": "src/Comment.tsx:42",
      "reason": "sanitized via DOMPurify before render",
      "review_by": "2026-09-01"
    }
  ]
}
```

- `rule` matches the finding's `rule` **or** `check_id`.
- `location` is exact **or** a prefix (`src/legacy/` accepts everything under it); omit to match anywhere.
- `review_by` is the expiry — once it passes, the exception **lapses** and the finding re-surfaces (the
  report flags the lapse). Omit for no expiry.

**Waivers that have gone dead.** When a waived finding is fixed at source — you fixed the code, or an
agentsec upgrade retired a false positive — the waiver stops matching anything. The footer names it:

```
_Unused waiver:_ waiver for llm-json-output-unvalidated @ scripts/transcribe_all.py matched nothing
  and its check ran — candidate to remove (re-confirm before deleting: it is an accepted-risk record)
```

Nothing is deleted for you. The line only appears when the check that owns the waiver actually **ran**
this scan, so a `--guards-only` run never calls your scanner waivers dead, and a waiver under an
`--exclude`d or archived path is left alone. `--changed-files-only` suppresses the disclosure entirely.

If most of the waivers this run *could* check report unused at once, the report **leads with** a scan-root
hint before the (still-capped) per-waiver list, so you see the likely explanation first: a re-rooted or
moved tree invalidates every `location` simultaneously, which looks identical to a lot of real fixes. The
list itself is capped at 10 entries with the remainder counted, never silently truncated.

**Waivers whose finding changed identity.** A waiver's `fingerprint` includes the start of the finding's
message, so when an agentsec upgrade rewords a check's message, the waiver stops matching and the
finding re-surfaces even though your code did not change. If a finding is still live at the waiver's own
rule + location, the footer says so under its own label instead of calling the waiver unused:

```
_Drifted waiver:_ waiver for ssrf-general/user-controlled-url @ app/fetch.py:42 (fingerprint 4a42c089b14ae6b4)
  did not match the live finding at the same rule + location (fingerprint b1b536568e84757b) — the finding's
  identity changed (e.g. its message was reworded, or a different finding now sits there); re-triage rather than remove
```

Re-triage the finding (a new waiver or a fix); don't delete the old record on the strength of this line
alone. Nothing is suppressed on your behalf: the finding stays in the report until you decide. When four
or more waivers for one check drift at once, a single summary line leads the list, and these never count
toward the scan-root hint above.

Snapshot the current state so only *new* findings surface afterwards (bandit-style baseline):

```bash
agentsec audit . --write-baseline agentsec-exceptions.json
```

### Triaging findings (`agentsec triage`)

`agentsec triage` walks the current findings and records a per-finding **verdict** (`real` / `fp` /
`guard-improvement` / `pending`); an `fp` or `guard-improvement` verdict becomes an expiring waiver when
you pass `--write-exception`. In a terminal it prompts interactively. In a non-interactive shell (CI, an
agent session, a pipe) a **bare** run is read-only — it lists the untriaged findings with their
fingerprints and exits `0`, so you can discover the set before choosing verdicts:

```bash
agentsec triage .                          # (piped/CI) read-only listing: fingerprint · guard · location
```

Then bulk-triage non-interactively with `--verdict`, narrowing to a subset with the selectors — `--guard`,
`--location` (a repo-relative, anchored path), and `--fingerprint` (the exact per-finding pin printed above):

```bash
agentsec triage . --guard auth-dependency-not-applied --verdict guard-improvement \
  --reason "cross-file router auth the guard can't see" \
  --improvement "teach the guard the shared-dependency form" \
  --triaged-by "you@example.com" --triaged-at 2026-09-14
agentsec triage . --verdict fp --fingerprint <fp-from-the-listing> --reason "4xx — guard too broad"
```

Add `--write-exception` to any of these — or on its own in a non-TTY, to re-emit waivers from an existing
triage file — to derive the matching waivers into the exception registry.

### Per-repo config (`.agentsec/`)

agentsec reads a small, optional `.agentsec/` directory at the repo root. Nothing here is required;
each file is opt-in. All are stdlib-JSON, read as UTF-8, and degrade gracefully if malformed.

| File | Purpose | Commit it? |
|---|---|---|
| `.agentsec/config.json` | per-project scan config (today: `archive_paths`) | **yes** — per-project, shared with the team |
| `.agentsec/suppress.json` | repo-local false-positive suppressions | **yes** — your team's accepted FPs |
| `~/.agentsec/gaps.json` | user-global "stack we don't cover yet" memory (written by `report-gap`) | no — user-global, machine-local |

**`config.json` — archived/dead-code trees.** Findings in archived trees (`old/`, `legacy/`, `archive/`, …)
are **always demoted** in ranking (they sort below product code, but are **never dropped** — a real bug
there still appears). If you want those trees **fully excluded** from the report, opt in:

```json
{ "archive_paths": ["old", "legacy"] }
```

- A **list** names the directory segments to exclude. **Every** guard's findings under those trees are
  dropped — including whole-file guards like `dependency-version-floor` and `rls-permissive-policy` (so a
  vulnerable dependency pinned in `old/` stops surfacing too, not just the noise-prone guards).
- `true` opts into the recommended default set
  (`old`, `archive`, `archived`, `deprecated`, `backup`, `backups`, `legacy`).
- **Opt-in, and disclosed.** With no config, nothing is excluded — a live directory that merely happens to
  be named `old/` is still fully scanned (only *demoted*). When you do opt in, the report footer says so:
  `Excluded as archived (.agentsec/config.json: old): N finding(s)` — the drop is never silent.
- Matches a directory **segment**, case-insensitively (a *file* named `old` is not excluded). For a
  one-off, per-invocation equivalent, use `--exclude old/`.

**`suppress.json` — repo-local false positives.** Same schema as the global
[exception registry](#14-exceptions--baselines), merged with it at audit time — so a team can record
*its own* FPs without touching the shared `agentsec-exceptions.json`:

```json
{ "exceptions": [
  { "rule": "frontend-xss/dangerously-set-inner-html",
    "location": "src/Comment.tsx:42",
    "reason": "sanitized via DOMPurify",
    "review_by": "2026-09-01" }
] }
```

- **`review_by` is REQUIRED here** (unlike the global registry, which may hold permanent entries). A local
  entry **without** an expiry is **not honored** — the finding re-surfaces and the report reminds you to add
  a date. This keeps a local file from becoming a silent forever-ignore. Once `review_by` passes, the entry
  lapses and the finding re-surfaces, same as the global baseline.
- The report footer discloses **"Locally suppressed (.agentsec/suppress.json): N"**, so a clean report can
  never hide a quiet local bypass.

### Inline opt-out pragmas (`# security: allow-<id>`)

Most guards also honour an **inline pragma** written in the code itself, for the one legitimate pattern the
guard cannot tell apart from the bug (each guard's wiki page names its token and what it is for; the
finding's remediation text shows the exact comment to write):

```python
allow_origins=["*"],  # security: allow-cors-wildcard -- public read-only API, no credentials
```

- **A pragma counts only as a comment**, in the file's own comment syntax: `#` (Python, Ruby, YAML, shell,
  Dockerfile, TOML, `.env`), `//` (JS/TS, Go, Java, and VS Code's JSONC `tasks.json` / `launch.json`),
  `#` or `//` (PHP, Terraform), `--` (SQL), or a block
  comment where the language has one. The same phrase inside a **string literal, docstring, YAML block
  scalar, SQL literal or SQL quoted identifier never suppresses** — a module that documents the opt-out
  to its readers, a help string or a test fixture quoting the syntax cannot silence a real finding. A few grammars have no comment
  dialect yet (Rust, the C family, Perl, JSON, Markdown, XML/SVG); a file of those types is matched on its raw text,
  so a quoted phrase there still suppresses. In SQL a `--` comment inside a `DO $$ … $$` block or a function body is a
  real comment and counts. The one SQL exception to "never suppresses": a phrase inside a dollar-quoted
  string that is not such a body (`COMMENT ON … IS $$…$$`) is read the same way, so it still counts.
  (Earlier releases matched
  the phrase anywhere in every file, strings included; that form was never documented and is gone — see
  [`BREAKING_CHANGES.md`](../BREAKING_CHANGES.md).)
- **Its reach is the guard's.** Some pragmas silence only the line they sit on, some the enclosing
  resource block or SQL statement, many the whole file, and a few the whole repo. The guard's wiki page
  (`wiki/guards/<id>.md`, "Detection design") states which.
- **It is a permanent, in-code decision.** Unlike a registry entry it has no `review_by`, and the report
  does not count findings a pragma silenced. Use it for a pattern that is safe *by design*; use the
  expiring exception registry above for a risk you are *accepting for now*.

## 15. Ingesting external reports

Service-dependent scanners run in CI emit JSON/XML; merge them into one unified report (repeatable
`--ingest KIND=PATH`):

```bash
agentsec audit . \
  --ingest zap=zap.json \
  --ingest splinter=splinter.json \
  --ingest schemathesis=schemathesis-junit.xml \
  --ingest jwt=jwt.txt \
  --ingest sarif=other-tool.sarif
```

Supported `KIND`s: `zap`, `splinter`, `schemathesis` (JUnit XML), `jwt` (text), `sarif` (any SARIF 2.1.0 tool).

## 16. Wiring agentsec into GitHub Actions

Three ways, smallest to largest:

1. **The agentsec GitHub Action** (recommended): one step. It runs agentsec straight from the action's own
   checkout (agentsec has no runtime dependencies), so there is no install step, no network fetch and no
   token at run time, and the agentsec version is exactly the commit you pin. Your code never leaves your
   runner. One audit produces everything: a job summary, capped inline annotations on the PR, a SARIF
   artifact, an optional code-scanning upload, and the pass/fail gate. `agentsec ci add self-audit .`
   writes this workflow for you, already pinned to the release commit
   ([section 12](#12-ci--the-cicd-component-library)); or add the step by hand:
   ```yaml
   name: agentsec
   on:
     pull_request:
     push:
       branches: [main]
   permissions:
     contents: read
   jobs:
     audit:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
           with:
             persist-credentials: false
         - uses: Zard-Lab/ai-agent-security@<40-hex-commit-sha>  # v0.22.x
           with:
             fail-on: high
   ```

   **Inputs** (all optional):

   | input | default | meaning |
   |---|---|---|
   | `path` | `.` | directory to scan, relative to the checkout root; SARIF and annotation paths stay repo-relative |
   | `fail-on` | `high` | lowest severity that fails the gate: `critical`, `high` or `medium` |
   | `mode` | `gate` | `gate` fails the job when the gate trips; `advisory` reports, warns and passes |
   | `scanners` | `deterministic` | `deterministic` (guards plus installed static scanners, reproducible), `guards-only`, or `all` |
   | `baseline` | empty | exception registry (`--baseline`); empty uses the CLI default |
   | `baseline-snapshot` | empty | a saved snapshot (`agentsec audit --save-snapshot`): only findings new since it fail the gate or get annotated |
   | `exclude` | empty | path patterns to drop, one per line (`--exclude`) |
   | `top` | `50` | how many findings the job summary lists in detail (the full tally is always shown) |
   | `annotations` | `10` | how many of the most severe findings that are not baselined to annotate inline (any severity, most severe first); `0` turns them off |
   | `coverage` | `false` | `true` adds the checklist coverage score card (`agentsec coverage`) to the job summary and the artifact; it never affects the verdict |
   | `upload-sarif` | `false` | `true` uploads the SARIF to code scanning (see permissions) |
   | `sarif-category` | `agentsec` | code-scanning category, so several scans of one repo stay apart |
   | `artifact-name` | `agentsec-sarif` | name of the uploaded artifact (SARIF plus report); must be unique within a run |
   | `python-version` | `3.12` | Python to set up; empty uses the runner's own `python` (3.12 or newer) |

   **Outputs**: `verdict` (`pass` or `fail` whatever the mode, or `error` when the scan did not complete and
   the step fails), `exit-code` (agentsec's own: 0 pass, 1 gate tripped or a guard killed over its time
   budget), `results` (the SARIF result count) and `sarif` (the SARIF file's path).

   **How it fails.** The action never passes `--no-fail`; agentsec's exit code is the verdict. In `advisory`
   mode a tripped gate becomes a warning and the job passes. A scan that wrote no readable SARIF, exited
   with anything other than 0 or 1, or had a guard killed over its time budget (a PARTIAL scan, read from
   the SARIF's error notification) did not complete, and fails the job in **every** mode: a run that did not
   happen never shows green. The artifact is uploaded before the gate step, so it is there either way. The
   summary ends with links to report a false positive or a missed detection; they only open an issue form.

   **Permissions.** `contents: read` is all the audit needs. `upload-sarif: true` also needs
   `security-events: write` (and `actions: read` on a private repo), and on a private repository code
   scanning needs GitHub Code Security, which is why the upload is opt-in; the artifact works everywhere.

   **Fork pull requests** get a read-only token, so a code-scanning upload from one fails (the artifact still
   uploads first). Leave `upload-sarif` off for `pull_request` runs from forks, and never switch the workflow
   to `pull_request_target` to get a write token: that runs with secrets against untrusted code.

   **A private copy of agentsec** (your own private fork, or a pin to a release from before agentsec was
   public). A remote `uses:` cannot read a private action owned by another account. Check the agentsec repository out with a token, then use it as a local action, and
   add `.agentsec-action/` to your `.gitignore` so the scan skips it (otherwise its own fixtures change what
   your stack is detected as; the action drops its findings either way and warns). Do not check it out to
   `.agentsec/`: that is agentsec's own per-repo config directory (`config.json`, `suppress.json`):
   ```yaml
         - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
           with:
             persist-credentials: false
         - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
           with:
             repository: <owner>/<private-agentsec-repo>
             ref: <40-hex-commit-sha>          # v0.21.x
             token: ${{ secrets.AGENTSEC_PAT }}  # read-only access to the agentsec repo
             path: .agentsec-action
             persist-credentials: false
         - uses: ./.agentsec-action
   ```

   **Pin by commit SHA**, never a tag or a branch: a tag can be moved to new code after you review it, which
   is how the March 2026 `trivy-action` compromise reached its users. Dependabot and Renovate bump a SHA pin
   that carries the `# vX.Y.Z` comment.
2. **Component library** — add individual production gates à la carte with
   [`agentsec ci add`](#12-ci--the-cicd-component-library).
3. **Pre-commit hook** — run the dependency-free guards locally before each commit. agentsec ships a hook
   manifest (`.pre-commit-hooks.yaml`), so reference it by `repo:` + `rev:` in your
   `.pre-commit-config.yaml`:
   ```yaml
   repos:
     - repo: https://github.com/Zard-Lab/ai-agent-security
       rev: vX.Y.Z    # an agentsec release tag; `pre-commit autoupdate` bumps it
       hooks:
         - id: agentsec-guards
   ```
   Run `pre-commit install` once; every commit then runs `agentsec audit --guards-only . --fail-on high`.
   pre-commit installs agentsec into its own environment from that `rev:`, so agentsec need not be on your
   `PATH`. It does need Python 3.12 or newer: pre-commit builds the hook's environment with the Python
   version pre-commit itself runs on, so if that is older, add `language_version: python3.12` under the
   hook. To change the threshold, override `args:` (e.g. `args: [".", "--fail-on", "critical"]`);
   `--guards-only` lives in the hook's `entry`, so an `args:` override keeps the run fast and scanner-free.

## 17. Claude Code skills

Drop `claude-skills/*` into a project's `.claude/skills/` to drive the CLI conversationally:

| skill | use |
|---|---|
| `/security` | hub — routes to the right mode |
| `/security-prime` | first-run scoping: `agentsec suggest-excludes` + consent-gated `.agentsec/config.json` write (`--accept`) |
| `/security-review` | fast pre-merge gate on current changes |
| `/security-audit` | full sweep + a dated report, then triage findings and waive any FPs into the exception registry (`agentsec triage`/`report`) |
| `/security-fix` | patch the mechanical findings from the latest audit (`agentsec fix`); waive accepted findings with `agentsec triage --write-exception` |
| `/add-ci` | add a CI gate from natural language → `agentsec ci add` |
| `/harden-python` · `/harden-js` | update deps to the supply-chain standard |

## 18. Reading the report

```
# Security check — 3 issue(s) found

Needs work before shipping. There are serious problems to fix first.
_(1 high, 2 medium)_

## Fix these first
- **dangerouslySetInnerHTML without sanitizer** — untrusted markdown rendered without sanitization.

## Security findings (3: 1 high, 2 medium)

- 🔴 **HIGH** [frontend-xss] `src/Comment.tsx:42` — dangerouslySetInnerHTML without sanitizer  _[OWASP:A03]_
  - _Fix:_ route through DOMPurify or rehype-sanitize before render.

_Stack:_ … _Checks run:_ frontend-xss, public-table-rls, bandit, …
_Skipped (N/A for this stack):_ stripe-payments
_Scanners not installed (skipped):_ trivy, gitleaks
```

Findings sort `critical → info`; the **Fix these first** block leads with the most exploitable. The footer
tells you what ran, what was N/A for the stack, which scanners weren't installed, how many were suppressed
by exceptions, any lapsed exceptions, and any waiver that has gone unused (§14).

If a Python file could not be parsed, the footer gains a `⚠ Python files that could not be parsed` line.
It names up to five files with the parser's message, for example `legacy.py (line 8: Missing parentheses in
call to 'print'...)`, and counts the rest. A file lands there when it is Python 2, uses syntax newer than
the Python running agentsec, or is a template or a truncated file. The AST-based checks skipped it or fell
back to a text scan, so findings in it may be missing. The line is a notice, not a gate failure, and paths
you `--exclude` or archive are left out.

SARIF output (`--format sarif`) carries the **coverage** half of that disclosure — scanners not installed,
tier-skipped, reduced or errored, and Python files that could not be parsed — as
`toolExecutionNotifications`. The **waiver** half (suppressed counts,
broad waivers, lapsed, unused) currently reaches the markdown/summary footer only; a SARIF-only CI run
does not see it. Tracked as issue #708.

## 19. Exit codes

| command | exit 0 | non-zero |
|---|---|---|
| `audit` / `live` / `scan` | no findings at/above `--fail-on` (or `--no-fail`) | findings hit the gate → exit 1 |
| `ci add` | installed (or dry-run) cleanly | `1` = file conflict / N-A for stack; `2` = unknown component |
| `detect` / `trifecta` / `doctor` / `coverage` / `report-gap` / `ci list` / `ci show` | always informational (0) | — |

## 20. Troubleshooting

- **A check I expected didn't run.** Probably N/A for the detected stack — check `agentsec detect .` and the
  report's *Skipped (N/A)* line. Force a CI component with `agentsec ci add <id> . --force`.
- **A scanner shows as "not installed".** Install it (`agentsec doctor` lists how) or run `agentsec setup`;
  `agentsec audit` runs whichever are present. Use `--guards-only` for a fast, hermetic run.
- **`live` skipped a scanner.** Its tool or target was missing — the footer says which. Install the tool or
  pass the matching `--*-url`.
- **The footer lists Python files that could not be parsed.** If the message points at newer syntax (for
  example `except A, B:` or a `t"..."` string, both Python 3.14), run agentsec on that Python version. If
  it says `invalid escape sequence`, the file parses but your run promotes `SyntaxWarning` to an error
  (`-W error`). Drop that flag for the audit.
- **Too many findings to fix at once.** Snapshot a baseline (`--write-baseline agentsec-exceptions.json`) so
  only new findings gate; burn it down over time (lapsed `review_by` dates re-surface entries).
- **CI keeps failing on a finding you've accepted.** Add an exception entry (with a `reason` and
  `review_by`) — see [§14](#14-exceptions--baselines).
- **agentsec sees a stack with no guards.** Expected for unsupported stacks (Django/Flask/Express/…) —
  flag it with [`report-gap`](#10-report-gap--flag-an-uncovered-stack) so we prioritize building them.
