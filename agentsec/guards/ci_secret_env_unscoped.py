"""Guard: GitHub Actions secrets injected into pull-request CI runs without environment
scoping (ci-secret-env-unscoped).

When a GitHub Actions workflow references ``${{ secrets.* }}`` inside a job that has
**no** ``environment:`` declaration, the secret is injected into any workflow run
triggered by that job's ``on:`` events — including a ``pull_request`` run.

This is NOT fork-PR exfiltration: GitHub does not pass repository secrets (other than
the built-in, read-only ``GITHUB_TOKEN``) to a ``pull_request`` run triggered from a
fork at all, regardless of this guard's finding. The real exposure is narrower: **any
contributor who can push a branch to this repository and open a PR against it** gets
the secret injected into that PR's CI run, before any review or merge — no environment
protection rule (required reviewers, restricted branches) gates it. For a public repo
with outside collaborators, or any repo where "can open a PR" is a broader set of people
than "can push to main," this is still a real gap: an `environment:` with required-
reviewer protection forces a second human to approve before the secret flows, which a
same-repo PR alone does not.

The fix is to declare an **environment** on the job:

    jobs:
      deploy:
        environment: production    # gates this job behind environment protection rules
        steps:
          - run: deploy.sh
            env:
              API_KEY: ${{ secrets.API_KEY }}

GitHub's **environment protection rules** let you restrict which branches/tags can
trigger jobs in that environment and optionally require reviewer approval. For the
bare-``pull_request`` case this guard detects, required-reviewer protection is what
closes the gap: it forces a second human to approve before the job runs, so a lone
contributor opening a same-repo PR can no longer get the secret injected unreviewed.

**Detection:**
- Walk every ``.yml`` / ``.yaml`` file under ``.github/workflows/``.
- Split each file into per-job text slices (keyed by 2-space-indented job names under
  ``jobs:``).
- For each job slice: if ``${{ secrets.`` appears and the 4-space-indented
  ``environment:`` key is absent, emit a HIGH finding at the line the job name was
  found.
- A file-level pragma (a ``# security: allow-unscoped-ci-secret`` comment anywhere in the
  file) silences the check for the whole file — use when all secrets are intentionally
  accessible repo-wide (e.g. public repos with no sensitive secrets).

**Standards:** OWASP:A02 (Cryptographic Failures / secret exposure).

A SECOND, unrelated-mechanism rule targets the gap this module's own docstring already named
above: `pull_request_target:` "runs in the BASE repo's context and separately CAN expose secrets
to a fork's code, but only if the workflow also checks out the fork's head — a different,
harder-to-detect pattern not caught here." This is GitHub's own documented "Pwn Request"
anti-pattern: a `pull_request_target`-triggered job that then runs `actions/checkout` with a
`ref:` naming the PR's own (fork-controlled) head — `github.event.pull_request.head.sha`,
`github.event.pull_request.head.ref`, `github.head_ref`, or a literal `refs/pull/<n>/merge` —
lets fork-authored code execute in the BASE repo's privileged context: the `GITHUB_TOKEN` in that
context typically has WRITE access, and any `${{ secrets.* }}` the job references is exposed to
code the fork author controls. This is more severe than the unscoped-secret gap above (arbitrary
code execution with repo-write privileges, not just secret exfiltration) and does not require
`${{ secrets.* }}` to be present at all — the write-scoped `GITHUB_TOKEN` alone is a real target.

Real-world precedent: **GHSA-9ppg-jx86-fqw7** ("Clinejection") and the 2026 **TanStack** npm
supply-chain compromise both root-caused in this exact checkout pattern (Clinejection additionally
chained an LLM-agent prompt injection to trigger it; TanStack chained it into GitHub Actions cache
poisoning across two separate workflows — see `actions_script_injection.py`'s
`cache-trust-boundary` rule for that second half).

Fires **CRITICAL** on a `pull_request_target:`-triggered workflow whose job checks out the fork's
own head ref. Rule `ci-secret-env-unscoped/pull-request-target-fork-checkout`. Suppress an
audited case with `# security: allow-pr-target-fork-checkout` anywhere in the file (a SEPARATE
pragma from the unscoped-secret rule's — the two threats are independent, so an author silencing
one should not accidentally silence the other).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, pragma_present, read, rel

_PRAGMA = "security: allow-unscoped-ci-secret"

_STANDARDS = ["OWASP:A02"]

# Job start: a word-character key at exactly 2-space indent, followed by a colon and
# optional trailing whitespace, on its own line.  Matches GitHub Actions job IDs.
_JOB_START = re.compile(r"^  ([\w-]+):\s*$", re.MULTILINE)

# The `on:` trigger block (the `on:` line through to the next top-level key / EOF).
_ON_SECTION = re.compile(r"(?ms)^on:.*?(?=^\S|\Z)")

# Matches the bare `pull_request` event key but NOT `pull_request_target` (or any other
# `pull_request_*` variant). Word boundary after `t` is only present when the next
# character is `:` or whitespace — the `_` in `pull_request_target` is a word char so
# `\b` does not match there.
# Known CI service tokens explicitly designed for safe use in fork PR workflows.
# These providers scope the token so it can only push benchmark/coverage data —
# a malicious fork cannot use them to access sensitive resources.
_SAFE_CI_SERVICE_TOKENS = frozenset({
    "CODSPEED_TOKEN",     # CodSpeed performance benchmarking
    "CODECOV_TOKEN",      # Codecov code coverage
    "SMOKESHOW_AUTH_KEY", # Smokeshow HTML coverage upload
    "SONAR_TOKEN",        # SonarCloud static analysis
    "SONARCLOUD_TOKEN",   # SonarCloud (alternate naming)
})

_BARE_PULL_REQUEST = re.compile(r"\bpull_request\b")

# NS-11: the "Pwn Request" checkout pattern — pull_request_target + a checkout of the fork's
# own head, independent of the unscoped-secrets rule above (own pragma, own trigger check).
_PULL_REQUEST_TARGET = re.compile(r"\bpull_request_target\b")
_PRAGMA_FORK_CHECKOUT = re.compile(r"#\s*security:\s*allow-pr-target-fork-checkout")
_CHECKOUT_STEP = re.compile(r"uses:\s*actions/checkout@")
_FORK_HEAD_REF = re.compile(
    r"ref:\s*\$\{\{\s*github\.(?:event\.pull_request\.head\.(?:sha|ref)|head_ref)\s*\}\}"
    r"|ref:\s*['\"]?refs/pull/\$\{\{\s*github\.event\.pull_request\.number\s*\}\}/merge",
    re.IGNORECASE,
)

# A `${{ secrets.* }}` reference, and the same reference with its name captured. GitHub Actions
# allows any amount of whitespace — including none — inside the expression braces, so
# `${{secrets.API_KEY}}` is the identical reference to `${{ secrets.API_KEY }}`. The job gate
# used to test the literal string `"${{ secrets."`, which the compact spelling fails, so the job
# was dropped before `_SECRET_NAME` (whose `\s*` always allowed both) ever ran (#422). Both
# spellings now come from one place, so the gate and the extraction cannot disagree again.
_SECRETS_REF = re.compile(r"\$\{\{\s*secrets\.")
_SECRET_NAME = re.compile(r"\$\{\{\s*secrets\.(\w+)\s*\}\}")

# A shell `run:` step inside a job slice. Step-level `run:` sits at 8-space indent
# (`        run:`) or is the first key after the step dash (`      - run:`).
# A `with:` sub-key named `run:` sits at 10-space indent and is NOT matched.
_SHELL_RUN_IN_JOB = re.compile(r"\n {8}run:|\n {6}-[ \t]+run:", re.MULTILINE)

# A job-level `if:` condition (4-space indent in a job definition) that explicitly
# restricts the job to push / release / tag / workflow_dispatch events or excludes
# pull_request.  No `pull_request` run (same-repo or fork) can satisfy these
# conditions, so secrets in the job are never injected on a PR run.
_JOB_IF_NON_PR = re.compile(
    r"\n    if:.*"
    r"(?:github\.event_name\s*==\s*['\"](?:push|release|workflow_dispatch|schedule)['\"]"
    r"|github\.event_name\s*!=\s*['\"]pull_request['\"]"
    r"|startsWith\s*\(\s*github\.ref\s*,\s*['\"]refs/tags/['\"]"
    r"|github\.ref\s*==\s*['\"]refs/heads/(?:main|master)['\"])",
    re.MULTILINE | re.IGNORECASE,
)


def _pull_request_triggerable(text: str) -> bool:
    """True only if the workflow is triggered by the bare `pull_request` event.

    NOT "reachable from a fork": GitHub withholds repo secrets (other than
    `GITHUB_TOKEN`) from a `pull_request` run triggered by a fork entirely, so that
    path is already safe regardless of this guard. What `pull_request:` DOES expose
    the secret to is any PR opened from a branch IN this repository (a contributor
    with push access, no fork needed) — the run gets the secret, unreviewed, the
    moment the PR is opened. `pull_request_target:` runs in the BASE repo's context
    and separately CAN expose secrets to a fork's code, but only if the workflow also
    checks out the fork's head — a different, harder-to-detect pattern not caught here."""
    m = _ON_SECTION.search(text)
    section = m.group(0) if m else ""
    return bool(_BARE_PULL_REQUEST.search(section))


def _pull_request_target_triggerable(text: str) -> bool:
    m = _ON_SECTION.search(text)
    section = m.group(0) if m else ""
    return bool(_PULL_REQUEST_TARGET.search(section))


def _fork_checkout_lines(text: str) -> list[int]:
    """Line numbers where a `ref:` inside a `- uses: actions/checkout@…` step names the PR's
    own (fork-controlled) head. Bounded to the CURRENT step's own lines — mirrors
    `ai_docker.py`'s `_check_mcp_port_exposed` block-tracking style: a step begins at a `- `
    dash, and ends at the next line whose indent is at or shallower than that dash's.

    `is_checkout` is checked on EVERY line of the step, not just the dash line (PR #741 review,
    Major 1). A step conventionally opens with `- name: ...` for readability, with `uses:` on its
    own line below — `- uses: actions/checkout@v4` and `- name: Checkout\n  uses: actions/checkout@v4`
    are the same step, but only the first form matched when `is_checkout` was set once, on the
    dash line, and never re-checked. That shape is, if anything, the more common one in real
    workflows, so the gap shipped as a silent miss on the majority case."""
    out: list[int] = []
    in_step = False
    step_indent = -1
    is_checkout = False
    for i, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped:
            continue
        indent = len(raw) - len(raw.lstrip())
        if stripped.startswith("- "):
            step_indent = indent
            is_checkout = bool(_CHECKOUT_STEP.search(stripped))
            in_step = True
            continue
        if in_step and indent <= step_indent:
            in_step = False
            is_checkout = False
        if in_step and not is_checkout:
            is_checkout = bool(_CHECKOUT_STEP.search(stripped))
        if in_step and is_checkout and _FORK_HEAD_REF.search(raw):
            out.append(i)
    return out


class CiSecretEnvUnscopedGuard(Guard):
    id = "ci-secret-env-unscoped"
    title = "GitHub Actions secret used without an environment scope"
    area = "Build pipeline"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `.github/workflows/deploy.yml`, which several guards trip at once, so the file stays in
    # `canary.py`'s base owned by no guard. The ownership rule this follows is documented on
    # `xxe_safe.py`.
    # .github/workflows/deploy.yml: `deploy` job uses ${{ secrets.DEPLOY_KEY }} with no
    # environment: key -> fires no-environment-scope (HIGH).
    #
    # No canary demonstration for the fork-checkout rule (NS-11): the shared deploy.yml is a
    # base file several guards trip on, and a pull_request_target trigger there would change
    # what the shared no-environment-scope plant means (that plant is deliberately triggered
    # by bare pull_request:, not _target:) — risking a cross-rule interaction on a file this
    # guard doesn't own. Coverage is its dedicated unit tests below; `canary_plant` still
    # declares (non-None), satisfying `test_every_guard_declares_its_own_plant`'s per-GUARD
    # (not per-rule) requirement.
    canary_plant = CanaryPlant(expects=frozenset({"ci-secret-env-unscoped/no-environment-scope"}))

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def _workflow_files(self, workflows: Path) -> list[Path]:
        """GitHub only executes workflow files placed DIRECTLY in `.github/workflows/` — a file
        in any subdirectory (`backup/`, `disabled/`, `templates/`) is never run and therefore not
        exploitable. `actions_script_injection.py`'s sibling scoping already fixed this same gap;
        this guard used recursive `iter_files()` instead and inherited the FP class the sibling's
        fix pattern was on hand for (PR #741 review, Minor 5). Top level only, not recursive."""
        return sorted(p for p in workflows.iterdir() if p.is_file() and p.suffix in (".yml", ".yaml"))

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        if not self.applies(profile):
            return []

        workflows = root / ".github" / "workflows"
        if not workflows.is_dir():
            return []

        out: list[Finding] = []
        for f in self._workflow_files(workflows):
            text = read(f)
            # File-level pragma silences the entire file.
            if pragma_present(_PRAGMA, text, dialect="yaml"):
                continue
            # Only pull_request-triggerable workflows can leak a secret to an unreviewed PR run.
            if not _pull_request_triggerable(text):
                continue

            # Find all job-name matches to slice the file into per-job sections.
            job_matches = list(_JOB_START.finditer(text))
            for idx, job_m in enumerate(job_matches):
                job_name = job_m.group(1)
                job_start = job_m.start()
                # The job section runs until the next job starts (or end of file).
                job_end = job_matches[idx + 1].start() if idx + 1 < len(job_matches) else len(text)
                job_slice = text[job_start:job_end]

                # Check for secret references in this job's slice.
                if not _SECRETS_REF.search(job_slice):
                    continue

                # GITHUB_TOKEN is a built-in automatic token scoped to the current run —
                # it cannot be exfiltrated in a useful way.  Skip jobs whose ONLY secret
                # reference is the built-in GITHUB_TOKEN.
                secret_refs = _SECRET_NAME.findall(job_slice)
                if secret_refs and all(r.upper() == "GITHUB_TOKEN" for r in secret_refs):
                    continue

                # Bounded-scope service tokens (CodSpeed, Codecov, etc.) are explicitly
                # designed for fork PR workflows — skip if ALL non-GITHUB_TOKEN refs
                # are known-safe service tokens.
                non_github = [r for r in secret_refs if r.upper() != "GITHUB_TOKEN"]
                if non_github and all(r.upper() in _SAFE_CI_SERVICE_TOKENS for r in non_github):
                    continue

                # A job with no shell `run:` steps exposes secrets only via `with:` inputs
                # to trusted GitHub Actions — fork shell code cannot read them.
                if not _SHELL_RUN_IN_JOB.search(job_slice):
                    continue

                # A job-level `if:` condition that restricts execution to push/release/tag
                # events means a fork PR can never trigger this job — secrets are safe.
                if _JOB_IF_NON_PR.search(job_slice):
                    continue

                # Check for a 4-space-indented environment: key within this job's slice.
                # GitHub Actions uses 4-space indent for job-level keys (job name at 2,
                # its keys at 4).
                if "\n    environment:" in job_slice:
                    continue

                # Compute the line number of the job name for the finding location.
                job_line = text[:job_m.start()].count("\n") + 1

                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title="GitHub Actions secret used without an environment scope",
                        location=f"{rel(root, f)}:{job_line}",
                        message=(
                            f"Job `{job_name}` references `${{{{ secrets.* }}}}` but declares "
                            "no `environment:` key. Without an environment, GitHub injects the "
                            "secret into any pull-request run against this repository, before "
                            "any review — including from a contributor who can push a branch "
                            "here but not to main. That contributor can exfiltrate the secret "
                            "via logs, curl, or build artifacts. (This trigger does not by "
                            "itself expose the secret to an outside fork PR — GitHub already "
                            "withholds secrets there.)"
                        ),
                        remediation=(
                            f"Add `environment: production` (or another gated environment) "
                            f"to job `{job_name}`:\n"
                            "    jobs:\n"
                            f"      {job_name}:\n"
                            "        environment: production\n"
                            "Then configure environment protection rules in GitHub "
                            "(Settings → Environments) to restrict which branches/tags "
                            "can trigger it and optionally require reviewer approval. "
                            "If broad secret access is intentional, add "
                            "`# security: allow-unscoped-ci-secret` anywhere in the file."
                        ),
                        rule="ci-secret-env-unscoped/no-environment-scope",
                        standards=list(_STANDARDS),
                    )
                )

        # NS-11 — a SEPARATE pass, own pragma, own trigger check: pull_request_target + a
        # checkout of the fork's own head (the "Pwn Request" pattern). Independent of secrets
        # presence, so it runs regardless of what the pass above found.
        for f in self._workflow_files(workflows):
            text = read(f)
            if pragma_present(_PRAGMA_FORK_CHECKOUT, text, dialect="yaml"):
                continue
            if not _pull_request_target_triggerable(text):
                continue
            for line_no in _fork_checkout_lines(text):
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="critical",
                        title="pull_request_target workflow checks out the PR's own (fork-controlled) code",
                        location=f"{rel(root, f)}:{line_no}",
                        message=(
                            "This job is triggered by `pull_request_target` (runs in the BASE "
                            "repo's context, with its GITHUB_TOKEN and secrets) and checks out "
                            "the PR's own head ref. Fork-authored code then executes with the "
                            "base repo's privileges — the write-scoped GITHUB_TOKEN alone is a "
                            "real target even with no other secrets referenced. This is GitHub's "
                            'documented "Pwn Request" anti-pattern, and the root cause of the '
                            "Clinejection (GHSA-9ppg-jx86-fqw7) and 2026 TanStack npm "
                            "supply-chain compromises."
                        ),
                        remediation=(
                            "Do not check out the PR's own head under pull_request_target. If "
                            "you need to build/test the PR's code, use the bare `pull_request:` "
                            "trigger instead (no privileged context, no secrets to a fork by "
                            "default) — or, if you specifically need pull_request_target for a "
                            "labeling/triage step, drop the checkout of `ref:` entirely and only "
                            "read PR metadata via the `github.event.pull_request` context. "
                            "Suppress an audited case with "
                            "`# security: allow-pr-target-fork-checkout` anywhere in the file."
                        ),
                        rule="ci-secret-env-unscoped/pull-request-target-fork-checkout",
                        standards=["OWASP:A08", "OWASP:A03"],
                    )
                )

        return out
