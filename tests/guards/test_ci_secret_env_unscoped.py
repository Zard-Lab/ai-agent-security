from __future__ import annotations

from agentsec.guards.ci_secret_env_unscoped import CiSecretEnvUnscopedGuard
from tests.guards._common import *  # noqa: F401,F403


def test_ci_secret_env_unscoped_fires(tmp_path: Path) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "deploy.yml").write_text(
        # fork-reachable (pull_request) + unscoped secret + no environment -> fires.
        "on:\n  pull_request:\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: echo ${{ secrets.API_KEY }}\n",
        encoding="utf-8",
    )
    findings = CiSecretEnvUnscopedGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert any(f.rule == "ci-secret-env-unscoped/no-environment-scope" for f in findings)

def test_ci_secret_env_unscoped_ignores_workflow_subdirectory(tmp_path: Path) -> None:
    # PR #741 review, Minor 5: GitHub only executes workflows placed DIRECTLY in
    # .github/workflows/. A copy under a subdirectory (backup/, disabled/, templates/) is never
    # run and must not fire either rule -- `actions_script_injection.py`'s sibling already fixed
    # this exact FP class (§C.1, 29 obsidian FPs); this guard used a recursive `iter_files()` and
    # inherited the same gap for both its no-environment-scope and fork-checkout rules.
    sub = tmp_path / ".github" / "workflows" / "backup"
    sub.mkdir(parents=True)
    (sub / "old-deploy.yml").write_text(
        "on:\n  pull_request:\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: echo ${{ secrets.API_KEY }}\n",
        encoding="utf-8",
    )
    (sub / "old-triage.yml").write_text(
        "on:\n  pull_request_target:\n"
        "jobs:\n  triage:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n",
        encoding="utf-8",
    )
    assert CiSecretEnvUnscopedGuard().run(tmp_path, _python_nodirs_prof(tmp_path)) == []


def test_ci_secret_env_unscoped_silent_on_non_fork_triggers(tmp_path: Path) -> None:
    # push/schedule-only workflows can't be triggered by a fork PR -> no exfil risk -> silent.
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "cron.yml").write_text(
        "on:\n  schedule:\n    - cron: '0 0 * * *'\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: echo ${{ secrets.API_KEY }}\n",
        encoding="utf-8",
    )
    assert CiSecretEnvUnscopedGuard().run(tmp_path, _python_nodirs_prof(tmp_path)) == []

def test_ci_secret_env_unscoped_environment_silences(tmp_path: Path) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "deploy.yml").write_text(
        "jobs:\n  build:\n    environment: production\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: echo ${{ secrets.API_KEY }}\n",
        encoding="utf-8",
    )
    assert CiSecretEnvUnscopedGuard().run(tmp_path, _python_nodirs_prof(tmp_path)) == []

def test_ci_secret_env_unscoped_no_workflows_silent(tmp_path: Path) -> None:
    assert CiSecretEnvUnscopedGuard().run(tmp_path, _python_nodirs_prof(tmp_path)) == []

def test_ci_secret_env_unscoped_github_token_only_silent(tmp_path: Path) -> None:
    # FP fix: GITHUB_TOKEN is a built-in automatic token; jobs that only use it
    # are not leaking user-defined secrets to fork PRs.
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        "on:\n  pull_request:\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          token: ${{ secrets.GITHUB_TOKEN }}\n",
        encoding="utf-8",
    )
    assert CiSecretEnvUnscopedGuard().run(tmp_path, _python_nodirs_prof(tmp_path)) == []

def test_ci_secret_env_unscoped_github_token_plus_other_fires(tmp_path: Path) -> None:
    # If a job references GITHUB_TOKEN AND another secret, it should still fire.
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "deploy.yml").write_text(
        "on:\n  pull_request:\n"
        "jobs:\n"
        "  deploy:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: deploy.sh\n"
        "        env:\n"
        "          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n"
        "          API_KEY: ${{ secrets.API_KEY }}\n",
        encoding="utf-8",
    )
    findings = CiSecretEnvUnscopedGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert any(f.rule == "ci-secret-env-unscoped/no-environment-scope" for f in findings)

def test_ci_secret_env_unscoped_silent_on_pull_request_target(tmp_path: Path) -> None:
    # pull_request_target runs in the BASE repo context and does not expose secrets to
    # fork code by default — only the bare `pull_request:` event does.
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "add-to-project.yml").write_text(
        "on:\n  pull_request_target:\n    types: [opened]\n"
        "jobs:\n  add:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/add-to-project@v1\n"
        "        with:\n"
        "          project-url: https://github.com/orgs/myorg/projects/1\n"
        "          github-token: ${{ secrets.ADD_TO_PROJECT_PAT }}\n",
        encoding="utf-8",
    )
    assert CiSecretEnvUnscopedGuard().run(tmp_path, _python_nodirs_prof(tmp_path)) == []

def test_ci_secret_env_unscoped_fires_on_bare_pull_request(tmp_path: Path) -> None:
    # The bare pull_request: event DOES expose secrets to fork code — must fire.
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        "on:\n  pull_request:\n    branches: [main]\n"
        "jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: deploy.sh\n"
        "        env:\n"
        "          API_KEY: ${{ secrets.DEPLOY_KEY }}\n",
        encoding="utf-8",
    )
    findings = CiSecretEnvUnscopedGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert any(f.rule == "ci-secret-env-unscoped/no-environment-scope" for f in findings)

def test_ci_secret_env_unscoped_silent_on_known_safe_service_token(tmp_path: Path) -> None:
    # CODSPEED_TOKEN is designed for fork PR use by its provider — must stay silent.
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "codspeed.yml").write_text(
        "on:\n  pull_request:\n    branches: [main]\n"
        "jobs:\n  benchmarks:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: codspeed-hq/codspeed-action@v3\n"
        "        with:\n"
        "          token: ${{ secrets.CODSPEED_TOKEN }}\n",
        encoding="utf-8",
    )
    assert CiSecretEnvUnscopedGuard().run(tmp_path, _python_nodirs_prof(tmp_path)) == []

def test_ci_secret_env_unscoped_silent_actions_only_job(tmp_path: Path) -> None:
    # A job with only `uses:` action steps and no shell `run:` step exposes
    # secrets only to trusted action code — fork shell cannot access them.
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "coverage.yml").write_text(
        "on:\n  pull_request:\n"
        "jobs:\n  report:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: smokeshow/smokeshow-action@v2\n"
        "        with:\n"
        "          auth-key: ${{ secrets.SMOKESHOW_AUTH_KEY }}\n"
        "          coverage-response-file: coverage.xml\n",
        encoding="utf-8",
    )
    assert CiSecretEnvUnscopedGuard().run(tmp_path, _python_nodirs_prof(tmp_path)) == []

def test_ci_secret_env_unscoped_fires_safe_token_plus_deploy_key(tmp_path: Path) -> None:
    # When a job mixes a safe token with a real deploy key it must still fire.
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        "on:\n  pull_request:\n"
        "jobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: deploy.sh\n"
        "        env:\n"
        "          CODSPEED_TOKEN: ${{ secrets.CODSPEED_TOKEN }}\n"
        "          DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}\n",
        encoding="utf-8",
    )
    findings = CiSecretEnvUnscopedGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert any(f.rule == "ci-secret-env-unscoped/no-environment-scope" for f in findings)

def test_ci_secret_env_unscoped_silent_push_only_job(tmp_path: Path) -> None:
    # A job gated by `if: github.event_name == 'push'` cannot run on a fork PR —
    # the `if:` condition fails. Secrets in that job are safe even with run: steps.
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        "on:\n  pull_request:\n  push:\n    branches: [main]\n"
        "jobs:\n"
        "  deploy-docs:\n"
        "    runs-on: ubuntu-latest\n"
        "    if: github.event_name == 'push'\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: ./deploy-docs.sh\n"
        "        env:\n"
        "          DOCS_TOKEN: ${{ secrets.DOCS_TOKEN }}\n",
        encoding="utf-8",
    )
    assert CiSecretEnvUnscopedGuard().run(tmp_path, _python_nodirs_prof(tmp_path)) == []

def test_ci_secret_env_unscoped_message_does_not_claim_fork_exfiltration(tmp_path: Path) -> None:
    # GitHub withholds secrets from a pull_request run triggered by a fork
    # entirely, so the finding must not claim fork-PR exfiltration for this trigger.
    # The real exposure is a same-repo contributor opening a PR; the message must name it.
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "deploy.yml").write_text(
        "on:\n  pull_request:\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: echo ${{ secrets.API_KEY }}\n",
        encoding="utf-8",
    )
    findings = CiSecretEnvUnscopedGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert findings
    message = next(f.message for f in findings if f.rule == "ci-secret-env-unscoped/no-environment-scope")
    assert "public fork" not in message.lower()
    assert "push a branch" in message.lower()

def test_ci_secret_env_unscoped_fires_without_job_if_condition(tmp_path: Path) -> None:
    # Same multi-trigger workflow but no `if:` gate on the job — fork PR can reach it.
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        "on:\n  pull_request:\n  push:\n    branches: [main]\n"
        "jobs:\n"
        "  deploy-docs:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: ./deploy-docs.sh\n"
        "        env:\n"
        "          DOCS_TOKEN: ${{ secrets.DOCS_TOKEN }}\n",
        encoding="utf-8",
    )
    findings = CiSecretEnvUnscopedGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert any(f.rule == "ci-secret-env-unscoped/no-environment-scope" for f in findings)


def test_ci_secret_env_unscoped_fires_on_compact_secrets_ref(tmp_path: Path) -> None:
    # ${{secrets.X}} without inner spaces is valid GitHub Actions syntax and must fire (#422):
    # the job gate matched the literal "${{ secrets." while the ref extraction below it already
    # allowed any whitespace, so the compact spelling was dropped before it was ever read.
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "deploy.yml").write_text(
        "on:\n  pull_request:\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: echo ${{secrets.MY_TOKEN}}\n",
        encoding="utf-8",
    )
    findings = CiSecretEnvUnscopedGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert any(f.rule == "ci-secret-env-unscoped/no-environment-scope" for f in findings)

def test_ci_secret_env_unscoped_environment_silences_compact_ref(tmp_path: Path) -> None:
    # FP-bait for the widening: the scoped/safe shape written compactly must stay silent.
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "deploy.yml").write_text(
        "on:\n  pull_request:\n"
        "jobs:\n  build:\n    environment: production\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: echo ${{secrets.MY_TOKEN}}\n",
        encoding="utf-8",
    )
    assert CiSecretEnvUnscopedGuard().run(tmp_path, _python_nodirs_prof(tmp_path)) == []

def test_ci_secret_env_unscoped_pr_target_fork_checkout_fires(tmp_path: Path) -> None:
    # GitHub's "Pwn Request" pattern (Clinejection/TanStack root cause): pull_request_target +
    # checking out the PR's own (fork-controlled) head ref.
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "triage.yml").write_text(
        "on:\n  pull_request_target:\n"
        "jobs:\n  triage:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n",
        encoding="utf-8",
    )
    findings = CiSecretEnvUnscopedGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    matches = [f for f in findings if f.rule == "ci-secret-env-unscoped/pull-request-target-fork-checkout"]
    assert len(matches) == 1
    assert matches[0].severity == "critical"


def test_ci_secret_env_unscoped_pr_target_fork_checkout_named_step_fires(tmp_path: Path) -> None:
    # PR #741 review, Major 1: a step opening with `- name: ...` (uses: on its own line below) is
    # the same step as `- uses: actions/checkout@v4` directly -- and the more conventional form,
    # since `name:` is written for readability. Must fire identically to the dash-line-uses shape.
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "triage.yml").write_text(
        "on:\n  pull_request_target:\n"
        "jobs:\n  triage:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - name: Checkout PR head\n"
        "        uses: actions/checkout@v4\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n",
        encoding="utf-8",
    )
    findings = CiSecretEnvUnscopedGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    matches = [f for f in findings if f.rule == "ci-secret-env-unscoped/pull-request-target-fork-checkout"]
    assert len(matches) == 1
    assert matches[0].severity == "critical"


def test_ci_secret_env_unscoped_pr_target_fork_checkout_head_ref_fires(tmp_path: Path) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "triage.yml").write_text(
        "on:\n  pull_request_target:\n"
        "jobs:\n  triage:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          ref: ${{ github.head_ref }}\n",
        encoding="utf-8",
    )
    findings = CiSecretEnvUnscopedGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert any(
        f.rule == "ci-secret-env-unscoped/pull-request-target-fork-checkout" for f in findings
    )


def test_ci_secret_env_unscoped_pr_target_fork_checkout_merge_ref_fires(tmp_path: Path) -> None:
    # The TanStack incident's exact literal form: refs/pull/<n>/merge.
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "bundle-size.yml").write_text(
        "on:\n  pull_request_target:\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          ref: refs/pull/${{ github.event.pull_request.number }}/merge\n",
        encoding="utf-8",
    )
    findings = CiSecretEnvUnscopedGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert any(
        f.rule == "ci-secret-env-unscoped/pull-request-target-fork-checkout" for f in findings
    )


def test_ci_secret_env_unscoped_pr_target_no_checkout_stays_silent(tmp_path: Path) -> None:
    # pull_request_target with NO checkout of the fork's head (e.g. only reading PR metadata,
    # or checking out the BASE ref) is safe -- must not fire.
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "label.yml").write_text(
        "on:\n  pull_request_target:\n"
        "jobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/labeler@v5\n",
        encoding="utf-8",
    )
    findings = CiSecretEnvUnscopedGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert [
        f for f in findings if f.rule == "ci-secret-env-unscoped/pull-request-target-fork-checkout"
    ] == []


def test_ci_secret_env_unscoped_pr_target_named_non_checkout_step_stays_silent(tmp_path: Path) -> None:
    # FP-bait for the Major 1 fix: a named step whose action is NOT actions/checkout, with a
    # `ref:`-like key in its `with:` block, must not be swept in just because it opens with
    # `- name: ...` the same way a real checkout step now does.
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "deploy.yml").write_text(
        "on:\n  pull_request_target:\n"
        "jobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - name: Set up Node\n"
        "        uses: actions/setup-node@v4\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n",
        encoding="utf-8",
    )
    findings = CiSecretEnvUnscopedGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert [
        f for f in findings if f.rule == "ci-secret-env-unscoped/pull-request-target-fork-checkout"
    ] == []


def test_ci_secret_env_unscoped_pr_target_checkout_base_ref_stays_silent(tmp_path: Path) -> None:
    # FP-bait: pull_request_target + a checkout, but of the BASE ref (default, or explicit) --
    # not the fork's head -- must stay silent.
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "build.yml").write_text(
        "on:\n  pull_request_target:\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n",
        encoding="utf-8",
    )
    findings = CiSecretEnvUnscopedGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert [
        f for f in findings if f.rule == "ci-secret-env-unscoped/pull-request-target-fork-checkout"
    ] == []


def test_ci_secret_env_unscoped_bare_pull_request_fork_head_ref_stays_silent(tmp_path: Path) -> None:
    # FP-bait: the SAME fork-head ref pattern under a BARE pull_request: trigger is not this
    # rule's target -- GitHub already withholds secrets from a fork-triggered pull_request run,
    # and checking out your own PR's head under pull_request: is the normal, safe default.
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        "on:\n  pull_request:\n"
        "jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n",
        encoding="utf-8",
    )
    findings = CiSecretEnvUnscopedGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert [
        f for f in findings if f.rule == "ci-secret-env-unscoped/pull-request-target-fork-checkout"
    ] == []


def test_ci_secret_env_unscoped_pr_target_fork_checkout_pragma_silences(tmp_path: Path) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "triage.yml").write_text(
        "# security: allow-pr-target-fork-checkout\n"
        "on:\n  pull_request_target:\n"
        "jobs:\n  triage:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n",
        encoding="utf-8",
    )
    findings = CiSecretEnvUnscopedGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert findings == []


def test_ci_secret_env_unscoped_pr_target_fork_checkout_other_step_ref_stays_silent(
    tmp_path: Path,
) -> None:
    # FP-bait: the fork-head ref pattern appears, but on a DIFFERENT (non-checkout) step --
    # must not be attributed to a checkout that isn't there.
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "comment.yml").write_text(
        "on:\n  pull_request_target:\n"
        "jobs:\n  comment:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: some/other-action@v1\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n",
        encoding="utf-8",
    )
    findings = CiSecretEnvUnscopedGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert [
        f for f in findings if f.rule == "ci-secret-env-unscoped/pull-request-target-fork-checkout"
    ] == []


def test_ci_secret_env_unscoped_compact_github_token_only_stays_silent(tmp_path: Path) -> None:
    # FP-bait: the built-in GITHUB_TOKEN skip must survive the widening — a job whose only
    # secret is the compact `${{secrets.GITHUB_TOKEN}}` is still not a finding.
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "deploy.yml").write_text(
        "on:\n  pull_request:\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: gh pr list\n"
        "        env:\n"
        "          GH_TOKEN: ${{secrets.GITHUB_TOKEN}}\n",
        encoding="utf-8",
    )
    assert CiSecretEnvUnscopedGuard().run(tmp_path, _python_nodirs_prof(tmp_path)) == []


def test_ci_secret_env_unscoped_file_pragma_comment_silences(tmp_path: Path) -> None:
    # The documented form of the file-level opt-out: a YAML comment anywhere in the workflow file.
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "deploy.yml").write_text(
        "# security: allow-unscoped-ci-secret\n"
        "on:\n  pull_request:\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: echo ${{ secrets.API_KEY }}\n",
        encoding="utf-8",
    )
    assert CiSecretEnvUnscopedGuard().run(tmp_path, _python_nodirs_prof(tmp_path)) == []


def test_ci_secret_env_unscoped_pragma_inside_a_run_script_does_not_silence(tmp_path: Path) -> None:
    # #424 E2: a `run: |` block scalar is string content to YAML, so a shell comment inside it that
    # carries the phrase is not a workflow comment and no longer opts the whole file out — the
    # raw-text match honoured it (and any quoted mention of the syntax) file-wide.
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "deploy.yml").write_text(
        "on:\n  pull_request:\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: |\n"
        "          # security: allow-unscoped-ci-secret\n"
        "          echo ${{ secrets.API_KEY }}\n",
        encoding="utf-8",
    )
    findings = CiSecretEnvUnscopedGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert any(f.rule == "ci-secret-env-unscoped/no-environment-scope" for f in findings)
