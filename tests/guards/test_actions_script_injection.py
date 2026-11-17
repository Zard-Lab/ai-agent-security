from __future__ import annotations

from agentsec.guards.actions_script_injection import ActionsScriptInjectionGuard
from tests.guards._common import *  # noqa: F401,F403


def test_actions_script_injection_flags_event_title(tmp_path: Path) -> None:
    _wf(tmp_path, "jobs:\n  b:\n    steps:\n      - run: echo ${{ github.event.pull_request.title }}\n")
    findings = ActionsScriptInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))
    assert len(findings) == 1
    assert findings[0].rule == "actions-script-injection/untrusted-run-interpolation"
    assert findings[0].severity == "high"

def test_actions_script_injection_flags_head_ref_multiline(tmp_path: Path) -> None:
    _wf(tmp_path, "jobs:\n  b:\n    steps:\n      - run: |\n          echo ${{ github.head_ref }}\n")
    assert len(ActionsScriptInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))) == 1

def test_actions_script_injection_passes_env_indirection(tmp_path: Path) -> None:
    _wf(
        tmp_path,
        "jobs:\n  b:\n    steps:\n      - env:\n"
        "          T: ${{ github.event.pull_request.title }}\n        run: echo \"$T\"\n",
    )
    assert ActionsScriptInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"python"})) == []

def test_actions_script_injection_passes_safe_context(tmp_path: Path) -> None:
    _wf(tmp_path, "jobs:\n  b:\n    steps:\n      - run: echo ${{ github.sha }} ${{ github.run_id }}\n")
    assert ActionsScriptInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"python"})) == []

def test_actions_script_injection_pragma(tmp_path: Path) -> None:
    _wf(
        tmp_path,
        "jobs:\n  b:\n    steps:\n      - run: echo ${{ github.event.pull_request.title }}"
        "  # security: allow-actions-interpolation\n",
    )
    assert ActionsScriptInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"python"})) == []

def test_actions_script_injection_passes_env_after_run(tmp_path: Path) -> None:
    # #423 FP-bait: a `- run:` block followed by the step's own `env:` sibling (indented
    # deeper than the dash but shallower than the run body). Keying run_indent off the
    # dash column used to treat this safe `env:` indirection as inside the run block.
    _wf(
        tmp_path,
        "jobs:\n  b:\n    steps:\n      - run: |\n          echo hi\n"
        "        env:\n          TITLE: ${{ github.event.pull_request.title }}\n",
    )
    assert ActionsScriptInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"python"})) == []

def test_actions_script_injection_no_workflows_silent(tmp_path: Path) -> None:
    assert ActionsScriptInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"python"})) == []

def test_actions_script_injection_ignores_workflow_subdirectory(tmp_path: Path) -> None:
    # FP-bait (§C.1): GitHub only executes workflows DIRECTLY in .github/workflows/. A copy under a
    # backup/ subdirectory is never run, so it is not exploitable and must not fire. This one bug
    # produced 29 obsidian FPs (archived/duplicate workflow trees).
    sub = tmp_path / ".github" / "workflows" / "backup"
    sub.mkdir(parents=True)
    (sub / "old.yml").write_text(
        "jobs:\n  b:\n    steps:\n      - run: echo ${{ github.event.pull_request.title }}\n", encoding="utf-8"
    )
    assert ActionsScriptInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"python"})) == []

# ── NS-13: cache trust-boundary crossing (repo-wide correlation) ────────────────

def _wf_named(tmp_path: Path, name: str, body: str) -> None:  # type: ignore[name-defined]
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / name).write_text(body, encoding="utf-8")


def test_cache_trust_boundary_fires_across_two_files(tmp_path: Path) -> None:
    # The real TanStack shape: a PR-triggered build workflow writes to the cache; a SEPARATE
    # tag-triggered release workflow (id-token: write) also uses caching -- two different files.
    _wf_named(
        tmp_path, "build.yml",
        "on:\n  pull_request:\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/setup-node@v4\n"
        "        with:\n"
        "          cache: 'pnpm'\n",
    )
    _wf_named(
        tmp_path, "release.yml",
        "on:\n  push:\n    tags: ['v*']\n"
        "jobs:\n"
        "  publish:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      id-token: write\n"
        "    steps:\n"
        "      - uses: actions/setup-node@v4\n"
        "        with:\n"
        "          cache: 'pnpm'\n",
    )
    findings = ActionsScriptInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))
    matches = [f for f in findings if f.rule == "actions-script-injection/cache-trust-boundary"]
    assert len(matches) == 1
    assert matches[0].severity == "critical"
    assert "build.yml" in matches[0].message


def test_cache_trust_boundary_is_review_confidence_not_proven(tmp_path: Path) -> None:
    # PR #741 review, Major 3: cache-trust-boundary is CRITICAL on an acknowledged heuristic
    # signal (the guard's own wiki doc admits cache-key scoping isn't modeled), so it belongs in
    # the confirm-by-hand bucket, not "proven" -- unlike this guard's OTHER rule, which is a
    # direct, provable code-injection finding.
    from agentsec.prioritize import confidence

    _wf_named(
        tmp_path, "build.yml",
        "on:\n  pull_request:\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/setup-node@v4\n"
        "        with:\n"
        "          cache: 'pnpm'\n",
    )
    _wf_named(
        tmp_path, "release.yml",
        "on:\n  push:\n    tags: ['v*']\n"
        "jobs:\n"
        "  publish:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      id-token: write\n"
        "    steps:\n"
        "      - uses: actions/setup-node@v4\n"
        "        with:\n"
        "          cache: 'pnpm'\n",
    )
    _wf_named(
        tmp_path, "interp.yml",
        "jobs:\n  b:\n    steps:\n      - run: echo ${{ github.event.pull_request.title }}\n",
    )
    findings = ActionsScriptInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))
    cache = [f for f in findings if f.rule == "actions-script-injection/cache-trust-boundary"]
    interp = [f for f in findings if f.rule == "actions-script-injection/untrusted-run-interpolation"]
    assert len(cache) == 1 and len(interp) == 1
    assert confidence(cache[0]) == "review"
    assert confidence(interp[0]) == "proven"


def test_cache_trust_boundary_self_referencing_job_wording_is_accurate(tmp_path: Path) -> None:
    # PR #741 review, Minor 4: a SINGLE job that is simultaneously PR-reachable, cache-writing
    # and id-token:write must not be described as "a job elsewhere in this repo" naming itself.
    _wf_named(
        tmp_path, "combo.yml",
        "on:\n  pull_request:\n"
        "jobs:\n"
        "  build-and-publish:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      id-token: write\n"
        "    steps:\n"
        "      - uses: actions/setup-node@v4\n"
        "        with:\n"
        "          cache: 'pnpm'\n",
    )
    findings = ActionsScriptInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))
    matches = [f for f in findings if f.rule == "actions-script-injection/cache-trust-boundary"]
    assert len(matches) == 1
    msg = matches[0].message
    assert "elsewhere in this repo" not in msg
    assert "build-and-publish" in msg
    assert "itself pull-request-reachable" in msg


def test_cache_trust_boundary_fires_same_file_two_jobs(tmp_path: Path) -> None:
    _wf_named(
        tmp_path, "ci.yml",
        "on:\n  pull_request:\n"
        "jobs:\n"
        "  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/cache@v4\n"
        "        with:\n"
        "          path: node_modules\n"
        "          key: cache-key\n"
        "  publish:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      id-token: write\n"
        "    steps:\n"
        "      - uses: actions/cache@v4\n"
        "        with:\n"
        "          path: node_modules\n"
        "          key: cache-key\n",
    )
    findings = ActionsScriptInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))
    assert any(f.rule == "actions-script-injection/cache-trust-boundary" for f in findings)


def test_cache_trust_boundary_no_privileged_job_stays_silent(tmp_path: Path) -> None:
    # A PR-reachable cache writer exists, but nothing has id-token: write -- no correlation.
    _wf_named(
        tmp_path, "build.yml",
        "on:\n  pull_request:\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/setup-node@v4\n"
        "        with:\n"
        "          cache: 'pnpm'\n",
    )
    findings = ActionsScriptInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))
    assert [f for f in findings if f.rule == "actions-script-injection/cache-trust-boundary"] == []


def test_cache_trust_boundary_no_pr_reachable_writer_stays_silent(tmp_path: Path) -> None:
    # A privileged, caching job exists, but nothing PR-reachable writes a cache -- no chain.
    _wf_named(
        tmp_path, "release.yml",
        "on:\n  push:\n    tags: ['v*']\n"
        "jobs:\n"
        "  publish:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      id-token: write\n"
        "    steps:\n"
        "      - uses: actions/setup-node@v4\n"
        "        with:\n"
        "          cache: 'pnpm'\n",
    )
    findings = ActionsScriptInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))
    assert [f for f in findings if f.rule == "actions-script-injection/cache-trust-boundary"] == []


def test_cache_trust_boundary_setup_action_without_cache_input_stays_silent(tmp_path: Path) -> None:
    # FP-bait: actions/setup-node with NO cache: input doesn't touch the Actions cache at all.
    _wf_named(
        tmp_path, "build.yml",
        "on:\n  pull_request:\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/setup-node@v4\n"
        "        with:\n"
        "          node-version: '22'\n",
    )
    _wf_named(
        tmp_path, "release.yml",
        "on:\n  push:\n    tags: ['v*']\n"
        "jobs:\n"
        "  publish:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      id-token: write\n"
        "    steps:\n"
        "      - uses: actions/cache@v4\n"
        "        with:\n"
        "          path: x\n          key: y\n",
    )
    findings = ActionsScriptInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))
    assert [f for f in findings if f.rule == "actions-script-injection/cache-trust-boundary"] == []


def test_cache_trust_boundary_pragma_silences_file(tmp_path: Path) -> None:
    _wf_named(
        tmp_path, "build.yml",
        "# security: allow-ci-cache-trust-boundary\n"
        "on:\n  pull_request:\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/setup-node@v4\n"
        "        with:\n"
        "          cache: 'pnpm'\n",
    )
    _wf_named(
        tmp_path, "release.yml",
        "on:\n  push:\n    tags: ['v*']\n"
        "jobs:\n"
        "  publish:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      id-token: write\n"
        "    steps:\n"
        "      - uses: actions/setup-node@v4\n"
        "        with:\n"
        "          cache: 'pnpm'\n",
    )
    findings = ActionsScriptInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))
    assert [f for f in findings if f.rule == "actions-script-injection/cache-trust-boundary"] == []


def test_actions_script_injection_scans_top_level_not_subdir_copy(tmp_path: Path) -> None:
    # A real top-level workflow still fires; a duplicate under a subdir alongside it does not.
    wf = tmp_path / ".github" / "workflows"
    (wf / "backup").mkdir(parents=True)
    body = "jobs:\n  b:\n    steps:\n      - run: echo ${{ github.head_ref }}\n"
    (wf / "ci.yml").write_text(body, encoding="utf-8")
    (wf / "backup" / "old.yml").write_text(body, encoding="utf-8")
    findings = ActionsScriptInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))
    assert len(findings) == 1  # only the top-level ci.yml, not the subdir copy
    assert findings[0].location.endswith("ci.yml:4")

