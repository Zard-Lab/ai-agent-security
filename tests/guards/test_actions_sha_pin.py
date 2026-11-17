from __future__ import annotations

from agentsec.guards.actions_sha_pin import ActionsShaPinGuard
from tests.guards._common import *  # noqa: F401,F403


def test_actions_sha_pin_flags_unpinned(tmp_path: Path) -> None:
    _wf(tmp_path, "steps:\n  - uses: actions/checkout@v4\n")
    findings = ActionsShaPinGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))
    assert len(findings) == 1
    assert findings[0].rule == "actions-sha-pin/unpinned-action"
    assert findings[0].severity == "high"

def test_actions_sha_pin_flags_branch_ref(tmp_path: Path) -> None:
    _wf(tmp_path, "steps:\n  - uses: actions/checkout@main\n")
    assert len(ActionsShaPinGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))) == 1

def test_actions_sha_pin_passes_pinned_sha(tmp_path: Path) -> None:
    _wf(tmp_path, "steps:\n  - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3\n")
    assert ActionsShaPinGuard().run(tmp_path, mkprofile(tmp_path, features={"python"})) == []

def test_actions_sha_pin_ignores_local_and_docker(tmp_path: Path) -> None:
    _wf(
        tmp_path,
        "steps:\n"
        "  - uses: ./.github/actions/local\n"
        "  - uses: docker://alpine@sha256:abc\n",
    )
    assert ActionsShaPinGuard().run(tmp_path, mkprofile(tmp_path, features={"python"})) == []

def test_actions_sha_pin_pragma_opt_out(tmp_path: Path) -> None:
    _wf(tmp_path, "steps:\n  - uses: my-org/my-action@v1  # security: allow-unpinned-action\n")
    assert ActionsShaPinGuard().run(tmp_path, mkprofile(tmp_path, features={"python"})) == []

def test_actions_sha_pin_no_workflows_silent(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("x = 1\n", encoding="utf-8")
    assert ActionsShaPinGuard().run(tmp_path, mkprofile(tmp_path, features={"python"})) == []

def test_actions_sha_pin_ignores_workflow_subdirectory(tmp_path: Path) -> None:
    # FP-bait (§C.1): a workflow copy under a subdir of .github/workflows/ is never executed by
    # GitHub, so an unpinned `uses:` there is not exploitable and must not fire.
    sub = tmp_path / ".github" / "workflows" / "disabled"
    sub.mkdir(parents=True)
    (sub / "old.yml").write_text("steps:\n  - uses: actions/checkout@v4\n", encoding="utf-8")
    assert ActionsShaPinGuard().run(tmp_path, mkprofile(tmp_path, features={"python"})) == []


def test_actions_sha_pin_bundles_multiple_steps_into_one_finding(tmp_path: Path) -> None:
    _wf(
        tmp_path,
        "steps:\n"
        "  - uses: actions/checkout@v4\n"
        "  - uses: actions/setup-python@v5\n"
        "  - uses: actions/cache@v3\n",
    )
    findings = ActionsShaPinGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))
    assert len(findings) == 1
    assert "`actions/checkout@v4`" in findings[0].message
    assert "`actions/setup-python@v5`" in findings[0].message
    assert "`actions/cache@v3`" in findings[0].message
    assert "3 steps" in findings[0].title


def test_actions_sha_pin_pragma_suppresses_one_step_others_still_fire(tmp_path: Path) -> None:
    _wf(
        tmp_path,
        "steps:\n"
        "  - uses: my-org/trusted@v1  # security: allow-unpinned-action\n"
        "  - uses: actions/checkout@v4\n",
    )
    findings = ActionsShaPinGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))
    assert len(findings) == 1
    assert "`actions/checkout@v4`" in findings[0].message
    assert "my-org/trusted" not in findings[0].message
