"""The composite GitHub Action at the repo root (`action.yml`).

Two layers. The static half gates what a reviewer would otherwise check by eye: every `uses:` is
pinned to a full commit SHA, no `${{ }}` expression is interpolated into a `run:` script (inputs
reach the shell through `env:` only, the script-injection rule), every `run:` step names its
shell, the enum inputs accept exactly the documented values, and every input and output is
documented in user-guide section 16.

The behavioural half runs the action's own bash, extracted from `action.yml`, against the
fixtures with a fake `$GITHUB_OUTPUT` / `$GITHUB_STEP_SUMMARY`. It asserts the artifacts and the
step outputs, never only the exit code (CLAUDE.md rule 3): a run that wrote no SARIF must fail in
every mode, advisory mode must still report `verdict=fail`, and the scanned repo must not be able
to shadow the CLI's imports. The `action-selftest` job in ci.yml runs the real action end to end;
these tests run the same scripts on every developer's machine first.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml

from agentsec.config import _CONFIG_REL
from agentsec.findings import COVERAGE_NOTIFICATION_ID, GUARD_BUDGET_NOTIFICATION_ID

_ROOT = Path(__file__).resolve().parents[1]
_ACTION_FILE = _ROOT / "action.yml"
_ACTION: dict[str, Any] = yaml.safe_load(_ACTION_FILE.read_text(encoding="utf-8"))
_STEPS: list[dict[str, Any]] = _ACTION["runs"]["steps"]
_USER_GUIDE = _ROOT / "docs" / "user-guide.md"

# The same shape `tests/test_templates.py` enforces for the CI templates: owner/repo[/path]@<40-hex>.
_SHA_PINNED = re.compile(r"^\S+@[0-9a-f]{40}$")
_EXPR_INPUT = re.compile(r"^\$\{\{\s*inputs\.([A-Za-z0-9_-]+)\s*\}\}$")

# The documented value sets. `fail-on` is exactly these three: the `--fail-on medium` rationale in
# the provider-key guards cites them as the choices CI offers.
_ENUMS: dict[str, tuple[str, ...]] = {
    "FAIL_ON": ("critical", "high", "medium"),
    "MODE": ("gate", "advisory"),
    "SCANNERS": ("deterministic", "guards-only", "all"),
    "COVERAGE": ("true", "false"),
    "UPLOAD_SARIF": ("true", "false"),
}


def _step(step_id: str) -> dict[str, Any]:
    return next(s for s in _STEPS if s.get("id") == step_id)


def _gate_step() -> dict[str, Any]:
    return next(s for s in _STEPS if s.get("name") == "agentsec gate")


def _user_guide_section_16() -> str:
    text = _USER_GUIDE.read_text(encoding="utf-8")
    start = text.index("## 16. ")
    return text[start:text.index("\n## 17. ", start)]


# --- static invariants -----------------------------------------------------------------------


def test_action_is_a_branded_composite_action() -> None:
    assert _ACTION["runs"]["using"] == "composite"
    assert _ACTION["name"] and _ACTION["description"]
    assert "never leaves" in _ACTION["description"]
    assert set(_ACTION["branding"]) == {"icon", "color"}


def test_every_uses_is_sha_pinned_with_a_version_comment() -> None:
    uses = [s["uses"] for s in _STEPS if "uses" in s]
    assert uses, "the action references no actions; the sweep below would prove nothing"
    unpinned = [u for u in uses if not _SHA_PINNED.match(u)]
    assert not unpinned, f"un-pinned action(s): {unpinned}"
    raw = _ACTION_FILE.read_text(encoding="utf-8")
    for u in uses:
        line = next(ln for ln in raw.splitlines() if f"uses: {u}" in ln)
        assert re.search(r"#\s*v\d", line), f"no `# vX.Y.Z` comment on: {line.strip()}"


def test_code_scanning_upload_uses_codeql_action_v4() -> None:
    """v3 is deprecated; the upload must be the v4 line, and only when the user opts in."""
    step = next(s for s in _STEPS if "upload-sarif" in s.get("uses", ""))
    assert step["uses"].startswith("github/codeql-action/upload-sarif@")
    line = next(ln for ln in _ACTION_FILE.read_text(encoding="utf-8").splitlines() if step["uses"] in ln)
    assert re.search(r"#\s*v4\.", line), line
    assert "inputs.upload-sarif == 'true'" in step["if"]


def test_no_run_script_interpolates_an_expression() -> None:
    """`${{ inputs.x }}` inside `run:` is pasted into the script before bash parses it, so an input
    value becomes shell code. Every value reaches the shell through `env:` instead."""
    runs = [s for s in _STEPS if "run" in s]
    assert len(runs) >= 2, "the sweep must see the audit and gate scripts"
    for s in runs:
        assert "${{" not in s["run"], f"step {s.get('name')!r} interpolates an expression into run:"


def test_every_run_step_names_its_shell() -> None:
    for s in _STEPS:
        if "run" in s:
            assert s.get("shell") == "bash", f"step {s.get('name')!r} has no `shell: bash`"


def test_every_input_reaches_the_audit_step_through_env_and_exists() -> None:
    """The audit step's `env:` names only declared inputs, and every input is consumed somewhere,
    so a renamed input cannot silently keep its old default."""
    declared = set(_ACTION["inputs"])
    referenced: set[str] = set()
    for s in _STEPS:
        for block in (s.get("env") or {}, s.get("with") or {}):
            for value in block.values():
                referenced |= set(re.findall(r"inputs\.([A-Za-z0-9_-]+)", str(value)))
        referenced |= set(re.findall(r"inputs\.([A-Za-z0-9_-]+)", str(s.get("if", ""))))
    assert referenced <= declared, f"undeclared input(s): {sorted(referenced - declared)}"
    assert declared <= referenced, f"input(s) never used: {sorted(declared - referenced)}"


def test_outputs_come_from_the_audit_step() -> None:
    assert set(_ACTION["outputs"]) == {"sarif", "verdict", "exit-code", "results"}
    for name, spec in _ACTION["outputs"].items():
        assert spec["value"] == f"${{{{ steps.audit.outputs.{name} }}}}", name


def test_enum_inputs_accept_exactly_the_documented_values() -> None:
    script = _step("audit")["run"]
    for var, values in _ENUMS.items():
        m = re.search(rf'case "\${var}" in ([^)]+)\)', script)
        assert m, f"no validation for {var}"
        assert tuple(m.group(1).split("|")) == values, (var, m.group(1))
    assert _ACTION["inputs"]["fail-on"]["default"] == "high"
    assert _ACTION["inputs"]["mode"]["default"] == "gate"


def test_the_action_never_passes_no_fail() -> None:
    """agentsec's exit code is the verdict the action reports; advisory mode is applied by the
    final step. A `--no-fail` would turn every result into a pass before anything could see it."""
    code = "\n".join(
        ln for ln in _step("audit")["run"].splitlines() if not ln.lstrip().startswith("#")
    )
    assert "--no-fail" not in code


def test_annotations_default_stays_small() -> None:
    """GitHub's per-step annotation caps are not documented precisely; 10 sits under any of them."""
    assert _ACTION["inputs"]["annotations"]["default"] == "10"


def test_user_guide_documents_every_input_and_output() -> None:
    section = _user_guide_section_16()
    missing = [n for n in [*_ACTION["inputs"], *_ACTION["outputs"]] if f"`{n}`" not in section]
    assert not missing, f"user-guide section 16 does not document: {missing}"
    for values in (_ENUMS["FAIL_ON"], _ENUMS["MODE"], _ENUMS["SCANNERS"]):
        for v in values:
            assert f"`{v}`" in section, f"user-guide section 16 does not name `{v}`"


def test_the_private_repo_checkout_dir_is_not_agentsecs_own_config_dir() -> None:
    """`<repo>/.agentsec/` holds the user's committed config.json and suppress.json. Checking the
    action out there would clobber them and the `.gitignore` advice would stop them being
    committed, so the documented checkout path must sit outside that directory."""
    sec = _user_guide_section_16()
    block = sec[sec.index("**A private copy of agentsec**"):sec.index("**Pin by commit SHA**")]
    paths = re.findall(r"^\s*path:\s*(\S+)\s*$", block, re.M)
    assert paths, "the private-repo recipe no longer checks agentsec out to a path"
    for path in paths:
        top = path.removeprefix("./").split("/")[0]
        assert top != _CONFIG_REL[0], f"checkout path {path!r} is agentsec's per-repo config dir"
        assert f"uses: ./{path}" in block and f"`{path}/`" in block, (
            "the checkout path, the local `uses:` and the .gitignore advice must name one directory"
        )


def test_user_guide_examples_pin_the_action_by_sha() -> None:
    """The docs tell users to pin by SHA (a moved tag is how the 2026 trivy-action compromise
    spread), so their own snippets must not show a tag or branch ref for agentsec."""
    section = _user_guide_section_16()
    refs = re.findall(r"uses:\s*(\S*ai-agent-security\S*)", section)
    assert refs, "section 16 shows no `uses:` line for the action"
    assert all(re.search(r"@(?:[0-9a-f]{40}|<[^>]+>)$", r) for r in refs), refs


# --- behavioural: the action's own bash ------------------------------------------------------


def _bash() -> str | None:
    """A real bash. On Windows only Git Bash counts: `bash.exe` in System32 is WSL, which would
    run the script in a different OS with a different `python`."""
    found = shutil.which("bash")
    if found is None:
        return None
    if sys.platform == "win32" and any(p in found.lower() for p in ("system32", "windowsapps")):
        return None
    return found


_BASH = _bash()
needs_bash = pytest.mark.skipif(_BASH is None, reason="needs bash (Git Bash on Windows)")


@dataclass
class _StepRun:
    returncode: int
    stdout: str
    stderr: str
    outputs: dict[str, str]
    summary: str


def _run_script(script: str, env: dict[str, str], tmp_path: Path, cwd: Path) -> _StepRun:
    assert _BASH is not None
    tmp_path.mkdir(parents=True, exist_ok=True)
    out, summary = tmp_path / "github_output", tmp_path / "step_summary"
    out.write_text("", encoding="utf-8")
    summary.write_text("", encoding="utf-8")
    script_file = tmp_path / "step.sh"
    script_file.write_text(script, encoding="utf-8", newline="\n")
    full_env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONSAFEPATH")}
    # The test interpreter (>= 3.12) is the `python` the script finds, as setup-python's would be.
    full_env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + full_env.get("PATH", "")
    full_env.update(env)
    full_env.update({"GITHUB_OUTPUT": str(out), "GITHUB_STEP_SUMMARY": str(summary),
                     "RUNNER_TEMP": str(tmp_path), "GITHUB_SERVER_URL": "https://github.com"})
    # How `shell: bash` invokes a step: errexit and pipefail on.
    proc = subprocess.run(  # noqa: S603
        [_BASH, "--noprofile", "--norc", "-eo", "pipefail", str(script_file)],
        cwd=cwd, env=full_env, capture_output=True, text=True, encoding="utf-8", timeout=110,
        check=False,
    )
    outputs = dict(
        ln.split("=", 1) for ln in out.read_text(encoding="utf-8").splitlines() if "=" in ln
    )
    return _StepRun(proc.returncode, proc.stdout, proc.stderr, outputs,
                    summary.read_text(encoding="utf-8"))


def _audit_env(action_repo: str = "", action_path: Path = _ROOT, **inputs: str) -> dict[str, str]:
    """The audit step's `env:` block resolved the way the runner would: each `${{ inputs.x }}`
    takes the given value or the declared default, read from action.yml so this cannot drift."""
    values = {name: str(spec.get("default", "")) for name, spec in _ACTION["inputs"].items()}
    for key, value in inputs.items():
        name = key.replace("_", "-")
        assert name in values, f"unknown input {name}"
        values[name] = value
    env: dict[str, str] = {"GITHUB_ACTION_PATH": str(action_path)}
    for var, expr in _step("audit")["env"].items():
        m = _EXPR_INPUT.match(str(expr))
        if m:
            env[var] = values[m.group(1)]
        elif "github.action_repository" in str(expr):
            env[var] = action_repo
        else:  # pragma: no cover - a new env entry needs a mapping here
            raise AssertionError(f"unmapped audit env entry {var}: {expr}")
    return env


def _run_audit(tmp_path: Path, *, cwd: Path = _ROOT, script: str | None = None,
               action_repo: str = "", action_path: Path = _ROOT, **inputs: str) -> _StepRun:
    return _run_script(script if script is not None else _step("audit")["run"],
                       _audit_env(action_repo, action_path, **inputs), tmp_path, cwd)


@needs_bash
@pytest.mark.parametrize(
    ("inputs", "message"),
    [
        ({"mode": "blocking"}, "mode must be gate or advisory"),
        ({"fail_on": "low"}, "fail-on must be critical, high or medium"),
        ({"fail_on": "info"}, "fail-on must be critical, high or medium"),
        ({"scanners": "every"}, "scanners must be"),
        ({"upload_sarif": "yes"}, "upload-sarif must be true or false"),
        ({"coverage": "yes"}, "coverage must be true or false"),
        ({"top": "ten"}, "top must be a whole number"),
        ({"annotations": "-1"}, "annotations must be a whole number"),
        ({"path": "no/such/dir"}, "path is not a directory"),
    ],
)
def test_invalid_inputs_fail_fast_before_any_scan(
    tmp_path: Path, inputs: dict[str, str], message: str
) -> None:
    run = _run_audit(tmp_path, **{"path": "tests/fixtures/action_clean", **inputs})
    assert run.returncode != 0
    assert f"::error title=agentsec action::{message}" in run.stdout
    assert "dir" not in run.outputs, "validation must stop the step before it scans anything"


@needs_bash
def test_an_error_value_cannot_start_a_second_workflow_command(tmp_path: Path) -> None:
    """The rejected value is echoed back; a newline in it is escaped, so it cannot begin a new
    `::command::` line of its own."""
    run = _run_audit(tmp_path, path="tests/fixtures/action_clean", mode="x\n::error::forged")
    assert "x%0A::error::forged" in run.stdout
    assert not any(ln.startswith("::error::forged") for ln in run.stdout.splitlines())


@needs_bash
@pytest.mark.slow
def test_clean_fixture_passes_the_gate_and_writes_every_artifact(tmp_path: Path) -> None:
    run = _run_audit(tmp_path, path="tests/fixtures/action_clean", scanners="guards-only",
                     action_repo="example-org/agentsec-fork")
    assert run.returncode == 0, run.stdout + run.stderr
    assert run.outputs["verdict"] == "pass" and run.outputs["exit-code"] == "0"
    sarif = Path(run.outputs["sarif"])
    data = json.loads(sarif.read_text(encoding="utf-8"))
    assert int(run.outputs["results"]) == len(data["runs"][0]["results"])
    assert (sarif.parent / "agentsec-findings.md").is_file()
    assert "## agentsec security audit" in run.summary
    assert "# Security check" in run.summary
    # The feedback loop: both issue forms, on the action's own repository.
    base = "https://github.com/example-org/agentsec-fork/issues/new?template="
    for form in ("false-positive.yml", "missed-detection.yml"):
        assert base + form in run.summary


@needs_bash
@pytest.mark.slow
def test_fail_on_reaches_the_cli_and_a_local_action_shows_no_feedback_link(tmp_path: Path) -> None:
    """The clean fixture carries medium findings only: `fail-on: medium` must trip on them, which
    proves the input reaches the CLI. A local `uses: ./` has no action repository, so no link."""
    run = _run_audit(tmp_path, path="tests/fixtures/action_clean", scanners="guards-only",
                     fail_on="medium")
    assert run.returncode == 0, "the audit step reports; only the gate step fails the job"
    assert run.outputs["verdict"] == "fail" and run.outputs["exit-code"] == "1"
    assert "issues/new" not in run.summary


@needs_bash
@pytest.mark.slow
def test_findings_fixture_reports_fail_with_repo_relative_sarif(tmp_path: Path) -> None:
    run = _run_audit(tmp_path, path="tests/fixtures/saas_sample", scanners="guards-only",
                     mode="advisory", annotations="2")
    assert run.returncode == 0, run.stdout + run.stderr
    assert run.outputs["verdict"] == "fail" and run.outputs["exit-code"] == "1"
    assert int(run.outputs["results"]) > 0
    data = json.loads(Path(run.outputs["sarif"]).read_text(encoding="utf-8"))
    uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in data["runs"][0]["results"] if "locations" in r]
    root = "tests/fixtures/saas_sample"   # a finding located at `.` maps to the root itself
    assert uris and all(u == root or u.startswith(root + "/") for u in uris), uris
    commands = [ln for ln in run.stdout.splitlines() if re.match(r"::(error|warning|notice) ", ln)]
    assert len(commands) == 2
    assert all("file=tests/fixtures/saas_sample/" in c for c in commands)


@needs_bash
@pytest.mark.slow
def test_exclude_lines_are_trimmed_and_blank_lines_ignored(tmp_path: Path) -> None:
    run = _run_audit(tmp_path, path="tests/fixtures/action_clean", scanners="guards-only",
                     exclude="  app.py  \r\n\n   \n")
    assert run.returncode == 0, run.stdout + run.stderr
    assert run.outputs["results"] == "0"


# A stand-in `agentsec` package for the action checkout: it records the argv the action built,
# optionally writes a SARIF with two results, and exits with the code it is told to. PYTHONPATH
# (the action path) precedes site-packages, so it shadows an installed agentsec.
_FAKE_MAIN = """\
import json, os, sys
args = sys.argv[1:]
with open(os.environ["FAKE_ARGV_OUT"], "a", encoding="utf-8") as fh:
    print(json.dumps(args), file=fh)
if args[0] == "coverage":
    if os.environ.get("FAKE_COVERAGE") == "1":
        with open(args[args.index("--out") + 1], "w", encoding="utf-8") as fh:
            print("# agentsec coverage score card", file=fh)
            print("COVERAGE-CARD-BODY", file=fh)
    sys.exit(int(os.environ.get("FAKE_COVERAGE_RC", "0")))
if os.environ.get("FAKE_WRITE_SARIF") == "1":
    run = {"results": [{}, {}]}
    note = os.environ.get("FAKE_NOTE_ID")
    if note:
        run["invocations"] = [{"executionSuccessful": True,
                               "toolExecutionNotifications": [{"descriptor": {"id": note}}]}]
    with open(args[args.index("--sarif-out") + 1], "w", encoding="utf-8") as fh:
        json.dump({"version": "2.1.0", "runs": [run]}, fh)
sys.exit(int(os.environ.get("FAKE_RC", "0")))
"""


def _fake_action(action_dir: Path) -> Path:
    pkg = action_dir / "agentsec"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "__main__.py").write_text(_FAKE_MAIN, encoding="utf-8")
    return action_dir


def _run_fake(tmp_path: Path, *, rc: int, write_sarif: bool, cwd: Path = _ROOT,
              action_dir: Path | None = None, note_id: str = "", fake_env: dict[str, str] | None = None,
              **inputs: str) -> tuple[_StepRun, list[str]]:
    action = _fake_action(action_dir or tmp_path / "action")
    argv_file = tmp_path / "argv.json"
    env = _audit_env("", action, **inputs)
    env.update({"FAKE_ARGV_OUT": str(argv_file), "FAKE_RC": str(rc),
                "FAKE_WRITE_SARIF": "1" if write_sarif else "0", "FAKE_NOTE_ID": note_id})
    env.update(fake_env or {})
    run = _run_script(_step("audit")["run"], env, tmp_path / "step", cwd)
    calls = _fake_calls(tmp_path)
    return run, calls[0] if calls else []


def _fake_calls(tmp_path: Path) -> list[list[str]]:
    """Every argv the fake CLI was invoked with, in order (the audit first)."""
    argv_file = tmp_path / "argv.json"
    if not argv_file.is_file():
        return []
    return [json.loads(ln) for ln in argv_file.read_text(encoding="utf-8").splitlines() if ln]


def _flag(argv: list[str], name: str) -> str | None:
    return argv[argv.index(name) + 1] if name in argv else None


@needs_bash
def test_default_inputs_build_the_documented_command(tmp_path: Path) -> None:
    run, argv = _run_fake(tmp_path, rc=0, write_sarif=True, path="tests/fixtures/action_clean")
    assert run.returncode == 0, run.stdout + run.stderr
    assert argv[:2] == ["audit", "tests/fixtures/action_clean"]
    assert _flag(argv, "--format") == "summary" and _flag(argv, "--top") == "50"
    assert _flag(argv, "--fail-on") == "high" and _flag(argv, "--annotations") == "10"
    assert "--deterministic" in argv and "--guards-only" not in argv
    assert "--no-fail" not in argv
    assert not any(a in argv for a in ("--baseline", "--baseline-snapshot", "--exclude"))
    assert run.outputs["sarif"] == _flag(argv, "--sarif-out")
    assert run.outputs["results"] == "2" and run.outputs["verdict"] == "pass"


@needs_bash
def test_inputs_map_onto_their_flags(tmp_path: Path) -> None:
    run, argv = _run_fake(
        tmp_path, rc=0, write_sarif=True, path="tests/fixtures/action_clean", scanners="all",
        fail_on="critical", top="5", annotations="0", baseline="ex.json",
        baseline_snapshot="snap.json", exclude="vendor/\n  docs  \n",
    )
    assert run.returncode == 0, run.stdout + run.stderr
    assert "--deterministic" not in argv and "--guards-only" not in argv   # all = no narrowing
    assert _flag(argv, "--fail-on") == "critical" and _flag(argv, "--top") == "5"
    assert _flag(argv, "--annotations") == "0"
    assert _flag(argv, "--baseline") == "ex.json" and _flag(argv, "--baseline-snapshot") == "snap.json"
    assert [argv[i + 1] for i, a in enumerate(argv) if a == "--exclude"] == ["vendor/", "docs"]
    _, guards_argv = _run_fake(tmp_path / "g", rc=0, write_sarif=True, path="tests/fixtures/action_clean",
                               scanners="guards-only")
    assert "--guards-only" in guards_argv and "--deterministic" not in guards_argv


@needs_bash
@pytest.mark.parametrize("mode", ["gate", "advisory"])
def test_a_run_that_writes_no_sarif_fails_in_every_mode(tmp_path: Path, mode: str) -> None:
    """Exit 1 with no SARIF is what an import failure or an early traceback looks like, and it
    is the same code a tripped gate uses. Only the artifact check tells them apart."""
    run, _ = _run_fake(tmp_path, rc=1, write_sarif=False, path="tests/fixtures/action_clean", mode=mode)
    assert run.returncode != 0
    assert "agentsec produced no readable SARIF (exit code 1)" in run.stdout
    assert run.outputs.get("verdict") == "error"
    assert "sarif" not in run.outputs


@needs_bash
def test_an_exit_code_other_than_0_or_1_is_a_crash_even_with_a_sarif(tmp_path: Path) -> None:
    run, _ = _run_fake(tmp_path, rc=3, write_sarif=True, path="tests/fixtures/action_clean",
                       mode="advisory")
    assert run.returncode != 0
    assert "agentsec exited 3, which is a crash rather than a verdict" in run.stdout
    assert run.outputs.get("verdict") == "error"


@needs_bash
def test_a_tripped_gate_with_a_sarif_is_a_verdict_not_a_crash(tmp_path: Path) -> None:
    """The opposite direction: exit 1 WITH a readable SARIF is the gate, so the audit step passes
    and hands `fail` to the gate step."""
    run, _ = _run_fake(tmp_path, rc=1, write_sarif=True, path="tests/fixtures/action_clean")
    assert run.returncode == 0, run.stdout
    assert run.outputs["verdict"] == "fail" and run.outputs["exit-code"] == "1"
    assert run.outputs["results"] == "2"


@needs_bash
@pytest.mark.parametrize("mode", ["gate", "advisory"])
def test_a_guard_killed_over_its_budget_fails_in_every_mode(tmp_path: Path, mode: str) -> None:
    """The CLI exits 1 for a budget-killed guard (#677), the code a tripped gate uses, so only the
    SARIF's error notification says the scan is PARTIAL. Advisory mode must not turn that into a
    green job; the partial SARIF is still handed on so its findings get uploaded."""
    run, _ = _run_fake(tmp_path, rc=1, write_sarif=True, path="tests/fixtures/action_clean",
                       mode=mode, note_id=GUARD_BUDGET_NOTIFICATION_ID)
    assert run.returncode != 0, run.stdout
    assert "the scan is PARTIAL" in run.stdout
    assert run.outputs.get("verdict") == "error"
    assert run.outputs.get("sarif") and run.outputs.get("results") == "2"


@needs_bash
def test_a_coverage_notification_is_not_a_partial_scan(tmp_path: Path) -> None:
    """The opposite direction: other tool notifications (a coverage disclosure) leave the
    verdict to the exit code."""
    run, _ = _run_fake(tmp_path, rc=1, write_sarif=True, path="tests/fixtures/action_clean",
                       mode="advisory", note_id=COVERAGE_NOTIFICATION_ID)
    assert run.returncode == 0, run.stdout
    assert run.outputs["verdict"] == "fail" and "PARTIAL" not in run.stdout


@needs_bash
def test_the_actions_own_checkout_inside_the_scan_is_excluded_and_flagged(tmp_path: Path) -> None:
    """The private-repo setup checks agentsec out to `.agentsec-action` inside the workspace.
    Scanning `.` would sweep in agentsec's own vulnerable fixtures, so the action excludes that
    subtree and warns; a scan root that does not contain the checkout gets no such exclusion."""
    repo = tmp_path / "repo"
    repo.mkdir()
    run, argv = _run_fake(tmp_path, rc=0, write_sarif=True, cwd=repo,
                          action_dir=repo / ".agentsec-action", path=".")
    assert run.returncode == 0, run.stdout + run.stderr
    assert [argv[i + 1] for i, a in enumerate(argv) if a == "--exclude"] == [".agentsec-action"]
    assert "own checkout (.agentsec-action) is inside the scanned path" in run.stdout

    _, outside = _run_fake(tmp_path / "o", rc=0, write_sarif=True, path="tests/fixtures/action_clean")
    assert "--exclude" not in outside


@needs_bash
@pytest.mark.skipif(shutil.which("git") is None, reason="needs git for check-ignore")
def test_a_gitignored_action_checkout_is_excluded_without_a_warning(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True, capture_output=True)  # noqa: S603, S607
    (repo / ".gitignore").write_text(".agentsec-action/\n", encoding="utf-8")
    run, argv = _run_fake(tmp_path, rc=0, write_sarif=True, cwd=repo,
                          action_dir=repo / ".agentsec-action", path=".")
    assert run.returncode == 0, run.stdout + run.stderr
    assert "--exclude" in argv
    assert "inside the scanned path" not in run.stdout


@needs_bash
@pytest.mark.slow
def test_the_scanned_repo_cannot_shadow_the_clis_imports(tmp_path: Path) -> None:
    """`python -m` puts the current directory (the repo under scan) first on sys.path, so a
    planted `json.py` would run in place of the stdlib. PYTHONSAFEPATH=1 keeps it off. Both
    directions: the step passes as written, and fails with the variable removed, which proves
    the plant is live and the test can tell the two apart."""
    repo = tmp_path / "repo"
    shutil.copytree(_ROOT / "tests" / "fixtures" / "action_clean", repo)
    (repo / "json.py").write_text("raise SystemExit('HIJACKED')\n", encoding="utf-8")
    script = _step("audit")["run"]
    assert 'PYTHONPATH="$GITHUB_ACTION_PATH" PYTHONSAFEPATH=1 ' in script

    safe = _run_audit(tmp_path / "safe", cwd=repo, path=".", scanners="guards-only")
    assert safe.outputs.get("verdict") == "pass", safe.stdout + safe.stderr

    unsafe = _run_audit(tmp_path / "unsafe", cwd=repo, path=".", scanners="guards-only",
                        script=script.replace("PYTHONSAFEPATH=1 ", ""))
    assert unsafe.returncode != 0 and "HIJACKED" in unsafe.stderr


@needs_bash
@pytest.mark.parametrize(
    ("mode", "exit_code", "rc", "marker"),
    [
        ("gate", "0", 0, "gate passed"),
        ("gate", "1", 1, "::error title=agentsec::"),
        ("advisory", "0", 0, "gate passed"),
        ("advisory", "1", 0, "::warning title=agentsec (advisory)::"),
        ("advisory", "", 1, "no verdict"),
        ("gate", "2", 1, "no verdict"),
    ],
)
def test_the_gate_step_applies_the_mode(
    tmp_path: Path, mode: str, exit_code: str, rc: int, marker: str
) -> None:
    run = _run_script(_gate_step()["run"], {"MODE": mode, "EXIT_CODE": exit_code}, tmp_path, _ROOT)
    assert run.returncode == rc, run.stdout
    assert marker in run.stdout



# --- coverage: the checklist score card ---------------------------------------------------------


@needs_bash
@pytest.mark.parametrize("coverage", ["true", "false"])
def test_coverage_adds_the_score_card_only_when_asked(tmp_path: Path, coverage: str) -> None:
    """Both directions: `coverage: true` runs `agentsec coverage` on the scanned path after the
    audit and puts the card in the summary and the artifact; the default runs it not at all."""
    run, argv = _run_fake(tmp_path, rc=0, write_sarif=True, path="tests/fixtures/action_clean",
                          coverage=coverage, fake_env={"FAKE_COVERAGE": "1"})
    assert run.returncode == 0, run.stdout + run.stderr
    calls = _fake_calls(tmp_path)
    assert calls[0] == argv and argv[0] == "audit"
    card = Path(run.outputs["dir"]) / "agentsec-coverage.md"
    if coverage == "true":
        assert len(calls) == 2 and calls[1][:2] == ["coverage", "tests/fixtures/action_clean"]
        assert Path(_flag(calls[1], "--out") or "") == card
        assert "<summary>Checklist coverage score card</summary>" in run.summary
        assert "COVERAGE-CARD-BODY" in run.summary and card.is_file()
    else:
        assert len(calls) == 1
        assert "coverage score card" not in run.summary and not card.exists()


@needs_bash
@pytest.mark.parametrize(("fake_env", "verdict", "rc"), [
    ({"FAKE_COVERAGE": "0"}, "pass", 0),                               # exit 0, wrote nothing
    ({"FAKE_COVERAGE": "1", "FAKE_COVERAGE_RC": "3"}, "pass", 0),     # crashed after writing
    ({"FAKE_COVERAGE": "0"}, "fail", 1),                               # the gate is still the audit's
])
def test_a_failed_score_card_warns_and_never_touches_the_verdict(
    tmp_path: Path, fake_env: dict[str, str], verdict: str, rc: int,
) -> None:
    run, _ = _run_fake(tmp_path, rc=rc, write_sarif=True, path="tests/fixtures/action_clean",
                       coverage="true", fake_env=fake_env)
    assert run.returncode == 0, run.stdout + run.stderr  # the audit step itself never fails on a verdict
    assert run.outputs["verdict"] == verdict and run.outputs["exit-code"] == str(rc)
    assert "the coverage score card could not be generated" in run.stdout
    assert "COVERAGE-CARD-BODY" not in run.summary
    assert not (Path(run.outputs["dir"]) / "agentsec-coverage.md").exists()


@needs_bash
@pytest.mark.slow
def test_coverage_writes_the_real_score_card(tmp_path: Path) -> None:
    run = _run_audit(tmp_path, path="tests/fixtures/action_clean", scanners="guards-only",
                     coverage="true")
    assert run.returncode == 0, run.stdout + run.stderr
    assert "could not be generated" not in run.stdout
    card = Path(run.outputs["sarif"]).parent / "agentsec-coverage.md"
    assert card.read_text(encoding="utf-8").startswith("# agentsec coverage score card")
    assert "# agentsec coverage score card" in run.summary
    assert "applicable checklist items are verified by a check" in run.summary
