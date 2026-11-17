"""Per-guard time budget (#677) — preemption, disclosure, gate, and parity, end to end.

A guard that HANGS walks straight past `audit()`'s `except`: the loop never advances and
the run dies at the CI job timeout, reporting nothing — which reads as a clean scan
(Rule 3). `guard_worker.py` runs the guards in a killable child; these tests pin the whole
channel: kill → `AuditResult.guards_budget_exceeded` → markdown footer → SARIF error
notification → unconditional gate failure → `RepoScan.error` for corpus-scan.

The hanging guard hangs in a REAL catastrophic regex (the pre-#674 shape that hung #673
for 90+ minutes), not a Python-level spin: the budget's whole claim is that it interrupts
a tight C-LEVEL loop, the class `signal`-based schemes (pytest-timeout included) cannot
preempt, so a `while True` bait would prove less than the mechanism promises.

Every test guard lives at module level: guards cross the spawn process boundary by pickle,
which resolves classes by module + qualname (spawn forwards `sys.path`, so this works for
a test module too — and for every registered guard, which the picklability drift test pins).
"""
from __future__ import annotations

import os
import pickle
import sys
import time
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from agentsec import cli
from agentsec.audit import AuditResult, audit
from agentsec.cli import _gate, _meta_lines
from agentsec.corpus import scan_repo
from agentsec.detect import StackProfile
from agentsec.findings import GUARD_BUDGET_NOTIFICATION_ID, Finding, to_sarif
from agentsec.guard_worker import run_guards_budgeted
from agentsec.guards.base import Guard
from agentsec.registry import ALL_GUARDS
from tests._budget_guards import (  # light module, see its docstring
    ChildKillingGuard,
    DieOnUnpickleGuard,
    HangingGuard,
    MainThreadProbeGuard,
    NumberedGuard,
    RaisingGuard,
    SentinelGuard,
    SleepingGuard,
    SlowStartGuard,
    StallOnUnpickleGuard,
    UnstartableGuard,
)
from tests._timing import TimingBudget, assert_within, register
from tests.conftest import mkprofile

_KILL_BUDGET = register(
    TimingBudget(
        name="guard-worker/hanging-guard-preemption",
        seconds=60.0,
        measured=1.6,
        # Measured at n=8192 spaces (157.1s); the test bait is n=262144, 32x larger, and the
        # search grows ~x7.8 per doubling (cubic-class), so the un-preempted case is ~5e6s —
        # 157.1 is the honest measured floor, not the size of the hole.
        regression=157.1,
        why="the per-guard budget kill stopped preempting the C-level regex loop (#677)",
    )
)

_DEATH_BUDGET = register(
    TimingBudget(
        name="guard-worker/child-death-sentinel-detection",
        seconds=20.0,
        measured=1.1,
        # Two max(_STARTUP_ALLOWANCE, budget) windows if only the pipe is watched — the
        # 2026-09-07 Windows rerun shape, where 2x60s crashed the worker at pytest-timeout.
        regression=120.0,
        why="child death stopped being observed on the process sentinel (Windows rerun, 2026-09-07)",
    )
)

_CANCEL_BUDGET = register(
    TimingBudget(
        name="guard-worker/lane-failure-cancels-the-other-lanes",
        seconds=20.0,
        # Timed from the failure, with lane 0's child booted and inside its 60s guard.
        measured=0.01,
        # The same scenario with `_LaneCancel.cancel` stubbed out: the error waits out the sleep.
        regression=60.04,
        why="a failing lane no longer cancels the others, so the error waits for the slowest lane",
    )
)



def test_all_registered_guards_are_picklable() -> None:
    """Drift gate for the process boundary: every registered guard must round-trip pickle
    (spawn passes them to the child as Process args). A future guard holding unpicklable
    state would otherwise break budgeted runs only, at runtime, on the CLI paths."""
    for g in ALL_GUARDS:
        clone = pickle.loads(pickle.dumps(g))
        assert clone.id == g.id


@pytest.mark.slow  # fixed-deadline confirmation: its cost IS the budget it must wait out
def test_hanging_guard_is_killed_and_the_next_guard_still_runs(tmp_path: Path) -> None:
    start = time.monotonic()
    out = run_guards_budgeted(tmp_path, mkprofile(tmp_path),
                              [HangingGuard(), SentinelGuard()], budget=1.0)
    # The wall-clock bound is the preemption claim itself: without the kill, the regex
    # alone runs for days (the #673 class this exists for).
    assert_within(time.monotonic() - start, _KILL_BUDGET)
    assert out.budget_exceeded == ["test-hanging-guard"]
    assert "test-hanging-guard" not in out.ran, "a killed guard must not count as run"
    assert "test-sentinel-guard" in out.ran, "guards after the killed one must still run"
    assert [f.check_id for f in out.findings] == ["test-sentinel-guard"]
    assert out.fallback_inprocess is False, "a budget kill must never engage the fallback"


def test_raising_guard_is_errored_not_budget_exceeded(tmp_path: Path) -> None:
    out = run_guards_budgeted(tmp_path, mkprofile(tmp_path),
                              [RaisingGuard(), SentinelGuard()], budget=30.0)
    assert out.errored == ["test-raising-guard"]
    assert out.budget_exceeded == []
    assert set(out.ran) == {"test-raising-guard", "test-sentinel-guard"}
    assert [f.check_id for f in out.findings] == ["test-sentinel-guard"]


def test_child_killing_guard_is_errored_and_the_run_continues(tmp_path: Path) -> None:
    out = run_guards_budgeted(tmp_path, mkprofile(tmp_path),
                              [ChildKillingGuard(), SentinelGuard()], budget=30.0)
    assert out.errored == ["test-child-killing-guard"]
    assert out.budget_exceeded == []
    assert [f.check_id for f in out.findings] == ["test-sentinel-guard"]


@pytest.mark.slow  # fixed-deadline confirmation (waits out the 1s budget) + a spawn
def test_budget_exceeded_surfaces_in_every_artifact_and_the_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rule 3: assert the ARTIFACTS (result field, footer, coverage notice, SARIF), then
    the exit code separately — a partial scan must not be able to present as clean."""
    monkeypatch.setattr("agentsec.audit.select_guards",
                        lambda profile: [HangingGuard(), SentinelGuard()])
    result = audit(tmp_path, run_scanners=False, guard_budget=1.0)

    assert result.guards_budget_exceeded == ["test-hanging-guard"]
    assert "test-hanging-guard" not in result.ran

    footer = "\n".join(_meta_lines(result, []))
    assert "test-hanging-guard" in footer
    assert "did NOT complete" in footer

    notices = result.coverage_notices()
    assert any("test-hanging-guard" in n and "time budget" in n for n in notices)

    sarif = to_sarif(result.findings, notifications=notices,
                     budget_exceeded=result.guards_budget_exceeded)
    notes = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    budget_notes = [n for n in notes if n["descriptor"]["id"] == GUARD_BUDGET_NOTIFICATION_ID]
    assert len(budget_notes) == 1
    assert budget_notes[0]["level"] == "error"
    assert "test-hanging-guard" in budget_notes[0]["message"]["text"]
    # The completed guard's finding survived the kill — streamed, not returned at the end.
    assert any(r["ruleId"] == "test/sentinel" for r in sarif["runs"][0]["results"])

    # Exit-code logic, asserted apart from the artifacts: the info-severity sentinel could
    # never trip a `high` gate, so a failure here is the budget state and nothing else.
    assert _gate(result, "high", no_fail=False) == 1
    assert _gate(result, "high", no_fail=True) == 0, "--no-fail must still win"


def test_gate_unchanged_when_nothing_exceeded_the_budget(tmp_path: Path,
                                                         monkeypatch: pytest.MonkeyPatch) -> None:
    """FP-bait for the gate widening: without a budget kill, an info finding still passes."""
    monkeypatch.setattr("agentsec.audit.select_guards", lambda profile: [SentinelGuard()])
    result = audit(tmp_path, run_scanners=False, guard_budget=30.0)
    assert result.guards_budget_exceeded == []
    assert result.guards_unbudgeted is False
    assert _gate(result, "high", no_fail=False) == 0


def test_zero_budget_keeps_the_legacy_inprocess_path(tmp_path: Path,
                                                     monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentsec.audit.select_guards", lambda profile: [SentinelGuard()])
    result = audit(tmp_path, run_scanners=False, guard_budget=0)
    assert [f.check_id for f in result.findings if f.check_id == "test-sentinel-guard"]
    assert result.guards_budget_exceeded == []


# The canary parity tests below share ONE canary tree and each distinct audit of it, built
# lazily per module (per xdist worker): the honest-guards test's budgeted run and the parallel
# test's single-lane run were the SAME call (`guard_budget=60.0, guard_workers=1`) made twice.
# Lazy and separate, so a worker that collects only one of the two tests builds only what that
# test reads, which is never more than before.
@pytest.fixture(scope="module")
def _canary_root(tmp_path_factory: pytest.TempPathFactory) -> Path:
    from agentsec.canary import write_canary_repo

    return write_canary_repo(tmp_path_factory.mktemp("budget-canary"))


@pytest.fixture(scope="module")
def _canary_inprocess(_canary_root: Path) -> AuditResult:
    return audit(_canary_root, run_scanners=False)


@pytest.fixture(scope="module")
def _canary_one_lane(_canary_root: Path) -> AuditResult:
    return audit(_canary_root, run_scanners=False, guard_budget=60.0, guard_workers=1)


@pytest.fixture(scope="module")
def _canary_four_lanes(_canary_root: Path) -> AuditResult:
    return audit(_canary_root, run_scanners=False, guard_budget=60.0, guard_workers=4)


# Its own marker, like the self-audit's and the corpus ReDoS gate's (#1137), because the 120s default
# (pyproject `timeout`) is too close: on the self-hosted Windows leg under CI's `-n auto --dist
# worksteal`, measured 2026-10-23 by hand on main-shape trees, this test took 46-103s (the parity
# test below 41-70s), and beside a second concurrent run both were killed at 120s, which under xdist
# on Windows presents as "worker crashed" with no message. A contributor's loaded dev box at `-n 3`
# hit the same kill. 300s is ~3x the worst uncontended reading and stays under the self-audit's
# 480s marker, so it fits the windows job's `timeout-minutes` arithmetic in ci.yml unchanged.
@pytest.mark.timeout(300)
@pytest.mark.slow  # two full canary-repo audits (broad scan-everything, plus a spawn)
def test_honest_guards_never_trip_and_findings_match_the_inprocess_run(
    _canary_one_lane: AuditResult, _canary_inprocess: AuditResult,
) -> None:
    """The FP-bait for the whole mechanism (Rule 1: the widening must not fire on honest
    guards) AND the parity proof: the process boundary must not change a single finding.
    Running the full registry through the boundary is also the strongest picklability
    check — every guard, every Finding, and the StackProfile cross it here."""
    budgeted, inprocess = _canary_one_lane, _canary_inprocess

    assert budgeted.guards_budget_exceeded == []

    def key(f: Finding) -> tuple[str, str, str, str]:
        return (f.check_id, f.rule, f.location, f.message)

    # ORDERED, not sorted: the in-process order already matches the one-lane order (measured
    # 2026-10-23), and SARIF and the baseline are order-bearing, so a boundary that reordered
    # findings is a parity break too.
    assert list(map(key, budgeted.findings)) == list(map(key, inprocess.findings))
    assert budgeted.ran == inprocess.ran
    assert budgeted.tools_errored == inprocess.tools_errored


@pytest.mark.slow  # fixed-deadline confirmation (waits out the 1s budget)
def test_scan_repo_surfaces_budget_exceeded_and_keeps_completed_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The corpus AC: a hostile repo reports WHICH guard exceeded (in `.error`, which the
    per-repo render prints and the fp/gap analyses filter on) instead of wedging the run."""
    monkeypatch.setattr("agentsec.audit.select_guards",
                        lambda profile: [HangingGuard(), SentinelGuard()])
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    scan = scan_repo("file://fixture", tmp_path, today=date(2026, 1, 1),
                     min_features=0, guard_budget=1.0)
    assert scan.error.startswith("budget-exceeded: ")
    assert "test-hanging-guard" in scan.error
    assert any(f.check_id == "test-sentinel-guard" for f in scan.findings)


@pytest.mark.slow  # fixed-deadline confirmation (waits out the 1s budget), full CLI pass
def test_cli_audit_prints_the_budget_line_and_fails_the_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """End to end through the real CLI: `--guard-budget` must actually thread through to
    `audit()` — a flag that parses but does nothing is the #609 M1 failure shape."""
    monkeypatch.setattr("agentsec.audit.select_guards",
                        lambda profile: [HangingGuard(), SentinelGuard()])
    rc = cli.main(["audit", str(tmp_path), "--guards-only", "--guard-budget", "1"])
    captured = capsys.readouterr()
    assert rc == 1, "a budget kill must fail the gate even with no gating-severity finding"
    assert "test-hanging-guard" in captured.out
    assert "did NOT complete" in captured.out
    assert "killed over time budget" in captured.err  # the CI one-line verdict names it


@pytest.mark.slow  # fixed-deadline confirmation: waits out one budget per startup attempt
def test_startup_stall_retries_once_then_falls_back_inprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#821 review Medium-2: a child lost BEFORE its first message blames no guard. One
    bounded retry, then the legacy in-process loop still produces every guard's results
    (the fallback never pickles, so the saboteur runs normally there). Spawn attempts are
    counted like the sibling test's — the follow-up review proved this test passed against
    the no-retry code without it, so the fallback asserts alone discriminate nothing."""
    from agentsec import guard_worker

    real_process = guard_worker._CTX.Process
    spawn_attempts: list[int] = []

    def counting_process(*args: object, **kwargs: object) -> object:
        spawn_attempts.append(1)
        return real_process(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(guard_worker._CTX, "Process", counting_process)
    # Startup is judged against _STARTUP_ALLOWANCE, not the budget; shrink it so this
    # test proves the stall diagnosis without waiting out two 60s real-world windows.
    monkeypatch.setattr(guard_worker, "_STARTUP_ALLOWANCE", 0.25)
    out = run_guards_budgeted(tmp_path, mkprofile(tmp_path),
                              [StallOnUnpickleGuard(), SentinelGuard()], budget=0.25)
    assert len(spawn_attempts) == 2, "one retry before the in-process fallback"
    assert out.fallback_inprocess is True, "the lapse must be disclosed, never silent"
    assert out.budget_exceeded == [], "a startup stall must not be blamed on any guard"
    assert out.errored == []
    assert set(out.ran) == {"test-stall-on-unpickle-guard", "test-sentinel-guard"}
    assert {f.check_id for f in out.findings} == {"test-stall-on-unpickle-guard",
                                                  "test-sentinel-guard"}


def test_startup_death_retries_once_then_falls_back_inprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The EOF-before-first-message variant of the same branch (child dies unpickling).
    Counts spawn attempts so the RETRY is asserted, not just the fallback — without the
    count this test would also pass against a no-retry implementation."""
    from agentsec import guard_worker

    real_process = guard_worker._CTX.Process
    spawn_attempts: list[int] = []

    def counting_process(*args: object, **kwargs: object) -> object:
        spawn_attempts.append(1)
        return real_process(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(guard_worker._CTX, "Process", counting_process)
    out = run_guards_budgeted(tmp_path, mkprofile(tmp_path),
                              [DieOnUnpickleGuard(), SentinelGuard()], budget=30.0)
    assert len(spawn_attempts) == 2, "one retry before the in-process fallback"
    assert out.fallback_inprocess is True, "the lapse must be disclosed, never silent"
    assert out.budget_exceeded == []
    assert out.errored == []
    assert {f.check_id for f in out.findings} == {"test-die-on-unpickle-guard",
                                                  "test-sentinel-guard"}


@pytest.mark.slow  # fixed-deadline confirmation: the 1.5s planted startup sleep is the scenario
def test_slow_startup_within_the_allowance_is_not_a_stall(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression for the 2026-09-07 Windows CI wedge (the 40-minute #821 job): startup
    slower than the per-guard budget must NOT be misdiagnosed as a stall — one spawn, no
    retry, no fallback, no guard blamed, both guards' findings intact."""
    from agentsec import guard_worker

    real_process = guard_worker._CTX.Process
    spawn_attempts: list[int] = []

    def counting_process(*args: object, **kwargs: object) -> object:
        spawn_attempts.append(1)
        return real_process(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(guard_worker._CTX, "Process", counting_process)
    out = run_guards_budgeted(tmp_path, mkprofile(tmp_path),
                              [SlowStartGuard(), SentinelGuard()], budget=1.0)
    assert len(spawn_attempts) == 1, "slow startup must not be diagnosed as a stall"
    assert out.fallback_inprocess is False
    assert out.budget_exceeded == [], "startup cost must never be blamed on a guard"
    assert out.errored == []
    assert set(out.ran) == {"test-slow-start-guard", "test-sentinel-guard"}
    assert {f.check_id for f in out.findings} == {"test-slow-start-guard",
                                                  "test-sentinel-guard"}


@pytest.mark.slow  # two spawns, each paying the 1.5s planted startup sleep
def test_respawn_after_a_child_death_also_gets_the_startup_allowance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The respawn variant of the same wedge: after a kill/death, the REPLACEMENT child
    pays the boot-and-import cost again, so its first message is judged against the
    allowance too — otherwise every 1s-budget respawn on a loaded box would cascade into
    the fallback (and flip `fallback_inprocess` on runs whose kills were legitimate)."""
    from agentsec import guard_worker

    real_process = guard_worker._CTX.Process
    spawn_attempts: list[int] = []

    def counting_process(*args: object, **kwargs: object) -> object:
        spawn_attempts.append(1)
        return real_process(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(guard_worker._CTX, "Process", counting_process)
    out = run_guards_budgeted(
        tmp_path, mkprofile(tmp_path),
        [ChildKillingGuard(), SlowStartGuard(), SentinelGuard()], budget=1.0)
    assert len(spawn_attempts) == 2, "one respawn for the killed child, no stall retries"
    assert out.fallback_inprocess is False
    assert out.errored == ["test-child-killing-guard"]
    assert out.budget_exceeded == []
    assert {f.check_id for f in out.findings} == {"test-slow-start-guard",
                                                  "test-sentinel-guard"}


@pytest.mark.slow  # waits out two (shrunk) startup windows before the fallback engages
def test_fallback_lapse_is_disclosed_in_notices_and_footer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rule 3 for the fallback itself: when the worker cannot start and the guards run
    unbudgeted, the lapse must be visible in the artifacts (result field, coverage notice,
    footer) — never a clean-looking run with hang protection silently off. And its own
    FP-bait: coverage is complete, so the lapse alone must NOT fail the gate (unlike a
    budget kill, which is a partial scan)."""
    from agentsec import guard_worker

    monkeypatch.setattr(guard_worker, "_STARTUP_ALLOWANCE", 0.25)
    monkeypatch.setattr("agentsec.audit.select_guards",
                        lambda profile: [StallOnUnpickleGuard(), SentinelGuard()])
    result = audit(tmp_path, run_scanners=False, guard_budget=0.25)
    assert result.guards_unbudgeted is True
    assert result.guards_budget_exceeded == []
    assert any("unbudgeted" in n for n in result.coverage_notices())
    footer = "\n".join(_meta_lines(result, []))
    assert "Guard time budget disabled" in footer
    assert _gate(result, "high", no_fail=False) == 0


@pytest.mark.skipif(sys.platform == "win32",
                    reason="fd-dup simulation of the leaked write handle is POSIX-only; on "
                           "Windows the leak is the native behavior and the plain "
                           "startup-death test exercises the same path")
def test_child_death_is_observed_on_the_process_not_the_pipe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The 2026-09-07 Windows rerun failure: a child that dies mid-unpickle (before
    claiming its duplicated pipe handle) leaves the parent's DupHandle copy holding the
    write end open, so the pipe never signals EOF and the death was noticed only at
    window expiry — two 60s startup windows pushed the startup-death test past
    pytest-timeout and crashed the xdist worker. Simulate that leak on POSIX by holding
    a dup of the write fd: the sentinel-aware wait must still see the death immediately
    (measured 4.01s via window expiry pre-fix at 2s windows; ~1s post-fix)."""
    from agentsec import guard_worker

    real_pipe = guard_worker._CTX.Pipe
    leaked: list[int] = []

    def leaky_pipe(duplex: bool = True) -> tuple[object, object]:
        recv, send = real_pipe(duplex)
        leaked.append(os.dup(send.fileno()))  # EOF can now never be signalled
        return recv, send

    monkeypatch.setattr(guard_worker._CTX, "Pipe", leaky_pipe)
    try:
        start = time.monotonic()
        out = run_guards_budgeted(tmp_path, mkprofile(tmp_path),
                                  [DieOnUnpickleGuard(), SentinelGuard()], budget=30.0)
        elapsed = time.monotonic() - start
    finally:
        for fd in leaked:
            os.close(fd)
    assert_within(elapsed, _DEATH_BUDGET)
    assert out.fallback_inprocess is True
    assert {f.check_id for f in out.findings} == {"test-die-on-unpickle-guard",
                                                  "test-sentinel-guard"}


@pytest.mark.slow  # waits out two (shrunk) startup windows before the fallback engages
def test_scan_repo_discloses_an_unbudgeted_fallback_without_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The corpus channel for the fallback lapse (#821 follow-up review, Medium): the
    findings are complete (every guard ran, in-process), so the repo must STAY in the
    fp/gap analyses (`.error` stays empty) — but the lapse must be visible on the
    RepoScan instead of rendering as a fully-protected clean scan."""
    from agentsec import guard_worker

    monkeypatch.setattr(guard_worker, "_STARTUP_ALLOWANCE", 0.25)
    monkeypatch.setattr("agentsec.audit.select_guards",
                        lambda profile: [StallOnUnpickleGuard(), SentinelGuard()])
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    scan = scan_repo("file://fixture", tmp_path, today=date(2026, 1, 1),
                     min_features=0, guard_budget=0.25)
    assert scan.error == "", "a complete unbudgeted scan must stay in the analyses"
    assert scan.unbudgeted is True
    assert {f.check_id for f in scan.findings} >= {"test-stall-on-unpickle-guard",
                                                   "test-sentinel-guard"}


@pytest.mark.slow  # waits out two (shrunk) startup windows before the fallback engages
def test_write_baseline_still_writes_on_an_unbudgeted_fallback_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """The High-1 refusal must not widen to the fallback lapse: an unbudgeted run is a
    COMPLETE scan (every guard ran), so the baseline is still a whole-posture claim and
    still writes — only a budget-killed (partial) scan refuses."""
    from agentsec import guard_worker

    monkeypatch.setattr(guard_worker, "_STARTUP_ALLOWANCE", 0.25)
    baseline = tmp_path / "agentsec-exceptions.json"
    monkeypatch.setattr("agentsec.audit.select_guards",
                        lambda profile: [StallOnUnpickleGuard(), SentinelGuard()])
    rc = cli.main(["audit", str(tmp_path), "--guards-only",
                   "--write-baseline", str(baseline), "--guard-budget", "0.25"])
    captured = capsys.readouterr()
    assert baseline.exists(), "a complete (if unbudgeted) scan must still baseline"
    assert rc == 0
    assert "Wrote baseline" in captured.out


@pytest.mark.slow  # fixed-deadline confirmation (waits out the 1s budget), full CLI pass
def test_write_baseline_refuses_a_partial_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """#821 review High-1: a baseline is a claim about the whole posture, so a scan with a
    budget-killed guard must write NOTHING and fail loudly — never a partial snapshot with
    a success message. Asserts the artifact (no file), then the exit code."""
    baseline = tmp_path / "agentsec-exceptions.json"
    monkeypatch.setattr("agentsec.audit.select_guards",
                        lambda profile: [HangingGuard(), SentinelGuard()])
    rc = cli.main(["audit", str(tmp_path), "--guards-only",
                   "--write-baseline", str(baseline), "--guard-budget", "1"])
    captured = capsys.readouterr()
    assert not baseline.exists(), "a partial scan must never bake a baseline"
    assert rc == 1
    assert "write-baseline refused" in captured.err
    assert "test-hanging-guard" in captured.err


def test_write_baseline_still_writes_on_a_clean_budgeted_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """The refusal's FP-bait (Rule 1): an honest budgeted run must still write the file."""
    baseline = tmp_path / "agentsec-exceptions.json"
    monkeypatch.setattr("agentsec.audit.select_guards", lambda profile: [SentinelGuard()])
    rc = cli.main(["audit", str(tmp_path), "--guards-only",
                   "--write-baseline", str(baseline), "--guard-budget", "30"])
    captured = capsys.readouterr()
    assert baseline.exists(), "the refusal must not block a complete scan"
    assert rc == 0
    assert "Wrote baseline" in captured.out


# ------------------------------------------------------------------ parallel lanes (workers > 1)
#
# `run_guards_budgeted(..., workers=N)` deals the guards into N lanes, each one the single-lane
# loop the tests above pin, then merges back into the caller's order. These pin what the lanes
# add: the merged order, position-keyed attribution (two entries may share an id), a kill or a
# fallback confined to its own lane, and the fallback running on the caller's thread.


def _counting_spawns(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    from agentsec import guard_worker

    real_process = guard_worker._CTX.Process
    spawns: list[int] = []

    def counting_process(*args: object, **kwargs: object) -> object:
        spawns.append(1)  # list.append is atomic under the GIL; lanes spawn from threads
        return real_process(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(guard_worker._CTX, "Process", counting_process)
    return spawns


def test_parallel_lanes_merge_back_into_the_callers_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Seven guards sharing one id over three lanes: round-robin puts n0/n3/n6 in lane 0, so
    any merge by lane, by completion or by id would scramble the n-sequence or drop
    duplicates. The spawn count proves three lanes really ran, not one."""
    spawns = _counting_spawns(monkeypatch)
    guards: list[Guard] = [NumberedGuard(n) for n in range(7)]
    out = run_guards_budgeted(tmp_path, mkprofile(tmp_path), guards, budget=30.0, workers=3)
    assert len(spawns) == 3
    assert [f.location for f in out.findings] == [f"n{n}.py:1" for n in range(7)]
    assert out.ran == ["test-numbered-guard"] * 7
    assert out.errored == [] and out.budget_exceeded == []
    assert out.fallback_inprocess is False


@pytest.mark.timeout(300)  # see the honest test's marker above: same measurements, same reason
def test_parallel_and_single_lane_audits_are_identical_on_the_canary(
    _canary_one_lane: AuditResult, _canary_four_lanes: AuditResult,
) -> None:
    """The parity proof for the whole change: the full registry over the everything-stack
    canary must report the same findings IN THE SAME ORDER at 1 and at 4 workers (an ordered
    comparison, like the in-process one above, because SARIF and the baseline are order-bearing),
    with nothing killed and nothing errored that the single lane did not also error."""
    single, parallel = _canary_one_lane, _canary_four_lanes

    def key(f: Finding) -> tuple[str, str, str, str]:
        return (f.check_id, f.rule, f.location, f.message)

    assert single.findings, "a canary run with no findings proves nothing about parity"
    assert list(map(key, parallel.findings)) == list(map(key, single.findings))
    assert parallel.ran == single.ran
    assert parallel.tools_errored == single.tools_errored
    assert parallel.guards_budget_exceeded == single.guards_budget_exceeded == []


@pytest.mark.slow  # fixed-deadline confirmation: its cost IS the budget it must wait out
def test_a_hang_in_one_lane_is_killed_while_the_other_lanes_finish(tmp_path: Path) -> None:
    """Lane 0 gets [hang, n0] and lane 1 gets [sentinel, n1]. The kill must stay in lane 0,
    lane 0 must still run n0 after it, and lane 1 must be untouched."""
    start = time.monotonic()
    guards: list[Guard] = [HangingGuard(), SentinelGuard(), NumberedGuard(0), NumberedGuard(1)]
    out = run_guards_budgeted(tmp_path, mkprofile(tmp_path), guards, budget=1.0, workers=2)
    assert_within(time.monotonic() - start, _KILL_BUDGET)
    assert out.budget_exceeded == ["test-hanging-guard"]
    assert out.ran == ["test-sentinel-guard", "test-numbered-guard", "test-numbered-guard"]
    assert [f.location for f in out.findings] == ["s.py:1", "n0.py:1", "n1.py:1"]
    assert out.fallback_inprocess is False, "a budget kill must never engage the fallback"


def test_a_lane_that_cannot_start_falls_back_on_the_callers_thread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Lane 0 holds only the child-killing probe, so it exhausts its startup retry (2
    spawns) while lane 1 runs normally (1 spawn). The fallback must be disclosed, must run on
    the caller's thread (never a lane thread), and its result must land in its own slot."""
    spawns = _counting_spawns(monkeypatch)
    guards: list[Guard] = [MainThreadProbeGuard(), NumberedGuard(1)]
    out = run_guards_budgeted(tmp_path, mkprofile(tmp_path), guards, budget=30.0, workers=2)
    assert len(spawns) == 3, "lane 0: one spawn and one retry; lane 1: one spawn"
    assert out.fallback_inprocess is True, "the lapse must be disclosed, never silent"
    assert out.ran == ["test-main-thread-probe-guard", "test-numbered-guard"]
    assert [f.title for f in out.findings] == ["main-thread=True", "numbered"]
    assert out.errored == [] and out.budget_exceeded == []


def test_workers_beyond_the_guard_count_spawn_one_child_per_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    spawns = _counting_spawns(monkeypatch)
    out = run_guards_budgeted(tmp_path, mkprofile(tmp_path),
                              [NumberedGuard(0), NumberedGuard(1)], budget=30.0, workers=8)
    assert len(spawns) == 2, "an empty lane must not spawn a child"
    assert [f.location for f in out.findings] == ["n0.py:1", "n1.py:1"]


def test_no_guards_spawn_no_child(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    spawns = _counting_spawns(monkeypatch)
    out = run_guards_budgeted(tmp_path, mkprofile(tmp_path), [], budget=30.0, workers=4)
    assert spawns == [] and out.ran == [] and out.findings == []


@pytest.mark.parametrize(("usable", "expected"), [(1, 1), (3, 3), (8, 8), (64, 8)])
def test_auto_workers_are_the_usable_cores_capped_at_eight(
    monkeypatch: pytest.MonkeyPatch, usable: int, expected: int,
) -> None:
    from agentsec import guard_worker
    from agentsec.guard_worker import default_guard_workers

    monkeypatch.setattr(guard_worker, "cgroup_cpu_limit", lambda: None)  # not this box's quota
    monkeypatch.setattr(os, "sched_getaffinity", lambda pid: set(range(usable)), raising=False)
    assert default_guard_workers() == expected


@pytest.mark.parametrize(("cores", "expected"), [(None, 1), (2, 2), (32, 8)])
def test_auto_workers_fall_back_to_the_machine_count_without_affinity(
    monkeypatch: pytest.MonkeyPatch, cores: int | None, expected: int,
) -> None:
    """Windows and macOS have no `sched_getaffinity`; `cpu_count()` may return None."""
    from agentsec import guard_worker
    from agentsec.guard_worker import default_guard_workers

    monkeypatch.setattr(guard_worker, "cgroup_cpu_limit", lambda: None)
    monkeypatch.delattr(os, "sched_getaffinity", raising=False)
    monkeypatch.setattr(os, "cpu_count", lambda: cores)
    assert default_guard_workers() == expected


@pytest.mark.parametrize(("usable", "quota", "expected"), [
    (64, 2, 2),     # the review's case: all cores visible, a 2-CPU quota
    (8, 1, 1),
    (3, 6, 3),      # a quota looser than the affinity never raises the count
    (64, 32, 8),    # nor lifts the cap
    (4, None, 4),   # no quota: the count is exactly what it was before quotas were read
])
def test_auto_workers_honour_a_cgroup_cpu_quota(
    monkeypatch: pytest.MonkeyPatch, usable: int, quota: int | None, expected: int,
) -> None:
    from agentsec import guard_worker
    from agentsec.guard_worker import default_guard_workers

    monkeypatch.setattr(guard_worker, "cgroup_cpu_limit", lambda: quota)
    monkeypatch.setattr(os, "sched_getaffinity", lambda pid: set(range(usable)), raising=False)
    assert default_guard_workers() == expected


def _cgroup_tree(tmp_path: Path, proc_line: str, files: dict[str, str]) -> tuple[Path, Path]:
    """A fake `/proc/self/cgroup` plus a fake `/sys/fs/cgroup` holding `files` (path: text)."""
    proc = tmp_path / "proc-self-cgroup"
    proc.write_text(proc_line + "\n", encoding="utf-8")
    root = tmp_path / "sys-fs-cgroup"
    for rel, text in files.items():
        f = root / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text, encoding="utf-8")
    root.mkdir(exist_ok=True)
    return proc, root


@pytest.mark.parametrize(("cpu_max", "expected"), [
    ("200000 100000", 2),
    ("150000 100000", 2),   # rounded up: 1.5 CPUs of time still feeds two children
    ("50000 100000", 1),
    ("max 100000", None),   # v2 for "no quota"
    ("0 100000", None),
    ("garbage", None),
    ("", None),
])
def test_cgroup_v2_quota_is_read_from_cpu_max(
    tmp_path: Path, cpu_max: str, expected: int | None,
) -> None:
    """The cgroup-namespaced container shape `docker run --cpus=N` produces (checked against
    real containers: --cpus=2 / 1.5 / 0.5 give 2 / 2 / 1)."""
    from agentsec.guard_worker import cgroup_cpu_limit

    proc, root = _cgroup_tree(tmp_path, "0::/", {"cpu.max": cpu_max + "\n"})
    assert cgroup_cpu_limit(proc, root) == expected


@pytest.mark.parametrize(("leaf", "parent", "expected"), [
    ("max 100000", "300000 100000", 3),      # the quota sits on an ancestor (a k8s pod's)
    ("400000 100000", "200000 100000", 2),   # the ancestor is tighter than the leaf
    ("100000 100000", "800000 100000", 1),   # the leaf is tighter than the ancestor
])
def test_cgroup_v2_takes_the_tightest_quota_up_the_hierarchy(
    tmp_path: Path, leaf: str, parent: str, expected: int,
) -> None:
    from agentsec.guard_worker import cgroup_cpu_limit

    proc, root = _cgroup_tree(tmp_path, "0::/kubepods/pod1/ctr", {
        "kubepods/pod1/ctr/cpu.max": leaf, "kubepods/pod1/cpu.max": parent,
    })
    assert cgroup_cpu_limit(proc, root) == expected


def test_cgroup_quota_is_found_without_a_cgroup_namespace(tmp_path: Path) -> None:
    """No cgroupns: /proc/self/cgroup shows the host-side path, which does not exist inside
    the container, whose own cgroup is the one mounted at the root."""
    from agentsec.guard_worker import cgroup_cpu_limit

    proc, root = _cgroup_tree(tmp_path, "0::/docker/abc123", {"cpu.max": "200000 100000"})
    assert cgroup_cpu_limit(proc, root) == 2


@pytest.mark.parametrize(("quota", "expected"), [("300000", 3), ("-1", None)])
def test_cgroup_v1_quota_is_read_from_cfs_files(
    tmp_path: Path, quota: str, expected: int | None,
) -> None:
    from agentsec.guard_worker import cgroup_cpu_limit

    proc, root = _cgroup_tree(tmp_path, "4:cpu,cpuacct:/docker/abc123", {
        "cpu,cpuacct/cpu.cfs_quota_us": quota + "\n",
        "cpu,cpuacct/cpu.cfs_period_us": "100000\n",
    })
    assert cgroup_cpu_limit(proc, root) == expected


def test_cgroup_lines_for_other_controllers_are_ignored(tmp_path: Path) -> None:
    """v1 lists one line per controller; only `cpu` carries a CPU quota. A `memory` line
    pointing at a directory that happens to hold quota files must not be read as one."""
    from agentsec.guard_worker import cgroup_cpu_limit

    proc, root = _cgroup_tree(tmp_path, "9:memory:/docker/abc123", {
        "memory/cpu.cfs_quota_us": "100000", "memory/cpu.cfs_period_us": "100000",
    })
    assert cgroup_cpu_limit(proc, root) is None


def test_no_cgroup_file_means_no_quota(tmp_path: Path) -> None:
    """Windows and macOS: there is no /proc/self/cgroup at all."""
    from agentsec.guard_worker import cgroup_cpu_limit

    assert cgroup_cpu_limit(tmp_path / "absent", tmp_path) is None


def test_an_undecodable_cgroup_name_never_aborts_and_still_finds_the_quota(
    tmp_path: Path,
) -> None:
    """Review finding (reproduced): a cgroup name is any bytes but `/`, and a non-UTF-8 one
    made the read raise UnicodeDecodeError out of every audit. It must decode, and the walk
    must still reach the quota above the odd name."""
    from agentsec.guard_worker import cgroup_cpu_limit

    proc, root = _cgroup_tree(tmp_path, "0::/", {"cpu.max": "200000 100000"})
    proc.write_bytes(b"0::/foo\xff\n")
    assert cgroup_cpu_limit(proc, root) == 2


@pytest.mark.skipif(not sys.platform.startswith("linux"),
                    reason="needs a filesystem that accepts a non-UTF-8 directory name")
def test_a_non_utf8_cgroup_name_resolves_to_its_own_directory(tmp_path: Path) -> None:
    """`surrogateescape` round-trips the raw bytes, so the leaf's own quota is read, not
    skipped (`errors="replace"` would point the walk at a directory that does not exist)."""
    from agentsec.guard_worker import cgroup_cpu_limit

    proc, root = _cgroup_tree(tmp_path, "0::/", {"cpu.max": "max 100000"})
    leaf = os.path.join(os.fsencode(root), b"pod\xff")
    os.mkdir(leaf)
    with open(os.path.join(leaf, b"cpu.max"), "w", encoding="utf-8") as f:
        f.write("300000 100000\n")
    proc.write_bytes(b"0::/pod\xff\n")
    assert cgroup_cpu_limit(proc, root) == 3


def test_a_path_outside_the_namespace_root_is_not_read_as_the_roots_quota(
    tmp_path: Path,
) -> None:
    """`/../x` means the process sits outside its cgroup namespace's root, so the mounted root
    need not be one of its ancestors: reading its quota could cap the pool by an unrelated
    cgroup's limit. The review suggested reading it anyway; unknown is the safe answer."""
    from agentsec.guard_worker import cgroup_cpu_limit

    proc, root = _cgroup_tree(tmp_path, "0::/../../x", {"cpu.max": "100000 100000"})
    assert cgroup_cpu_limit(proc, root) is None


def test_cgroup_v1_falls_back_to_the_cpu_mount(tmp_path: Path) -> None:
    """The controller list can name the mount in either order (`cpuacct,cpu`); distros also
    expose `cpu` alone. A real directory stands in for the usual symlink (Windows CI)."""
    from agentsec.guard_worker import cgroup_cpu_limit

    proc, root = _cgroup_tree(tmp_path, "4:cpuacct,cpu:/docker/x", {
        "cpu/cpu.cfs_quota_us": "200000", "cpu/cpu.cfs_period_us": "100000",
    })
    assert cgroup_cpu_limit(proc, root) == 2


def test_cgroup_v1_takes_the_tightest_quota_up_the_hierarchy(tmp_path: Path) -> None:
    from agentsec.guard_worker import cgroup_cpu_limit

    proc, root = _cgroup_tree(tmp_path, "4:cpu,cpuacct:/kubepods/pod1/ctr", {
        "cpu,cpuacct/kubepods/pod1/ctr/cpu.cfs_quota_us": "-1",
        "cpu,cpuacct/kubepods/pod1/ctr/cpu.cfs_period_us": "100000",
        "cpu,cpuacct/kubepods/pod1/cpu.cfs_quota_us": "300000",
        "cpu,cpuacct/kubepods/pod1/cpu.cfs_period_us": "100000",
    })
    assert cgroup_cpu_limit(proc, root) == 3


def test_a_hybrid_host_reads_the_v1_quota_beside_an_empty_v2_tree(tmp_path: Path) -> None:
    """Hybrid mode lists a `0::` line next to the v1 lines, but the v2 tree carries no
    `cpu` controller, so the quota lives on the v1 side only."""
    from agentsec.guard_worker import cgroup_cpu_limit

    proc, root = _cgroup_tree(tmp_path, "0::/user.slice", {
        "cpu,cpuacct/user.slice/cpu.cfs_quota_us": "200000",
        "cpu,cpuacct/user.slice/cpu.cfs_period_us": "100000",
    })
    proc.write_text("4:cpu,cpuacct:/user.slice\n1:name=systemd:/user.slice\n0::/user.slice\n",
                    encoding="utf-8")
    assert cgroup_cpu_limit(proc, root) == 2


def test_odd_cgroup_entries_never_raise(tmp_path: Path) -> None:
    """A `cpu.max` that is a directory or not text, and a path holding `:` (kept whole by the
    split), each read as "nothing here" and the walk moves on to the root's quota."""
    from agentsec.guard_worker import cgroup_cpu_limit

    proc, root = _cgroup_tree(tmp_path, "0::/a:b", {"cpu.max": "200000 100000"})
    (root / "odd").mkdir()
    (root / "odd" / "cpu.max").mkdir()
    assert cgroup_cpu_limit(proc, root) == 2
    proc.write_text("0::/odd\n", encoding="utf-8")
    assert cgroup_cpu_limit(proc, root) == 2
    (root / "bin").mkdir()
    (root / "bin" / "cpu.max").write_bytes(b"\xff\xfe 100000\n")  # not text: no raise, no quota
    proc.write_text("0::/bin\n", encoding="utf-8")
    assert cgroup_cpu_limit(proc, root) == 2

def test_cli_passes_guard_workers_through_and_defaults_to_auto(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agentsec import guard_worker
    from agentsec.guard_worker import GuardRunOutcome

    seen: list[int] = []

    def fake_run(root: Path, profile: StackProfile, guards: list[Guard], budget: float,
                 workers: int = 1) -> GuardRunOutcome:
        seen.append(workers)
        return GuardRunOutcome()

    monkeypatch.setattr(guard_worker, "run_guards_budgeted", fake_run)
    monkeypatch.setattr(guard_worker, "default_guard_workers", lambda: 5)
    monkeypatch.setattr(cli, "default_guard_workers", lambda: 5)
    assert cli.main(["audit", str(tmp_path), "--guards-only", "--no-fail",
                     "--guard-workers", "3"]) == 0
    assert cli.main(["audit", str(tmp_path), "--guards-only", "--no-fail"]) == 0
    assert seen == [3, 5]


def test_cli_rejects_a_guard_worker_count_below_one(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["audit", str(tmp_path), "--guards-only", "--guard-workers", "0"])
    assert exc.value.code == 2


@pytest.mark.parametrize("planted", [OSError("planted spawn failure"), KeyboardInterrupt()])
def test_a_failing_lane_cancels_the_others_promptly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, planted: BaseException,
) -> None:
    """Review finding (reproduced): with lanes, an exception in one lane, or a Ctrl-C in the
    caller, used to wait for every other lane to finish, where a single lane stops at once.
    Lane 0 holds a guard that sleeps a minute; lane 1 waits until that guard is running in
    its child, then fails to spawn. The error must surface well inside that minute, timed
    from the failure, and lane 0's child must be dead when it does. KeyboardInterrupt
    is raised from a lane here, not delivered to the main thread (a real SIGINT would end the
    pytest session); both arrive in the same `except BaseException`."""
    from agentsec import guard_worker

    real_process = guard_worker._CTX.Process
    children: list[Any] = []
    raised_at: list[float] = []
    marker = tmp_path / "sleeping-guard-running"

    def process(*args: Any, **kwargs: Any) -> Any:
        if any(isinstance(g, UnstartableGuard) for g in kwargs["args"][2]):
            deadline = time.monotonic() + 60
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            raised_at.append(time.monotonic())
            raise planted
        child = real_process(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(guard_worker._CTX, "Process", process)
    with pytest.raises(type(planted)):
        run_guards_budgeted(tmp_path, mkprofile(tmp_path),
                            [SleepingGuard(), UnstartableGuard()], budget=120.0, workers=2)
    assert marker.exists(), "the sleeping guard never ran, so nothing was cancelled"
    assert_within(time.monotonic() - raised_at[0], _CANCEL_BUDGET)
    assert not any(c.is_alive() for c in children), "a cancelled lane must not leak its child"


def test_every_lane_can_fall_back_and_the_fallbacks_stay_in_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both lanes exhaust their startup retry (2 spawns each). The two fallback tails are
    run once each, on the caller's thread, in the caller's order."""
    spawns = _counting_spawns(monkeypatch)
    guards: list[Guard] = [MainThreadProbeGuard(), DieOnUnpickleGuard()]
    out = run_guards_budgeted(tmp_path, mkprofile(tmp_path), guards, budget=30.0, workers=2)
    assert len(spawns) == 4
    assert out.fallback_inprocess is True
    assert out.ran == ["test-main-thread-probe-guard", "test-die-on-unpickle-guard"]
    assert [f.title for f in out.findings] == ["main-thread=True", "fallback ran me"]


@pytest.mark.parametrize("argv", [
    ["audit", "{root}", "--guards-only", "--no-fail", "--guard-workers", "3"],
    ["audit", "{root}", "--guards-only", "--guard-workers", "3",
     "--write-baseline", "{root}/agentsec-exceptions.json"],
    ["live", "{root}", "--guards-only", "--no-fail", "--guard-workers", "3"],
])
def test_every_budgeted_cli_path_threads_guard_workers_through(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, argv: list[str],
) -> None:
    """The #609 shape (a flag that parses and does nothing) for the paths the audit-only
    test above does not reach: the baseline writer and `live` each make their own call."""
    from agentsec import guard_worker
    from agentsec.guard_worker import GuardRunOutcome

    seen: list[int] = []

    def fake_run(root: Path, profile: StackProfile, guards: list[Guard], budget: float,
                 workers: int = 1) -> GuardRunOutcome:
        seen.append(workers)
        return GuardRunOutcome()

    monkeypatch.setattr(guard_worker, "run_guards_budgeted", fake_run)
    assert cli.main([a.format(root=tmp_path) for a in argv]) == 0
    assert seen == [3]
