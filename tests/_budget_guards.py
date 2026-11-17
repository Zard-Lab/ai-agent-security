"""Test-only guards for tests/test_guard_budget.py, in a module that imports almost nothing.

Every budgeted test spawns children, and a spawned child unpickles its guards by module +
qualname, so it imports the module each guard class lives in. Defined in the test module
itself, that import pulled in pytest, agentsec.cli and the whole guard registry: ~0.9s per
child on Linux against ~0.15s from here (measured 2026-10-23), paid by ~50 children.
"""
from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import TYPE_CHECKING

from agentsec.findings import Finding
from agentsec.guards.base import Guard

if TYPE_CHECKING:
    from agentsec.detect import StackProfile

# The pre-#674 pattern shape: three adjacent quantifiers that all match a space, then a
# literal that will be absent — the engine partitions the whitespace run combinatorially
# before it can fail. 256 KiB of spaces puts completion far beyond any test machine.
_HANG = re.compile(r"(?:const|let|var)\s+(.+?)\s*=\s*require\(")
_HANG_BAIT = "const" + " " * 262_144 + "x"


class HangingGuard(Guard):
    id = "test-hanging-guard"
    title = "test: hangs in a C-level regex loop (pre-#674 shape)"

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        _HANG.search(_HANG_BAIT)
        return []


class SentinelGuard(Guard):
    id = "test-sentinel-guard"
    title = "test: emits one finding"

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        return [Finding(check_id=self.id, severity="info", title="sentinel",
                        location="s.py:1", rule="test/sentinel")]


class RaisingGuard(Guard):
    id = "test-raising-guard"
    title = "test: raises (the crash contract, not the hang contract)"

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        raise ValueError("planted crash")


class ChildKillingGuard(Guard):
    """Kills the whole child interpreter — the segfault-class failure. In-process this
    would take the entire audit down; the worker must record it and carry on."""

    id = "test-child-killing-guard"
    title = "test: hard-exits the worker child"

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        os._exit(3)


class _StartupSaboteurGuard(Guard):
    """Base for guards whose UNPICKLING sabotages the child — spawn unpickles the Process
    args before `_child_main` runs, so no ("start", …) is ever sent: the exact
    "worker lost before its first message" branch (#821 review, Medium-2). In-process the
    instances are never pickled, so the fallback runs them normally."""

    def __getstate__(self) -> dict[str, bool]:
        # Non-empty state on purpose: with an empty __dict__, object.__getstate__ returns
        # None and pickle would skip __setstate__ entirely.
        return {"planted": True}

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        return [Finding(check_id=self.id, severity="info", title="fallback ran me",
                        location="f.py:1", rule=f"test/{self.id}")]


class StallOnUnpickleGuard(_StartupSaboteurGuard):
    id = "test-stall-on-unpickle-guard"
    title = "test: stalls the child during arg unpickling (startup-stall shape)"

    def __setstate__(self, state: dict[str, bool]) -> None:  # noqa: ARG002
        time.sleep(600)  # parent's SIGKILL ends this; the child never reaches _child_main


class DieOnUnpickleGuard(_StartupSaboteurGuard):
    id = "test-die-on-unpickle-guard"
    title = "test: kills the child during arg unpickling (startup-death shape)"

    def __setstate__(self, state: dict[str, bool]) -> None:  # noqa: ARG002
        os._exit(5)


class SlowStartGuard(Guard):
    """Child startup slower than the BUDGET but well inside the ALLOWANCE — the shape that
    wedged the 2026-09-07 Windows CI run: under `-n auto` contention, interpreter boot +
    imports overran the 1s test budgets, got misdiagnosed as a startup stall, and the
    fallback ran the catastrophic-regex bait in-process, where no per-test timeout can
    preempt it (a timer thread needs the GIL, which `re` never drops mid-match). The 1.5s
    sleep lands in `__setstate__` because startup cost IS unpickle-adjacent cost — same
    channel, honest stand-in for a slow boot."""

    id = "test-slow-start-guard"
    title = "test: child startup slower than the per-guard budget"

    def __getstate__(self) -> dict[str, bool]:
        return {"planted": True}

    def __setstate__(self, state: dict[str, bool]) -> None:  # noqa: ARG002
        time.sleep(1.5)  # > the 1s test budget, far below _STARTUP_ALLOWANCE

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        return [Finding(check_id=self.id, severity="info", title="ran in the child",
                        location="s.py:1", rule=f"test/{self.id}")]


class NumberedGuard(Guard):
    """Every instance shares one id and stamps its own number on its finding, so a test can
    see both the order of the merge and that results are keyed by position, not by id."""

    id = "test-numbered-guard"
    title = "test: emits one finding stamped with its number"

    def __init__(self, n: int) -> None:
        self.n = n

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        return [Finding(check_id=self.id, severity="info", title="numbered",
                        location=f"n{self.n}.py:1", rule="test/numbered")]


class MainThreadProbeGuard(DieOnUnpickleGuard):
    """Kills any child it is pickled into, so its lane falls back in-process; its finding
    records whether that fallback ran on the caller's (main) thread."""

    id = "test-main-thread-probe-guard"
    title = "test: reports which thread the in-process fallback ran it on"

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        import threading

        on_main = threading.current_thread() is threading.main_thread()
        return [Finding(check_id=self.id, severity="info", title=f"main-thread={on_main}",
                        location="m.py:1", rule="test/main-thread")]


class SleepingGuard(Guard):
    """Holds its lane's child for a minute: long enough that waiting for it is unmistakable,
    short of the budget the cancel test runs under, so only a cancel can end it early. The
    marker file says the child is booted and inside the guard."""

    id = "test-sleeping-guard"
    title = "test: sleeps for a minute in the child"

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        (root / "sleeping-guard-running").write_text("1", encoding="utf-8")
        time.sleep(60)
        return []


class UnstartableGuard(Guard):
    """A marker: the test's Process wrapper refuses to build any child whose list holds one."""

    id = "test-unstartable-guard"
    title = "test: its lane's child cannot be created"

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        return []
