"""`tests/conftest.py::_session_shared`, the one-audit-per-session cache the canary consumers read.

It is cross-process state in the test harness itself, so its failure modes are pinned here rather
than trusted: a second worker must reuse the published blob, a waiter must take the builder's blob
instead of computing a duplicate, and every way the builder can fail (its compute raises, it dies
holding the lock) must end with the waiter computing its OWN copy - fail-safe, never a stale or
empty result passed off as the audit."""
from __future__ import annotations

import pickle
import threading
import time
from collections.abc import Callable
from pathlib import Path

import pytest

import tests.conftest as conftest
from agentsec.audit import AuditResult
from agentsec.detect import StackProfile
from tests._timing import TimingBudget, assert_within, register


class _Factory:
    """The one `TempPathFactory` method `_session_shared` reads: a worker's basetemp, `<root>/gwN`."""

    def __init__(self, root: Path, worker: str) -> None:
        self._base = root / worker

    def getbasetemp(self) -> Path:
        self._base.mkdir(parents=True, exist_ok=True)
        return self._base


def _result(tag: str) -> AuditResult:
    return AuditResult(profile=StackProfile(root=Path(".")), findings=[], ran=[tag], skipped=[])


def _shared(root: Path, worker: str, compute: Callable[[], AuditResult]) -> AuditResult:
    # `_Factory` is a duck-typed stand-in for pytest's TempPathFactory.
    factory = _Factory(root, worker)
    return conftest._session_shared(factory, "probe", compute).load()  # type: ignore[arg-type]


_LOCK, _BLOB = "shared-probe-run1.lock", "shared-probe-run1.pickle"


@pytest.fixture
def as_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PYTEST_XDIST_WORKER", "gw0")
    monkeypatch.setenv("PYTEST_XDIST_TESTRUNUID", "run1")


def test_a_published_blob_is_reused_without_computing(tmp_path: Path, as_worker: None) -> None:
    calls: list[str] = []

    def compute() -> AuditResult:
        calls.append("x")
        return _result("first")

    assert _shared(tmp_path, "gw0", compute).ran == ["first"]
    # Drop the builder's lock so the second worker can only get the blob from the fast path; with
    # the lock left in place the wait loop would read the blob too and hide a missing fast path.
    (tmp_path / _LOCK).unlink()
    assert _shared(tmp_path, "gw1", compute).ran == ["first"]
    assert calls == ["x"], "the second worker recomputed instead of reading the published blob"


def test_a_waiter_takes_the_builders_blob_instead_of_computing(
    tmp_path: Path, as_worker: None
) -> None:
    (tmp_path / _LOCK).touch()  # another worker is mid-compute

    def publish_later() -> None:
        time.sleep(0.3)
        tmp = tmp_path / f"{_BLOB}.gw9.tmp"
        tmp.write_bytes(pickle.dumps(_result("builder")))
        tmp.replace(tmp_path / _BLOB)

    t = threading.Thread(target=publish_later)
    t.start()
    try:
        got = _shared(tmp_path, "gw1", lambda: pytest.fail("the waiter computed a duplicate"))
    finally:
        t.join()
    assert got.ran == ["builder"]


def test_a_builder_whose_compute_raised_releases_the_lock_and_the_waiter_computes(
    tmp_path: Path, as_worker: None
) -> None:
    def broken() -> AuditResult:
        raise RuntimeError("audit crashed")

    with pytest.raises(RuntimeError, match="audit crashed"):
        _shared(tmp_path, "gw0", broken)
    assert not (tmp_path / _LOCK).exists(), "a failed builder left its lock behind"
    assert _shared(tmp_path, "gw1", lambda: _result("own")).ran == ["own"]


def test_a_builder_that_died_holding_the_lock_costs_the_wait_then_a_compute(
    tmp_path: Path, as_worker: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A timeout kill on Windows takes the whole worker: its lock stays and no blob ever arrives."""
    monkeypatch.setattr(conftest, "_SHARED_WAIT_S", 0.3)
    (tmp_path / _LOCK).touch()
    t0 = time.monotonic()
    assert _shared(tmp_path, "gw1", lambda: _result("own")).ran == ["own"]
    assert time.monotonic() - t0 >= 0.3, "the waiter gave up before its deadline"


def test_every_load_is_its_own_copy(tmp_path: Path, as_worker: None) -> None:
    factory = _Factory(tmp_path, "gw0")
    shared = conftest._session_shared(factory, "probe", lambda: _result("x"))  # type: ignore[arg-type]
    a, b = shared.load(), shared.load()
    a.ran.append("mutated")
    assert b.ran == ["x"], "one consumer's mutation reached another's copy"


def test_outside_xdist_nothing_touches_the_disk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("PYTEST_XDIST_WORKER", raising=False)
    assert _shared(tmp_path, "solo", lambda: _result("mem")).ran == ["mem"]
    assert not list(tmp_path.glob("shared-*")), "a non-xdist session wrote to the shared basetemp root"


# Measured 2026-10-23: 0.301s healthy (5 of 5 runs; the builder drops its lock after 0.3s and the
# waiter polls every 0.1s). With the wait loop's `lock.exists()` early exit deleted, the waiter sat
# out the whole 30s `_SHARED_WAIT_S` the test sets: 30.09s, which is the `regression` recorded here.
_GIVE_UP_BUDGET = register(
    TimingBudget(
        name="session-shared-audit/waiter-leaves-when-the-builder-gives-up",
        seconds=10.0,
        measured=0.301,
        regression=30.09,
        why="a waiter whose builder dropped its lock sits out the full wait instead of computing",
    )
)


def test_a_waiter_whose_builder_gives_up_mid_wait_computes_at_once(
    tmp_path: Path, as_worker: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PR #1143 review, M1: the builder drops its lock WHILE this worker is waiting (its compute
    raised, or its publish failed). The waiter must notice and compute its own copy, not sit out
    the whole wait."""
    monkeypatch.setattr(conftest, "_SHARED_WAIT_S", 30.0)
    (tmp_path / _LOCK).touch()

    def builder_gives_up() -> None:
        time.sleep(0.3)
        (tmp_path / _LOCK).unlink()

    t = threading.Thread(target=builder_gives_up)
    t.start()
    t0 = time.monotonic()
    try:
        got = _shared(tmp_path, "gw1", lambda: _result("own"))
    finally:
        t.join()
    assert got.ran == ["own"]
    assert_within(time.monotonic() - t0, _GIVE_UP_BUDGET, "the waiter sat out its deadline after the builder gave up")


def test_a_builder_whose_publish_fails_releases_the_lock(
    tmp_path: Path, as_worker: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PR #1143 review, M2: on Windows `os.replace` can fail (a scanner holding the tmp file). The
    builder still has its result, but nobody will ever publish, so it must release the lock."""
    def no_replace(src: object, dst: object) -> None:
        raise PermissionError("held open")

    monkeypatch.setattr(conftest.os, "replace", no_replace)
    assert _shared(tmp_path, "gw0", lambda: _result("own")).ran == ["own"]
    assert not (tmp_path / _LOCK).exists(), "an unpublished builder kept the lock; waiters would stall"
    assert not (tmp_path / _BLOB).exists()


def test_a_blob_from_another_run_is_never_read(
    tmp_path: Path, as_worker: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A root that outlived its run (PR #1143 review, Low 1): what run 0 published must not answer
    run 1, so the names carry xdist's per-run id."""
    monkeypatch.setenv("PYTEST_XDIST_TESTRUNUID", "run0")
    assert _shared(tmp_path, "gw0", lambda: _result("stale")).ran == ["stale"]
    monkeypatch.setenv("PYTEST_XDIST_TESTRUNUID", "run1")
    assert _shared(tmp_path, "gw0", lambda: _result("fresh")).ran == ["fresh"]
