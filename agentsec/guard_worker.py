"""Per-guard time budget: run the static guards in a killable child process (issue #677).

Why a process boundary, and not something lighter:

- A guard that HANGS (catastrophic regex backtracking, any unbounded loop) never returns,
  so the `try/except` around `g.run()` in `audit()` cannot see it — the loop simply stops
  advancing, and the only thing that ends the run is an external kill (the CI job-level
  `timeout-minutes`), which reports nothing. A killed gate with zero findings reads exactly
  like a clean scan (review-doctrine Rule 3; demonstrated live by #673).
- The guard cannot defend itself: `guard_sandbox.py` bans the `signal`/`multiprocessing`
  import roots and every wall-clock read for guard modules — correctly, so the budget must
  live here, in the caller, outside the sandboxed dirs.
- A `SIGALRM` watchdog in the caller would not work either: signals fire only between
  Python bytecodes on the main thread, so they cannot preempt a tight C-level loop (the
  exact #673 class), and Windows has no SIGALRM at all (see the pytest-timeout notes in
  `pyproject.toml`). Every timeout in this codebase that actually works crosses an OS
  process boundary (`runners/base.py::exec_capture`); this module gives guard execution
  the same property.

Mechanism: ONE child process runs the guards in order, streaming a ("start", id) /
("done", id, findings, errored) message per guard back over a pipe. The parent waits at
most `budget` seconds between messages — except for each child's FIRST message, which gets
`_STARTUP_ALLOWANCE`: before it can speak, a spawned child must boot an interpreter,
import the guard registry and unpickle its arguments, a cost that belongs to the machine
and its load, never to any guard. On a per-guard budget breach it SIGKILLs the child,
records the in-flight guard as budget-exceeded, and respawns a child for the remaining
guards; a startup-window breach blames no guard (one bounded retry, then the DISCLOSED
in-process fallback). The parent waits on the pipe AND the child's process sentinel, so a
dead child is noticed immediately even where the pipe cannot say so (see the wait below).
Common case: exactly one spawn per audit. Pathological case: one respawn per hanging guard, and
every completed guard's findings survive because they were streamed, not returned at the end.

Parallel lanes (`workers` > 1): the guards are dealt round-robin into N lanes, and each lane
is exactly the loop above (its own child, budget clock, respawns and startup retry), driven
from a parent thread. The lanes share nothing but the read-only arguments; their results are
merged back into the caller's guard order, so the outcome is the one a single lane would
produce, only sooner. Each child keeps its own per-run caches, so derived file state is
computed once per lane rather than once per audit: that duplication is the price of the
speedup and is why the auto count is capped (`_MAX_AUTO_WORKERS`).

The `spawn` start method is used on every platform: it is the only one Windows has, and
using it on Linux too means both CI legs exercise the identical code path (fork would also
inherit parent state that spawn forces us to pass explicitly — the honest contract).
Everything crossing the boundary is plain picklable data: `StackProfile`, `Finding`, the
stateless guard instances, and `GitignoreCapNotice` (guard walks trip `.gitignore` caps in
the CHILD's run context, so the child ships its notices back for the parent's disclosure).

A guard that kills the whole child interpreter (segfault-class, `os._exit`) is recorded as
errored — strictly better than today's in-process behavior, where it would kill the audit.

Deliberately NOT exception-safe against its own setup failures: if `Process.start()` itself
raises (resource exhaustion, an unpicklable guard injected by an embedder), the exception
propagates out of `audit()` uncaught. That is the doctrine's preferred failure mode — a
loud crash, never a clean-looking miss (#821 review, Low-4).
"""
from __future__ import annotations

import multiprocessing
import os
import threading
from concurrent.futures import FIRST_EXCEPTION, ThreadPoolExecutor
from concurrent.futures import wait as _futures_wait
from dataclasses import dataclass, field
from multiprocessing.connection import wait as _mp_wait
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agentsec import walk
from agentsec.astutil import ParseCandidates, parse_failure_candidates, parse_failure_run, share_parse_cache
from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.guards.base import derived_state_run, read_run

if TYPE_CHECKING:
    from multiprocessing.connection import Connection
    from multiprocessing.process import BaseProcess

    from agentsec.guards.base import Guard
    from agentsec.walk import GitignoreCapNotice

# Generous by design: an honest guard finishes in milliseconds-to-seconds even on a large
# monorepo, #673 hung for 90+ minutes, and the Windows CI leg runs ~2-3x slower than Linux.
# A budget that a legitimate guard can trip on slow hardware would be a Rule-3 false alarm.
DEFAULT_GUARD_BUDGET: float = 60.0

_KILL_GRACE = 15.0  # join() allowance after kill(); SIGKILL/TerminateProcess is not refusable

# The window for each child's FIRST message, decoupled from the per-guard budget: startup
# (interpreter boot + importing the registry + unpickling the guard list) is a property of
# the machine and its load, and it dwarfs a small budget on a contended box. Conflating the
# two is what wedged the 2026-09-07 Windows CI run for its whole 40-minute job timeout:
# spawn startup under `-n auto` contention overran the test suite's 1s budgets, two
# misdiagnosed "stalls" in a row engaged the in-process fallback, and the fallback ran the
# planted catastrophic regex unbudgeted — where nothing CAN preempt it (pytest-timeout's
# only Windows method is a timer thread, and a thread needs the GIL, which `re` holds for
# the entire C-level match). max()'d with the budget so raising the budget never tightens
# the startup window. Applies to respawns too: they pay the same boot-and-import cost.
_STARTUP_ALLOWANCE: float = 60.0

# Consecutive children lost BEFORE their first message (a spawn/import/unpickle stall or
# death, not any guard's doing) before giving up on process isolation and falling back to
# the legacy in-process loop for the rest. One retry: a transient stall (loaded box, cold
# imports) self-heals; a deterministic one would burn a full budget per attempt forever,
# and the fallback — which re-accepts the pre-#677 hang exposure for the tail, so the lapse
# is DISCLOSED (`fallback_inprocess` → an audit coverage notice), never silent — at least
# still produces results, where refusing to run would produce none (#821 review, Medium-2).
_MAX_STARTUP_ATTEMPTS = 2

# Ceiling for the AUTO worker count (`default_guard_workers`). Measured on an 8-core box over
# ai-agent-mastery (1,162 files, 341 applicable guards): 1 child 29.0s, 4 children 9.95s,
# 8 children 5.78s, same finding count. Each child pays its own spawn + registry import
# (~0.66s measured) and keeps its own per-run caches (`walk_run`/`derived_state_run` do not
# cross the process boundary), so past ~8 the per-child fixed cost and the duplicated
# derived state eat the gain. An explicit `--guard-workers N` is not capped.
_MAX_AUTO_WORKERS = 8

_CTX = multiprocessing.get_context("spawn")


def default_guard_workers() -> int:
    """The AUTO guard-worker count: the cores this process may run on, capped.

    `sched_getaffinity` is this process's share (a CPU-pinned CI container, `taskset`), where
    `os.cpu_count()` is the whole machine's; it does not exist on Windows or macOS, which fall
    back to the machine count. Neither sees a CPU *quota* (`docker --cpus=2`, a k8s CPU
    limit), which leaves every core visible but throttles the container to its share, so the
    quota (`cgroup_cpu_limit`) caps the count too. Without that, 8 children on a 2-CPU quota
    run each guard ~4x slower against the same wall-clock budget, and an honest slow guard
    can be killed and fail the gate. Windows job-object CPU limits are not read."""
    # Linux only. Read through `getattr`, not a direct access in try/except: typeshed declares it
    # only for Linux, so the direct spelling fails mypy and pyright on a Windows/macOS host (#1031).
    affinity = getattr(os, "sched_getaffinity", None)
    usable = len(affinity(0)) if affinity is not None else (os.cpu_count() or 1)
    quota = cgroup_cpu_limit()
    if quota is not None:
        usable = min(usable, quota)
    return max(1, min(usable, _MAX_AUTO_WORKERS))


_PROC_SELF_CGROUP = Path("/proc/self/cgroup")
_CGROUP_ROOT = Path("/sys/fs/cgroup")


def cgroup_cpu_limit(proc_cgroup: Path = _PROC_SELF_CGROUP,
                     cgroup_root: Path = _CGROUP_ROOT) -> int | None:
    """The CPUs this process's cgroup quota allows, rounded up, or None when none applies.

    Linux only (elsewhere `proc_cgroup` does not exist, so None). Reads cgroup v2 `cpu.max`
    (`<quota> <period>`, or `max <period>` for none) and v1 `cpu.cfs_quota_us` /
    `cpu.cfs_period_us` (quota -1 for none), at the process's own cgroup and every ancestor up
    to the hierarchy root, and returns the tightest: a quota on any ancestor (a k8s pod, a
    systemd slice) binds everything below it. Walking up from the full path also covers a
    container without a cgroup namespace, whose `/proc/self/cgroup` shows the host-side path
    (`/docker/<id>`) while its own cgroup is the one mounted at the root.

    This reads the host only to SIZE the guard pool, as `sched_getaffinity`/`cpu_count` already
    did. The findings are the same at any worker count whenever no guard is budget-killed
    (`test_parallel_and_single_lane_audits_are_identical_on_the_canary`). The one way pool
    size can reach the report is through the per-guard budget: a guard near it may trip at one
    size and not another, and a trip is disclosed and fails the gate. Reading the quota lowers
    the contention behind most trips. It cannot rule one out: the deal decides which guard in
    a lane pays that lane's cold-cache cost, so one guard can run slower at a smaller pool.
    An unreadable or malformed file means "no quota known",
    which leaves the count where it was before quotas were read.

    `surrogateescape`: a cgroup name is any bytes but `/`, so the file need not be UTF-8. The
    escape keeps such a name intact for the path join instead of raising (which would abort
    the audit) or replacing bytes (which would point the walk at a directory that is not
    there)."""
    try:
        lines = proc_cgroup.read_text(encoding="utf-8", errors="surrogateescape").splitlines()
    except (OSError, ValueError):
        return None
    tightest: int | None = None
    for line in lines:
        fields = line.split(":", 2)
        if len(fields) != 3:
            continue
        _, controllers, cgroup_path = fields
        parts = [p for p in cgroup_path.strip().split("/") if p]
        if ".." in parts:
            # The process sits outside its cgroup namespace's root. The mount root is then
            # not necessarily one of its ancestors, so its quota could belong to an unrelated
            # cgroup and read too LOW. Unknown (the pre-quota count) is the safe answer.
            continue
        if controllers == "":  # v2 unified hierarchy: "0::/path"
            mounts, reader = [cgroup_root], _cgroup_v2_cpus
        elif "cpu" in controllers.split(","):  # v1: "4:cpu,cpuacct:/path"
            mounts, reader = [cgroup_root / controllers, cgroup_root / "cpu"], _cgroup_v1_cpus
        else:
            continue
        for mount in mounts:
            for depth in range(len(parts), -1, -1):
                cpus = reader(mount.joinpath(*parts[:depth]))
                if cpus is not None and (tightest is None or cpus < tightest):
                    tightest = cpus
    return tightest


def _cgroup_v2_cpus(d: Path) -> int | None:
    fields = (_read_cgroup_file(d / "cpu.max") or "").split()
    if len(fields) != 2 or fields[0] == "max":
        return None
    return _quota_cpus(fields[0], fields[1])


def _cgroup_v1_cpus(d: Path) -> int | None:
    quota = _read_cgroup_file(d / "cpu.cfs_quota_us")
    period = _read_cgroup_file(d / "cpu.cfs_period_us")
    if quota is None or period is None:
        return None
    return _quota_cpus(quota.strip(), period.strip())


def _read_cgroup_file(p: Path) -> str | None:
    try:
        return p.read_text(encoding="utf-8")
    except (OSError, ValueError):  # absent here (the usual case), unreadable, or not text
        return None


def _quota_cpus(quota: str, period: str) -> int | None:
    try:
        q, p = int(quota), int(period)
    except ValueError:
        return None
    if q <= 0 or p <= 0:  # v1 writes -1 for "no quota"
        return None
    return -(-q // p)  # ceil: a 1.5-CPU quota still has two CPUs' worth of time to give


@dataclass
class GuardRunOutcome:
    """What the budgeted run produced — the same shape audit()'s in-process loop fills."""

    findings: list[Finding] = field(default_factory=list)
    ran: list[str] = field(default_factory=list)          # guards whose run() returned or raised
    errored: list[str] = field(default_factory=list)      # raised, or killed the child interpreter
    budget_exceeded: list[str] = field(default_factory=list)  # killed over the per-guard budget
    cap_notices: list[GitignoreCapNotice] = field(default_factory=list)  # child-side walk caps
    parse_candidates: ParseCandidates = field(default_factory=ParseCandidates)  # child-side, #1001
    fallback_inprocess: bool = False  # worker never started; the tail ran unbudgeted (disclosed)


# A guard tagged with its position in the caller's list. Lanes record every result against
# this position, never against `Guard.id`, so the merge can rebuild the caller's exact order
# even if two entries share an id (a test that registers one guard class twice).
type _Slot = tuple[int, Guard]


@dataclass
class _LaneOutcome:
    """One lane's results, keyed by `_Slot` position so `run_guards_budgeted` can merge every
    lane back into the caller's guard order (parallel output must equal serial output)."""

    findings: dict[int, list[Finding]] = field(default_factory=dict)
    ran: set[int] = field(default_factory=set)
    errored: set[int] = field(default_factory=set)
    budget_exceeded: set[int] = field(default_factory=set)
    cap_notices: list[GitignoreCapNotice] = field(default_factory=list)
    parse_candidates: ParseCandidates = field(default_factory=ParseCandidates)
    # Slots this lane gave up on after _MAX_STARTUP_ATTEMPTS consecutive startup failures.
    # The lane does NOT run them itself: in a parallel run it is a parent THREAD, and the
    # in-process loop must run on the caller's thread, inside the caller's run caches, and
    # never concurrently with another lane's fallback. The caller runs them after the join.
    fallback: list[_Slot] = field(default_factory=list)


class _LaneCancel:
    """The stop signal a parallel run shares across its lanes.

    Without it, an exception in the caller's thread (Ctrl-C) or in one lane left every other
    lane driving its child to completion, so the error surfaced only after the slowest lane
    finished, where a single lane stops at once (its `finally` kills its child). `cancel()`
    kills every tracked child; each lane, woken by its child's death, sees the flag and
    returns instead of reading the death as a guard crash and respawning.

    The lock closes the start-up race: a lane that starts a child after `cancel()` took its
    snapshot finds the flag set in `track()` and kills that child itself."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._set = False
        self._live: set[BaseProcess] = set()

    def is_set(self) -> bool:
        with self._lock:
            return self._set

    def track(self, proc: BaseProcess) -> bool:
        """Register a started child. False when the run is already cancelled: the caller
        must kill the child rather than wait on it."""
        with self._lock:
            if self._set:
                return False
            self._live.add(proc)
            return True

    def untrack(self, proc: BaseProcess) -> None:
        with self._lock:
            self._live.discard(proc)

    def cancel(self) -> None:
        with self._lock:
            self._set = True
            victims = list(self._live)
        for proc in victims:
            proc.kill()  # tolerated on an already-exited child; the lane's `finally` joins it


def _child_main(root: Path, profile: StackProfile, guards: list[Guard], conn: Connection,
                lanes: int = 1) -> None:
    """Child entry: run each guard under the per-run caches, streaming results per guard.

    The caches matter for parity, not just speed: without `walk_run()`/`derived_state_run()`
    (and `read_run()`, the per-path read memo `audit()` also opens, #597)
    the tree would be re-walked and every file re-derived once per guard — the #544
    regression class. The cap notices are captured INSIDE the walk context (exit clears
    them) and shipped last; if this child is later killed, the next child re-walks the same
    tree and re-trips the same caps, so notices are only lost when the final child dies —
    a run that already carries the loud budget-exceeded disclosure.

    Parse-failure candidates (#1001) travel the same way, so a killed child loses the ones its
    earlier guards recorded. Later guards usually re-parse the same files and re-record them,
    but nothing guarantees it. A kill already fails the gate and is disclosed loudly, so the
    run is never reported as complete either way."""
    share_parse_cache(lanes)  # this lane's share of the audit's parse-cache cap (astutil)
    try:
        with walk.walk_run(), derived_state_run(), read_run(), parse_failure_run():
            for g in guards:
                # INVARIANT the parent's retry bound relies on: nothing may block between
                # one guard's ("done", …) and the next guard's ("start", …). The parent
                # resets its consecutive-silent-children counter on every received message,
                # so a blocking point between sends would let repeated between-guard stalls
                # respawn once per stall — bounded only by list progress, not by
                # _MAX_STARTUP_ATTEMPTS (#821 follow-up review, Low-B).
                conn.send(("start", g.id))
                try:
                    found = g.run(root, profile)
                except Exception:  # noqa: BLE001 — mirror audit()'s guard contract (a crash never aborts)
                    conn.send(("done", g.id, [], True))
                else:
                    conn.send(("done", g.id, found, False))
            conn.send(("caps", walk.gitignore_cap_notices()))
            conn.send(("parse", parse_failure_candidates()))
        conn.send(("end",))
    finally:
        conn.close()


def _run_inprocess(slots: list[_Slot], root: Path, profile: StackProfile,
                   lane: _LaneOutcome) -> None:
    """The legacy unbudgeted loop, byte-for-byte audit()'s contract — the fallback when the
    worker itself fails to start (never the answer to a guard hang). Its caller sets
    `fallback_inprocess` so the lapsed hang protection is disclosed, never silent."""
    for pos, g in slots:
        try:
            lane.findings[pos] = g.run(root, profile)
        except Exception:  # noqa: BLE001
            lane.errored.add(pos)
        lane.ran.add(pos)


def _run_lane(root: Path, profile: StackProfile, slots: list[_Slot],
              budget: float, cancel: _LaneCancel | None = None, lanes: int = 1) -> _LaneOutcome:
    """Run one lane's guards through killable children (exactly one in the common case).

    The parent never blocks longer than `budget` between child messages, so a guard stuck
    in a C-level loop is killed for real — the interruption `signal`/threads cannot give.
    Startup failures get the bounded retry; past it the tail is handed back in
    `_LaneOutcome.fallback` for the caller to run in-process (see that field). A set
    `cancel` ends the lane early with partial results, which the caller then discards."""
    out = _LaneOutcome()
    remaining = list(slots)
    startup_failures = 0  # consecutive children lost before their first message
    while remaining:
        if cancel is not None and cancel.is_set():
            break
        recv_conn, send_conn = _CTX.Pipe(duplex=False)
        proc = _CTX.Process(
            target=_child_main, args=(root, profile, [g for _, g in remaining], send_conn, lanes),
            daemon=True,
        )
        proc.start()
        send_conn.close()  # the child holds the write end; ours must close for EOF to work
        idx = 0            # position in `remaining` the child is currently on
        started = False    # has ("start", …) arrived for remaining[idx] without its ("done", …)?
        ended = False
        # Until its first message, the child is in its startup phase (boot + imports +
        # unpickle) — machine cost, not guard cost, so it is judged against
        # _STARTUP_ALLOWANCE, never against the per-guard budget (the 2026-09-07 CI wedge).
        awaiting_first = True
        try:
            if cancel is not None and not cancel.track(proc):
                return out  # cancelled while this child was starting; the finally kills it
            while True:
                window = max(_STARTUP_ALLOWANCE, budget) if awaiting_first else budget
                try:
                    # Wait on the pipe AND the process sentinel. The pipe alone is not
                    # enough: on Windows, a child that dies before claiming its duplicated
                    # pipe handle (mid-unpickle — the startup-death shape) leaves the
                    # parent's DupHandle copy holding the write end open, so EOF never
                    # arrives and the death would be noticed only at window expiry. Two
                    # 60s windows of exactly that pushed the startup-death test past
                    # pytest-timeout on the 2026-09-07 Windows rerun and crashed the
                    # xdist worker. The sentinel observes the death itself, instantly,
                    # on every platform.
                    ready = _mp_wait([recv_conn, proc.sentinel], timeout=window)
                    if cancel is not None and cancel.is_set():
                        return out  # `cancel()` killed the child; not a guard crash
                    if proc.sentinel in ready and recv_conn not in ready:
                        # The child is dead and the pipe holds nothing — the same state a
                        # broken pipe reports where it CAN; route it to that branch.
                        raise EOFError
                    if not ready:
                        # Breach: no message for a full window. kill() (SIGKILL /
                        # TerminateProcess) is the point — no cleanup handler in the child
                        # can refuse it, unlike every signal-based scheme.
                        proc.kill()
                        proc.join(_KILL_GRACE)
                        if started:
                            out.budget_exceeded.add(remaining[idx][0])
                            remaining = remaining[idx + 1:]
                        else:
                            # The worker stalled before attributing work to any guard
                            # (spawn/import/unpickle stall). Blaming a guard would be a
                            # false diagnosis: retry the tail with a fresh child (bounded by
                            # _MAX_STARTUP_ATTEMPTS), then fall back to the legacy loop.
                            startup_failures += 1
                            if startup_failures < _MAX_STARTUP_ATTEMPTS:
                                remaining = remaining[idx:]
                            else:
                                out.fallback = remaining[idx:]
                                remaining = []
                        break
                    msg: tuple[Any, ...] = recv_conn.recv()
                except (EOFError, OSError):
                    # The child interpreter died without saying goodbye (segfault-class,
                    # os._exit). Attribute it to the in-flight guard as errored and carry on;
                    # a death BEFORE any message gets the same bounded retry as a stall.
                    proc.join(_KILL_GRACE)
                    if started:
                        out.errored.add(remaining[idx][0])
                        out.ran.add(remaining[idx][0])
                        remaining = remaining[idx + 1:]
                    else:
                        startup_failures += 1
                        if startup_failures < _MAX_STARTUP_ATTEMPTS:
                            remaining = remaining[idx:]
                        else:
                            out.fallback = remaining[idx:]
                            remaining = []
                    break
                startup_failures = 0  # the child spoke: the spawn machinery works
                awaiting_first = False
                if msg[0] == "start":
                    started = True
                elif msg[0] == "done":
                    _, gid, found, errored_flag = msg
                    pos, expected = remaining[idx]
                    if gid != expected.id:
                        # The child runs `remaining` strictly in order, so this is a protocol
                        # bug. Crash loudly rather than file findings under the wrong guard.
                        raise RuntimeError(f"guard worker out of step: got {gid!r}, "
                                           f"expected {expected.id!r}")
                    out.findings[pos] = found
                    out.ran.add(pos)
                    if errored_flag:
                        out.errored.add(pos)
                    idx += 1
                    started = False
                elif msg[0] == "caps":
                    out.cap_notices.extend(msg[1])
                elif msg[0] == "parse":
                    out.parse_candidates |= msg[1]
                elif msg[0] == "end":
                    proc.join(_KILL_GRACE)
                    remaining = []
                    ended = True
                    break
        finally:
            if cancel is not None:
                cancel.untrack(proc)
            recv_conn.close()
            if not ended and proc.is_alive():  # never leak a worker on an unexpected exit path
                proc.kill()
                proc.join(_KILL_GRACE)
    return out


def _run_lanes_concurrently(root: Path, profile: StackProfile, lanes: list[list[_Slot]],
                            budget: float) -> list[_LaneOutcome]:
    """Drive every lane from its own thread, failing as promptly as a single lane would.

    The first exception from any lane, or one raised in this thread while it waits (Ctrl-C),
    cancels the rest (`_LaneCancel`) and propagates. `FIRST_EXCEPTION` matters as much as the
    cancel: collecting results in lane order would block on lane 0 while lane 2's error sat
    unreported in its future."""
    cancel = _LaneCancel()
    pool = ThreadPoolExecutor(max_workers=len(lanes), thread_name_prefix="agentsec-guard-lane")
    try:
        futures = [pool.submit(_run_lane, root, profile, lane, budget, cancel, len(lanes)) for lane in lanes]
        done, _ = _futures_wait(futures, return_when=FIRST_EXCEPTION)
        for f in done:
            exc = f.exception()
            if exc is not None:
                raise exc
        return [f.result() for f in futures]
    except BaseException:
        cancel.cancel()
        raise
    finally:
        pool.shutdown(wait=True)  # prompt after a cancel: every lane returns once woken


def run_guards_budgeted(root: Path, profile: StackProfile, guards: list[Guard],
                        budget: float, workers: int = 1) -> GuardRunOutcome:
    """Run `guards` with a per-guard wall-clock `budget` (seconds), preemption included.

    `workers` > 1 deals the guards round-robin into that many lanes. Each lane is its own
    child process with its own budget clock, driven by a parent thread that only waits on
    pipes, so the threads never contend for the GIL. The guards' cost is spread flat (no
    guard was over 2% of the total on the flagship), which is why a static deal balances.
    Results are merged back into `guards` order, so a parallel run reports the same findings
    in the same order as a single-lane run."""
    slots: list[_Slot] = list(enumerate(guards))
    n = max(1, min(workers, len(slots)))
    lanes = [slots[i::n] for i in range(n)]
    if n == 1:
        results = [_run_lane(root, profile, lanes[0], budget)]
    else:
        results = _run_lanes_concurrently(root, profile, lanes, budget)

    merged = _LaneOutcome()
    for r in results:
        merged.findings.update(r.findings)
        merged.ran |= r.ran
        merged.errored |= r.errored
        merged.budget_exceeded |= r.budget_exceeded
        merged.cap_notices.extend(r.cap_notices)
        merged.parse_candidates |= r.parse_candidates
        merged.fallback.extend(r.fallback)

    # The in-process fallback below records into the CALLER's parse-failure run, which audit()
    # reads itself, so only the children's candidates travel in the outcome.
    out = GuardRunOutcome(cap_notices=merged.cap_notices, parse_candidates=merged.parse_candidates)
    if merged.fallback:
        # On the caller's thread and after every lane has joined: see `_LaneOutcome.fallback`.
        out.fallback_inprocess = True
        _run_inprocess(sorted(merged.fallback, key=lambda s: s[0]), root, profile, merged)
    for pos, g in slots:
        out.findings.extend(merged.findings.get(pos, ()))
        if pos in merged.ran:
            out.ran.append(g.id)
        if pos in merged.errored:
            out.errored.append(g.id)
        if pos in merged.budget_exceeded:
            out.budget_exceeded.append(g.id)
    return out
