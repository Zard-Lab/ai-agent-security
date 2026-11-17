"""Shared test helpers."""
from __future__ import annotations

import contextlib
import importlib.util
import os
import pickle
import re
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from importlib.abc import Loader
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING

import pytest

from agentsec.audit import AuditResult, audit
from agentsec.detect import StackProfile

if TYPE_CHECKING:
    from xdist.workermanage import WorkerController

_REPO = Path(__file__).resolve().parents[1]


def load_validator() -> ModuleType:
    """Import `scripts/validate-checklist.py` ONCE per session and return the module.

    Hyphenated filename, so it can't be imported by name — loaded by path, like
    `tests/test_doc_counts.py` does for `scripts/doc_counts.py`. The one-instance guarantee
    matters: `tests/test_standards_format.py` and `tests/test_validate_checklist.py` both use it,
    and `test_reflection_rule_is_not_forked` asserts function IDENTITY across the two (the
    reflection rule must not fork). A second `exec_module` would silently break that."""
    cached = sys.modules.get("validate_checklist")
    if cached is not None:
        return cached
    spec = importlib.util.spec_from_file_location(
        "validate_checklist", _REPO / "scripts" / "validate-checklist.py"
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["validate_checklist"] = mod  # register before exec so @dataclass resolves __module__
    _exec_guarded(spec.loader, mod, "validate-checklist.py")
    return mod


def _exec_guarded(loader: Loader, mod: ModuleType, name: str) -> None:
    """`exec_module`, but a refusal from the script's checkout guard fails cleanly (#701).

    Both `scripts/validate-checklist.py` and `scripts/doc_counts.py` refuse to run when
    `import agentsec` resolved to a different checkout than the script lives in, and they refuse by
    raising `SystemExit`. That is a `BaseException`, so pytest's collection machinery does not catch
    it and it reaches the top-level mainloop as `INTERNALERROR> ... SystemExit: 2` with no tests
    run. The developer who trips this is exactly the one the guard exists to help - working in a
    worktree whose interpreter resolves `agentsec` through an editable install pointing elsewhere -
    and pytest internals are a worse answer than the message the guard already wrote to stderr.

    This does NOT keep the rest of the suite running: a collection error still interrupts the run.
    Converting the shape is the whole point, so the reason is legible instead of buried."""
    try:
        loader.exec_module(mod)
    except SystemExit as exc:  # pragma: no cover - needs a genuinely mixed checkout to reach
        pytest.fail(
            f"{name} refused to load (exit {exc.code}); its reason is on stderr above. "
            "Usually: `agentsec` resolved to a different checkout than this one.",
            pytrace=False,
        )


@pytest.hookimpl(optionalhook=True)
def pytest_configure_node(node: WorkerController) -> None:
    """xdist, controller side: tell each worker which scheduler is dealing it tests.

    A worker's own `config.option.dist` is reset to "no" (`xdist/remote.py`), so this is the only
    way `pytest_collection_modifyitems` below can know the run is under `--dist worksteal`."""
    node.workerinput["agentsec_dist"] = node.config.getoption("dist")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Under `--dist worksteal`, move the `run_first` tests to the front of the collection.

    worksteal deals the collection out in contiguous ranges and steals from the TAIL of a busy
    worker's queue, so a test at the very front starts at once and the rest of that worker's range
    is stolen by the others while it runs. Collected where it sits, the self-audit test started
    near the end and ran alone for ~3 min with the other 7 workers idle (the Windows leg in ci.yml
    has the numbers). Under `--dist load` a front-loading move hands every marked test to worker
    0's first chunk with no stealing to rebalance it: a slow-tier-first hook measured 342s against
    241s there (ci.yml's linux pytest comment). So every other scheduler keeps the order as it is."""
    if getattr(config, "workerinput", {}).get("agentsec_dist") != "worksteal":
        return
    first = [item for item in items if item.get_closest_marker("run_first")]
    if first:
        items[:] = first + [item for item in items if not item.get_closest_marker("run_first")]


@pytest.fixture(autouse=True)
def _isolate_corpus_cache(tmp_path_factory: pytest.TempPathFactory,
                          monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the persistent corpus clone cache at a throwaway dir for every test.

    `corpus_scan()` runs an eviction pass over `_corpus_cache_root()` whenever `use_cache` is set,
    and several tests call it without overriding the cache root. Without this guard, running the
    suite would silently prune a developer's real `~/.cache/agentsec/corpus-repos`. Redirecting the
    root here makes that impossible by construction, for this and any future test.

    The dir is made LAZILY, on the first call, and the same one is returned for the rest of the
    test. An eager `tmp_path_factory.mktemp()` here created one dir per test for the whole suite,
    and pytest's numbered-dir scheme lists the entire basetemp on every `mktemp()` to pick the next
    suffix, so every test paid a cost that grew with the suite, corpus user or not. Isolation
    is unchanged: each test that asks still gets a fresh dir under basetemp, never the real cache.
    It holds because every consumer CALLS `_corpus_cache_root()` at use time (a module-global
    lookup the monkeypatch reaches); `tests/test_test_infra.py` pins it."""
    base = tmp_path_factory.getbasetemp()
    made: list[Path] = []

    def fake_root() -> Path:
        if not made:
            made.append(Path(tempfile.mkdtemp(prefix="corpus-cache-", dir=base)))
        return made[0]

    monkeypatch.setattr("agentsec.corpus._corpus_cache_root", fake_root)


@dataclass(frozen=True)
class SharedAudit:
    """One `audit(run_scanners=False)` of a generated repo, computed once per test SESSION.

    `load()` hands every caller its OWN deep copy (a fresh unpickle), so no consumer can mutate
    what another reads. The audit itself is never shared with a test that asserts run-to-run
    determinism: those keep their own second, fresh run."""
    blob: bytes

    def load(self) -> AuditResult:
        result = pickle.loads(self.blob)
        assert isinstance(result, AuditResult)
        return result


# How long a worker waits for ANOTHER worker's in-flight shared audit before computing its own.
# The audit is ~3.5s on idle Linux and 16-31s on winci under 8-way contention (2026-10-23); the
# wait plus a fallback compute must fit inside one test's 120s `timeout` (pyproject.toml), since
# both run in the waiting test's setup.
_SHARED_WAIT_S = 60.0


def _session_shared(
    tmp_path_factory: pytest.TempPathFactory, name: str, compute: Callable[[], AuditResult]
) -> SharedAudit:
    """`compute()` once per session, shared across xdist workers through the session's basetemp root.

    Under xdist every worker's basetemp is `<session root>/popen-gwN`, and the controller creates
    that root fresh for each run; the blob and lock names also carry xdist's per-run id
    (`PYTEST_XDIST_TESTRUNUID`), so a blob found there was written by THIS run's code even if the
    root were ever reused. The first worker to need it takes an `O_EXCL` lock file, computes, and
    publishes atomically (`os.replace`); a worker that finds the lock taken waits for the blob
    instead of computing a duplicate (two racing computes were measured on every local A/B round
    before the lock). The wait is fail-SAFE, never fail-open: if the builder dies (a timeout kill
    takes the whole worker on Windows), its compute raises, or its publish fails, the lock is
    released (or, for a dead builder, the wait runs out) and the waiter computes its own copy,
    which costs what not sharing did. A torn blob cannot be read - only a complete file is ever
    renamed into place - and a corrupt one raises in `pickle.loads`, an error rather than a pass.
    Outside xdist (`getbasetemp().parent` is then shared across sessions) nothing touches the disk."""
    worker = os.environ.get("PYTEST_XDIST_WORKER")
    if worker is None:
        return SharedAudit(pickle.dumps(compute()))
    run = os.environ.get("PYTEST_XDIST_TESTRUNUID", "run")
    root = tmp_path_factory.getbasetemp().parent
    blob = root / f"shared-{name}-{run}.pickle"
    lock = root / f"shared-{name}-{run}.lock"
    try:
        return SharedAudit(blob.read_bytes())
    except OSError:
        pass
    holder = False
    try:
        os.close(os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
        holder = True
    except FileExistsError:
        deadline = time.monotonic() + _SHARED_WAIT_S
        while time.monotonic() < deadline:
            try:
                return SharedAudit(blob.read_bytes())
            except OSError:  # not published yet, or (Windows) mid-replace
                pass
            if not lock.exists():  # the builder gave up (its compute or publish failed): compute our own
                break
            time.sleep(0.1)
    published = False
    try:
        data = pickle.dumps(compute())
        tmp = blob.with_name(f"{blob.name}.{worker}.tmp")
        tmp.write_bytes(data)
        with contextlib.suppress(OSError):  # Windows: a reader holds the target open, or a scanner the tmp
            os.replace(tmp, blob)
        published = blob.exists()
    finally:
        if holder and not published:  # nobody else will publish: stop the waiters waiting it out
            with contextlib.suppress(OSError):
                lock.unlink()
    return SharedAudit(data)


@pytest.fixture(scope="session")
def canary_audit(tmp_path_factory: pytest.TempPathFactory) -> SharedAudit:
    """The liveness canary's `audit()`, once per session (see `_session_shared`)."""
    from agentsec.canary import write_canary_repo

    def compute() -> AuditResult:
        root = Path(tempfile.mkdtemp(prefix="shared-canary-", dir=tmp_path_factory.getbasetemp()))
        return audit(write_canary_repo(root), run_scanners=False)

    return _session_shared(tmp_path_factory, "canary-audit", compute)


@pytest.fixture(scope="session")
def clean_canary_audit(tmp_path_factory: pytest.TempPathFactory) -> SharedAudit:
    """The clean canary's `audit()`, once per session (see `_session_shared`)."""
    from agentsec.clean_canary import write_clean_canary_repo

    def compute() -> AuditResult:
        root = Path(tempfile.mkdtemp(prefix="shared-clean-canary-", dir=tmp_path_factory.getbasetemp()))
        return audit(write_clean_canary_repo(root), run_scanners=False)

    return _session_shared(tmp_path_factory, "clean-canary-audit", compute)


def tmp_dir_prefix(test_name: str) -> str:
    """The name prefix of a test's `tmp_path`: pytest's own sanitising rule, cut to 22 chars.

    22, not pytest's 30: `mkdtemp` appends 8 random chars where pytest appends a short counter,
    so 22 + "-" + 8 keeps the dir name no longer than the built-in's usual `<30 chars><N>`. Every
    path a test builds under `tmp_path` inherits this length, and Windows MAX_PATH is a hard
    ceiling some tests already run close to (see `test_walk_deep_tree_does_not_hit_recursion_limit`)."""
    return re.sub(r"[\W]", "_", test_name)[:22] + "-"


@pytest.fixture
def tmp_path(request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory) -> Path:
    """pytest's `tmp_path`, created in O(1) instead of O(dirs already in basetemp).

    The built-in names its dir `<test name><N>` and finds `N` by listing the whole basetemp on
    every call (`_pytest.pathlib.make_numbered_dir`), so the suite's tmp-dir cost grows with the
    square of the tests in one process. `tempfile.mkdtemp` picks a random unique name instead.

    What is kept: the dir is fresh, empty, mode 0o700 and under the same basetemp, so it rotates
    out with the session like the built-in's (`tmp_path_retention_count`), and its name still
    starts with the sanitised test name (`tmp_dir_prefix`) so a failing test's dir is findable.
    Under xdist each worker has its own basetemp, and `mkdtemp` names are unique regardless.
    What is not: `tmp_path_retention_policy` is not consulted; every dir is kept, which is the
    built-in's default policy (`all`) and the one this project runs with."""
    return Path(tempfile.mkdtemp(prefix=tmp_dir_prefix(request.node.name), dir=tmp_path_factory.getbasetemp()))


def mkprofile(root: Path, **overrides: object) -> StackProfile:
    """Build a StackProfile for a tmp fixture root with explicit overrides.

    Guards key off `features` + the dir fields, so tests set just those.
    """
    prof = StackProfile(root=root)
    for k, v in overrides.items():
        setattr(prof, k, v)
    return prof


# The head of a real schema dump, which `sql_state.find_dumps` requires on top of a dump-like name
# (#1037): pg_dump's session preamble, as `supabase db dump` writes it, with no pg_dump banner (the
# flagship's shape). Prepend it to a planted `schema-snapshot.sql` that should supersede anything:
# a dump-named file without it reads as hand-written and supersedes nothing. It adds
# `PG_DUMP_HEAD_LINES` lines, so a line number in the dump is that plus its line in the body.
PG_DUMP_HEAD = (
    "SET statement_timeout = 0;\n"
    "SET lock_timeout = 0;\n"
    "SET idle_in_transaction_session_timeout = 0;\n"
    "SET client_encoding = 'UTF8';\n"
    "SET standard_conforming_strings = on;\n"
    "SELECT pg_catalog.set_config('search_path', '', false);\n"
    "SET check_function_bodies = false;\n"
    "SET xmloption = content;\n"
    "SET client_min_messages = warning;\n"
    "SET row_security = off;\n"
)
PG_DUMP_HEAD_LINES = PG_DUMP_HEAD.count("\n")
