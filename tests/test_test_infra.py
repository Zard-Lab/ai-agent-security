"""The suite's conftest fixtures still isolate, and its scheduling hook reorders only under worksteal.

Both fixtures were rewritten for speed: the corpus-cache root is made lazily instead of once per
test, and `tmp_path` uses `tempfile.mkdtemp` instead of pytest's numbered dirs, whose creation
lists the whole basetemp on every call. A speedup is only safe if it keeps what the fixtures
exist for, so this pins the direction traded against: a fresh, private dir per test, and a corpus
cache that can never be the developer's real one.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

import pytest

from agentsec import corpus
from tests.conftest import pytest_collection_modifyitems, pytest_configure_node, tmp_dir_prefix

if TYPE_CHECKING:
    from xdist.workermanage import WorkerController

# Captured at import, before any test's monkeypatch is active: the REAL cache location, which the
# autouse fixture must keep every test away from.
_REAL_CACHE_ROOT = corpus._corpus_cache_root

# Paths `tmp_path` handed out in this process. Under xdist the two tests below may land on
# different workers; each worker has its own basetemp, so sharing across workers is impossible
# by construction and the distinctness check only has work to do within one process.
_SEEN: list[Path] = []


def _check_fresh_tmp_path(tmp_path: Path, tmp_path_factory: pytest.TempPathFactory,
                          request: pytest.FixtureRequest) -> None:
    assert tmp_path.is_dir()
    assert not any(tmp_path.iterdir()), "tmp_path must start empty"
    assert tmp_path.parent == tmp_path_factory.getbasetemp()
    # Findable by test name, the way pytest's own numbered dirs are, and no longer than theirs
    # usually are (`<30 chars><N>`): every path a test builds under it inherits the length.
    assert tmp_path.name.startswith(tmp_dir_prefix(request.node.name))
    assert len(tmp_path.name) <= 31, tmp_path.name
    assert all(tmp_path != seen for seen in _SEEN), "two tests were handed the same tmp_path"
    (tmp_path / "marker").write_text("x", encoding="utf-8")
    _SEEN.append(tmp_path)


def test_tmp_path_is_a_fresh_private_dir_under_basetemp(
    tmp_path: Path, tmp_path_factory: pytest.TempPathFactory, request: pytest.FixtureRequest
) -> None:
    _check_fresh_tmp_path(tmp_path, tmp_path_factory, request)


def test_tmp_path_is_not_shared_with_the_previous_test(
    tmp_path: Path, tmp_path_factory: pytest.TempPathFactory, request: pytest.FixtureRequest
) -> None:
    # Same checks: if the previous test's dir were reused, its marker would make this one non-empty.
    _check_fresh_tmp_path(tmp_path, tmp_path_factory, request)


def test_corpus_cache_root_is_lazy_isolated_and_stable(tmp_path_factory: pytest.TempPathFactory) -> None:
    base = tmp_path_factory.getbasetemp()
    before = set(base.glob("corpus-cache-*"))

    root = corpus._corpus_cache_root()

    # Lazy: the dir is created by the first call, not by the fixture. An eager fixture would have
    # made it before this test body ran, so it would already be in `before`.
    assert set(base.glob("corpus-cache-*")) - before == {root}
    assert root.is_dir() and root.parent == base
    # Stable: one test sees one cache dir, however many times it asks.
    assert corpus._corpus_cache_root() == root
    assert set(base.glob("corpus-cache-*")) - before == {root}
    # Isolated: never the developer's real cache, nor anything inside it.
    real = _REAL_CACHE_ROOT()
    assert real != root and real not in root.parents


def test_corpus_consumers_reach_the_isolated_root() -> None:
    """The laziness is only equivalent if consumers CALL `_corpus_cache_root()` at use time; one
    that bound the path at import would bypass the fixture and prune the real cache. Exercise a
    real consumer with no `cache_root` and watch it act on the isolated dir."""
    root = corpus._corpus_cache_root()
    stale = root / "entry-without-marker"
    stale.mkdir()

    assert corpus.evict_stale_cache() == 1
    assert not stale.exists()


# --- run_first: the worksteal-only collection reorder ------------------------------------------

def _items(*names: str) -> list[pytest.Item]:
    """Stand-in items: a name, and a `run_first` marker on any name starting with "first"."""
    def item(name: str) -> SimpleNamespace:
        mark = pytest.mark.run_first.mark if name.startswith("first") else None
        return SimpleNamespace(name=name, get_closest_marker=lambda m: mark if m == "run_first" else None)
    return [cast(pytest.Item, item(n)) for n in names]


def _order(dist: str | None, items: list[pytest.Item]) -> list[str]:
    config = SimpleNamespace() if dist is None else SimpleNamespace(workerinput={"agentsec_dist": dist})
    pytest_collection_modifyitems(cast(pytest.Config, config), items)
    return [item.name for item in items]


def test_run_first_tests_lead_the_collection_under_worksteal() -> None:
    order = _order("worksteal", _items("a", "first-1", "b", "first-2", "c"))
    assert order == ["first-1", "first-2", "a", "b", "c"], "marked tests first, everything else in order"


@pytest.mark.parametrize("dist", ["load", "loadscope", "no", None], ids=["load", "loadscope", "no", "serial"])
def test_the_collection_order_is_untouched_under_any_other_scheduler(dist: str | None) -> None:
    # The traded-against direction: under `load` this move put the whole marked set on worker 0's
    # first chunk and lost (ci.yml's linux pytest comment), and a serial run has nothing to overlap.
    assert _order(dist, _items("a", "first-1", "b")) == ["a", "first-1", "b"]


def test_each_worker_is_told_the_controllers_scheduler() -> None:
    # Workers see `config.option.dist == "no"`, so the reorder only ever works through this channel.
    node = SimpleNamespace(workerinput={}, config=SimpleNamespace(getoption=lambda name: {"dist": "worksteal"}[name]))
    pytest_configure_node(cast("WorkerController", node))
    assert node.workerinput["agentsec_dist"] == "worksteal"
