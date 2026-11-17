from __future__ import annotations

from agentsec.guards.background_tasks import BackgroundTasksGuard
from tests.guards._common import *  # noqa: F401,F403


def test_background_tasks_flags_bare_unmarked(tmp_path: Path) -> None:
    (tmp_path / "m.py").write_text("import asyncio\nasyncio.create_task(do())\n", encoding="utf-8")
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = BackgroundTasksGuard().run(tmp_path, prof)
    assert len(findings) == 1 and findings[0].severity == "low"

def test_background_tasks_passes_marked_and_stored(tmp_path: Path) -> None:
    (tmp_path / "m.py").write_text(
        "import asyncio\n"
        "asyncio.create_task(do())  # background-safe: handles own exc\n"
        "task = asyncio.create_task(other())\n"
        "await asyncio.create_task(third())\n", encoding="utf-8"
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert BackgroundTasksGuard().run(tmp_path, prof) == []

def test_background_tasks_skips_nonproduct_path(tmp_path: Path) -> None:
    # T2b: now consults is_nonproduct_path — a bare spawn under tests/ is offline tooling, not served.
    sub = tmp_path / "tests"
    sub.mkdir()
    (sub / "m.py").write_text("import asyncio\nasyncio.create_task(do())\n", encoding="utf-8")
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert BackgroundTasksGuard().run(tmp_path, prof) == []
    # but an opt-in archive tree only skips when configured (archive_segments threaded)
    ev = tmp_path / "evals"
    ev.mkdir()
    (ev / "seed.py").write_text("import asyncio\nasyncio.create_task(do())\n", encoding="utf-8")
    assert len(BackgroundTasksGuard().run(tmp_path, prof)) == 1  # evals/ NOT skipped by default
    prof_optin = mkprofile(tmp_path, features={"python"}, python_dirs=["."],
                           archive_segments=frozenset({"evals"}))
    assert BackgroundTasksGuard().run(tmp_path, prof_optin) == []  # skipped once opted in

