"""Tests for the cross-module import-closure reachability signal (exclude advisor)."""
from __future__ import annotations

from pathlib import Path

from agentsec.reachability import _imports, app_reachable_files, unreachable_dirs
from tests.conftest import mkprofile


def _prof(root: Path):  # type: ignore[no-untyped-def]
    return mkprofile(root, features={"python", "fastapi"}, python_dirs=["."])


def _w(p: Path, body: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


def test_imports_survives_deep_binop_chain(tmp_path: Path) -> None:
    # H12: a hostile deep binary-op chain makes ast.parse raise RecursionError (a
    # RuntimeError subclass, not caught by the old (SyntaxError, ValueError) tuple).
    # _imports must degrade to an empty set, never propagate the crash out of audit.
    deep = "1" + "+1" * 50000
    assert _imports(tmp_path / "x.py", deep, {}, set()) == set()


def test_imports_survives_deeply_nested_unary_memoryerror(tmp_path: Path) -> None:
    # #370: a deeply nested unary makes ast.parse raise MemoryError ("Parser stack overflowed"),
    # which the old tuple didn't catch. Now routed through safe_ast_parse -> degrade to empty set
    # (and even if this depth parses on some version, the expression has no imports -> set()).
    deep = "x = " + "-" * 7000 + "1\n"
    assert _imports(tmp_path / "x.py", deep, {}, set()) == set()


def test_served_closure_includes_app_excludes_evals(tmp_path: Path) -> None:
    _w(tmp_path / "app" / "main.py", "from fastapi import FastAPI\nfrom app.routes import r\napp = FastAPI()\n")
    _w(tmp_path / "app" / "routes.py", "from app.db import q\nr = 1\n")
    _w(tmp_path / "app" / "db.py", "q = 2\n")
    _w(tmp_path / "evals" / "seed.py", "import asyncio\nasyncio.run(1)\n")  # never imported by app
    _w(tmp_path / "evals" / "judge.py", "x = 1\n")

    reachable = app_reachable_files(tmp_path, _prof(tmp_path))
    names = {f.relative_to(tmp_path).as_posix() for f in reachable}
    assert names == {"app/main.py", "app/routes.py", "app/db.py"}

    unreach = unreachable_dirs(tmp_path, _prof(tmp_path))
    assert "evals" in unreach
    assert "app" not in unreach


def test_relative_imports_resolved(tmp_path: Path) -> None:
    _w(tmp_path / "svc" / "app.py", "from fastapi import FastAPI\nfrom . import handlers\napp = FastAPI()\n")
    _w(tmp_path / "svc" / "handlers.py", "from .util import helper\n")
    _w(tmp_path / "svc" / "util.py", "def helper(): ...\n")
    _w(tmp_path / "tools" / "oneoff.py", "print('not served')\n")

    reachable = {f.relative_to(tmp_path).as_posix() for f in app_reachable_files(tmp_path, _prof(tmp_path))}
    assert reachable == {"svc/app.py", "svc/handlers.py", "svc/util.py"}
    assert "tools" in unreachable_dirs(tmp_path, _prof(tmp_path))


def test_no_entrypoint_means_no_signal(tmp_path: Path) -> None:
    # A repo with no served entrypoint yields an empty closure -> no reachability signal (don't guess).
    _w(tmp_path / "lib" / "a.py", "x = 1\n")
    _w(tmp_path / "lib" / "b.py", "y = 2\n")
    assert app_reachable_files(tmp_path, _prof(tmp_path)) == set()
    assert unreachable_dirs(tmp_path, _prof(tmp_path)) == set()


def test_served_evals_endpoint_is_reachable(tmp_path: Path) -> None:
    # The robustness case: an `evals/` dir that IS imported by the app must NOT look unreachable.
    _w(tmp_path / "app" / "main.py", "from fastapi import FastAPI\nimport app.evals.endpoint\napp = FastAPI()\n")
    _w(tmp_path / "app" / "evals" / "__init__.py", "")
    _w(tmp_path / "app" / "evals" / "endpoint.py", "def route(): ...\n")

    assert "app/evals" not in unreachable_dirs(tmp_path, _prof(tmp_path))


def test_syntax_error_file_skipped(tmp_path: Path) -> None:
    _w(tmp_path / "main.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    _w(tmp_path / "broken" / "x.py", "def (((\n")  # unparseable — must not raise
    # should not raise; broken/ is just unreachable
    assert "broken" in unreachable_dirs(tmp_path, _prof(tmp_path))
