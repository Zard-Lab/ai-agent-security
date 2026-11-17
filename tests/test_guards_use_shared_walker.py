"""Drift gate: no guard may enumerate files with its own recursive walk (#1042).

Every guard lists files through the shared walker (`agentsec/walk.py::walk_files`, reached via
``guards/base.py::iter_files`` / ``iter_files_named``). The walker is the one place that owns the
exclude policy: ``DEFAULT_EXCLUDE_DIRS`` (``.venv``, ``site-packages``, ``node_modules``, ``.git`` ...),
nested git worktrees, ``.gitignore`` and the never-follow-a-symlink rule. A bare ``Path.rglob`` honours
none of it, so a guard that uses one descends into every vendored tree under its root.

Measured on #1042: ``ssrf-dns-rebind-toctou`` read and parsed 50,147 site-packages files (273s) on a
working tree with per-component venvs and was killed over its 60s budget, scan PARTIAL. Where the venv
was small enough to finish, it and the MCP guards raised HIGH/CRITICAL findings anchored in
``.venv/.../site-packages/``. 98a05a1f (2026-06-23) had already moved 7 guards off ``rglob``, but with no
gate, and new guards re-copied the idiom within three months. Per-guard tests never catch it: a tmp
fixture has no ``.venv`` for the guard to wander into. This gate looks at the code shape instead.

THE SHAPE. A call, in any module under ``agentsec/guards/``, that walks a directory tree recursively on
its own: ``<x>.rglob(...)``, ``<x>.glob("**...")`` / ``glob.iglob("**...")`` (pattern positional or
keyword), ``os.walk(...)``, or ``Path.walk()`` (any ``.walk(`` whose receiver is not the ``ast`` module).
A single-level ``glob("*.yml")`` is bounded and allowed.

WHAT IT CANNOT SEE. It is a tripwire for the copied idiom, not a proof. It misses a bare-name call
(``from os import walk``), a pattern built at runtime (``root.glob(f"**/{n}")``, a variable), an aliased
method (``w = root.rglob``) and hand-rolled ``os.scandir`` recursion, and it would wrongly flag
``import ast as a; a.walk(t)``. No guard does any of these today; review still owns them.

No pin. #1042 moved every site, so there is no legacy set to drain. The floor below proves the walk
still sees the guard population, so a detector that went blind cannot report clean.
"""
from __future__ import annotations

import ast
import functools
from pathlib import Path

import pytest

from agentsec.astutil import safe_ast_parse

_GUARDS = Path(__file__).resolve().parent.parent / "agentsec" / "guards"


def _guard_modules() -> list[Path]:
    """Every guard module: the single population both the gate and the floor draw from."""
    return sorted(p for p in _GUARDS.glob("*.py") if p.name != "__init__.py")


def _is_recursive_glob(call: ast.Call) -> bool:
    """A string-literal argument, positional or keyword (``pattern=``), that contains ``**``."""
    return any(
        isinstance(v, ast.Constant) and isinstance(v.value, str) and "**" in v.value
        for v in (*call.args, *(kw.value for kw in call.keywords))
    )


def _bypass_calls_in_source(src: str, filename: str) -> set[str]:
    """``line N: <call>`` for each self-made recursive walk in one source string."""
    tree = safe_ast_parse(src, filename)
    if tree is None:  # a guard that will not parse is its own loud failure, never a silent skip
        return {f"<unparseable: {filename}>"}
    out: set[str] = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        attr, receiver = node.func.attr, node.func.value
        if (
            attr == "rglob"
            or (attr in ("glob", "iglob") and _is_recursive_glob(node))
            or (attr == "walk" and not (isinstance(receiver, ast.Name) and receiver.id == "ast"))
        ):
            out.add(f"line {node.lineno}: {ast.unparse(node)}")
    return out


@functools.cache
def _bypass_sites() -> frozenset[tuple[str, str]]:
    """Every (module stem, ``line N: <call>``) across ``agentsec/guards/`` that walks on its own.

    Cached: two tests read it, and parsing every guard module is the whole cost of this file.
    """
    return frozenset(
        (path.stem, site)
        for path in _guard_modules()
        for site in _bypass_calls_in_source(path.read_text(encoding="utf-8"), path.name)
    )


def test_no_guard_walks_the_tree_without_the_shared_walker() -> None:
    """The gate. A new ``rglob`` / ``glob("**")`` / ``os.walk`` / ``Path.walk`` in a guard fails here."""
    sites = sorted(_bypass_sites())
    assert not sites, (
        "guard(s) enumerate files with their own recursive walk, which skips DEFAULT_EXCLUDE_DIRS, "
        "nested worktrees and .gitignore and so descends into .venv/site-packages/node_modules "
        "(#1042). Use `iter_files(d, (\".py\",))`, `iter_files_named(root, \"<glob>\")` or "
        "`walk_files(root)`; pass `respect_gitignore=False` where the old walk had to see gitignored "
        "files (a secret, a local settings file, a data corpus):\n"
        + "\n".join(f"  agentsec/guards/{mod}.py {site}" for mod, site in sites)
    )


def test_the_gate_sees_the_population_it_claims_to() -> None:
    """A walk that went blind would pass the gate forever. The floor sits well below the live count.

    Counts over the same ``_guard_modules()`` the gate scans. A detector that stopped recognising the
    shape is caught by ``test_detector_discriminates`` below.
    """
    modules = _guard_modules()
    assert len(modules) >= 250, f"only {len(modules)} guard modules walked: has the gate gone blind?"


# The detector's own behaviour, through the SAME `_bypass_calls_in_source` the gate uses.
@pytest.mark.parametrize(
    ("src", "bypasses"),
    [
        ('for f in d.rglob("*.py"):\n    pass\n', True),
        ('files = list(root.rglob(".claude"))\n', True),
        ('for p in root.glob("**/*.json"):\n    pass\n', True),
        ('for p in root.glob(pattern="**/*.json"):\n    pass\n', True),  # keyword pattern
        ('import glob\nfor p in glob.iglob("**/*.py", recursive=True):\n    pass\n', True),
        ("import os\nfor dp, dn, fn in os.walk(root):\n    pass\n", True),
        ("for dp, dn, fn in root.walk():\n    pass\n", True),
        ('for f in iter_files(d, (".py",)):\n    pass\n', False),
        ('for f in iter_files_named(root, "*", respect_gitignore=False):\n    pass\n', False),
        ("for node in ast.walk(tree):\n    pass\n", False),
        ('for p in wf.glob("*.yml"):\n    pass\n', False),  # one level: bounded, allowed
        ('"""Use this instead of `root.rglob(<pattern>)`."""\n', False),  # a mention, not a call
    ],
)
def test_detector_discriminates(src: str, bypasses: bool) -> None:
    assert bool(_bypass_calls_in_source(src, "<inline>")) is bypasses


def test_unparseable_guard_is_surfaced_not_skipped() -> None:
    """A guard that will not parse must fail loudly, never be silently dropped (Rule 3)."""
    found = _bypass_calls_in_source("def run(:\n    pass\n", "broken.py")
    assert found and "unparseable" in next(iter(found))
