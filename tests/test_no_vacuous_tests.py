"""Drift gate: no ``test_*`` function may be vacuous — docstring-only or otherwise empty (#797).

A ``test_*`` whose body contains no statement other than a docstring asserts nothing, yet pytest
collects it and it "passes" unconditionally. A green suite therefore says nothing about it. That is
CLAUDE.md Rule 3's "a failure that presents as success", turned on the tests themselves, and it has
already silently disabled real regression guards **twice** — both times when a hand-resolved
conflict merge of a shared test file shifted a docstring off its ``def``, orphaning the body:

  * ``65c7d211`` (the #792<->#793 merge) emptied four bodies in
    ``tests/guards/test_agent_loop_circuit_breaker.py``, including the #778 ``channel_name.poll()``
    HIGH regression guard. Found and repaired in PR #795 (#794).
  * ``de6ec312`` emptied ``test_escaped_apostrophe_does_not_let_a_router_steal_the_next_prefix`` in
    ``tests/guards/test_auth_dependency_not_applied.py`` — the regression guard for a Critical
    FAIL-OPEN auth bypass. Restored alongside this gate (#797).

A green ``-n 2`` suite reported success through both, and the #792 trajectory review counted
``def test_`` functions and grepped their names and concluded "nothing dropped" while four bodies
were gone: a name/count check cannot see a body that swapped places. This gate looks at the body.

WHY THE SIGNAL IS "DOCSTRING-ONLY", NOT "HAS NO ``assert`` STATEMENT". The naive form is unusable:
across this suite it flags dozens of legitimate tests whose assertion is a ``pytest.raises(...)``
context, a mock ``.assert_called_once()`` / ``.assert_not_called()``, an ``assert_within``-style
helper, or a "must not raise / must parse" smoke check (exception-absence IS the assertion). The
docstring-only / zero-statement form has zero false positives on the shipping suite, which is why
this gate needs no allowlist. A bare ``pass`` body is deliberately NOT flagged: the recurrence
mechanism (a merge orphaning a body) always leaves the *docstring* behind, so docstring-only is the
precise shape, and a ``pass`` body is a visible, deliberate act rather than this accident.

WHY ASSERT THE ARTIFACT. The gate asserts the offender LIST is empty (Rule 3): a check that only
runs, or that asserts an exit code, is itself the failure class it polices.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from agentsec.astutil import safe_ast_parse

_TESTS = Path(__file__).resolve().parent


def _test_files() -> list[Path]:
    """Every ``test_*.py`` under ``tests/`` — the single population BOTH gates below draw from.

    The gate (``_vacuous_tests``) and the anti-blind-spot floor
    (``test_the_gate_sees_the_population_it_claims_to``) MUST list files through here, exactly as
    ``test_blank_run_anchors.py``'s floor shares ``_iter_multiline_patterns()`` with its gate. If the
    floor re-implements its own walk, a regression in the gate's discovery (e.g. ``.rglob`` -> ``.glob``,
    which silently stops recursing into ``tests/guards/`` — where both real casualties lived) leaves the
    floor untouched and green, defeating the one blind-spot class the floor exists to catch (#798 review).
    """
    return sorted(_TESTS.rglob("test_*.py"))


def _is_docstring_expr(stmt: ast.stmt) -> bool:
    """A bare-constant expression statement: a docstring, or an ``...`` / stray-literal body.

    Matches the issue's detector exactly — every ``ast.Expr`` wrapping an ``ast.Constant``. This
    deliberately treats a lone ``...`` (Ellipsis is a Constant) as vacuous too, and does not depend
    on the string being the *first* statement, so a body that is only string-expressions still
    counts as empty.
    """
    return isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant)


def _vacuous_in_source(src: str, filename: str) -> list[tuple[int, str]]:
    """Every vacuous ``test_*`` function in one source string, as ``(lineno, name)``.

    A function is vacuous when, after dropping docstring/bare-constant statements, its body is
    empty. Both ``def`` and ``async def`` are inspected, at any nesting depth.
    """
    tree = safe_ast_parse(src, filename)
    if tree is None:  # a test file that will not parse is its own loud failure, never a silent skip
        return [(0, f"<unparseable: {filename}>")]
    out: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        if not node.name.startswith("test_"):
            continue
        if not any(not _is_docstring_expr(stmt) for stmt in node.body):
            out.append((node.lineno, node.name))
    return out


def _vacuous_tests() -> list[tuple[str, int, str]]:
    """Every vacuous ``test_*`` across ``tests/**/test_*.py``, as ``(relpath, lineno, name)``."""
    out: list[tuple[str, int, str]] = []
    for path in _test_files():
        rel = path.relative_to(_TESTS).as_posix()
        for lineno, name in _vacuous_in_source(path.read_text(encoding="utf-8"), rel):
            out.append((rel, lineno, name))
    return out


def test_no_vacuous_test_functions() -> None:
    """The gate. A ``test_*`` whose body is only a docstring fails here the moment a merge empties it."""
    offenders = _vacuous_tests()
    assert not offenders, (
        "vacuous test function(s) — a docstring-only/empty body that asserts nothing and 'passes' "
        "unconditionally (#797). A conflict merge most likely orphaned the body; recover it from the "
        "commit that introduced it:\n"
        + "\n".join(f"  {rel}:{lineno} {name}" for rel, lineno, name in offenders)
    )


def test_the_gate_sees_the_population_it_claims_to() -> None:
    """A detector that silently stopped finding test functions would pass the gate above forever.

    The same anti-blind-spot guard ``test_blank_run_anchors.py`` puts on its own sweep. Floors are
    well below the live counts so ordinary growth/pruning never trips them, but a walk that has gone
    blind (parses nothing, or stops recognising ``test_*``) fails loudly instead of reporting clean.
    It counts over the SAME ``_test_files()`` the gate scans, so a regression in file discovery trips
    here too — that shared population is the whole point (#798 review).
    """
    files = 0
    funcs = 0
    for path in _test_files():
        files += 1
        tree = safe_ast_parse(path.read_text(encoding="utf-8"), path.name)
        if tree is None:  # unparseable: the gate lists it as an offender; it adds 0 functions here
            continue
        funcs += sum(
            isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef) and n.name.startswith("test_")
            for n in ast.walk(tree)
        )
    assert files >= 300, f"only {files} test files walked — has the gate gone blind?"
    assert funcs >= 5000, f"only {funcs} test_* functions seen — has the detector gone blind?"


def test_test_files_recurses_into_subdirectories() -> None:
    """Pin the recursion the shared discovery depends on. A ``.rglob`` -> ``.glob`` slip on
    ``_test_files()`` silently drops ``tests/guards/`` (where both real casualties lived). Because the
    gate AND the floor both list through ``_test_files()``, that slip trips the floor (``files < 300``)
    instead of passing green; this pins it directly as well (#798 review)."""
    listed = {p.relative_to(_TESTS).as_posix() for p in _test_files()}
    assert "guards/test_auth_dependency_not_applied.py" in listed  # a known nested test file
    assert any("/" in rel for rel in listed), "no nested test files listed — discovery stopped recursing"


# The detector's own behaviour, exercised through the SAME `_vacuous_in_source` the gate uses, so a
# detector that stopped working cannot pass here while the gate above silently reports clean.
_DOCSTRING_ONLY = 'def test_x():\n    """only a docstring, no body"""\n'
_ELLIPSIS_ONLY = "def test_x():\n    ...\n"
_EMPTY_ASYNC = 'async def test_x():\n    """orphaned async body"""\n'
_REAL_BODY = 'def test_x():\n    """doc"""\n    assert 1 == 1\n'
_MOCK_ASSERT = 'def test_x():\n    """doc"""\n    m.assert_called_once()\n'  # exception-absence style
_RAISES_SMOKE = 'def test_x():\n    """doc"""\n    with pytest.raises(ValueError):\n        f()\n'
_PASS_ONLY = 'def test_x():\n    """doc"""\n    pass\n'  # deliberately NOT flagged (see module docstring)
_NON_TEST = 'def helper():\n    """docstring-only, but not a test"""\n'
_NESTED = 'def outer():\n    def test_inner():\n        """orphaned nested body"""\n'
# A skip-decorated docstring-only stub IS flagged: the detector reads the body, not decorators, and
# the recurrence mechanism (a merge orphaning a body) never touches a skip stub. Recorded, not
# special-cased (#798 review): a deliberate stub should carry a real body or an explicit `pass`.
_SKIP_DECORATED = '@pytest.mark.skip(reason="later")\ndef test_x():\n    """not implemented yet"""\n'


@pytest.mark.parametrize(
    ("src", "vacuous"),
    [
        (_DOCSTRING_ONLY, True),
        (_ELLIPSIS_ONLY, True),  # a lone `...` is a bare Constant, so it counts as empty
        (_EMPTY_ASYNC, True),  # `async def` is inspected too
        (_NESTED, True),  # any nesting depth
        (_REAL_BODY, False),
        (_MOCK_ASSERT, False),  # a mock-assert call IS a non-docstring statement
        (_RAISES_SMOKE, False),  # a `pytest.raises` smoke check IS a statement
        (_PASS_ONLY, False),  # `pass` is a statement, and out of scope by design
        (_NON_TEST, False),  # a non-`test_*` function is never flagged
        (_SKIP_DECORATED, True),  # decorators are not read; a skip stub with only a docstring is flagged
    ],
)
def test_detector_discriminates(src: str, vacuous: bool) -> None:
    assert bool(_vacuous_in_source(src, "<inline>")) is vacuous


def test_unparseable_test_file_is_surfaced_not_skipped() -> None:
    """A test file that will not parse must fail loudly, never be silently dropped (Rule 3)."""
    found = _vacuous_in_source("def test_x(:\n    pass\n", "broken.py")
    assert found and "unparseable" in found[0][1]
