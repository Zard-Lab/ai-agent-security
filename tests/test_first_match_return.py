"""Drift gate: no guard may return its first finding from inside an all-files loop (#425).

A guard's ``_check_*`` helper that loops over every scanned file and does ``return [Finding(...)]``
on the first match caps its rule at ONE finding repo-wide. Every later violation, in that file or any
other, is never evaluated. Worse than an undercount: findings are suppressed AFTER the guard runs, so
one exception or baseline entry on the single reported instance hides every other instance of the
rule, and the audit comes back clean. That is CLAUDE.md Rule 3's "a failure that presents as success".

#425 fixed 14 such rules in 7 guards (16 return sites). Every one was original authoring, copied
sibling to sibling, and the idiom was re-copied at least once after the issue was filed (plugin-security
PLG008). A one-violation fixture cannot tell "fires per sink" from "fires once", so per-guard tests
never caught it. This gate looks at the code shape instead.

THE SHAPE. A ``return`` of a non-empty list literal, inside a loop, inside a function in
``agentsec/guards/``, where the function's OUTERMOST loop iterates a file collection (its iterable's
source mentions ``files`` / ``iter_files`` / ``python_scan_dirs`` / ``manifest`` / ``glob`` ...). The
outermost-loop test is what separates a repo-wide cap from a per-file helper, whose loop runs over one
file's lines and whose early return is ordinary per-file dedup.

THE PINNED REMAINDER. ``_DOCUMENTED_FIRE_ONCE`` holds the sites that still have the shape on purpose:
documented and test-locked as one finding per rule since each guard was authored (#425's "Group B"),
plus guardrail-architecture's absence-type ``no-external-guardrail`` (one finding per project is the
whole claim). Whether the per-sink ones should stay fire-once is an open product decision, not settled
here. The set may only SHRINK: a new site fails the gate, and a pinned site that loses the shape fails
the second test until its entry is removed, so the pin never outlives the code it excuses.

WHY ASSERT THE ARTIFACT. Both tests assert a set difference is empty, and the floor below proves the
walk still sees the guard population, so a detector that went blind cannot report clean.
"""
from __future__ import annotations

import ast
import functools
import re
from pathlib import Path

import pytest

from agentsec.astutil import safe_ast_parse

_GUARDS = Path(__file__).resolve().parent.parent / "agentsec" / "guards"

# The outermost loop's iterable, as source text, names a file collection.
_FILE_COLLECTION = re.compile(r"files|iter_files|python_scan_dirs|nemo_configs|manifest|_dirs\(|glob")

# (module stem, function) pairs that keep the shape by design. Shrink-only: see the module docstring.
_DOCUMENTED_FIRE_ONCE = frozenset({
    # wiki/guards/agent-tool-overpermission.md "each emitting at most one finding";
    # locked by test_agent_tool_overpermission_at_most_one_finding_per_rule.
    ("agent_tool_overpermission", "_check_dangerous_import"),
    ("agent_tool_overpermission", "_check_allow_dangerous"),
    ("agent_tool_overpermission", "_check_subprocess_in_tool"),
    ("agent_tool_overpermission", "_check_unscoped_toolkit_load"),
    ("agent_tool_overpermission", "_check_wildcard_tools_literal"),
    # Absence-type: "no guardrail layer anywhere" is one claim per project (wiki: "One finding per
    # project"). PR #266 fixed this guard's Rule 4 for this class and deliberately left Rule 1.
    ("guardrail_architecture", "_check_no_external_guardrail"),
    # Locked by test_langchain_unsafe_chain_at_most_one_finding_per_rule.
    ("langchain_unsafe_chain", "_check_dangerous_chain"),
    ("langchain_unsafe_chain", "_check_allow_dangerous_code"),
    # Locked by test_mcp_tool_unverified_fires_on_bare_import (len == 1 over three matches).
    ("mcp_tool_unverified", "_check_python"),
    ("mcp_tool_unverified", "_check_configs"),
    # Locked by test_system_prompt_exposure_at_most_one_finding_per_rule.
    ("system_prompt_exposure", "_check_hardcoded"),
    ("system_prompt_exposure", "_check_logged"),
    ("system_prompt_exposure", "_check_in_response"),
    ("system_prompt_exposure", "_check_concat_leakage"),
})


def _guard_modules() -> list[Path]:
    """Every guard module: the single population both the gate and the floor draw from."""
    return sorted(p for p in _GUARDS.glob("*.py") if p.name != "__init__.py")


def _capped_in_source(src: str, filename: str) -> set[str]:
    """Function names in one source string that return a list literal from inside an all-files loop.

    Nested ``def``s are scoped on their own (their loops start fresh), and comprehensions and lambdas
    are not descended into, since a ``return`` cannot sit inside either.
    """
    tree = safe_ast_parse(src, filename)
    if tree is None:  # a guard that will not parse is its own loud failure, never a silent skip
        return {f"<unparseable: {filename}>"}
    out: set[str] = set()

    def walk(node: ast.AST, func: ast.FunctionDef | ast.AsyncFunctionDef | None, outermost: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
                walk(child, child, "")
            elif isinstance(child, ast.For | ast.AsyncFor | ast.While):
                if outermost:
                    walk(child, func, outermost)
                else:
                    walk(child, func, ast.unparse(child.iter) if isinstance(child, ast.For | ast.AsyncFor)
                         else "while")
            elif isinstance(child, ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp | ast.Lambda):
                continue
            else:
                if (
                    isinstance(child, ast.Return)
                    and func is not None
                    and outermost
                    and isinstance(child.value, ast.List)
                    and child.value.elts
                    and _FILE_COLLECTION.search(outermost)
                ):
                    out.add(func.name)
                walk(child, func, outermost)

    walk(tree, None, "")
    return out


@functools.cache
def _capped_sites() -> frozenset[tuple[str, str]]:
    """Every (module stem, function) across ``agentsec/guards/`` with the first-match-return shape.

    Cached: three tests read it, and parsing every guard module is the whole cost of this file.
    """
    return frozenset(
        (path.stem, name)
        for path in _guard_modules()
        for name in _capped_in_source(path.read_text(encoding="utf-8"), path.name)
    )


def test_no_new_first_match_return_in_an_all_files_loop() -> None:
    """The gate. A new ``return [Finding(...)]`` inside an all-files loop fails here."""
    new = sorted(_capped_sites() - _DOCUMENTED_FIRE_ONCE)
    assert not new, (
        "guard helper(s) return their first finding from inside an all-files loop, capping the rule at "
        "one finding repo-wide; an exception on that one then hides every other instance (#425). "
        "Accumulate instead: `out: list[Finding] = []`, `out.append(Finding(...))` (with `break`/"
        "`continue` for per-tool or per-line dedup), and `return out` after the loops:\n"
        + "\n".join(f"  agentsec/guards/{mod}.py::{func}" for mod, func in new)
    )


def test_documented_fire_once_pin_only_shrinks() -> None:
    """A pinned site that no longer has the shape must leave the pin, so the excuse never outlives it."""
    stale = sorted(_DOCUMENTED_FIRE_ONCE - _capped_sites())
    assert not stale, (
        "_DOCUMENTED_FIRE_ONCE names site(s) that no longer return a first match from an all-files "
        "loop; remove them from the pin:\n"
        + "\n".join(f"  agentsec/guards/{mod}.py::{func}" for mod, func in stale)
    )


def test_the_gate_sees_the_population_it_claims_to() -> None:
    """A walk that went blind would pass the gate forever. The floor sits well below the live count.

    Counts over the same ``_guard_modules()`` the gate scans. A detector that stopped recognising the
    shape is caught by the shrink-only test above (every pinned site would read as stale) and by
    ``test_detector_discriminates`` below.
    """
    modules = _guard_modules()
    assert len(modules) >= 250, f"only {len(modules)} guard modules walked — has the gate gone blind?"


# The detector's own behaviour, through the SAME `_capped_in_source` the gate uses.
_CAPPED = (
    "def _check(root, files):\n"
    "    for f, text in files:\n"
    "        for n, line in enumerate(text.splitlines(), 1):\n"
    "            if bad(line):\n"
    "                return [Finding(n)]\n"
    "    return []\n"
)
_CAPPED_OUTER_ONLY = (
    "def _check(root, files):\n"
    "    for f in files:\n"
    "        if bad(f):\n"
    "            return [Finding(f)]\n"
    "    return []\n"
)
_CAPPED_IN_RUN = (  # the rag-no-instruction-filter shape: run() returns the first file's finding
    "def run(self, root, profile):\n"
    "    for f, text in files:\n"
    "        finding = self._check_file(root, f, text)\n"
    "        if finding is not None:\n"
    "            return [finding]\n"
    "    return []\n"
)
_ACCUMULATES = (
    "def _check(root, files):\n"
    "    out = []\n"
    "    for f, text in files:\n"
    "        for n, line in enumerate(text.splitlines(), 1):\n"
    "            if bad(line):\n"
    "                out.append(Finding(n))\n"
    "    return out\n"
)
_PER_FILE = (  # one file's lines: an early return is per-file dedup, not a repo-wide cap
    "def _check_file(root, f, text):\n"
    "    for n, line in enumerate(text.splitlines(), 1):\n"
    "        if bad(line):\n"
    "            return [Finding(n)]\n"
    "    return []\n"
)
_EMPTY_RETURN_IN_LOOP = (  # the repo-wide pragma pre-pass: `return []` is the opt-out, not a cap
    "def run(self, root, profile):\n"
    "    for _f, text in files:\n"
    "        if PRAGMA in text:\n"
    "            return []\n"
    "    return self._check(root, files)\n"
)
_NESTED_DEF_RESETS = (  # a helper defined inside the files loop scopes its own loops
    "def run(self, root, profile):\n"
    "    for f in files:\n"
    "        def inner(lines):\n"
    "            for n in lines:\n"
    "                return [Finding(n)]\n"
    "        inner(f)\n"
)


@pytest.mark.parametrize(
    ("src", "capped"),
    [
        (_CAPPED, True),
        (_CAPPED_OUTER_ONLY, True),
        (_CAPPED_IN_RUN, True),
        (_ACCUMULATES, False),
        (_PER_FILE, False),
        (_EMPTY_RETURN_IN_LOOP, False),
        (_NESTED_DEF_RESETS, False),
    ],
)
def test_detector_discriminates(src: str, capped: bool) -> None:
    assert bool(_capped_in_source(src, "<inline>")) is capped


def test_unparseable_guard_is_surfaced_not_skipped() -> None:
    """A guard that will not parse must fail loudly, never be silently dropped (Rule 3)."""
    found = _capped_in_source("def _check(:\n    pass\n", "broken.py")
    assert found and "unparseable" in next(iter(found))
