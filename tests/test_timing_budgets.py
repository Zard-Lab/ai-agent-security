"""The gate on wall-clock budgets: every one must be justified by two real measurements.

Why this is a test and not a convention: the budget that turned `main` red on 2026-08-22 was
mis-calibrated the day it was written, and nothing anywhere stated a minimum headroom, so there was
no moment at which anyone could have been told. The failure surfaced weeks later on an unrelated
docs-only commit, on the one CI leg slow enough to expose it. A convention nobody can violate loudly
is a convention that gets violated quietly.

Two halves, pulling in opposite directions on purpose:

- **Headroom** — the budget must clear its measured healthy value by `MIN_HEADROOM`, so a slower box
  cannot manufacture a failure.
- **Still catches the bug** — the budget must stay below the regression it exists to detect. This is
  the CLAUDE.md Rule 1 direction: raising a budget is a *narrowing* of the test's sensitivity, and a
  budget raised until it stopped flaking has usually been raised past the thing it was watching.
"""

from __future__ import annotations

import ast
import functools
import re
import textwrap
from collections.abc import Iterator
from pathlib import Path

import pytest

# Importing the modules that own budgets is what populates the registry — a budget is registered as
# a side effect of its call site being imported, exactly like ALL_GUARDS.
import tests.guards.test_base  # noqa: F401
import tests.guards.test_docker_latest_base_tag  # noqa: F401
import tests.guards.test_llm_json_output_unvalidated  # noqa: F401
import tests.guards.test_path_traversal  # noqa: F401
import tests.guards.test_policy_exists_rls_disabled  # noqa: F401
import tests.guards.test_policy_no_role_scope  # noqa: F401
import tests.guards.test_rls_auth_uid_unwrapped  # noqa: F401
import tests.guards.test_rls_update_privileged_column  # noqa: F401
import tests.guards.test_unsafe_deserialization  # noqa: F401
import tests.test_regex_redos_safety  # noqa: F401
import tests.test_shared_audit  # noqa: F401
from tests._timing import (
    ALL_BUDGETS,
    ALL_NORMALIZED,
    MIN_HEADROOM,
    NORMALIZED_MIN_HEADROOM,
    NormalizedCostBudget,
    TimingBudget,
)

# Both budget kinds are gated by the same three rules; only the required headroom differs, because
# a normalized reading has machine speed divided out and so needs far less slack.
_Budget = TimingBudget | NormalizedCostBudget
_GATED: list[tuple[_Budget, float]] = [(b, MIN_HEADROOM) for b in ALL_BUDGETS] + [
    (b, NORMALIZED_MIN_HEADROOM) for b in ALL_NORMALIZED
]

_TESTS_DIR = Path(__file__).resolve().parent

# A bare wall-clock assertion, in BOTH idioms this repo actually uses:
#
#   assert elapsed < 5.0                          # a named elapsed variable
#   assert time.monotonic() - start < 5.0         # the clock difference inline, no variable
#
# The second form is the more common one here (it is what test_walk.py uses, and what #676's
# acceptance criteria then cite as "the house `time.monotonic()` pattern"). An earlier version of
# this gate matched only the first, so it passed green while blind to 20 of the 26 assertions in the
# suite — the "failure that presents as success" shape this very module exists to prevent, and the
# reason the sweep below is now recorded as data rather than asserted in prose.
#
# Known limits, stated rather than implied: a threshold held in a named constant is matched, but a
# reversed comparison (`assert 5.0 > elapsed`), a multi-line parenthesized assert, or a helper that
# hides the comparison entirely are not. The gate covers the idioms in use, not every expressible
# one; widen it when a new shape appears rather than assuming it is already covered.
# `timing` and an optional `max(...)`/`min(...)` wrapper were added in #770 (F2): the sweep
# reported "all registered" while `tests/test_guards_base_perf.py` asserted `max(timings) <
# 0.05` over real `monotonic()` readings. Two things hid it - the variable was named
# `timings`, matching none of the stems, and the duration sat inside a call rather than bare
# after `assert`. A gate that is green because it is not looking is the exact failure this
# gate exists to catch (CLAUDE.md rule 3).
#
# Deliberately NOT widened to "any assert compared to a number". That was measured against the
# suite while fixing this and it catches `assert len(m._rules) < 200` (a count, not a
# duration) plus three `_FakeClock` assertions in test_complexity_probe.py that are
# hardware-independent BY DESIGN. Widening a sweep is still a widening: see
# `test_the_sweep_does_not_match_counts_or_fake_clock_assertions` for the direction traded
# against.
_BARE_WALL_CLOCK = re.compile(
    r"^\s*assert\s+(?:(?:max|min)\(\s*)?(?:"
    r"\w*(?:elapsed|duration|took|secs|seconds|timing)\w*"
    r"|(?:time\.)?(?:monotonic|perf_counter)\(\)\s*-\s*\w+"
    r")\s*\)?\s*<=?\s*[\w.]+",
    re.MULTILINE,
)

# Timing assertions that predate this rule and are NOT registered as TimingBudgets, because none of
# them records the regression value a TimingBudget requires and inventing one would make the gate
# assert a fiction.
#
# Each entry carries the count and the WORST measured headroom in that file, so the allowlist states
# evidence instead of claiming it: `test_grandfathered_entries_clear_minimum_headroom` checks the
# recorded number against MIN_HEADROOM, which is what makes this dict falsifiable. Every figure below
# came from one sweep that instrumented all 25 assertions and read their real elapsed values (not
# pytest's `call` duration, which includes fixture work); re-derive with the sweep described in
# .claude/reports/complexity-probe-and-timing-budget-headroom-report.md.
#
# A caveat these numbers earned the hard way. The sweep takes ONE sample per assertion, so an entry
# near the line records whichever side of its own spread that sample landed on. The
# pathological-SQL entry in test_policy_exists_rls_disabled.py was recorded at 10.3x and read as
# "barely over"; re-measured 25 times during the #691 fix-commit review it came in at 10.08x median
# and 9.07x worst, UNDER the floor in 10 of 25 runs — the recorded figure was above even the best of
# the 25. It has since been converted to a growth + normalized-cost assertion, which is what the rule
# below says to do with an entry that cannot clear the floor. Treat any single-sample figure within
# ~2x of MIN_HEADROOM as unproven until it has been measured with repeats.
_GRANDFATHERED: dict[str, tuple[int, float]] = {
    # path relative to tests/  ->  (bare wall-clock assertions allowed, worst measured headroom)
    #
    # The 5 entries below are the 7 bare wall-clock assertions in PR #693's own 5 new
    # Database Security guards (policy-no-role-scope, sensitive-columns, rls-auth-uid-unwrapped,
    # matview-exposed, storage-no-rls) — this gate did not exist on `main` when that PR branched,
    # so they were never registered. Measured across 3 repeats each, worst sample recorded, before
    # registering (2026-08-25); 3 of the 7 originally had a 5.0s/8.0s ceiling that measured under
    # MIN_HEADROOM (as low as ~7.5x) and were widened (still leaving minutes of margin below the
    # actual quadratic/O(n^2) regression each guards against — see each assertion's own comment).
    "guards/test_rls_auth_uid_unwrapped.py": (2, 10.6),  # tightest of the 5, see comment above
    "guards/test_policy_no_role_scope.py": (1, 13.3),
    "guards/test_sensitive_columns.py": (2, 13.6),
    "guards/test_matview_exposed.py": (1, 15.7),
    "guards/test_storage_no_rls.py": (1, 15.7),
    "guards/test_target_blank_noopener.py": (1, 14.7),
    "guards/test_policy_exists_rls_disabled.py": (1, 23.4),
    "guards/test_base.py": (7, 16.8),  # +2 vs the pre-Ruby/Java/PHP baseline: the Java support's
    # strip_java_comments pathological-block test (worst headroom ~18.8x at its own 5.0s
    # ceiling) AND the strip_php_comments pathological-block test (~16.8x at its own
    # 5.0s ceiling, now the file's recorded worst) both landed here once feat/prob326 merged
    # main's Java support in alongside this branch's own PHP addition — verified against the
    # actual post-merge sweep, not assumed from either side's pre-merge count. -1 since (Batch 273):
    # the strip_js_comments unterminated-block test became two `assert_growth` checks.
    "guards/test_public_table_rls.py": (1, 19.3),
    "guards/test_open_redirect.py": (3, 21.9),
    "guards/test_mcp_transport_no_auth.py": (1, 60.7),  # PR #915 review F1: the bounded `[^)]{0,2000}`
    # guard run measured 0.247s worst of 7 at n=128k against its own 15.0s ceiling (unbounded: 60.9s).
    "guards/test_js_command_injection.py": (1, 11.2),  # -1 (2026-11-06): the colon superlinear test
    # became an `assert_growth` check; its `(`-dense param measured 29.1x on linux but ~4.3x on the
    # self-hosted Windows leg (3.5s idle at n=32k) and failed there under load. The one left is the
    # module-binder blank-line run: 1.33-1.34s worst-of-5 at n=160k on that Windows host -> 11.2x.
    "guards/test_rls_multiple_permissive_policies.py": (1, 35.5),
    "guards/test_rls_permissive_policy.py": (1, 35.6),
    "guards/test_pg_anon_grant.py": (1, 46.8),
    "test_walk.py": (2, 44.5),
    "guards/test_pg_rls_no_policy.py": (1, 62.0),
    "guards/test_request_model_extra_forbid.py": (1, 239.9),
    "guards/test_multi_agent_prompt_origin.py": (1, 453.5),
    "guards/test_csv_injection.py": (1, 864.4),
    "guards/test_vite_sourcemap_prod.py": (1, 1564.4),
}


def test_the_registry_is_not_empty() -> None:
    # A gate with nothing registered passes trivially and reads as coverage — the "failure that
    # presents as success" class (CLAUDE.md Rule 3). If a refactor empties the registry, say so.
    assert ALL_BUDGETS, "no TimingBudget is registered; the headroom gate below asserts nothing"
    assert ALL_NORMALIZED, "no NormalizedCostBudget is registered; the constant-factor gate is blind"


@pytest.mark.parametrize(("budget", "floor"), _GATED, ids=lambda x: x.name if hasattr(x, "name") else "")
def test_every_timing_budget_clears_minimum_headroom(budget: _Budget, floor: float) -> None:
    assert budget.limit >= budget.measured * floor, (
        f"{budget.name}: a {budget.limit:.2f} ceiling over a {budget.measured:.2f} healthy run is "
        f"only {budget.headroom:.1f}x headroom, under the {floor:.0f}x minimum. The Windows "
        f"CI leg alone is up to 3.2x slower (see ci.yml's validate-windows timeout comment) "
        f"before runner contention."
    )


@pytest.mark.parametrize(("budget", "floor"), _GATED, ids=lambda x: x.name if hasattr(x, "name") else "")
def test_every_timing_budget_still_catches_its_regression(budget: _Budget, floor: float) -> None:
    assert budget.limit < budget.regression, (
        f"{budget.name}: a {budget.limit:.2f} ceiling is at or above the {budget.regression:.2f} "
        f"regression it exists to catch — the test would now pass WITH the bug present."
    )


@pytest.mark.parametrize(("budget", "floor"), _GATED, ids=lambda x: x.name if hasattr(x, "name") else "")
def test_a_budget_with_no_room_between_its_two_measurements_is_reported(
    budget: _Budget, floor: float
) -> None:
    # Both halves can only hold at once if healthy and broken are at least MIN_HEADROOM apart. When
    # they are not, no absolute budget exists that satisfies the rule, and the honest answer is a
    # growth-ratio assertion (tests/_timing.py::assert_growth), not a fudged number.
    assert budget.window >= floor, (
        f"{budget.name}: healthy {budget.measured:.2f} and regression {budget.regression:.2f} are "
        f"only {budget.window:.1f}x apart, under the {floor:.0f}x minimum — no fixed ceiling can "
        f"both clear the noise and stay under the bug. Use assert_growth instead."
    )


def test_new_wall_clock_assertions_are_registered_or_grandfathered() -> None:
    """A NEW bare `assert elapsed < N` must register a TimingBudget or be added above deliberately.

    This is the half that makes the gate reach code it does not import: the parametrized tests above
    can only see budgets that were registered, so on their own they would be blind to exactly the
    mistake being prevented — someone writing a fresh untracked budget.
    """
    offenders: list[str] = []
    for path in sorted(_TESTS_DIR.rglob("test_*.py")):
        if "fixtures" in path.parts:
            continue
        rel = path.relative_to(_TESTS_DIR).as_posix()
        found = len(_BARE_WALL_CLOCK.findall(path.read_text(encoding="utf-8")))
        allowed, _ = _GRANDFATHERED.get(rel, (0, 0.0))
        if found > allowed:
            offenders.append(f"{rel}: {found} bare wall-clock assertion(s), {allowed} grandfathered")
    assert not offenders, (
        "unregistered wall-clock budget(s) — wrap them in a TimingBudget (tests/_timing.py) so the "
        "headroom gate can see them, or add them to _GRANDFATHERED with the measured headroom:\n  "
        + "\n  ".join(offenders)
    )


def test_grandfathered_entries_do_not_outlive_their_assertions() -> None:
    """An allowlist entry that no longer matches anything is stale permission nobody asked for."""
    stale = [
        rel
        for rel, (allowed, _) in _GRANDFATHERED.items()
        if len(_BARE_WALL_CLOCK.findall((_TESTS_DIR / rel).read_text(encoding="utf-8"))) != allowed
    ]
    assert not stale, f"_GRANDFATHERED counts no longer match the code: {stale}"


def test_the_sweep_sees_the_population_it_claims_to() -> None:
    """The gate is only worth its name if the regex finds the assertions that actually exist.

    Its predecessor matched one of the two idioms in use and passed green over the other 20, so this
    pins the total the sweep can see. A drop means the regex stopped matching a shape it used to —
    the silent direction, which the offender check cannot detect because fewer hits always looks
    like compliance.
    """
    total = sum(
        len(_BARE_WALL_CLOCK.findall(p.read_text(encoding="utf-8")))
        for p in _TESTS_DIR.rglob("test_*.py")
        if "fixtures" not in p.parts
    )
    expected = sum(count for count, _ in _GRANDFATHERED.values())
    assert total == expected, (
        f"the sweep sees {total} bare wall-clock assertion(s) but _GRANDFATHERED accounts for "
        f"{expected}. If the regex was narrowed, it is now blind to a shape it used to catch."
    )


def test_grandfathered_entries_clear_minimum_headroom() -> None:
    """The recorded headroom is a claim; this is what makes it falsifiable rather than prose.

    The previous version of the allowlist asserted in a comment that every entry "was measured and
    clears MIN_HEADROOM comfortably". That sentence was untrue for 20 of the 26 assertions, and
    nothing could contradict it because it was prose. Now the number is data and the rule checks it.
    """
    tight = {rel: hr for rel, (_, hr) in _GRANDFATHERED.items() if hr < MIN_HEADROOM}
    assert not tight, (
        f"grandfathered assertion(s) under the {MIN_HEADROOM:.0f}x minimum: {tight}. These cannot "
        f"stay on the allowlist — convert them to a growth assertion (tests/_timing.py::assert_growth)."
    )


# ------------------------------------------------------------------ growth call sites (#758)
#
# `assert_growth` promises a machine-speed-independent verdict, and `classify` delivers the half of
# that promise which matters here — discarding a contended reading — only from THREE ratios up. At
# two it takes their mean, so the outlier keeps half its weight. Every call site in the repo sat at
# exactly three sizes (two ratios) when #758 was filed, which is why a healthy linear workload read
# as `quadratic` on the Windows leg.
#
# This is a gate rather than a comment for the same reason the headroom rule above is: the knowledge
# already existed, written out in full at `tests/test_complexity_probe.py`'s own quadratic test, and
# it stayed there. A convention that lives in a comment on one test does not reach the next call
# site somebody writes.

_MIN_GROWTH_SIZES = 4


def _own_scope_nodes(func: ast.FunctionDef | ast.AsyncFunctionDef) -> Iterator[ast.AST]:
    """Every node in ``func`` except those belonging to a nested function's own scope.

    A nested helper that happens to bind the same name binds a DIFFERENT variable, and collecting
    both made the gate resolve `sizes` to whichever assignment the walk reached last. That is not a
    cosmetic mix-up: with `sizes = [1, 2, 3]` in the test and a shadowing `sizes = [1, 2, 3, 4]` in a
    helper beside it, the gate reported 4 for a call site that passes 3 and let it through. A false
    pass, in the gate whose entire job is to prevent one (#759 fix-commit review).
    """
    stack: list[ast.AST] = list(ast.iter_child_nodes(func))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            continue  # a separate scope: its bindings are not this function's
        stack.extend(ast.iter_child_nodes(node))


def _growth_sizes_in_source(source: str, rel: str) -> list[tuple[str, str, int]]:
    """Resolve one module's ``assert_growth`` calls to ``(file, test name, size count)``.

    Split out from the suite-wide sweep so the resolver can be tested against source it is HANDED,
    rather than only through whatever the real test tree happens to contain today. A gate that is
    only ever exercised on inputs it already passes cannot tell you which inputs it misses.

    Resolved through the AST rather than a regex because the sizes are written several ways: inline
    at the call, via a local ``sizes = [...]``, and positionally or by keyword. A call whose size
    list cannot be resolved is reported as ``-1`` and fails the gate, because a gate that quietly
    skips what it cannot read is the failure mode this whole area is about.
    """
    sites: list[tuple[str, str, int]] = []
    tree = ast.parse(source)
    # `ast.walk` reaches a call inside a nested helper twice: once walking the enclosing test, once
    # walking the nested `def` itself. Deduping on node identity records it once. Which of the two
    # scopes supplies the reported NAME depends on `ast.walk`'s traversal order, which the stdlib
    # docs leave unspecified, so treat that name as a locator and never as part of the verdict: the
    # size count is identical either way. Left undeduped this inflates the population figure that
    # `test_the_growth_sweep_sees_the_call_sites_it_claims_to` asserts against, so a call site that
    # had gone missing could be masked by one merely counted twice.
    seen: set[int] = set()
    for func in ast.walk(tree):
        if not isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        literals = {
            target.id: len(node.value.elts)
            for node in _own_scope_nodes(func)
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.List | ast.Tuple)
            for target in node.targets
            if isinstance(target, ast.Name)
        }
        for node in ast.walk(func):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "assert_growth"
            ):
                continue
            if id(node) in seen:
                continue
            seen.add(id(node))
            # `sizes` is positional-OR-keyword in `assert_growth`'s signature, so BOTH spellings
            # have to be read. Checking only `args[1]` made `assert_growth(scan, sizes=[...])`
            # invisible — not even reaching the `-1` fallback this docstring promises — so the gate
            # would have gone silent on precisely the regression it exists to catch (#759 review).
            positional = node.args[1] if len(node.args) >= 2 else None
            keyword = next((kw.value for kw in node.keywords if kw.arg == "sizes"), None)
            arg = positional if positional is not None else keyword
            if isinstance(arg, ast.List | ast.Tuple):
                count = len(arg.elts)
            elif isinstance(arg, ast.Name):
                count = literals.get(arg.id, -1)
            else:
                count = -1  # unreadable, or no `sizes` at all: fail loudly rather than skip
            sites.append((rel, func.name, count))
    return sites


@functools.cache
def _growth_call_sites() -> tuple[tuple[str, str, int], ...]:
    """Every ``assert_growth`` call in the suite, as ``(file, test name, size count)``.

    Cached: both callers walk the whole suite, and parsing every test file twice cost more than
    the assertions it feeds.
    """
    sites: list[tuple[str, str, int]] = []
    for path in sorted(_TESTS_DIR.rglob("test_*.py")):
        if "fixtures" in path.parts:
            continue
        rel = path.relative_to(_TESTS_DIR).as_posix()
        sites.extend(_growth_sizes_in_source(path.read_text(encoding="utf-8"), rel))
    return tuple(sites)


@pytest.mark.slow
def test_growth_assertions_pass_enough_sizes_for_the_median_to_work() -> None:
    offenders = [
        f"{rel}::{name} passes {count} sizes"
        for rel, name, count in _growth_call_sites()
        if count < _MIN_GROWTH_SIZES
    ]
    assert not offenders, (
        f"assert_growth needs at least {_MIN_GROWTH_SIZES} sizes, i.e. three ratios: "
        "`statistics.median` of TWO ratios is their mean, so a single contended reading keeps half "
        "its weight and moves the verdict (#758). A count of -1 means the size list could not be "
        "resolved from the AST — inline the list or assign it to a plain local:\n  "
        + "\n  ".join(offenders)
    )


def _classifying_measure_sites(source: str, rel: str) -> list[tuple[str, str, int]]:
    """``(file, test, size count)`` for each ``measure(...)`` in a test that also calls ``classify``.

    The gate above resolves ``assert_growth`` call sites, and that is not the only way to reach a
    growth verdict: a test can call ``measure()`` and ``classify()`` directly, which is what the four
    classification tests in ``test_complexity_probe.py`` do. Those were invisible to it, and two of
    them sat at three sizes — the exact condition the rule forbids — while the sweep reported full
    coverage. One of the two then failed 3 of 7 `pytest -n auto` runs on the Windows CI guest.

    The pairing is what makes this checkable: a bare ``measure()`` is legitimately called with two
    sizes by the bridge tests, which assert on series SHAPE and never classify. Only a measurement
    whose result reaches ``classify`` needs three ratios, so the presence of both calls in one test
    function is the signal, not ``measure`` alone.

    **A test driving a FAKE clock is exempt, and must be.** The rule exists because a contended
    reading moves a two-ratio median; a scripted duration cannot be contended. The #758 regression
    tests classify a THREE-size series on purpose — that is the bug being reproduced — so a gate
    that forced four sizes on them would delete the evidence it was written to protect. Detected by
    the fake-clock helpers those tests use (``_with_clock`` / ``_FakeClock``) or by the ``advance``
    fixture, rather than by name, so a new fake-clock test is exempt automatically.
    """
    sites: list[tuple[str, str, int]] = []
    tree = ast.parse(source)
    _FAKE_CLOCK_MARKERS = {"_with_clock", "_FakeClock", "advance"}

    def _callee(node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ""

    for func in ast.walk(tree):
        if not isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        calls = [n for n in ast.walk(func) if isinstance(n, ast.Call)]
        if not any(_callee(c) == "classify" for c in calls):
            continue
        names = {n.id for n in ast.walk(func) if isinstance(n, ast.Name)}
        names |= {a.arg for a in func.args.args}
        if names & _FAKE_CLOCK_MARKERS:
            continue  # virtual clock: no scheduler, so no contended reading to outvote
        literals = {
            target.id: len(node.value.elts)
            for node in _own_scope_nodes(func)
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.List | ast.Tuple)
            for target in node.targets
            if isinstance(target, ast.Name)
        }
        for call in calls:
            if _callee(call) != "measure":
                continue
            positional = call.args[1] if len(call.args) >= 2 else None
            keyword = next((kw.value for kw in call.keywords if kw.arg == "sizes"), None)
            arg = positional if positional is not None else keyword
            if isinstance(arg, ast.List | ast.Tuple):
                count = len(arg.elts)
            elif isinstance(arg, ast.Name):
                count = literals.get(arg.id, -1)
            else:
                count = -1
            sites.append((rel, func.name, count))
    return sites


@functools.cache
def _classifying_measure_call_sites() -> tuple[tuple[str, str, int], ...]:
    sites: list[tuple[str, str, int]] = []
    for path in sorted(_TESTS_DIR.rglob("test_*.py")):
        if "fixtures" in path.parts:
            continue
        rel = path.relative_to(_TESTS_DIR).as_posix()
        sites.extend(_classifying_measure_sites(path.read_text(encoding="utf-8"), rel))
    return tuple(sites)


def test_classifying_measure_calls_pass_enough_sizes_for_the_median_to_work() -> None:
    """The same three-ratio rule, for the call shape that reaches a verdict without `assert_growth`."""
    offenders = [
        f"{rel}::{name} passes {count} sizes"
        for rel, name, count in _classifying_measure_call_sites()
        if count < _MIN_GROWTH_SIZES
    ]
    assert not offenders, (
        f"a measure() whose result is classified needs at least {_MIN_GROWTH_SIZES} sizes, i.e. "
        "three ratios: `statistics.median` of TWO ratios is their mean, so one contended reading "
        "moves the verdict by half its excursion (#758, and 3 of 7 Windows `-n auto` runs). A count "
        "of -1 means the size list could not be resolved from the AST — inline it or assign it to a "
        "plain local:\n  " + "\n  ".join(offenders)
    )


def test_the_classifying_measure_sweep_sees_the_call_sites_it_claims_to() -> None:
    """Anti-vacuity: this gate passes trivially if the AST walk finds nothing, which is how a rename
    would disable it in silence — the same hole its `assert_growth` sibling pins below."""
    sites = _classifying_measure_call_sites()
    assert len(sites) >= 4, f"expected the classification call sites, found {len(sites)}: {sites}"
    assert {rel for rel, _, _ in sites} >= {"test_complexity_probe.py"}, (
        f"the sweep lost the file it used to see: {sorted({rel for rel, _, _ in sites})}"
    )


def test_the_classifying_measure_sweep_distinguishes_shape_tests_from_verdict_tests() -> None:
    """The FP-bait direction. A `measure()` that never classifies is testing series SHAPE and is
    legitimately called with two sizes (the bridge tests); pulling those in would force four sizes
    on tests whose whole point is a two-element list, so the pairing must actually discriminate."""
    source = textwrap.dedent(
        """
        def test_shape_only() -> None:
            elapsed = cp.measure(workload, [10, 160], ceiling=0.5)
            assert len(elapsed) == 2

        def test_verdict() -> None:
            elapsed = cp.measure(workload, [1, 2, 3])
            assert cp.classify(cp.growth_ratios(elapsed), 2) == "linear"

        def test_verdict_on_a_fake_clock(monkeypatch) -> None:
            _with_clock(monkeypatch, [0.1, 0.2, 0.4])
            elapsed = cp.measure(workload, [1, 2, 3])
            assert cp.classify(cp.growth_ratios(elapsed), 2) == "linear"

        def test_verdict_on_the_advance_fixture(advance) -> None:
            elapsed = cp.measure(workload, [1, 2, 3])
            assert cp.classify(cp.growth_ratios(elapsed), 2) == "linear"
        """
    )
    # only the real-clock verdict test is in scope: the shape test never classifies, and the two
    # fake-clock ones have no scheduler that could contend a reading
    assert _classifying_measure_sites(source, "x.py") == [("x.py", "test_verdict", 3)]


def test_the_growth_sweep_sees_the_call_sites_it_claims_to() -> None:
    """The gate above passes vacuously if the AST walk finds nothing, which is exactly how a rename
    of `assert_growth` would disable it in silence. Pin that it still finds the population."""
    sites = _growth_call_sites()
    assert len(sites) >= 8, f"expected the known assert_growth call sites, found {len(sites)}: {sites}"
    assert {rel for rel, _, _ in sites} >= {
        "test_detect.py",
        "guards/test_base.py",
        "guards/test_csv_injection.py",
        "guards/test_docker_latest_base_tag.py",
        "guards/test_docker_nonroot_user.py",
        "guards/test_policy_exists_rls_disabled.py",
    }, f"the sweep lost a file it used to see: {sorted({rel for rel, _, _ in sites})}"


def test_the_growth_sweep_reads_every_shape_a_call_site_can_be_written_in() -> None:
    """The resolver, against source handed to it rather than against the tree that already passes.

    Each case below is a shape a future call site could legitimately be written in. The keyword one
    is not hypothetical: `sizes` is positional-or-keyword, and reading only `args[1]` made
    `assert_growth(scan, sizes=[...])` invisible to this gate entirely — a three-size regression
    written that way would have sailed through the check that exists to stop it (#759 review).
    """
    source = textwrap.dedent(
        """
        def test_positional() -> None:
            assert_growth(scan, [1, 2, 3, 4], expected="linear")

        def test_keyword_is_not_invisible() -> None:
            assert_growth(scan, sizes=[1, 2, 3], expected="linear")

        def test_via_a_local() -> None:
            sizes = [1, 2, 3, 4, 5]
            assert_growth(scan, sizes, expected="linear")

        def test_keyword_pointing_at_a_local() -> None:
            sizes = [1, 2, 3, 4, 5, 6]
            assert_growth(scan, sizes=sizes, expected="linear")

        def test_unreadable_is_reported_not_skipped() -> None:
            assert_growth(scan, make_sizes(), expected="linear")
        """
    )
    assert _growth_sizes_in_source(source, "x.py") == [
        ("x.py", "test_positional", 4),
        ("x.py", "test_keyword_is_not_invisible", 3),
        ("x.py", "test_via_a_local", 5),
        ("x.py", "test_keyword_pointing_at_a_local", 6),
        ("x.py", "test_unreadable_is_reported_not_skipped", -1),
    ]


def test_a_keyword_written_undersized_call_site_actually_fails_the_gate() -> None:
    """The shape above, carried through to the assertion. Resolving a call is only useful if the
    gate then rejects it, and this is the direction the gate exists for."""
    source = "def test_x() -> None:\n    assert_growth(scan, sizes=[1, 2, 3], expected='linear')\n"
    sites = _growth_sizes_in_source(source, "x.py")
    assert [c for _, _, c in sites] == [3]
    assert any(c < _MIN_GROWTH_SIZES for _, _, c in sites), "the gate must reject this"


def test_a_call_inside_a_nested_helper_is_counted_once_under_the_enclosing_test() -> None:
    """`ast.walk` reaches such a call twice, once per enclosing scope. Counted twice it would
    inflate the population figure that the anti-vacuity check asserts against, which is how a call
    site that had gone missing could be masked by one that was merely double-counted."""
    source = textwrap.dedent(
        """
        def test_outer() -> None:
            def helper() -> None:
                assert_growth(scan, [1, 2, 3, 4], expected="linear")
            helper()
        """
    )
    assert _growth_sizes_in_source(source, "x.py") == [("x.py", "test_outer", 4)]


def test_a_nested_helper_shadowing_sizes_cannot_resolve_the_enclosing_call() -> None:
    """A nested helper binding the same name binds a DIFFERENT variable.

    Collecting both let the shadow win and the gate reported FOUR sizes for a call site that passes
    three, which is a false pass in the gate that exists to prevent one. The enclosing test's own
    binding is the one that governs its call.
    """
    source = textwrap.dedent(
        """
        def test_outer() -> None:
            sizes = [1, 2, 3]
            def helper() -> None:
                sizes = [1, 2, 3, 4]
                return sizes
            assert_growth(scan, sizes, expected="linear")
        """
    )
    (_, _, count), *rest = _growth_sizes_in_source(source, "x.py")
    assert not rest, "one call site, counted once"
    assert count == 3, "the enclosing test's own `sizes` governs, not the helper's shadow"
    assert count < _MIN_GROWTH_SIZES, "and the gate must therefore still reject it"


# The drift gate for `tests/_timing.py`'s citation of the Windows slowdown measurement lives in the
# maintainers' private test module: the measurement is in a CI workflow this repository does not publish.


def test_the_sweep_does_not_match_counts_or_fake_clock_assertions() -> None:
    """The direction traded against for #770 F2's widening (CLAUDE.md rule 1).

    Widening `_BARE_WALL_CLOCK` to see `max(timings)` must not turn it into "any assert against a
    number". These four are real assertions in this suite that a careless widening catches, and
    none of them is a wall-clock budget: a count of parsed rules, and three readings from
    `_FakeClock`, which exists precisely so those tests do NOT depend on machine speed. If this
    test fails, the sweep has started demanding budgets for things that have no duration."""
    for benign in (
        "    assert len(m._rules) < 200, 'rule explosion'",
        "    assert projected < 3.0",
        "    assert exponent is not None and 2.9 < exponent < 3.1",
        "    assert len(elapsed) == 1 and all(e <= 0.02 for e in elapsed)",
    ):
        assert not _BARE_WALL_CLOCK.search(benign), (
            f"the bare-wall-clock sweep now matches {benign.strip()!r}, which is not a wall-clock "
            "budget. Narrow the regex rather than registering a TimingBudget for it."
        )


def test_the_sweep_sees_a_duration_wrapped_in_max() -> None:
    """The positive half: the shape that was invisible until #770 F2."""
    assert _BARE_WALL_CLOCK.search("    assert max(timings) < 0.05, 'not bounded'")
