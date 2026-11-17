"""ReDoS (catastrophic-backtracking) safety gate for agentsec's OWN guard regex patterns.

`agentsec/guards/*.py` is ~1200 compiled regex patterns run against arbitrary, potentially
adversarial source code (the repo being scanned) - none of them were previously checked for
catastrophic-backtracking safety. This is that check, wired in as a permanent CI gate rather than
a one-off scan: `scripts/lint_regex_redos.py` implements the two-stage lint (static
nested-quantifier/alternation heuristic, then a subprocess-timeout runtime confirmation only for
patterns the static pass flags) and `test_no_guard_pattern_is_confirmed_vulnerable` below runs it
over the real guard corpus and fails if any pattern is CONFIRMED vulnerable.

`scripts/lint_regex_redos.py` is loaded by path (hyphen-free name, but `scripts/` is not a
package) via the same `importlib.util.spec_from_file_location` convention `tests/test_doc_counts.py`
uses for `scripts/doc_counts.py` - see that file's comment for why the module is registered in
`sys.modules` before `exec_module`.
"""
from __future__ import annotations

import importlib.util
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from tests._timing import TimingBudget, assert_within, register

_REPO = Path(__file__).resolve().parents[1]
_SCRIPT = _REPO / "scripts" / "lint_regex_redos.py"
_spec = importlib.util.spec_from_file_location("lint_regex_redos", _SCRIPT)
assert _spec is not None and _spec.loader is not None
L = importlib.util.module_from_spec(_spec)
sys.modules["lint_regex_redos"] = L  # register before exec so @dataclass can resolve cls.__module__
_spec.loader.exec_module(L)

# Shared budget for the three "stage 2 must clear a linear-safe pattern fast" tests below. Wide
# window, so an absolute budget is comfortable - see tests/_timing.py on when it is not.
# Measured 2026-09-03, this box, after the growth-classifier change: healthy is the WORST of the
# three call sites (0.358 / 0.454 / 0.000).
#
# NOTE on what `elapsed` now means, because it changed and the old note here is why this comment
# was rewritten rather than left alone. `confirm_vulnerable` returns the LAST READING taken, not
# the wall-clock round trip, so a confirmed pattern no longer reports ~10.01s - it reports
# whatever its last completed probe cost (0.0 when it was killed before reporting any). The old
# regression signal named here ("burning the whole flat DEFAULT_TIMEOUT growth sequence, elapsed
# 10.012s") therefore no longer exists and this budget can no longer be the thing that catches
# it. That direction is still covered, more directly: each of these three tests asserts
# `confirmed is False` FIRST, which fails outright if a linear-safe pattern starts being
# confirmed. This budget now guards the narrower property it can actually see - that clearing
# stays fast.
_LINEAR_CLEAR_BUDGET = register(
    TimingBudget(
        name="redos-lint/linear-safe-pattern-clears-fast",
        seconds=5.0,
        measured=0.39,
        regression=10.01,
        why="stage 2 got slow clearing a linear-safe pattern (the #580 round-4 FP class)",
    )
)


# The exponential-wall PoCs (`(a+)+b`, `(a+){1,30}b`, `(a{1,5})+b`) produce ONE reading at n=8 in
# microseconds and then never finish n=32, so their verdict is "killed at the wall", and the only
# thing the deadline decides is how long the test waits for that kill. The evidence path is
# independent of the deadline's size: one reading leaves no measured exponent, so the worker's
# forecast and its `spent + r > ceiling` repeat stop (the two places `timeout` enters as `ceiling`)
# are both inert. So these tests wait out a short deadline instead of `DEFAULT_TIMEOUT`, and in
# exchange assert the evidence SHAPE, not just `confirmed is True`: a run that confirmed through
# spawn starvation (zero readings, the residual `confirm_vulnerable` discloses) or through the
# resample is NOT the wall, and used to pass these tests indistinguishably.
_WALL_TIMEOUT = 2.5


def _wall_outcome(pattern: str) -> L.Stage2Outcome:
    o = L._confirm_outcome(pattern, 0, timeout=_WALL_TIMEOUT)
    # Spawn starvation, not the wall: no readings, or a starved first sample that `_confirm_outcome`
    # then resampled (#1142 pre-review, M1). Re-measure at the production deadline; the strict
    # `_assert_wall` still judges that run, so the retry cannot turn a real failure into a pass.
    if not o.readings or o.resampled:
        o = L._confirm_outcome(pattern, 0, timeout=L.DEFAULT_TIMEOUT)
    return o


def _assert_wall(o: L.Stage2Outcome, what: str) -> None:
    evidence = (f"readings={list(o.readings)} growth={o.growth} refused={o.refused} "
                f"timed_out={o.timed_out} resampled={o.resampled}")
    assert o.confirmed is True, f"stage 2 must catch {what} hanging, not clear it. Evidence: {evidence}"
    assert o.timed_out and not o.resampled, f"{what} must be confirmed by the kill at the wall: {evidence}"
    assert 1 <= len(o.readings) <= L._WALL_MAX_READINGS, f"{what} is not the wall shape: {evidence}"
    assert o.readings[0][0] == L._PROBE_MIN_N, f"{what}: the n={L._PROBE_MIN_N} reading is missing: {evidence}"


# --------------------------------------------------------------------------- stage 1: static heuristic


@pytest.mark.parametrize(
    "pattern",
    [
        r"(a+)+",  # the textbook catastrophic shape
        r"(a*)*",
        r"(a+)*",
        r"(\d+)+",
        r"(a|ab)+c",  # alternation inside a repeated group, no inner quantifier needed
        r"([a-zA-Z]+)*!",
        r"((a+)+)+",  # nested-nested - still caught by scanning every group, any depth
    ],
)
def test_is_suspect_flags_classic_redos_shapes(pattern: str) -> None:
    assert L.is_suspect(pattern) is True


@pytest.mark.parametrize(
    "pattern",
    [
        r"[a-z]+",  # a quantified class with no group at all
        r"\bre\.compile\(",
        r"(?:abc)+",  # repeated group, but nothing catastrophic inside it
        r"(foo|bar)",  # alternation, but the group itself is not repeated
        r"\s*x",  # a single unbounded quantifier, no adjacency - nothing to be ambiguous with
        r"(a+){1}b",  # bounded outer, upper bound 1 - the group can't repeat, so no ambiguity
        r"(a+){0,1}b",  # same, spelled as a range
    ],
)
def test_is_suspect_does_not_flag_ordinary_patterns(pattern: str) -> None:
    assert L.is_suspect(pattern) is False


# --------------------------------------------------------- stage 1: PR #580 review, Critical 1 + 2
# `scripts/lint_regex_redos.py`'s stage-1 filter previously missed two real catastrophic shapes,
# both of which were confirmed to reach production undetected (see PR #580's review comment): an
# ungrouped run of adjacent unbounded quantifiers (Critical 1), and a group whose OUTER quantifier
# is bounded but whose INNER quantifier is unbounded (Critical 2). Each pair below tests both
# directions per CLAUDE.md's "Changing a check" Rule 1: the widening (the vulnerable shape now
# gets flagged) and the direction traded against (an ordinary neighbour pattern that merely LOOKS
# like the new shape stays cleared by stage 2, same as any other over-flagged stage-1 SUSPECT).


def test_is_suspect_flags_ungrouped_adjacent_unbounded_quantifiers() -> None:
    """Critical 1: no parentheses at all - `is_suspect`'s old group-only scan never saw this."""
    assert L.is_suspect(r"\s*\s*\s*\s*\s*\s*\s*\s*x") is True


def test_is_suspect_flags_bounded_outer_with_unbounded_inner_quantifier() -> None:
    """Critical 2: `{1,30}` bounds the OUTER repeat, but the INNER `+` is still unbounded, so the
    group can still absorb the same run of characters exponentially many ways across its repeats."""
    assert L.is_suspect(r"(a+){1,30}b") is True


# `slow` on every stage-2 confirmation below: proving a hang means WAITING OUT `DEFAULT_TIMEOUT`
# (10s), so the cost is the deadline itself rather than the work, and 8 of them dominate the
# suite's wall-clock. This is a RUNTIME mark only - it changes nothing about what the full gate
# runs. The corpus drift gate `test_no_guard_pattern_is_confirmed_vulnerable` already carried
# its own `slow` mark and is untouched here.
@pytest.mark.slow
def test_lint_mechanism_confirms_critical_1_ungrouped_adjacent_quantifiers() -> None:
    """End-to-end: the exact PoC from PR #580's review - stage 1 flags it, and stage 2's real
    subprocess timing run confirms the hang, not just the string heuristic.

    This is also the round-2 regression test: a single FIXED probe length (n=32) cleared this
    exact PoC on the review's own machine (1.49s, under the 3.0s deadline) while confirming it on
    a slower one - a hardware-dependent gate. `confirm_vulnerable` now GROWS the probe until
    either a timeout proves the hang or growth demonstrates linear behaviour, which is what makes
    this assertion hold regardless of which machine runs it."""
    pattern = r"\s*\s*\s*\s*\s*\s*\s*\s*x"
    assert L.is_suspect(pattern) is True

    confirmed, elapsed = L.confirm_vulnerable(pattern, 0, timeout=L.DEFAULT_TIMEOUT)
    assert confirmed is True, (
        f"stage 2 must catch the ungrouped adjacent-quantifier PoC hanging (returned after "
        f"{elapsed:.2f}s at the last probe, not confirmed)"
    )


@pytest.mark.slow
def test_lint_mechanism_confirms_critical_2_bounded_outer_unbounded_inner() -> None:
    """End-to-end: the exact PoC from PR #580's review - the module's own docstring recommends
    bounding an outer quantifier as the fix for a nested-quantifier finding, which is exactly what
    silently reintroduces this bug if the inner quantifier is left unbounded."""
    pattern = r"(a+){1,30}b"
    assert L.is_suspect(pattern) is True
    # bounding only the outer repeat does not remove the ambiguity
    _assert_wall(_wall_outcome(pattern), pattern)


# ------------------------------------------------- stage 1: PR #580 round-4, the parenthesization gap
# Surfaced by PR #674's RCA for issue #673 (a real 90+ minute `agentsec audit` hang): a plain
# capture group wrapping exactly one quantified atom (`(.+?)`) was invisible to the adjacency scan
# above, because a bare `(` was treated as a run-resetting atom with no quantifier of its own, and
# every real instance of this shape in the guard corpus IS parenthesised (the whole point of the
# middle segment is to capture something - a binding clause, a call argument, a loop target).


@pytest.mark.parametrize(
    "pattern",
    [
        r"\s+(.+?)\s*=",  # the exact gap Dean's review found: clean before this fix
        r"\s+(?:.+?)\s*=",  # non-capturing group, same shape
        r"(?:const|let|var)\s+(.+?)\s*=\s*require\(",  # #673's actual hanging pattern (excerpt)
        r"import\s+(.+?)\s+from\s+",  # #673's sibling hanging pattern (excerpt)
        r"json\.loads\s*\(\s*(.+?)\s*\)",  # llm_json_output_unvalidated.py:71's shape
        r"\bfor\s+(?P<loop>[^\n=]*?)\s+in\s",  # path_traversal.py:147's shape (named group)
    ],
)
def test_is_suspect_flags_adjacent_quantifiers_through_a_capture_group(pattern: str) -> None:
    assert L.is_suspect(pattern) is True


@pytest.mark.slow
def test_lint_mechanism_confirms_parenthesized_adjacent_quantifiers() -> None:
    """End-to-end: a capture group wrapping a single quantified atom does not change the
    backtracking shape versus the ungrouped form at all - stage 2 must confirm the hang exactly
    like it does for the already-covered ungrouped case."""
    pattern = r"\s+(.+?)\s*="
    assert L.is_suspect(pattern) is True

    confirmed, elapsed = L.confirm_vulnerable(pattern, 0, timeout=L.DEFAULT_TIMEOUT)
    assert confirmed is True, (
        f"stage 2 must catch the parenthesized adjacent-quantifier PoC hanging (returned after "
        f"{elapsed:.2f}s at the last probe, not confirmed)"
    )


def test_is_suspect_does_not_flag_a_group_with_more_than_one_interior_atom() -> None:
    """Direction traded against: `(ab)` and `(a+b)` are groups too, but their interiors are not a
    SINGLE quantified atom (more than one piece, or no quantifier at all) - the group-transparency
    fix deliberately does not try to characterize these, so they fall back to the pre-existing
    per-character walk over the interior, unchanged."""
    assert L.is_suspect(r"\s+(ab)\s+") is False
    assert L.is_suspect(r"\s+(a)\s+") is False


def test_lint_mechanism_clears_adjacent_quantifiers_over_non_overlapping_classes() -> None:
    """Direction traded against: `\\s+\\d+` trips the new Critical-1 adjacency check (both `\\s+`
    and `\\d+` are unbounded and back-to-back - stage 1 is deliberately high recall, see
    `is_suspect`'s docstring), but it is actually linear-safe because whitespace and digit
    characters never overlap, so there is only one way to split the input between the two
    quantifiers. Stage 2 must clear it fast, same contract as the pre-existing
    `test_lint_mechanism_clears_a_pattern_that_only_looks_suspicious` case."""
    pattern = r"\s+\d+"
    assert L.is_suspect(pattern) is True

    confirmed, elapsed = L.confirm_vulnerable(pattern, 0, timeout=L.DEFAULT_TIMEOUT)
    assert confirmed is False, f"a linear-safe pattern must not be confirmed vulnerable ({elapsed:.2f}s)"
    assert_within(elapsed, _LINEAR_CLEAR_BUDGET, "adjacent non-overlapping quantifiers")


def test_lint_mechanism_clears_parenthesized_adjacency_over_non_overlapping_classes() -> None:
    """Direction traded against, stage 2, for the group-transparency fix above: `\\s+(\\d+?)\\s*`
    trips the new group-transparent adjacency check (both `\\s+` and the group's interior `\\d+?`
    are unbounded and back-to-back), but whitespace and digit characters never overlap, so it is
    actually linear-safe - same contract as
    `test_lint_mechanism_clears_adjacent_quantifiers_over_non_overlapping_classes` above, mirrored
    to the parenthesized case."""
    pattern = r"\s+(\d+?)\s*"
    assert L.is_suspect(pattern) is True

    confirmed, elapsed = L.confirm_vulnerable(pattern, 0, timeout=L.DEFAULT_TIMEOUT)
    assert confirmed is False, f"a linear-safe pattern must not be confirmed vulnerable ({elapsed:.2f}s)"
    assert_within(elapsed, _LINEAR_CLEAR_BUDGET, "group-transparent non-overlapping adjacency")


def test_is_suspect_flags_bounded_but_overlapping_group_interior() -> None:
    """Round-3 addendum, point (i): a BOUNDED inner quantifier is not evidence of safety on its
    own - `[^\\n;]{0,200}?` still overlaps `\\s+` on the space character (`[^\\n;]` excludes only
    newline and semicolon, so it matches a space too) and still backtracks quadratically on
    adversarial input. What actually removes the ambiguity is a DISJOINT first character
    (`[^\\s]`), not the `{0,n}` cap - a group-transparency check that only widened to
    `_is_unbounded` (matching a bare `+`/`*`) would still miss this exact trap;
    `_quantifier_repeatable` (unbounded OR upper bound > 1) is required in the group-transparent
    branch of `_contains_adjacent_unbounded_quantifiers`, same as it already is for the group-loop
    check below it."""
    assert L.is_suspect(r"\s+([^\n;]{0,200}?)\s*=") is True


@pytest.mark.slow
def test_lint_mechanism_confirms_bounded_but_overlapping_group_interior() -> None:
    """End-to-end companion to the test above - a bounded-but-overlapping inner quantifier through
    a transparent group is a genuine hang, not just a stage-1 over-flag (measured directly: this
    is confirmed via `confirm_vulnerable`'s growth classification, same as the unbounded
    `(.+?)` case)."""
    pattern = r"\s+([^\n;]{0,200}?)\s*="
    assert L.is_suspect(pattern) is True

    confirmed, elapsed = L.confirm_vulnerable(pattern, 0, timeout=L.DEFAULT_TIMEOUT)
    assert confirmed is True, (
        f"stage 2 must catch the bounded-but-overlapping group-interior pattern hanging (returned "
        f"after {elapsed:.2f}s, not confirmed) - a bound alone does not make this safe"
    )


@pytest.mark.slow
def test_lint_mechanism_confirms_the_real_corpus_hang_patterns() -> None:
    """The 4 real, currently-shipped guard patterns issue #673's RCA identified as exploitable but
    invisible to `is_suspect` before this fix - the EXACT text as it appears in
    `agentsec/guards/unsafe_deserialization.py` (`_JS_TYPES_CJS`/`_JS_TYPES_ESM`),
    `llm_json_output_unvalidated.py:71`, and `path_traversal.py:147`, not simplified stand-ins.

    Each carries a REQUIRED LITERAL PREFIX before its ambiguous run (`(?:const|let|var)\\s+`,
    `import\\s+`, `json\\.loads\\s*\\(\\s*`, `\\bfor\\s+`) - a probe built without satisfying that
    prefix never reaches the ambiguity at all (`.search()` fails the literal match at every string
    offset in linear time, a false 'not confirmed' that looks like safety but is really "the probe
    never got there"). `build_probe` now anchors its sample atom on where the flagged adjacency run
    actually starts (`_adjacent_unbounded_run_start`, not the first `_ATOM` match anywhere in the
    pattern text - which for `json\\.loads\\s*\\(\\s*(.+?)\\s*\\)` would incorrectly pick the
    UNRELATED `\\s*` between `loads` and the literal `\\(`) and prepends a best-effort
    literalization of everything before that run (`_literalize_prefix`).

    This class is also POLYNOMIAL, not exponential (Dean's #675 filing: "`_NESTED` models
    re-quantified exponential forms, and this class is polynomial"), so it needs a much larger `n`
    than the classic `(a+)+b` shape before its real slope is visible above ordinary subprocess-
    spawn noise (measured directly against `_JS_TYPES_CJS`: clears in ~2s at n=512, reliably times
    out by n=1024) - `_PROBE_MAX_N` was raised to 2048 (itself a member of the growth sequence, so
    it is actually reached) and `_run_probe_once` now uses the WORKER's own reported regex-only
    timing for the growth loop's early-exit ratio rather than the wall-clock round-trip through
    `subprocess.run`, so spawn overhead can no longer be mistaken for "this pattern is linear"
    before growth ever reaches the `n` where the real slope would have shown up."""
    real_patterns = [
        r"""(?:const|let|var)\s+(.+?)\s*=\s*require\(\s*['"]js-yaml-js-types['"]""",
        r"""import\s+(.+?)\s+from\s+['"]js-yaml-js-types['"]""",
        r"json\.loads\s*\(\s*(.+?)\s*\)",
        r"\bfor\s+(?P<loop>[^\n=]*?)\s+in\s",
    ]
    for pattern in real_patterns:
        assert L.is_suspect(pattern) is True, f"stage 1 must flag {pattern!r}"
        o = L._confirm_outcome(pattern, 0)
        assert o.confirmed is True, (
            f"stage 2 must catch {pattern!r} hanging (returned after {o.elapsed:.2f}s instead of "
            "not confirmed) - this is a real pattern from agentsec's own guard corpus, exploitable "
            "per issue #673's RCA (90+ minutes on a 281KB real-world file). Evidence: "
            f"readings={list(o.readings)} ratios="
            f"{[round(r, 2) for r in L._growth_ratios([s for _, s in o.readings])]} "
            f"growth={o.growth} refused={o.refused} timed_out={o.timed_out}"
        )


def test_literalize_prefix_renders_plain_and_escaped_literals() -> None:
    """Sanity-check `_literalize_prefix` directly against the literal-prefix shapes the real
    corpus patterns above actually need, not just trusting the end-to-end `confirm_vulnerable`
    result above to prove it works."""
    assert L._literalize_prefix("json") == "json"
    assert L._literalize_prefix(r"json\.loads\(") == "json.loads("
    assert L._literalize_prefix(r"(?:const|let|var)") == "const"


def test_literalize_prefix_bails_on_unresolvable_fragments() -> None:
    """A fragment too ambiguous for this narrow resolver to answer confidently must return `None`
    (the caller then falls back to no prefix at all - a weaker probe that may under-confirm, never
    a false 'confirmed vulnerable') rather than guess wrong and build a probe that can never
    match."""
    assert L._literalize_prefix("a|b") is None  # top-level alternation
    assert L._literalize_prefix("(?=lookahead)") is None  # lookaround assertion


# ------------------------------------------------------- stage 1/2: PR #580 round-2 review, High
# The mirror image of Critical 2: round-1 fixed a bounded-but-repeatable OUTER quantifier over an
# unbounded inner one (`(a+){1,30}b`). The same ambiguity exists with the bound on the OTHER side
# of the nesting - an unbounded OUTER quantifier over a bounded-but-repeatable INNER one.


def test_is_suspect_flags_unbounded_outer_with_bounded_repeatable_inner_quantifier() -> None:
    """High: `{1,5}` bounds the INNER repeat, but it still allows more than one match (1 to 5
    characters), so the unbounded OUTER `+` can still partition the same run of `a`s across its
    repeats in exponentially many ways - the group's outer trailing quantifier being unbounded is
    exactly the shape `is_suspect`'s group loop scans for."""
    assert L.is_suspect(r"(a{1,5})+b") is True


def test_is_suspect_does_not_flag_inner_quantifier_bounded_to_exactly_one() -> None:
    """Direction traded against: `{1,1}` (and its `{1}` equivalent) caps the inner repeat at
    exactly one match, removing the partition ambiguity entirely - same reasoning as the existing
    `(a+){1}b`/`(a+){0,1}b` outer-position cases, mirrored to the inner position."""
    assert L.is_suspect(r"(a{1,1})+b") is False


@pytest.mark.slow
def test_lint_mechanism_confirms_bounded_repeatable_inner_under_unbounded_outer() -> None:
    """End-to-end: the exact PoC from PR #580's round-2 review - stage 1 now flags it, and stage
    2's real subprocess timing run confirms the hang."""
    pattern = r"(a{1,5})+b"
    assert L.is_suspect(pattern) is True
    # a bounded-but-repeatable inner quantifier under an unbounded outer one has the same
    # partition ambiguity as the outer-position case Critical 2 fixed
    _assert_wall(_wall_outcome(pattern), pattern)


# ---------------------------------------------------- stage 2: PR #580 round-2 review, Medium
# "A crashed worker is indistinguishable from a safe pattern" - the old `confirm_vulnerable`
# read ANY non-timeout subprocess exit as "did not time out", silently turning a real crash (a
# pattern the worker's `re.compile` rejects, an import failure, an OOM kill) into a false "not
# vulnerable". `_run_probe_once` now raises instead.


def test_run_probe_once_raises_on_worker_crash_rather_than_reporting_safe() -> None:
    """An unbalanced paren is a valid Python string but an invalid regex - `re.compile` raises
    inside the worker subprocess, which must surface as a loud failure, not a quiet 'cleared'."""
    with pytest.raises(RuntimeError, match="stage-2 worker crashed"):
        L._run_probe_once("(", 0, "aaa", timeout=L.DEFAULT_TIMEOUT)


# --------------------------------------------------------------------------- stage 2: not vacuous
# Requirement: prove the lint mechanism itself works end-to-end, not just that stage 1's string
# heuristic returns a bool - feed it a deliberately pathological pattern and confirm BOTH that
# stage 1 flags it AND that stage 2's subprocess-timeout run actually catches the resulting hang.


@pytest.mark.slow
def test_lint_mechanism_catches_a_deliberately_evil_pattern() -> None:
    pattern = r"(a+)+b"
    assert L.is_suspect(pattern) is True, "stage 1 must flag the textbook evil regex"
    # the lint mechanism would be vacuous if stage 2 did not catch this one
    _assert_wall(_wall_outcome(pattern), pattern)


def test_lint_mechanism_clears_a_pattern_that_only_looks_suspicious() -> None:
    """`(?:\\.\\d+)*` trips stage 1 (an inner `+` inside a repeated group - see `is_suspect`'s
    docstring on why stage 1 is deliberately high-recall), but it is actually linear-safe: the
    literal `\\.` anchors every iteration, so iterations can't overlap. Stage 2 must clear it fast
    - this is the precision half of the two-stage design, proven end-to-end."""
    pattern = r"(?:\.\d+)*"
    assert L.is_suspect(pattern) is True

    confirmed, elapsed = L.confirm_vulnerable(pattern, 0, timeout=L.DEFAULT_TIMEOUT)
    assert confirmed is False, f"a linear-safe pattern must not be confirmed vulnerable ({elapsed:.2f}s)"
    assert_within(elapsed, _LINEAR_CLEAR_BUDGET, "literal-anchored repeated group")


@pytest.mark.slow
def test_lint_end_to_end_via_lint_function() -> None:
    """The same two cases, run through the actual `lint()` driver (not the stage functions
    directly) - proves the wiring between stage 1 and stage 2, and the `LintResult` shape, work
    together the way the CI gate below relies on."""
    sites = [
        L.PatternSite(module="t", file=Path("t.py"), line=1, name="EVIL", pattern=r"(a+)+b", flags=0),
        L.PatternSite(module="t", file=Path("t.py"), line=2, name="FINE", pattern=r"[a-z]+", flags=0),
    ]
    results = L.lint(sites, timeout=_WALL_TIMEOUT)
    if not results[0].readings or results[0].resampled:  # spawn starvation, not the wall (`_wall_outcome`)
        results = L.lint(sites, timeout=L.DEFAULT_TIMEOUT)
    by_name = {r.site.name: r for r in results}

    assert by_name["FINE"].suspect is False
    assert by_name["FINE"].confirmed_vulnerable is False

    assert by_name["EVIL"].suspect is True
    assert by_name["EVIL"].confirmed_vulnerable is True
    evil = by_name["EVIL"]
    _assert_wall(
        L.Stage2Outcome(confirmed=evil.confirmed_vulnerable, elapsed=evil.elapsed, growth=evil.growth,
                        readings=evil.readings, refused=evil.refused, timed_out=evil.timed_out,
                        resampled=evil.resampled),
        "EVIL via lint()",
    )


@pytest.mark.slow
def test_lint_parallel_confirmations_match_serial_verdicts_in_site_order() -> None:
    """Stage-2 confirmations run on a thread pool now (the ci-parallel plan, phase 3). The two
    properties that parallelism could break, pinned:

    1. Verdict parity with the serial driver - the direction traded against here is a SAFE
       suspect flipping to a false CONFIRMED under pool contention (a starved probe crossing the
       wall-clock deadline), so both patterns are stage-1 suspects that stage 2 must CLEAR; the
       confirmed=True path through `lint()` is covered by the end-to-end test above.
    2. Site-order stability - results must join back in input order, never completion order
       (the report's byte-stability across runs depends on it), and a duplicated suspect must
       still share its single confirmation (the dedup contract in `lint()`'s docstring)."""
    safe_a = r"\s+\d+"
    safe_b = r"\s+(\d+?)\s*"
    sites = [
        L.PatternSite(module="t", file=Path("t.py"), line=1, name="SAFE_A", pattern=safe_a, flags=0),
        L.PatternSite(module="t", file=Path("t.py"), line=2, name="FINE", pattern=r"[a-z]+", flags=0),
        L.PatternSite(module="t", file=Path("t.py"), line=3, name="SAFE_B", pattern=safe_b, flags=0),
        L.PatternSite(module="t", file=Path("t.py"), line=4, name="SAFE_A_DUP", pattern=safe_a, flags=0),
    ]

    results = L.lint(sites, timeout=L.DEFAULT_TIMEOUT)

    # site order, not completion order
    assert [r.site.name for r in results] == ["SAFE_A", "FINE", "SAFE_B", "SAFE_A_DUP"]

    by_name = {r.site.name: r for r in results}
    assert by_name["FINE"].suspect is False

    # verdict parity with a direct (serial) confirmation of each unique suspect
    for name, pattern in (("SAFE_A", safe_a), ("SAFE_B", safe_b)):
        serial = L._confirm_outcome(pattern, 0, timeout=L.DEFAULT_TIMEOUT)
        pooled = by_name[name]
        assert pooled.suspect is True
        assert pooled.confirmed_vulnerable is serial.confirmed is False, (
            f"{name} is linear-safe; the pooled driver must clear it exactly as the serial one "
            f"does. Pooled evidence: readings={list(pooled.readings)} growth={pooled.growth} "
            f"refused={pooled.refused} timed_out={pooled.timed_out} "
            f"resampled={pooled.resampled}; serial evidence: "
            f"readings={list(serial.readings)} growth={serial.growth} "
            f"refused={serial.refused} timed_out={serial.timed_out} resampled={serial.resampled}"
        )

    # the duplicate shares its first occurrence's single confirmation (same cached tuple)
    assert by_name["SAFE_A_DUP"].confirmed_vulnerable == by_name["SAFE_A"].confirmed_vulnerable
    assert by_name["SAFE_A_DUP"].elapsed == by_name["SAFE_A"].elapsed


# ------------------------------------------------------- stage-2 pool width vs. pytest-xdist
#
# `_probe_workers` sizes the stage-2 thread pool, and its whole job is to keep every probe
# subprocess on a core of its own - because per-probe wall-clock elapsed IS the verdict, so a
# starved-but-safe pattern crossing `DEFAULT_TIMEOUT` reads as a false CONFIRMED. Not a flake: a
# safe guard regex reported as catastrophically vulnerable.
#
# It used to read `os.cpu_count()` and nothing else, which is the machine's core count rather than
# this process's share of it. Under `pytest -n auto` that is wrong by the worker count - a 4-thread
# pool on an 8-core box that already has 7 sibling pytest workers on it - and wrong in the
# direction that manufactures the false CONFIRMED. These pin both the arithmetic and the invariant
# the pool constructor depends on.


def _pool_width(monkeypatch: pytest.MonkeyPatch, *, cores: int, lanes: int | str | None) -> int:
    """`_probe_workers()` as seen on a box with `cores` cores and `lanes` sibling pytest workers.

    `L.os` is swapped rather than the stdlib `os` module, so the fake cannot leak into anything
    else in the process (the seam `tests/test_complexity_probe.py::_FakeClock` uses). Only
    `_probe_workers` and `_xdist_worker_count` read `os` in this module, so the namespace below is
    the whole surface.
    """
    env = dict(os.environ)
    env.pop("PYTEST_XDIST_WORKER_COUNT", None)
    if lanes is not None:
        env["PYTEST_XDIST_WORKER_COUNT"] = str(lanes)
    monkeypatch.setattr(L, "os", SimpleNamespace(cpu_count=lambda: cores, environ=env))
    return int(L._probe_workers())


@pytest.mark.parametrize(
    ("cores", "expected"),
    [(1, 2), (2, 2), (4, 2), (8, 4), (16, 8), (64, 8)],  # floor 2, half, cap _MAX_PROBE_WORKERS
)
def test_probe_pool_is_half_the_cores_when_this_process_has_the_machine(
    monkeypatch: pytest.MonkeyPatch, cores: int, expected: int
) -> None:
    """The unchanged path: the CLI, the pre-commit hook, and a serial pytest run all land here.

    This is the FP-bait direction for the xdist change below - narrowing the pool under xdist must
    not quietly narrow it for the ordinary standalone run, where nothing else is on the box and the
    parallelism is what keeps the corpus gate cheap.
    """
    assert _pool_width(monkeypatch, cores=cores, lanes=None) == expected


@pytest.mark.parametrize(
    ("cores", "lanes", "expected"),
    [
        (8, 2, 2),  # 8//2 = 4 available, half of that
        (8, 4, 1),  # 8//4 = 2 available, half rounds to 1
        (8, 8, 1),  # `-n auto` on this box: one core's share, so confirmations go serial
        (64, 4, 8),  # still capped by _MAX_PROBE_WORKERS
        (2, 8, 1),  # more workers than cores: the floor, never zero
    ],
)
def test_probe_pool_shrinks_to_this_processes_share_under_xdist(
    monkeypatch: pytest.MonkeyPatch, cores: int, lanes: int, expected: int
) -> None:
    assert _pool_width(monkeypatch, cores=cores, lanes=lanes) == expected


def test_a_single_xdist_lane_is_indistinguishable_from_no_xdist() -> None:
    """`-n 1` still sets the variable. One lane is the whole machine, so it must take the
    standalone branch rather than halving a budget that has nothing to share with."""
    # asserted through the helper on both spellings so the boundary is pinned, not assumed
    with pytest.MonkeyPatch.context() as mp:
        assert _pool_width(mp, cores=8, lanes=1) == _pool_width(mp, cores=8, lanes=None) == 4


@pytest.mark.parametrize("raw", ["", "   ", "abc", "3.5", "-3", "0"])
def test_a_malformed_xdist_worker_count_degrades_instead_of_raising(
    monkeypatch: pytest.MonkeyPatch, raw: str
) -> None:
    """The variable is only ever written by the plugin, but a lint run is not a pytest run and must
    not be able to die on a stray environment value. Every unreadable spelling means "assume this
    process has the machine", which is the pre-existing behaviour."""
    assert _pool_width(monkeypatch, cores=8, lanes=raw) == 4


@pytest.mark.parametrize("cores", [0, 1, 2, 3, 8, 64])
@pytest.mark.parametrize("lanes", [None, 1, 2, 7, 8, 32, 1000])
def test_the_pool_width_is_always_a_legal_thread_pool_size(
    monkeypatch: pytest.MonkeyPatch, cores: int, lanes: int | None
) -> None:
    """The direction traded against, and the reason the floor is 1 rather than 0.

    Narrowing the pool is the safe direction for the VERDICT, but `lint()` feeds this straight into
    `ThreadPoolExecutor(max_workers=...)`, which raises `ValueError` at zero or below. A narrowing
    that turned the corpus gate into a crash would be a worse bug than the one it fixed, so the
    invariant is asserted across the degenerate boxes, not reasoned about.
    """
    width = _pool_width(monkeypatch, cores=cores, lanes=lanes)
    assert width >= 1, "a zero-width pool raises ValueError out of lint()"
    assert width <= L._MAX_PROBE_WORKERS
    with ThreadPoolExecutor(max_workers=width):  # the real constructor, not a proxy for it
        pass


@pytest.mark.slow
def test_lint_verdicts_are_identical_at_the_narrowed_xdist_pool_width() -> None:
    """Rule 1 end-to-end: the narrowing must change only the SPEED, never the verdicts.

    `lint()` is the thing the corpus gate calls, so parity is asserted through it rather than
    through `_probe_workers` alone - a pool width that changed which patterns clear stage 2 would
    be the false CONFIRMED this whole area exists to prevent, just arriving by a different route.
    """
    safe_a = r"\s+\d+"
    safe_b = r"\s+(\d+?)\s*"
    sites = [
        L.PatternSite(module="t", file=Path("t.py"), line=1, name="SAFE_A", pattern=safe_a, flags=0),
        L.PatternSite(module="t", file=Path("t.py"), line=2, name="FINE", pattern=r"[a-z]+", flags=0),
        L.PatternSite(module="t", file=Path("t.py"), line=3, name="SAFE_B", pattern=safe_b, flags=0),
    ]

    def outcomes(lanes: int | None) -> list[L.LintResult]:
        with pytest.MonkeyPatch.context() as mp:
            env = dict(os.environ)
            env.pop("PYTEST_XDIST_WORKER_COUNT", None)
            if lanes is not None:
                env["PYTEST_XDIST_WORKER_COUNT"] = str(lanes)
            mp.setattr(L, "os", SimpleNamespace(cpu_count=lambda: 8, environ=env))
            return L.lint(sites)

    def evidence(r: L.LintResult) -> str:
        return (f"readings={list(r.readings)} growth={r.growth} refused={r.refused} "
                f"timed_out={r.timed_out} resampled={r.resampled}")

    wide_r = outcomes(None)  # 4 workers
    narrow_r = outcomes(8)  # 1 worker, the `-n auto` share on an 8-core box
    wide = [(r.site.name, r.suspect, r.confirmed_vulnerable) for r in wide_r]
    narrow = [(r.site.name, r.suspect, r.confirmed_vulnerable) for r in narrow_r]
    # The evidence chain on a mismatch, so a contention-induced false CONFIRMED is diagnosable
    # from the CI log instead of inferred from the decision rule (#831 was inferred).
    assert wide == narrow, "the xdist-narrowed pool changed a stage-2 verdict:\n" + "\n".join(
        f"  {w.site.name}: wide {evidence(w)}\n  {w.site.name}: narrow {evidence(n)}"
        for w, n in zip(wide_r, narrow_r, strict=True)
        if w.confirmed_vulnerable != n.confirmed_vulnerable
    )
    assert [name for name, suspect, _ in wide if suspect] == ["SAFE_A", "SAFE_B"], (
        "both suspects must still reach stage 2 — parity over an empty suspect set proves nothing"
    )
    assert not any(confirmed for _, _, confirmed in wide), "these patterns are linear-safe"


# --------------------------------------------------------------------------- discovery sanity


def test_collect_all_patterns_finds_real_patterns() -> None:
    """A floor, not an exact count (`agentsec/guards/*.py` grows over time) - the point is that
    discovery actually walks real guard source and extracts real patterns, not that it silently
    returns an empty list and the gate below passes vacuously (the 'failure that presents as
    success' category CLAUDE.md calls out - assert the artifact, not just that nothing crashed)."""
    sites = L.collect_all_patterns()
    assert len(sites) > 500
    # spot-check: a pattern known to live in agentsec/guards/command_injection.py should be found
    assert any(s.module == "agentsec.guards.command_injection" for s in sites)


# ------------------------------------------------------------- discovery: round-3 review, High
# The coverage claim ("N patterns scanned") was silently missing an unknown-sized slice: 8 fully-
# static, security-critical constants (cross-module imports, function-call composition) failed to
# resolve for reasons the module docstring never described, with zero disclosure anywhere in the
# tool's output. `unresolved_site_count()` makes that gap a visible, trackable number instead.


def test_unresolved_site_count_matches_a_direct_ast_count() -> None:
    """Sanity-check `unresolved_site_count`/`count_re_calls` against an independent, from-scratch
    AST walk over one real guard file - not just trusting the two functions agree with each other
    by construction."""
    import ast

    path = L.GUARDS_DIR / "base.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    direct_count = sum(
        1
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in L._RE_METHODS
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "re"
    )
    assert L.count_re_calls(path) == direct_count
    assert direct_count > 0  # base.py is known to define several re.compile sites


def test_unresolved_site_count_stays_within_budget() -> None:
    """Round-3 review, High: discovery silently dropped 8 fully-static regex constants (cross-
    module imports, function-call composition) via two undocumented resolver gaps, with zero
    disclosure. This asserts the SIZE of the unresolved-site gap, not any specific guard's
    pattern - a regression here (a new constant silently falling into the same undocumented gap)
    fails CI as a number instead of vanishing into "N scanned, 0 vulnerable". The budget is set
    well above the count measured when this test was written (44), not exact-pinned, so ordinary
    ADDITIONS to the well-understood, genuinely-dynamic per-call class (the module docstring's
    documented, accepted limitation) don't make this test flaky - only a jump large enough to
    suggest a NEW static constant fell into the undocumented gap should trip it."""
    unresolved = L.unresolved_site_count()
    # 90 -> 91 (#1041, #872): main had grown to exactly 90, and #872 adds one site of the module
    # docstring's SECOND class, `base.py::PER_ROUTE_PRIV_FACTORY` (built on `_PRIV_NAME =
    # boundaried_stems(...)`). Looked at before absorbing, as asked: it is fully static, and since
    # this linter cannot scan it, its backtracking is pinned by its own growth test instead
    # (`test_per_route_priv_factory_is_linear_on_a_stem_dense_identifier`). The moved
    # `PER_ROUTE_AUTH_FACTORY` nets to zero (it left `auth_dependency_not_applied.py`).
    # 91 -> 93 with the aisbom research-cycle batch (2026-10-08): +2 from
    # ml_gguf_template_injection.py's `_word_pattern`/`_call_pattern` helpers, which build a
    # pattern via `re.escape(token) +` string concatenation over a small fixed internal token
    # list (Jinja SSTI escape/call names) -- exactly the documented, accepted "genuinely-dynamic
    # per-call class" above, not a new undocumented gap (verified: both call sites traced by hand
    # via extract_pattern_sites()/count_re_calls() against that one file before raising this).
    # 93 -> 94 with the sonar-iac research-cycle batch (2026-10-25): +1 from
    # s3_mfa_delete_disabled.py's `_bucket_ref_pattern`-shaped helper
    # (`re.compile(rf"(?m)^\s*bucket\s*=\s*aws_s3_bucket\.{re.escape(bucket_name)}\.")`),
    # deliberately mirroring aws_observability_hygiene.py's own pre-existing helper of the exact
    # same shape (already one of this budget's 93) -- a per-call pattern built from a function
    # parameter, always wrapped in `re.escape()`, the same documented genuinely-dynamic class
    # above, traced by hand via extract_pattern_sites()/count_re_calls() before raising this.
    # 94 -> 95 with the sonar-iac batch's round-1 H6 fix (new helper, `base.py::literal_bool_state`,
    # re.escape()-wrapped per round-2 review H-2): `re.search(rf'\b{re.escape(attr)}\s*=\s*"?([A-Za-z_][\w.]*)"?',
    # text)` builds its pattern from the `attr` parameter -- a per-call pattern built from a
    # function parameter, always wrapped in `re.escape()`, the same documented genuinely-dynamic
    # class above, traced by hand via extract_pattern_sites()/count_re_calls() before raising this.
    budget = 95
    assert unresolved <= budget, (
        f"{unresolved} call sites are unresolved by extract_pattern_sites, more than the budget "
        f"of {budget} - a new resolver gap (or a shrinking one worth lowering this budget) needs "
        f"a look before this is silently absorbed. See the module docstring's two documented "
        f"unresolved classes."
    )


def test_report_discloses_unresolved_site_count() -> None:
    """The CLI/report output itself must say the gap exists, not just the library function - a
    human running `python scripts/lint_regex_redos.py` by hand, without reading this test file or
    the module docstring, needs to see this number too.

    Uses a small synthetic `results` list rather than running `lint()` over the real corpus -
    `report()`'s disclosure line is independent of what was scanned, and running the real corpus's
    ~200+ SUSPECT patterns through stage 2 here would make this an accidental second copy of the
    slow-marked CI gate below, in a test function that isn't marked `slow` (this repo's own Rule 5:
    a scan-everything cost must be `slow`-marked, not merely fast-seeming from its name)."""
    import contextlib
    import io

    results = [
        L.LintResult(
            site=L.PatternSite(module="t", file=Path("t.py"), line=1, name="FINE", pattern=r"[a-z]+", flags=0),
            suspect=False,
            confirmed_vulnerable=False,
            elapsed=0.0,
        )
    ]
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        L.report(results, unresolved=7)
    assert "7 call site(s) could not be statically resolved" in buf.getvalue()

    buf_zero = io.StringIO()
    with contextlib.redirect_stdout(buf_zero):
        L.report(results, unresolved=0)
    assert "could not be statically resolved" not in buf_zero.getvalue()


# --------------------------------------------------------------------------- the CI gate


# This value is COUPLED to `timeout-minutes` on the windows leg in ci.yml, same as the self-audit
# test's own marker (see that test's comment, `tests/test_self_audit.py`) - a per-test timeout can
# only fire if it fits inside what the job has left after the rest of the suite; raising one
# without checking the other makes it decorative (pyproject.toml's `[tool.pytest.ini_options]`
# `timeout` comment). 360s is smaller than the self-audit test's own marker (this is
# subprocess-timed regex confirmation, not a full audit pipeline run), and both fit inside the
# windows leg's `timeout-minutes` with the rest of the suite stacked on top.
#
# WHY 360 and not the 180 it was: on the self-hosted Windows leg (`-n auto --dist worksteal`, 8
# workers on 8 cores) `_probe_workers` floors the stage-2 pool at 1, so ~380 probe subprocesses
# run one after another on a saturated machine. Measured 2026-10-22 on that runner by hand, CI idle,
# main @ 8d743801 (412 suspects): 168.7s under the CI command, 98.7s at `-n 3`, 94.7s for `lint()`
# alone at the `-n 3` pool width. Real CI runs measure ~1.2x the by-hand time (ci.yml's own
# comment), so ~200s against 180: the leg failed on most runs that day with "worker crashed" and no
# message, which is how a pytest-timeout kill presents under xdist on Windows (reproduced there
# with a 20s marker). The cost grew with the suspect count and the 2026-10-12 worksteal change that
# runs this test beside the others, not with any single pattern. 360 is ~1.8x the CI estimate.
#
# 2026-10-23, the settled-top-step skip (`_WORKER_SRC`): the same by-hand winci measurement under the
# CI command fell from 168.7s to 41.0s (one round, CI idle; Linux `-n 3`: 52s -> 15s), because 77% of
# stage 2 was the n=8192 step of ~35 safe quadratic patterns that the decision rule then discarded.
# The marker stays at 360 on purpose: one round is not the three alternated ones ci.yml's protocol
# asks for before a budget moves, and a marker that is not hit costs nothing. Re-measure before
# lowering it; the cost still scales with the suspect count.
#
# WHY this needs its own marker now, when it did not before: this is a scan-everything test whose
# cost scales with the SUSPECT count (round-3 review's own documented trade, `is_suspect`'s
# docstring - "SUSPECT count therefore scales with corpus size... CI cost scales with it too"), and
# the round-3 fix widened stage 1 twice over: once to close the parenthesized-group false-negative
# (the whole point of this round), and that alone moved SUSPECT from 128 to 222 measured against
# the current corpus. The default 120s budget was already tight at 128; it is not enough at 222,
# particularly on a loaded machine where `subprocess.run` spawn cost (not the regex work itself)
# dominates - see `DEFAULT_TIMEOUT`'s own comment for the measurements that motivated raising it.
@pytest.mark.timeout(360)
@pytest.mark.slow
def test_no_guard_pattern_is_confirmed_vulnerable() -> None:
    """The permanent safety net: every regex pattern actually used across `agentsec/guards/*.py`
    must not be confirmed vulnerable to catastrophic backtracking.

    `slow`-marked per this repo's convention for scan-everything tests (dominates wall-clock,
    not a correctness-tier gate distinction - see `pyproject.toml`'s `markers` entry): stage 1 is
    cheap over the whole corpus, but stage 2 subprocess-confirms every pattern stage 1 flags, and
    that dominates the runtime. Always included in the full gate (`pytest -q`, mandatory before
    push), just excluded from the fast `-m "not slow"` dev loop.

    This USED TO spuriously flag an otherwise-quadratic-not-catastrophic pattern on a heavily
    loaded machine - `rls_update_privileged_column.py`'s `_TO_CLAUSE` was the known victim -
    because stage 2 took its verdict from whether one subprocess outlived a flat deadline, which
    contention alone can decide. That was issue #762, and it is fixed at the source rather than
    documented around here: `confirm_vulnerable` now classifies the GROWTH of the probe series,
    and a slow or contended machine scales every reading together so it cancels out of a ratio.
    Reproduced on the loaded Windows CI guest before and after: `_TO_CLAUSE` exceeded the 10s
    deadline (old rule: CONFIRMED VULNERABLE) while completing 5 of 6 probes, which is 2-3 usable
    ratios classifying `quadratic` (new rule: cleared, correctly).

    So a failure here should now be read as a real finding first. If this test ever does need
    excluding for one run, verify the same pattern reproduces identically on `origin/main`
    unmodified before treating it as pre-existing - a bare exclusion with no record of why is
    exactly the failure this note exists to prevent.
    """
    sites = L.collect_all_patterns()
    results = L.lint(sites)
    vulnerable = [r for r in results if r.confirmed_vulnerable]
    assert not vulnerable, "confirmed-vulnerable regex pattern(s) in agentsec/guards - fix the shape:\n" + "\n".join(
        f"  {r.site.module}:{r.site.line} ({r.site.name}): {r.site.pattern!r}\n"
        f"    evidence: readings={list(r.readings)} growth={r.growth} "
        f"refused={r.refused} timed_out={r.timed_out} resampled={r.resampled}"
        for r in vulnerable
    )


# --- the growth classifier (issue #762) --------------------------------------------------------
#
# Stage 2's verdict is the growth SHAPE of the probe series, not whether one subprocess outlived
# a deadline. These tests cover both directions per CLAUDE.md rule 1: the change is simultaneously
# a NARROWING (a killed batch can now be cleared) and a WIDENING (a finished batch can now be
# confirmed), so each needs the opposite direction asserted.


def _probe_module() -> ModuleType:
    """`scripts/complexity_probe.py`, loaded the same by-path way as the lint script above."""
    spec = importlib.util.spec_from_file_location(
        "complexity_probe", _REPO / "scripts" / "complexity_probe.py"
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["complexity_probe"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_growth_constants_match_complexity_probe() -> None:
    """The lint's classification constants are a COPY of `complexity_probe`'s, because the stage-2
    worker is a `python -S -c` source string that cannot import from this repo. A copy drifts
    silently unless something pins it - this is that pin (plan task 4)."""
    cp = _probe_module()
    assert L.NOISE_FLOOR == cp.NOISE_FLOOR
    assert L._UNMEASURED_EXPONENT == cp._UNMEASURED_EXPONENT
    assert L._LINEAR_MAX == cp._LINEAR_MAX
    assert L._QUADRATIC_MAX == cp._QUADRATIC_MAX
    assert L._WORKER_REPEATS == cp.DEFAULT_REPEATS
    assert L._REPEAT_BELOW == cp._REPEAT_BELOW


@pytest.mark.parametrize(
    "elapsed",
    [
        [0.001, 0.004, 0.016, 0.064],       # linear at m=4
        [0.001, 0.016, 0.256, 4.096],       # quadratic at m=4
        [0.001, 0.064, 4.096, 262.144],     # cubic at m=4
        [0.001, 0.004, 0.016],              # exactly two ratios: the floor `classify` allows
        [1e-9, 1e-8, 0.5, 8.0],             # sub-noise baselines that must be dropped
        [0.0, 0.0, 0.0, 0.0],               # all-zero: no ratio survives
        # Two SURVIVING ratios whose median is zero. The all-zero row above cannot reach this:
        # its baselines are under NOISE_FLOOR, so every ratio is dropped and both sides
        # short-circuit on `len(ratios) < 2` without ever taking a median. Only a series that
        # alternates above and below the floor gets real ratios of 0.0 into `median`, which is
        # where the copy used to raise `math domain error` while the original returned a verdict
        # (PR #767, F2 - the gap that made this drift test a partial pin rather than a real one).
        [0.001, 0.0, 0.001, 0.0],
    ],
)
def test_growth_ratios_and_classify_agree_with_complexity_probe(elapsed: list[float]) -> None:
    """The lint's `_growth_ratios`/`_classify` must answer identically to the originals.

    Anti-vacuity: the table above is asserted to actually exercise more than one class, so a
    future edit that made every case `indeterminate` could not quietly pass this test."""
    cp = _probe_module()
    assert L._growth_ratios(elapsed) == cp.growth_ratios(elapsed)
    mine = L._classify(L._growth_ratios(elapsed), 4)
    theirs = (
        cp.classify(cp.growth_ratios(elapsed), 4)
        if len(cp.growth_ratios(elapsed)) >= 2
        else "indeterminate"
    )
    assert mine == theirs


def test_the_classifier_agreement_table_is_not_vacuous() -> None:
    """Anti-vacuity guard for the parametrized test above: the table must actually span classes,
    or the agreement it asserts would be trivially true and would stop protecting anything."""
    tables = [
        [0.001, 0.004, 0.016, 0.064],
        [0.001, 0.016, 0.256, 4.096],
        [0.001, 0.064, 4.096, 262.144],
        [0.0, 0.0, 0.0, 0.0],
    ]
    classes = {L._classify(L._growth_ratios(e), 4) for e in tables}
    assert {"linear", "quadratic", "cubic-or-worse", "indeterminate"} <= classes


def test_classify_refuses_a_verdict_on_a_single_ratio() -> None:
    """One ratio is a single measurement pair with nothing to cross-check it. This module's own
    round-3 history is that trusting one is how a real catastrophic pattern read as linear."""
    assert L._classify([64.0], 4) == "indeterminate"
    assert L._classify([64.0, 64.0], 4) == "cubic-or-worse"


def test_decode_stream_normalizes_every_shape_the_platforms_return() -> None:
    """`TimeoutExpired.stdout` is `bytes` on Linux and `str` on Windows from the identical call,
    and `None` vs `''` when nothing was flushed. All four measured, not assumed - a parser
    written against one platform breaks on the other."""
    assert L._decode_stream(b'[8, 0.5]\n') == "[8, 0.5]\n"
    assert L._decode_stream("[8, 0.5]\n") == "[8, 0.5]\n"
    assert L._decode_stream(None) == ""
    assert L._decode_stream("") == ""
    # A kill can land mid-character; a truncated UTF-8 sequence must not raise.
    assert L._decode_stream(b"[8, 0.5]\n\xff") is not None


def test_parse_worker_stream_keeps_readings_and_discards_a_torn_line() -> None:
    """A kill can land mid-write, leaving a truncated trailing JSON line. Reproduced on both
    platforms. It must be discarded, never guessed at - a misparsed fragment would put a
    fabricated number into a security verdict's evidence."""
    obs, refused = L._parse_worker_stream('[8, 0.001]\n[32, 0.016]\n[128, 0.2')
    assert obs == [(8, 0.001), (32, 0.016)]
    assert refused is None


def test_parse_worker_stream_reports_a_refusal_only_when_the_exponent_was_measured() -> None:
    """A refusal computed from `_UNMEASURED_EXPONENT` is arithmetic on a guess. It must not reach
    a verdict wearing the same clothes as a measurement, so only the measured flag is honoured."""
    _obs, measured = L._parse_worker_stream('[8, 0.001]\n["skipped", 32, 6.19, true]')
    assert measured == pytest.approx(6.19)
    _obs, guessed = L._parse_worker_stream('[8, 0.001]\n["skipped", 32, 3.0, false]')
    assert guessed is None


def test_parse_worker_stream_ignores_junk_without_raising() -> None:
    """`parse` must be total over unexpected shapes, the same contract runners' parsers carry."""
    obs, refused = L._parse_worker_stream('not json\n{}\n[]\n[1,2,3]\n["skipped"]\n[8, 0.5]\n')
    assert obs == [(8, 0.5)]
    assert refused is None


# --- the stage-2 decision table, driven directly (PR #767, F4) ----------------------------------
#
# Everything above reaches `confirm_vulnerable` through a real regex under a real clock, which is
# the right way to test that the PROBES work but the wrong way to test what the VERDICT RULE does
# with them: a row of the table is only exercised if some real pattern happens to produce that
# shape on this box, and measured against the real guard corpus most of them never do (229 stage-2
# runs: zero timed out, zero produced a refusal). So the #762 fix itself - a killed batch clearing
# because its shape is quadratic - had no test that would go red if the row were reverted.
#
# `_run_probe_batch` is the seam: it returns exactly `(timed_out, observations, refused_exponent)`,
# so feeding synthetic triples through it exercises the rule with no clock, no subprocess and no
# dependence on how busy the machine is. Both review findings this table exists because of (F1's
# false negative, F3's discarded refusal) are shapes a real pattern did not produce here.


_Batch = tuple[bool, list[tuple[int, float]], float | None]  # what `_run_probe_batch` returns


def _stub_batches(monkeypatch: pytest.MonkeyPatch, *samples: _Batch) -> list[int]:
    """Feed `samples` to successive `_run_probe_batch` calls; the LAST one repeats for any
    further call, the way a synthetic pattern reproduces its own shape. Returns the call log,
    so a test can assert how many samples a verdict consumed (#831: a thin CONFIRMED is
    sampled exactly twice, everything else exactly once)."""
    calls: list[int] = []

    def fake(*_a: object, **_k: object) -> _Batch:
        calls.append(len(calls) + 1)
        return samples[min(len(calls), len(samples)) - 1]

    monkeypatch.setattr(L, "_run_probe_batch", fake)
    return calls


def _verdict(
    monkeypatch: pytest.MonkeyPatch,
    *,
    timed_out: bool,
    obs: list[tuple[int, float]],
    refused: float | None,
) -> tuple[bool, float]:
    """`confirm_vulnerable`'s verdict for a synthetic batch result, with no probe actually run."""
    _stub_batches(monkeypatch, (timed_out, obs, refused))
    return L.confirm_vulnerable(r"(a+)+b", 0)


# Readings at the real growth factor of 4, chosen so each row lands unambiguously in one class:
# ratios of 4 -> linear, 16 -> quadratic, 64 -> cubic. All baselines clear NOISE_FLOOR.
_LINEAR = [(8, 0.001), (32, 0.004), (128, 0.016), (512, 0.064)]
_QUADRATIC = [(8, 0.001), (32, 0.016), (128, 0.256), (512, 4.096)]
_CUBIC = [(8, 0.001), (32, 0.064), (128, 4.096), (512, 262.144)]
_NO_RATIOS = [(8, 1e-9), (32, 2e-9)]  # sub-noise baselines: every ratio dropped

_DECISION_TABLE: list[tuple[str, bool, list[tuple[int, float]], float | None, bool]] = [
    # (why, timed_out, observations, refused, expected_confirmed)
    ("cubic growth, finished", False, _CUBIC, None, True),
    ("cubic growth, killed", True, _CUBIC, None, True),
    # The #762 fix. Before this PR both of these were CONFIRMED purely because the batch was
    # killed, which is the wrong security verdict on a safe pattern that merely ran slowly.
    ("quadratic growth, KILLED", True, _QUADRATIC, None, False),
    ("linear growth, KILLED", True, _LINEAR, None, False),
    ("quadratic growth, finished", False, _QUADRATIC, None, False),
    # No classifiable series: the caller falls back to the other two kinds of evidence.
    ("indeterminate + measured cubic refusal", False, _NO_RATIOS, 6.19, True),
    ("indeterminate + killed (the backstop)", True, _NO_RATIOS, None, True),
    ("indeterminate + finished (the ordinary corpus case)", False, _NO_RATIOS, None, False),
    # The #768 F3 hoist: a measured cubic-or-worse refusal confirms in EVERY growth class. The
    # first row is the flattened-knee false negative the corpus-hang gate flaked on (week of
    # 2026-08-31): host load inflates the small-n baselines, the median reads quadratic, and the
    # worker's measured ~2.9-exponent refusal of the top step used to be DISCARDED.
    ("quadratic growth + measured cubic refusal (#768 F3, the flattened knee)", False, _QUADRATIC, 2.9, True),
    ("linear growth, killed, + measured cubic refusal", True, _LINEAR, 6.19, True),
    # FP-bait for the hoist (CLAUDE.md rule 1 - the widening's traded direction): a refusal BELOW
    # `_QUADRATIC_MAX` is a safe forecast-skip of an expensive step, not evidence of catastrophe,
    # and must not confirm anywhere. The killed row also pins that the hoist did not smuggle
    # `timed_out` into the classified branches - the #762 anti-regression with `refused` set.
    ("quadratic growth + measured SUB-cubic refusal (a safe forecast skip)", False, _QUADRATIC, 2.0, False),
    ("linear growth, killed, + sub-cubic refusal", True, _LINEAR, 1.0, False),
    # One expensive reading, then a clean finish. This is the state F1 used to manufacture: the
    # worker refused the next step on an ASSUMED exponent and exited 0, and the pattern cleared.
    # It is no longer reachable through `confirm_vulnerable`, which always sends six probes and
    # (post-fix) can only stop early on a MEASURED refusal or a kill - `_run_probe_batch` still
    # produces it for a single-probe call. Kept as a pin on the rule rather than on the path: if
    # some future change lets the worker stop short on a guess again, the shape comes back, and
    # `test_the_worker_never_refuses_a_step_on_an_assumed_exponent` is what guards the path.
    ("one reading, finished (the shape F1 used to manufacture)", False, [(8, 0.2)], None, False),
    # The spawn residual `confirm_vulnerable`'s docstring discloses: killed during process spawn,
    # so not one reading was flushed. Since #831 this is a THIN confirmed and is sampled again;
    # the stub reproduces the kill, so it confirms here. `_RESAMPLE_TABLE` below pins the other
    # half (a spawn kill that does NOT reproduce clears).
    ("no readings at all, killed twice", True, [], None, True),
]


@pytest.mark.parametrize(
    ("why", "timed_out", "obs", "refused", "expected"),
    _DECISION_TABLE,
    ids=[row[0] for row in _DECISION_TABLE],
)
def test_the_stage_2_decision_table_is_what_the_docstring_says(
    monkeypatch: pytest.MonkeyPatch,
    why: str,
    timed_out: bool,
    obs: list[tuple[int, float]],
    refused: float | None,
    expected: bool,
) -> None:
    """Every row of `confirm_vulnerable`'s documented verdict table, exercised directly.

    Deterministic by construction: no clock, no subprocess, no contention. A row that changes
    meaning fails here rather than flaking somewhere downstream on a busy CI leg."""
    confirmed, _elapsed = _verdict(monkeypatch, timed_out=timed_out, obs=obs, refused=refused)
    assert confirmed is expected, f"{why}: expected confirmed={expected}, got {confirmed}"


def test_the_decision_table_covers_both_verdicts_and_every_growth_class() -> None:
    """Anti-vacuity: a table that only ever asserted one verdict, or only reached one class, would
    pass while testing nothing. This is the guard that the table above stays a real matrix."""
    assert {row[4] for row in _DECISION_TABLE} == {True, False}, "table asserts only one verdict"
    classes = {
        L._classify(L._growth_ratios([s for _, s in row[2]]), L._PROBE_GROWTH_FACTOR)
        for row in _DECISION_TABLE
    }
    assert {"linear", "quadratic", "cubic-or-worse", "indeterminate"} <= classes
    assert any(row[1] for row in _DECISION_TABLE) and any(not row[1] for row in _DECISION_TABLE)
    assert any(row[3] is not None for row in _DECISION_TABLE)
    # The #768 F3 rows must keep BOTH refusal directions represented: a measured refusal that
    # confirms, and a sub-cubic one that stays cleared (the hoist's FP-bait). Deleting either
    # class of row fails loudly here instead of quietly un-testing the hoist.
    assert any(row[3] is not None and row[4] for row in _DECISION_TABLE)
    assert any(row[3] is not None and not row[4] for row in _DECISION_TABLE)


# --- evidence sufficiency: the thin-verdict resample (#831) ------------------------------------
#
# The series shapes below are the REAL ones, to the order of magnitude: `_QUAD_FULL` is `\s+\d+`
# on a quiet box (n=8/32/128 under NOISE_FLOOR, so two usable ratios of ~16x); `_THIN_CUBIC` is
# the same pattern with its n=2048 reading inflated ~4x by sustained contention (ratios 16x /
# 62x, median exponent 2.65) and the top step refused on that inflated pair - the exact shape
# the self-hosted Windows leg confirmed on PR #827 and the dev box reproduced under 3x CPU
# oversubscription; `_THIN_KILLED` is the same quiet series killed during the top step (one
# usable ratio). All six probes are what `_confirm_outcome` sends, so a six-reading series is
# COMPLETE and a five-reading one is not.
_SIZES = [8, 32, 128, 512, 2048, 8192]
_QUAD_FULL = [(8, 1e-6), (32, 8e-6), (128, 9e-5), (512, 1.5e-3), (2048, 2.3e-2), (8192, 0.36)]
_THIN_CUBIC = [(8, 1e-6), (32, 8e-6), (128, 1.5e-4), (512, 2.4e-3), (2048, 0.15)]
_THIN_KILLED = _QUAD_FULL[:5]
_SUBFLOOR_FULL = [(n, 5e-6) for n in _SIZES]  # finished every probe in microseconds
_CUBIC_FULL = [(n, 0.001 * 64 ** i) for i, n in enumerate(_SIZES)]  # 64x per step throughout
# Near-instant through n=2048, explosive at n=8192, and the batch killed AFTER the top reading
# flushed: zero usable ratios (the exploding step's baseline is sub-floor and is dropped), so
# `indeterminate` + complete. The disclosed residual of the complete-series rule (#832 review):
# the old backstop confirmed it on the kill, and only when the kill happened to land in the
# teardown window - on a clean finish it cleared under both rules.
_KNEE_FULL = [(8, 1e-6), (32, 1e-6), (128, 1e-6), (512, 1e-6), (2048, 9e-5), (8192, 9.5)]
_WALL_ONE = [(8, 2e-6)]  # `(a+)+b`: microseconds at n=8, never finishes n=32
_WALL_TWO = [(8, 2e-6), (32, 3e-5)]
_C1_SHAPE = [(8, 1e-3), (32, 0.5)]  # measured 6.19 between n=8 and n=32, refuses n=128

_RESAMPLE_TABLE: list[tuple[str, _Batch, _Batch | None, bool, int]] = [
    # (why, first sample, second sample or None to repeat the first, expected_confirmed,
    #  expected number of batches consumed)
    #
    # The #831 fix, both directions of the resample.
    ("thin cubic + refusal (the SAFE_A flip), resample finishes quadratic",
     (False, _THIN_CUBIC, 3.0), (False, _QUAD_FULL, None), False, 2),
    ("thin cubic + refusal, reproduces on the resample",
     (False, _THIN_CUBIC, 3.0), None, True, 2),
    ("thin cubic by growth alone (two ratios, no refusal), resample clears",
     (False, _THIN_CUBIC, None), (False, _QUAD_FULL, None), False, 2),
    ("indeterminate + measured refusal on five readings, resample clears",
     (False, _THIN_KILLED, 2.9), (False, _QUAD_FULL, None), False, 2),
    ("indeterminate + killed during the top step, resample finishes",
     (True, _THIN_KILLED, None), (False, _QUAD_FULL, None), False, 2),
    ("indeterminate + killed during the top step, killed again",
     (True, _THIN_KILLED, None), None, True, 2),
    ("spawn starvation (no readings, killed), resample finishes",
     (True, [], None), (False, _QUAD_FULL, None), False, 2),
    ("spawn starvation twice", (True, [], None), None, True, 2),
    # A complete series is never confirmed by the kill - and the kill never voids a growth
    # verdict either (the traded direction).
    ("complete sub-floor series, killed: the regex finished all six", (True, _SUBFLOOR_FULL, None), None, False, 1),
    ("complete series, killed, cubic by growth: still confirmed, not resampled",
     (True, _CUBIC_FULL, None), None, True, 1),
    # Pins the disclosed residual (see `_KNEE_FULL`), so a change to it is deliberate: this row
    # asserts today's behaviour, not the desired one.
    ("complete series with an explosive sub-floor-baseline last step, killed: cleared (residual)",
     (True, _KNEE_FULL, None), None, False, 1),
    # The exponential wall is never resampled: one batch, CONFIRMED, exactly as before #831.
    ("the wall: one reading then killed", (True, _WALL_ONE, None), None, True, 1),
    ("the wall: two readings then killed", (True, _WALL_TWO, None), None, True, 1),
    ("the C1 shape: two readings, measured refusal of the third step", (False, _C1_SHAPE, 6.19), None, True, 1),
    # Full evidence is not resampled, and a clear is never resampled.
    ("three cross-checking ratios, cubic: not thin", (False, _CUBIC, None), None, True, 1),
    ("a quadratic clear is one sample", (False, _QUAD_FULL, None), None, False, 1),
    ("a thin clear (indeterminate + finished) is one sample", (False, _NO_RATIOS, None), None, False, 1),
]


@pytest.mark.parametrize(
    ("why", "first", "second", "expected", "batches"),
    _RESAMPLE_TABLE,
    ids=[row[0] for row in _RESAMPLE_TABLE],
)
def test_a_thin_confirmed_is_sampled_twice_and_the_second_sample_decides(
    monkeypatch: pytest.MonkeyPatch,
    why: str,
    first: _Batch,
    second: _Batch | None,
    expected: bool,
    batches: int,
) -> None:
    """#831: a CONFIRMED resting on fewer than `_RESAMPLE_MIN_RATIOS` usable ratios is sampled
    again and must confirm twice; the exponential wall (1-2 readings, then nothing) is the one
    thin shape that is not, because it is what a real hang produces. Deterministic: no clock,
    no subprocess, no contention - the call log says how many batches the verdict consumed."""
    pattern = r"\s+\d+"
    # The gate itself, on the first sample alone: thin exactly when a second batch is expected.
    _stub_batches(monkeypatch, first)
    first_outcome = L._sample_outcome(pattern, 0, L._probe_sequence(pattern), L.DEFAULT_TIMEOUT)
    assert L._is_thin(first_outcome) is (batches == 2), f"{why}: the resample gate disagrees"

    calls = _stub_batches(monkeypatch, first, *([second] if second is not None else []))
    o = L._confirm_outcome(pattern, 0)
    assert o.confirmed is expected, f"{why}: expected confirmed={expected}, got {o.confirmed}"
    assert len(calls) == batches, f"{why}: expected {batches} batch(es), consumed {len(calls)}"
    assert o.resampled is (batches == 2), f"{why}: the outcome must say whether it was resampled"
    # The evidence carried is the DECIDING sample's, so a log reads the verdict's own readings.
    deciding = second if (second is not None and batches == 2) else first
    assert o.readings == tuple(deciding[1])
    assert o.timed_out is deciding[0]


def test_the_resample_table_covers_both_directions() -> None:
    """Anti-vacuity for the table above: a resample that flipped a verdict to cleared, one that
    reproduced and confirmed, and single-sample rows on both verdicts - delete any of them and
    this fails instead of quietly un-testing half of #831."""
    resampled = [row for row in _RESAMPLE_TABLE if row[4] == 2]
    single = [row for row in _RESAMPLE_TABLE if row[4] == 1]
    assert any(not row[3] for row in resampled), "no row where the resample cleared"
    assert any(row[3] for row in resampled), "no row where the resample reproduced"
    assert any(row[3] for row in single) and any(not row[3] for row in single)
    # The wall rows (a real hang's only thin shape) must stay represented as single-sample
    # CONFIRMEDs: they are the negative control for the resample's cost and its safety.
    walls = [row for row in single if row[3] and 1 <= len(row[1][1]) <= L._WALL_MAX_READINGS]
    assert len(walls) >= 2, "the exponential wall rows are the resample's negative control"


def test_lint_and_report_carry_the_resample_into_the_evidence_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rule 3, assert the artifact: a CONFIRMED that took two samples must SAY so in the report,
    and `LintResult` must carry `resampled` either way, otherwise a log cannot tell two
    contention samples from one real one. A cleared row prints no evidence line at all (the
    determinism doctrine: a passing run's output stays byte-identical), so the cleared half is
    asserted on `LintResult` only."""
    import contextlib
    import io

    _stub_batches(monkeypatch, (False, _THIN_CUBIC, 3.0))
    site = L.PatternSite(module="t", file=Path("t.py"), line=1, name="THIN", pattern=r"\s+\d+", flags=0)
    (result,) = L.lint([site])
    assert result.confirmed_vulnerable is True and result.resampled is True
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        assert L.report([result]) == 1
    assert "resampled=True" in buf.getvalue()

    _stub_batches(monkeypatch, (False, _THIN_CUBIC, 3.0), (False, _QUAD_FULL, None))
    (cleared,) = L.lint([site])
    assert cleared.confirmed_vulnerable is False and cleared.resampled is True
    assert cleared.readings == tuple(_QUAD_FULL), "the deciding sample's evidence is what is carried"


def test_confirm_vulnerable_reports_the_last_reading_not_a_wall_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`elapsed` is the last reading obtained, and 0.0 when the batch was killed before flushing
    any - inventing the subprocess round trip in its place would be a fabricated measurement
    wearing the same type as a real one."""
    _confirmed, elapsed = _verdict(monkeypatch, timed_out=False, obs=_QUADRATIC, refused=None)
    assert elapsed == pytest.approx(4.096)
    _confirmed, empty = _verdict(monkeypatch, timed_out=True, obs=[], refused=None)
    assert empty == 0.0


# --- the forecast may only refuse on a MEASURED exponent (PR #767, F1) --------------------------


def _run_worker_on_scripted_costs(
    costs: list[float], sizes: list[int], ceiling: float
) -> str:
    """Run the REAL `_WORKER_SRC` with its clock replaced by a scripted cost per probe.

    The forecast's inputs are wall-clock readings, so the only way to test the decision it makes
    is to control them. Two surgical substitutions into the shipped source - not a reimplementation
    of it - so the branch under test is the one that actually runs in production. Both are asserted
    to have applied: a substitution that silently matched nothing would leave this test passing
    against an unmodified worker and proving nothing (CLAUDE.md rule 3)."""
    import json
    import subprocess

    src = L._WORKER_SRC
    before = src
    src = src.replace("ceiling = d['ceiling']\n", "ceiling = d['ceiling']\ncosts = d['costs']\n")
    assert src != before, "the ceiling line moved - re-point this substitution"
    before = src
    src = src.replace("        r = time.perf_counter() - t0\n", "        r = costs.pop(0)\n")
    assert src != before, "the timing line moved - re-point this substitution"

    payload = json.dumps(
        {
            "pattern": "a",
            "flags": 0,
            "ceiling": ceiling,
            "costs": costs,
            "probes": [[n, "a" * n] for n in sizes],
        }
    )
    # `check=False` plus an explicit raise, mirroring `_run_probe_batch`'s own crash contract:
    # `CalledProcessError` reports only an exit code, and the one thing worth knowing when a
    # substituted worker fails is what it said on stderr.
    done = subprocess.run(
        [sys.executable, "-S", "-c", src],
        input=payload,
        capture_output=True,
        encoding="utf-8",
        timeout=60,
        check=False,
    )
    if done.returncode != 0:
        raise RuntimeError(f"scripted worker crashed (exit {done.returncode}): {done.stderr.strip()}")
    return done.stdout


def test_the_worker_never_refuses_a_step_on_an_assumed_exponent() -> None:
    """One reading is not enough to forecast from, and the fallback is a GUESS.

    Before this was gated, a single reading above `ceiling / _PROBE_GROWTH_FACTOR ** 3` (0.156s at
    the default 10s) made `_UNMEASURED_EXPONENT` project the next step over budget, so the worker
    broke and exited 0. The parent then saw one reading, no refusal it would honour
    (`_parse_worker_stream` discards an assumed one, correctly) and no timeout - and cleared the
    pattern. Reproduced against `(a+)+b`, the textbook evil regex this file's own suite requires to
    confirm: a FALSE NEGATIVE, the worst direction. Ending the series early IS reaching a verdict,
    because the step not taken is the evidence not gathered.

    Nine costs, not three: each size now takes `_WORKER_REPEATS` attempts (0.2 sits under
    `_REPEAT_BELOW`, so the at-most-two stop never fires), and every attempt pops one cost."""
    out = _run_worker_on_scripted_costs([0.2] * 9, sizes=[8, 32, 128], ceiling=10.0)
    assert "skipped" not in out, f"refused a step with only a guess to justify it:\n{out}"
    obs, refused = L._parse_worker_stream(out)
    assert [n for n, _ in obs] == [8, 32, 128], "the series stopped short"
    assert refused is None


def test_the_worker_still_refuses_a_step_once_the_exponent_is_measured() -> None:
    """The direction traded against (CLAUDE.md rule 1): gating the refusal on `meas` NARROWS when
    the worker may stop early, so the case it exists for must still fire. Two readings four sizes
    apart at a 64x cost ratio measure an exponent of exactly 3.0, which projects the next step at
    ~41s against a 10s ceiling. That step must not be attempted - skipping it is where this
    module's speed win comes from.

    The cost list is attempt-shaped: size 8 pops three 0.01s (under `_REPEAT_BELOW`, full
    repeats), size 32 pops exactly two 0.64s (at-most-two: the second attempt agrees the size is
    expensive), and the 99.0 sentinel must never be popped - if the refusal regressed and n=128
    ran, the sentinel would enter the series and the `== [8, 32]` assert below names it."""
    out = _run_worker_on_scripted_costs(
        [0.01] * 3 + [0.64] * 2 + [99.0], sizes=[8, 32, 128], ceiling=10.0
    )
    assert "skipped" in out, f"burned an over-budget step it could already forecast:\n{out}"
    obs, refused = L._parse_worker_stream(out)
    assert [n for n, _ in obs] == [8, 32], "the refused step was run anyway"
    assert refused == pytest.approx(3.0), "the refusal must carry the MEASURED exponent"


# --- min-of-N repeated readings (#768 F5) -------------------------------------------------------
#
# The worker used to take each reading exactly once, which put the OS scheduler inside a security
# verdict: one stalled sample corrupts a growth ratio, and the median-of-few in `_classify` flips
# the verdict in EITHER direction (measured the week of 2026-08-31 - a catastrophic corpus pattern
# cleared on the loaded Linux leg, SAFE_B and a real guard pattern confirmed on the Windows legs).
# Each size is now timed up to `_WORKER_REPEATS` times, keeping the MINIMUM, mirroring
# `complexity_probe.measure` (#758). All scripted-cost, no real sleeps: the decisions under test
# are control flow, not machine speed.


def test_the_worker_keeps_the_minimum_of_repeated_readings() -> None:
    """The core F5 property, protecting BOTH verdict directions: a one-sided stall on any single
    attempt vanishes from the series, because the minimum of the repeats is what streams to the
    parent. Size 8's second attempt stalls 150x; the flushed reading must be the honest 0.001."""
    out = _run_worker_on_scripted_costs(
        [0.001, 0.15, 0.001] + [0.002] * 3, sizes=[8, 32], ceiling=10.0
    )
    obs, refused = L._parse_worker_stream(out)
    assert obs == [(8, 0.001), (32, 0.002)], "a stalled attempt leaked into the series"
    assert refused is None


def test_a_stalled_attempt_no_longer_flips_a_safe_pattern_to_cubic() -> None:
    """The SAFE_B false CONFIRMED, end to end through the real worker + parse + classify (runs
    33732076040 / 34063499093 / 34068384757 attempt 1: a linear-safe pattern reported
    catastrophically vulnerable because one mid-series reading absorbed a scheduler stall).

    Direction traded against: FALSE POSITIVE. The workload is linear at the growth factor (4x cost
    per 4x size); the first attempt of size 32 is stalled 75x. Min-of-3 discards the stall and the
    series must classify `linear`. The counterfactual assert pins that this test is not vacuous:
    the same stall under the old min-of-1 semantics lands in the cubic band."""
    out = _run_worker_on_scripted_costs(
        [0.001] * 3 + [0.3, 0.004, 0.004] + [0.016] * 3, sizes=[8, 32, 128], ceiling=10.0
    )
    obs, _refused = L._parse_worker_stream(out)
    series = [secs for _, secs in obs]
    assert series == [0.001, 0.004, 0.016]
    assert L._classify(L._growth_ratios(series), 4) == "linear"
    # min-of-1 verdict on the identical stall: the flake this test exists to close.
    assert L._classify(L._growth_ratios([0.001, 0.3, 0.016]), 4) == "cubic-or-worse"


def test_the_forecast_reads_the_min_not_the_last_raw_attempt() -> None:
    """FALSE-POSITIVE direction, at the refusal seam: the forecast block reads `obs[-1]`, so it
    must see the de-noised minimum, never the last raw attempt. Size 32's LAST attempt stalls to
    0.8s - as a raw last reading that measures an exponent of 2.0 and projects 12.8s for n=128
    (over the 10s ceiling: a manufactured refusal, which the F3 hoist would turn straight into a
    CONFIRMED); as the min (0.2s) the exponent is 1.0, n=128 projects 0.8s and must run."""
    out = _run_worker_on_scripted_costs(
        [0.05] * 3 + [0.2, 0.2, 0.8] + [0.001] * 3, sizes=[8, 32, 128], ceiling=10.0
    )
    assert "skipped" not in out, f"a stalled last attempt manufactured a refusal:\n{out}"
    obs, refused = L._parse_worker_stream(out)
    assert (32, 0.2) in obs, "the forecast fed on the raw attempt, not the min"
    assert [n for n, _ in obs] == [8, 32, 128]
    assert refused is None


def test_an_expensive_reading_is_repeated_at_most_twice() -> None:
    """The trade the repeats must not break: additive noise cannot move a verdict at readings
    already at or above `_REPEAT_BELOW`, so a size stops after TWO agreeing attempts (two, not
    one, because the first attempt alone could itself be the inflated one). Exactly two costs are
    scripted - a third attempt would pop an empty list, crash the worker, and fail this test
    through the harness's own RuntimeError."""
    out = _run_worker_on_scripted_costs([0.3, 0.26], sizes=[8], ceiling=100.0)
    obs, _refused = L._parse_worker_stream(out)
    assert obs == [(8, 0.26)], "the min of the two attempts is the reading"


def test_repeats_stop_rather_than_cross_the_batch_deadline() -> None:
    """The trade in the other direction: repeats may never spend the batch deadline. Without the
    `spent + r > ceiling` stop, re-timing an expensive-but-safe top step pushes a batch that used
    to FINISH past the kill, converting `indeterminate + finished -> cleared` into
    `indeterminate + killed -> CONFIRMED` - a false positive manufactured by the de-noising
    itself. Exactly two costs: with the stop, each size takes one attempt (no budget for a
    second); without it, the second cost is consumed as a size-8 repeat (obs[0] would read
    `(8, 0.3)`) and the third attempt crashes the worker on an empty cost list."""
    out = _run_worker_on_scripted_costs([0.6, 0.3], sizes=[8, 32], ceiling=1.0)
    obs, _refused = L._parse_worker_stream(out)
    assert obs == [(8, 0.6), (32, 0.3)], "a repeat spent budget the batch did not have"



# --- a SETTLED top step is not run -----------------------------------------------------------------
#
# When the series before the LAST probe already carries two or more usable ratios, all under the
# cubic band edge, the decision rule cannot be moved by anything the last probe measures: the
# median of 3+ ratios ignores one extreme (so growth stays sub-cubic), there is no step after it to
# refuse (so no refusal can be hoisted), and a classified series is cleared even when killed (#762).
# The worker therefore skips it and says so (`["settled", n]`, which `_parse_worker_stream` ignores).
# That step is the corpus gate's n=8192 quadratic tail. The tests below pin the worker predicate in
# both directions AND tie it to the parent rule differentially, so a later change to `_classify`
# that made the last probe matter again fails here instead of silently voiding the skip.


def test_a_settled_top_step_is_not_run() -> None:
    """The skip: two sub-cubic ratios (4x, 4x) before n=512. The 99.0 sentinel would be popped
    (and reported) if n=512 ran."""
    out = _run_worker_on_scripted_costs(
        [0.001] * 3 + [0.004] * 3 + [0.016] * 3 + [99.0], sizes=[8, 32, 128, 512], ceiling=1000.0
    )
    obs, refused = L._parse_worker_stream(out)
    assert '["settled", 512]' in out
    assert [n for n, _ in obs] == [8, 32, 128], "a settled top step was run"
    assert refused is None


def test_a_cubic_earlier_ratio_keeps_the_top_step() -> None:
    """The direction traded against: one cubic ratio (64x) in the prefix, so the series is not
    settled and the top step must run."""
    out = _run_worker_on_scripted_costs(
        [0.001] * 3 + [0.064] * 3 + [0.1] * 3 + [0.2] * 3, sizes=[8, 32, 128, 512], ceiling=10.0
    )
    obs, _refused = L._parse_worker_stream(out)
    assert "settled" not in out
    assert [n for n, _ in obs] == [8, 32, 128, 512], "an unsettled top step was skipped"


def test_a_single_usable_ratio_keeps_the_top_step() -> None:
    """The direction traded against: n=8 is sub-floor, so only ONE usable ratio precedes the top
    step, and with two ratios the median is a mean the top ratio CAN move. The top step must run."""
    out = _run_worker_on_scripted_costs(
        [1e-5] * 3 + [0.001] * 3 + [0.016] * 3 + [0.2] * 3, sizes=[8, 32, 128, 512], ceiling=10.0
    )
    obs, _refused = L._parse_worker_stream(out)
    assert "settled" not in out
    assert [n for n, _ in obs] == [8, 32, 128, 512]


def test_the_settled_skip_never_changes_a_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    """Differential: random five-reading prefixes go through the REAL worker (scripted costs, a
    sentinel top step); for every prefix the worker settles, the parent's verdict on the truncated
    series must equal its verdict on every full series the skipped step could have produced - a
    tiny, an explosive and a quadratic top reading, finished or killed mid-step. Anti-vacuity: both
    settled and unsettled prefixes must occur, and an unsettled one must exist whose top step DOES
    move the verdict (proving the predicate is not trivially safe because nothing ever matters)."""
    import random

    rng = random.Random(1137)
    sizes = [8, 32, 128, 512, 2048]
    probes = [(n, "x") for n in [*sizes, 8192]]
    settled_seen = unsettled_seen = top_matters_seen = 0

    def verdict(batch: _Batch) -> bool:
        _stub_batches(monkeypatch, batch)
        return bool(L._sample_outcome(r"\s+\d+", 0, probes, L.DEFAULT_TIMEOUT).confirmed)

    for _ in range(200):
        prefix = [rng.choice([1e-6, 5e-5, 2e-4, 1e-3])]
        for _n in sizes[1:]:
            prefix.append(prefix[-1] * rng.choice([1.0, 4.0, 16.0, 30.0, 40.0, 64.0]))
        if prefix[-1] >= 0.24:  # keep every size at three attempts so the cost script is exact
            continue
        costs = [c for c in prefix for _r in range(3)] + [99.0, 99.0]
        out = _run_worker_on_scripted_costs(costs, sizes=[*sizes, 8192], ceiling=1e9)
        obs, _refused = L._parse_worker_stream(out)
        assert obs[:5] == list(zip(sizes, prefix, strict=True)), out
        last = prefix[-1]
        alternatives: list[_Batch] = [
            (False, [*obs[:5], (8192, top)], None) for top in (0.0, last, last * 16, last * 1e4)
        ] + [(True, list(obs[:5]), None)]
        if "settled" in out:
            settled_seen += 1
            assert len(obs) == 5
            want = verdict((False, list(obs), None))
            for alt in alternatives:
                assert verdict(alt) == want, f"prefix {prefix}: the skipped step could have moved {alt}"
        else:
            unsettled_seen += 1
            if len({verdict(alt) for alt in alternatives}) > 1:
                top_matters_seen += 1
    assert settled_seen >= 10 and unsettled_seen >= 10, (settled_seen, unsettled_seen)
    assert top_matters_seen >= 1, "no unsettled prefix where the top step mattered: vacuous"


def test_a_ratio_at_the_float_edge_keeps_the_top_step() -> None:
    """PR #1142 review, M1. B = nextafter(32.0, 0) is under 4 ** 2.5 as a product, but the parent
    computes `log(B) / log(4)`, which rounds to exactly 2.5: cubic-or-worse. With ratios [2, B] the
    two-ratio median is a mean (quadratic), so an explosive top ratio DOES move the verdict - the
    parent reads [2, B, X] as cubic. A worker that settled on the product form skipped exactly that
    step. Readings are powers of two so every ratio is exact."""
    import math

    edge = math.nextafter(32.0, 0.0)
    r0 = 2.0 ** -10
    r1, r2 = 2 * r0, 2 * r0 * edge
    assert r2 / r1 == edge and math.log(edge) / math.log(4) == L._QUADRATIC_MAX
    assert L._classify([2.0, edge], 4) == "quadratic"
    assert L._classify([2.0, edge, 1e4], 4) == "cubic-or-worse", "the top step must matter here"
    out = _run_worker_on_scripted_costs(
        [r0] * 3 + [r1] * 3 + [r2] * 3 + [0.2] * 3, sizes=[8, 32, 128, 512], ceiling=1000.0
    )
    obs, _refused = L._parse_worker_stream(out)
    assert "settled" not in out, "the worker settled on a ratio the parent reads as cubic"
    assert [n for n, _ in obs] == [8, 32, 128, 512]


def test_a_starved_then_resampled_wall_is_retried_not_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    """#1142 pre-review, M1: a first sample starved at spawn (zero readings, killed) is resampled; if the
    second sample gets its n=8 reading the outcome has readings AND `resampled=True`. The 2.5s wall
    tests must retry that at the production deadline, not fail it as "not the wall shape"."""
    calls: list[float] = []
    starved: _Batch = (True, [], None)
    one_reading: _Batch = (True, [(8, 1e-06)], None)

    def fake_batch(pattern: str, flags: int, probes: object, timeout: float) -> _Batch:
        calls.append(timeout)
        return starved if len(calls) == 1 else one_reading

    monkeypatch.setattr(L, "_run_probe_batch", fake_batch)
    o = _wall_outcome(r"(a+)+b")
    assert calls == [_WALL_TIMEOUT, _WALL_TIMEOUT, L.DEFAULT_TIMEOUT], calls
    _assert_wall(o, "a starved-then-resampled wall")


def test_a_zero_reading_in_the_prefix_keeps_the_top_step() -> None:
    """PR #1142 round-2 review, R2-M1 (the still-fires side of round-1 L1). A prior reading of exactly
    0.0 must not settle: the parent's `_classify` reads a 0.0 ratio as indeterminate, so the top step
    can still decide the verdict. The worker's `q[1] > 0` guard is what stops it; without the guard the
    log form crashes the worker on `log(0)`, and the old product form settles on the zero."""
    out = _run_worker_on_scripted_costs(
        [0.001] * 3 + [0.004] * 3 + [0.0] * 3 + [99.0] * 3, sizes=[8, 32, 128, 512], ceiling=1000.0
    )
    obs, _refused = L._parse_worker_stream(out)
    assert "settled" not in out, "the worker settled on a prefix holding a 0.0 reading"
    assert [n for n, _ in obs] == [8, 32, 128, 512]


def test_a_real_wall_is_not_remeasured(monkeypatch: pytest.MonkeyPatch) -> None:
    """PR #1142 round-2 review, R2-L1: the traded direction of the starvation retry. A genuine wall at
    the short deadline (one n=8 reading, killed, not resampled) is judged as is, never re-run at the
    production deadline, or the 2.5s saving the wall PoCs exist for silently disappears."""
    calls: list[float] = []

    def fake_batch(pattern: str, flags: int, probes: object, timeout: float) -> _Batch:
        calls.append(timeout)
        return (True, [(8, 1e-06)], None)

    monkeypatch.setattr(L, "_run_probe_batch", fake_batch)
    o = _wall_outcome(r"(a+)+b")
    assert calls == [_WALL_TIMEOUT], calls
    _assert_wall(o, "a genuine wall")
