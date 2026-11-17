"""Unit tests for scripts/complexity_probe.py — proving the classifier DISCRIMINATES.

A complexity classifier that is only ever shown steep workloads will happily call everything steep,
and nothing would notice. So every classification test here has a partner in the opposite direction:
the genuinely cubic `docker_latest_base_tag` stage matcher must come back ``"cubic-or-worse"``, and
the merely-quadratic `rls_update_privileged_column._TO_CLAUSE` must come back ``"quadratic"`` — the
second is the regression test for PR #580's claimed "fourth ReDoS site", which was a false positive
produced by reading a fixed wall clock instead of a growth shape. (#429 later replaced that regex
with a linear scan in the guard; the pattern lives on here, frozen, as ``_QUADRATIC_REFERENCE``.)

The timed cases run real workloads, so they are calibrated to stay small: every one is milliseconds
except the blank-run measurement of `_VULNERABLE` (~9s on an idle Linux box, 2026-10-23), which is
why it is taken ONCE per module (`_vulnerable_blank_run`) and shared by the three tests that read it.
Sizes were chosen by measurement, not by guess — a workload whose readings sit
under `NOISE_FLOOR` classifies `"indeterminate"` no matter how steep it truly is.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

_REPO = Path(__file__).resolve().parents[1]
_SCRIPT = _REPO / "scripts" / "complexity_probe.py"
_spec = importlib.util.spec_from_file_location("complexity_probe", _SCRIPT)
assert _spec is not None and _spec.loader is not None
cp = importlib.util.module_from_spec(_spec)
sys.modules["complexity_probe"] = cp  # register before exec so annotations can resolve
_spec.loader.exec_module(cp)


# ------------------------------------------------------------------- the virtual clock (#762)
#
# Every test below that asserts on the SHAPE of a measured series — `len(elapsed)`, or which sizes
# the run entered — is asserting on a control-flow decision, not on how fast this box is. Those
# decisions used to be driven by real `time.sleep()` workloads at millisecond scale, which put the
# OS scheduler inside the assertion: one stalled reading inflates a forecast, `measure` stops a step
# early, and `len(elapsed)` comes back one short on a CI leg that had nothing to do with the change
# under test. That is #762 (and #704 before it, whose recommended remedy — drive `measure` against a
# fake clock — is what this is).
#
# `advance` is a drop-in for `time.sleep(x)` inside a test workload: it charges exactly `x` seconds
# to the reading in progress and returns immediately. The arithmetic in each workload is therefore
# unchanged and still readable as "this size costs this much"; only the scheduler is gone.
#
# Deliberately NOT applied to `test_measure_abandons_the_sequence_once_a_size_exceeds_the_ceiling`,
# which stays on a real clock as the end-to-end proof that the ceiling fires against a real
# `time.sleep`. A file where every clock is virtual has stopped testing the one it ships with.


@pytest.fixture
def advance(monkeypatch: pytest.MonkeyPatch) -> Callable[[float], None]:
    """A virtual `time.sleep` for probe workloads: charge `seconds` to the reading in progress.

    Installed over the probe module's own `time` name (the same seam `_FakeClock` uses), so the
    patch cannot leak into anything else in the process that reads the clock — pytest's own
    timeout plugin included.

    `measure` reads the clock in strict start/end pairs. The opening read reports the current
    virtual time; the closing read banks whatever the workload charged in between. A workload that
    raises before charging (the `picky` case below) therefore consumes nothing and leaves the pair
    open, which is correct: no reading was taken.
    """
    now = 0.0
    pending = 0.0
    opening = True

    def clock() -> float:
        nonlocal now, pending, opening
        if opening:
            opening = False
            return now
        opening = True
        now += pending
        pending = 0.0
        return now

    def charge(seconds: float) -> None:
        nonlocal pending
        pending = seconds

    monkeypatch.setattr(cp, "time", SimpleNamespace(perf_counter=clock))
    return charge


# --------------------------------------------------------------------- classification, timed
# Each workload's sizes are measured to clear NOISE_FLOOR at the SMALLEST size, so all steps
# survive `growth_ratios`. See the module docstring on why that matters.


def test_classifies_a_linear_workload_as_linear() -> None:
    # A pure-Python loop: one unit of work per element, nothing nested.
    #
    # FIVE sizes at a 2x step, for the median reason spelled out in the rls test below — and bought
    # by halving the step rather than extending the range, so the top reading (the expensive one)
    # stays where it was. This was one of two call sites left at three ratios-worth when #759 fixed
    # the others, and neither gate could see it: `test_growth_assertions_pass_enough_sizes...`
    # resolves `assert_growth` calls, and this reaches `classify` through a bare `measure` instead.
    # Smallest reading ~1.9ms, well over NOISE_FLOOR. Measured 4 ratios, ~0.05s total.
    sizes = [50_000, 100_000, 200_000, 400_000, 800_000]
    elapsed = cp.measure(lambda n: sum(1 for _ in range(n)), sizes)
    assert len(cp.growth_ratios(elapsed)) == 4, "a discarded step would silently remove the median"
    assert cp.classify(cp.growth_ratios(elapsed), 2) == "linear"


def test_classifies_a_quadratic_workload_as_quadratic() -> None:
    # Nested loops — unambiguously n**2, and unambiguously NOT the cubic class.
    #
    # FOUR sizes, not three, and the reason is the whole point of using a median: three sizes give
    # two ratios, and `statistics.median` of two values is their mean, so a single contended sample
    # moves the verdict by its full amount. Three ratios is the smallest number at which the median
    # actually discards an outlier. Measured exponent 2.09-2.11 across repeated runs (band [1.5,
    # 2.5)), which is 0.39 of margin, and at m=2 a 2x timing hiccup on one reading is exactly what
    # the median now absorbs.
    elapsed = cp.measure(lambda n: sum(1 for _ in range(n) for _ in range(n)), [300, 600, 1200, 2400])
    assert cp.classify(cp.growth_ratios(elapsed), 2) == "quadratic"


# Readings taken in separate passes over the size list, not back to back. `measure`'s min-of-3 repeats
# run within milliseconds of each other, so a contended phase longer than that adds its delay to all
# three and the minimum keeps it. On the Windows CI guest that is observed, not hypothetical: the CLI
# rls test below once read 16.4ms at n=128 as a min-of-3 (healthy 1.4ms, so one 15.6ms scheduling
# quantum, #704, on every repeat), 2026-10-31. A fixed delay on the cheap sizes flattens the ratios
# they open, which is how this file's cubic test read `quadratic` (#1174). Passes about a second apart
# need the contention to cover the cheap sizes in every pass to bias them.
_PASSES = 3


def _per_size_minimum(passes: Sequence[Sequence[float]], sizes: Sequence[int]) -> list[float]:
    """The fastest reading of each size across separate `measure` passes (see `_PASSES`)."""
    assert all(len(p) == len(sizes) for p in passes), f"a pass stopped early: {passes}"
    return [min(readings) for readings in zip(*passes, strict=True)]


def test_classifies_the_docker_stage_matcher_as_cubic() -> None:
    # The real catastrophic pattern from `docker_latest_base_tag._stage_names` (inline there, so it
    # is spelled out rather than imported). `\s+ . .+ . \s+` over a whitespace run is three nested
    # ambiguous quantifiers; at n=8192 it takes ~156s, which is why this probes only to n=512.
    stage = re.compile(r"^\s*FROM\s+.+\s+AS\s+(\S+)\s*$", re.MULTILINE | re.IGNORECASE)
    # Four sizes for the median-of-three reason above. Sized so the smallest reading (~1ms) still
    # sits an order of magnitude over NOISE_FLOOR — drop below it and the step is discarded, which
    # would silently put this back to two ratios. Measured exponent 2.92-2.99 over repeated runs.
    #
    # One reading per size per pass, `_PASSES` passes: the same three readings at the cheap sizes as
    # the default repeats, spread in time instead of adjacent. Measured idle 2026-11-11, 10 runs on the
    # Windows CI guest: ratios 7.7-8.1 (readings 1.6ms-0.79s), 2.7s a run there and 2.0s on linux.
    sizes = [96, 192, 384, 768]
    passes = [
        cp.measure(lambda n: stage.search("FROM" + " " * n + "!"), sizes, repeats=1) for _ in range(_PASSES)
    ]
    elapsed = _per_size_minimum(passes, sizes)
    ratios = cp.growth_ratios(elapsed)
    assert len(ratios) == 3, "a discarded step would silently remove the median"
    assert cp.classify(ratios, 2) == "cubic-or-worse", f"elapsed={elapsed} ratios={ratios}"


def test_separate_passes_outvote_a_contended_phase(advance: Callable[[float], None]) -> None:
    # The proof that `_PASSES` fixes what it says, on the virtual clock, because the real failure is
    # a Windows scheduling episode that cannot be produced on demand. The same cubic cost as the test
    # above (1.7ms at n=96, the guest's idle reading), plus one 15.6ms quantum on every reading taken
    # in the first 0.3s of measurement: the shape of the 16.4ms CLI reading in `_PASSES`.
    spent = 0.0

    def cubic_while_contended(n: int) -> None:
        nonlocal spent
        cost = 0.0017 * (n / 96) ** 3 + (0.0156 if spent < 0.3 else 0.0)
        spent += cost
        advance(cost)

    sizes = [96, 192, 384, 768]
    # Back to back, the default: the CI failure, reproduced (ratios 1.7, 3.7, 8.0).
    adjacent = cp.growth_ratios(cp.measure(cubic_while_contended, sizes))
    assert cp.classify(adjacent, 2) == "quadratic", adjacent
    spent = 0.0
    passes = [cp.measure(cubic_while_contended, sizes, repeats=1) for _ in range(_PASSES)]
    separate = cp.growth_ratios(_per_size_minimum(passes, sizes))
    assert cp.classify(separate, 2) == "cubic-or-worse", separate


# The retired `rls_update_privileged_column._TO_CLAUSE`, frozen verbatim with its flags. #429 replaced
# it in the guard with a linear scan, so importing it would now fail, and probing the replacement
# would read `linear`. This module needs a KNOWN-quadratic real-world pattern as its calibration
# fixture, and quadratic is exactly what this one is.
_QUADRATIC_REFERENCE = re.compile(
    r"\bto\s+(?P<roles>[\w,\s\"]+?)(?=\busing\b|\bwith\s+check\b|\bas\b|;|$)", re.IGNORECASE
)


def test_classifies_the_rls_to_clause_as_quadratic_not_catastrophic() -> None:
    # FP-BAIT, and the point of the whole module. PR #580's round-4 addendum names this pattern a
    # fourth catastrophic-backtracking site and would have #676 widened to rewrite it. It is the
    # ordinary bounded profile of a lazy quantifier followed by a lookahead: ~16x per 4x step (4**2),
    # against the ~64x (4**3) the real catastrophic pattern above shows. It reads as vulnerable only
    # on hardware slow enough for a quadratic 8192-char probe to cross a fixed 10s deadline.
    #
    # FOUR sizes, for the median-of-three reason spelled out in the quadratic test above, and this
    # one is not theoretical: at three sizes this test failed **3 of 7** `pytest -n auto` runs on the
    # Windows CI guest (2026-09-02, measured on the box). Two ratios means `statistics.median` takes
    # their mean, so one contended reading moves the verdict by half its excursion and a genuinely
    # quadratic pattern reads `cubic-or-worse` — which is the exact false CONFIRMED this test exists
    # to disprove, arriving through the scheduler instead of through the regex.
    #
    # 8192 rather than a fourth size below 128: at 128 the reading is ~0.4ms, only ~4x over
    # NOISE_FLOOR, so a smaller step would be discarded by `growth_ratios` and silently put this
    # back to two ratios — the failure mode the cubic test's own assertion guards against. Measured
    # ratios 16.02/16.24/16.04 (4**2 per 4x step, the bounded profile), ~1.9s.

    # FIVE sizes at a 2x step, NOT three at 4x. More ratios is what the median needs, and the way to
    # buy them is to halve the STEP, never to extend the range: the top reading is what costs, and it
    # is the one the ceiling forecast can refuse.
    #
    # At three sizes this failed 3 of 7 `pytest -n auto` runs on the Windows CI guest (2026-09-02,
    # measured on the box), because two ratios means `statistics.median` takes their mean and one
    # contended reading moves the verdict by half its excursion — reporting the `cubic-or-worse` this
    # test exists to disprove, arriving through the scheduler instead of through the regex.
    #
    # The first attempt at a fix appended 8192 and was WRONG in two ways, both instructive. It cost
    # 1.9s against this version's 0.14s, on work whose entire purpose is making CI cheaper. And it
    # put the top reading next to the ceiling: under contention the 2048 reading inflates ~6x
    # (0.11s -> 0.64s), the forecast for 8192 becomes 0.64 * 4**2 = 10.2s against the 10s default,
    # `measure` correctly refuses the step, and the series silently falls back to two ratios — so it
    # still failed 3 of 6 runs, through a different door. Extending downward has neither problem:
    # 2048 stays the top, and the added readings are the cheap ones.
    #
    # 128 is the floor: its reading is ~0.42ms, ~4x over NOISE_FLOOR (0.1ms). A smaller size would be
    # discarded by `growth_ratios` and silently cost a ratio. Measured ratios ~4.0 per 2x step
    # (exponent 2, the bounded profile), 4 ratios, ~0.14s total.
    sizes = [128, 256, 512, 1024, 2048]
    probes = {n: cp.build_probe(_QUADRATIC_REFERENCE.pattern, n) for n in sizes}
    elapsed = cp.measure(lambda n: _QUADRATIC_REFERENCE.search(probes[n]), sizes)
    # Loud, not silent: a discarded or refused step puts this back toward two ratios, where one
    # contended reading moves the verdict. This assertion is what made the truncation diagnosable.
    assert len(cp.growth_ratios(elapsed)) == 4, "a discarded step would silently remove the median"
    assert cp.classify(cp.growth_ratios(elapsed), 2) == "quadratic"


# ------------------------------------------------------------------ classification, pure units


@pytest.mark.parametrize("ratios", [[], [16.0]])
def test_classify_says_indeterminate_rather_than_guessing_from_too_few_samples(
    ratios: list[float],
) -> None:
    # One ratio is a single measurement pair with nothing to cross-check it. Guessing from it is
    # the exact failure this module exists to prevent, so it must not produce a class.
    assert cp.classify(ratios, 4) == "indeterminate"


def test_classify_median_absorbs_one_contended_sample() -> None:
    # A quadratic run where one step was hit by scheduler contention and read 10x high. The mean
    # would be dragged into the cubic band; the median is not.
    assert cp.classify([16.0, 160.0, 15.5, 16.2], 4) == "quadratic"


def test_classify_rejects_a_degenerate_multiplier() -> None:
    # A multiplier of 1 means the sizes never grew, so no exponent is recoverable (and log(1) is a
    # division by zero waiting to happen).
    assert cp.classify([16.0, 16.0, 16.0], 1) == "indeterminate"


def test_growth_ratios_drops_steps_whose_baseline_is_noise() -> None:
    # The round-3 lesson, encoded: a ratio computed FROM a sub-noise-floor reading is noise divided
    # by noise. Only the two steps with a real baseline survive.
    elapsed = [1e-7, 1e-6, 0.01, 0.16, 2.56]
    assert cp.growth_ratios(elapsed) == pytest.approx([16.0, 16.0])


def test_growth_ratios_never_divides_by_zero() -> None:
    # A workload too fast to measure at all reads as exactly 0.0; that must not raise.
    assert cp.growth_ratios([0.0, 0.0, 0.5]) == []


def test_measure_abandons_the_sequence_once_a_size_exceeds_the_ceiling() -> None:
    # `re` cannot be interrupted in-process and Windows has no signal.alarm, so the ceiling is a
    # between-sizes check: the over-budget size still completes, and the sequence stops after it
    # rather than attempting the next (4x more expensive) one.
    seen: list[int] = []

    def slow_at_the_top(n: int) -> None:
        seen.append(n)
        if n >= 100:
            import time

            time.sleep(0.05)

    elapsed = cp.measure(slow_at_the_top, [10, 100, 1000], ceiling=0.01)
    assert len(elapsed) == 2, "must stop after the over-ceiling size, not run the next one"
    assert 1000 not in seen


def test_measure_forecasts_the_next_size_and_refuses_to_enter_a_blowup(
    advance: Callable[[float], None],
) -> None:
    # The bug this closes: a post-hoc ceiling check cannot stop the step that blows up. The real
    # docker matcher reads a comfortable 2.5s at n=2048 and 156s at n=8192, so "was that too slow?"
    # only ever asks the question after the damage. Here the 3rd size would take ~100x the 2nd; the
    # forecast must refuse it rather than measure it.
    seen: list[int] = []

    def steep(n: int) -> None:
        seen.append(n)
        advance(0.001 * (n / 10) ** 2)  # cost grows quadratically in n

    # n=10 -> 1ms, n=40 -> 16ms, n=160 -> 256ms. Both measured sizes sit under the 0.1s ceiling, so
    # a post-hoc check never fires and the old code ran the 256ms step; the forecast (16ms x the
    # observed 16x growth = 256ms projected) refuses it.
    elapsed = cp.measure(steep, [10, 40, 160], ceiling=0.1)
    assert 160 not in seen, "the forecast must skip the projected-over-ceiling size, not run it"
    assert len(elapsed) == 2


def test_measure_still_runs_a_benign_sequence_to_the_top() -> None:
    # FP-bait for the forecast: a linear workload must not be truncated by it. Without this, the
    # cheapest way to "fix" the hang would be to abort everything, and nothing would object.
    elapsed = cp.measure(lambda n: sum(1 for _ in range(n)), [50_000, 200_000, 800_000], ceiling=10.0)
    assert len(elapsed) == 3


def test_report_names_the_sizes_it_skipped() -> None:
    # A probe that silently drops the sizes you asked for while printing a confident verdict is the
    # "failure that presents as success" shape. The notice was previously unreachable: the caller
    # passed the already-truncated size list, so the "did we skip any?" check compared a list to
    # itself and was always False.
    text = cp.format_report("x", [128, 512, 2048, 8192], [0.1, 0.2], "quadratic", 4)
    assert "2048,8192" in text
    assert "x" in cp.format_report("x", [128, 512], [0.1, 0.2], "linear", 4)
    assert "stopped before" not in cp.format_report("x", [128, 512], [0.1, 0.2], "linear", 4)


# ----------------------------------------------------------- the forecast, before any growth exists
#
# The forecast's protection is only real where it is DECISIVE, and the tests that shipped with it
# were all constant-multiplier sequences whose refused step already had two readings behind it — so
# they exercised the measured-growth branch and would have passed identically whatever the
# no-growth-yet assumption was. That gap is the whole of finding #1 in the fix-commit review: the
# first forecast of any run has exactly one reading behind it, and it is the DECIDING one whenever
# the size list opens with a large jump (`--sizes 128,8192`, or any two-element list — both of which
# the CLI accepts). The pair below pins the assumption from both sides, since either direction alone
# has a trivial wrong answer: always-refuse passes the first, always-proceed passes the second.


def _cubic(seen: list[int], advance: Callable[[float], None]) -> object:
    """A genuinely cubic workload whose smallest reading sits an order of magnitude over
    ``NOISE_FLOOR``, so the exponent it produces is measured rather than discarded as noise."""

    def workload(n: int) -> None:
        seen.append(n)
        advance(0.001 * (n / 10) ** 3)

    return workload


def test_measure_refuses_a_blowup_that_only_the_first_forecast_could_stop(
    advance: Callable[[float], None],
) -> None:
    # n=10 -> 1ms, n=160 -> 4.1s, against a 0.5s ceiling: the far size is a real blowup and the only
    # forecast that can prevent it is made from a single reading. The sizes are chosen so the
    # assumption is DECISIVE rather than incidental — 1ms x 16**2 = 0.26s reads as safe and proceeds,
    # 1ms x 16**3 = 4.1s does not. A quadratic assumption therefore runs the 4.1s step and this test
    # fails; the docker stage matcher is the real instance of the same shape, at 156s.
    seen: list[int] = []
    elapsed = cp.measure(_cubic(seen, advance), [10, 160], ceiling=0.5)
    assert 160 not in seen, "the blowup ran: the no-growth-yet assumption is too optimistic"
    assert len(elapsed) == 1


def test_measure_bridges_a_benign_early_jump_instead_of_refusing_it(
    advance: Callable[[float], None],
) -> None:
    # FP-bait for the assumption above, and the reason it can afford to be conservative. The same
    # 16x opening jump over a LINEAR workload is entirely safe, and assuming the worst would truncate
    # it to a single reading — which classifies `indeterminate`, a fabricated verdict of exactly the
    # kind this module exists to prevent (it is why the assumption was once softened to quadratic,
    # reopening the hang above). Neither assumption alone can pass both tests: the bridge reading is
    # what does, by replacing the guess with a measurement before deciding.
    seen: list[int] = []

    def linear(n: int) -> None:
        seen.append(n)
        advance(0.001 * (n / 10))

    elapsed = cp.measure(linear, [10, 160], ceiling=0.5)
    assert len(elapsed) == 2, "a benign sequence was truncated by the conservative assumption"
    assert seen.count(40) == 1, "the bridge reading was never taken; the pass above is luck"


def test_the_bridge_reading_stays_out_of_the_returned_series(
    advance: Callable[[float], None],
) -> None:
    # The bridge sits at a size the caller never asked for, so letting it into the series would break
    # the constant per-step multiplier that `growth_ratios`/`classify` read the readings with — it
    # would show up as one anomalous ratio and could flip the verdict. It is a safety measurement,
    # not data.
    seen: list[int] = []

    def linear(n: int) -> None:
        seen.append(n)
        advance(0.001 * (n / 10))

    elapsed = cp.measure(linear, [10, 160], ceiling=0.5)
    assert 40 in seen and len(elapsed) == 2, "expected a bridge at 40 and only the 2 asked-for sizes"


def test_a_workload_that_refuses_an_unasked_size_falls_back_to_the_guess(
    advance: Callable[[float], None],
) -> None:
    # A workload may be closed over a probe table keyed on exactly the sizes it was handed (several
    # tests in this very file are), so the bridge must not be able to turn a bounded sequence into a
    # crash. The conservative guess stands instead, which for this steep workload means refusing.
    probes = {10: "a" * 10, 160: "a" * 160}
    seen: list[int] = []

    def picky(n: int) -> None:
        seen.append(n)
        advance(0.001 * (len(probes[n]) / 10) ** 3)  # KeyError at any bridge size

    elapsed = cp.measure(picky, [10, 160], ceiling=0.5)
    assert len(elapsed) == 1 and 160 not in seen


# --------------------------------------------------------- the forecast, across uneven size steps


def test_forecast_rescales_observed_growth_to_the_next_steps_own_multiplier() -> None:
    # Finding #2: the raw cost ratio of the previous step is only transferable to the next one if
    # both steps multiply the input by the same amount. These are the review's own measurements of
    # the docker matcher at an uneven `--sizes 128,2048,2060`: a 16x step measured ~4066x, and
    # reapplying that multiplier unchanged to a 1.006x nudge projects ~10,000s for a step whose true
    # cost was measured at 2.502s — a refusal printed as "projected over the ceiling" for a step that
    # was never in danger. Normalizing to an exponent divides the size list back out.
    observations = [(128, 0.00063), (2048, 2.5616)]
    projected = cp._projected_cost(observations, 2060)
    assert projected < 3.0, f"projected {projected:.1f}s for a step measured at 2.502s"


def test_an_uneven_final_step_is_not_truncated(advance: Callable[[float], None]) -> None:
    # The same property end-to-end rather than as arithmetic: a 4x step followed by a 1.025x nudge.
    # Under the raw-ratio forecast the measured 64x growth is reapplied to the nudge (0.064s x 64 =
    # 4.1s, over the ceiling) and the last size is refused; under the exponent it projects 0.069s.
    seen: list[int] = []
    elapsed = cp.measure(_cubic(seen, advance), [10, 40, 41], ceiling=0.5)
    assert len(elapsed) == 3, "an uneven but benign final step was refused"


# ------------------------------------------------------------------ the exponent behind the forecast


def test_observed_exponent_is_none_until_two_readings_exist() -> None:
    assert cp._observed_exponent([]) is None
    assert cp._observed_exponent([(128, 0.5)]) is None


def test_observed_exponent_discards_a_baseline_under_the_noise_floor() -> None:
    # `growth_ratios` drops a step whose BASELINE is noise; the forecast must drop it for a sharper
    # reason. There, a ratio built on noise yields a wrong verdict; here it yields a wrong verdict
    # that the ceiling then TRUSTS — the route by which a guess launders itself into a measurement
    # and the sequence walks into the blowup with apparent evidence behind it.
    noise = cp.NOISE_FLOOR / 10
    assert cp._observed_exponent([(10, noise), (80, 0.01)]) is None
    assert cp._observed_exponent([(10, cp.NOISE_FLOOR * 10), (80, 0.01)]) is not None


def test_observed_exponent_reads_a_real_growth_shape() -> None:
    # 64x cost over a 4x step is 4**3 — cubic, whatever the machine's absolute speed.
    exponent = cp._observed_exponent([(512, 0.04), (2048, 2.56)])
    assert exponent is not None and 2.9 < exponent < 3.1


def test_forecast_never_projects_less_than_the_reading_it_came_from() -> None:
    # A growing input that measured CHEAPER is a cache or scheduling artifact, not a workload that
    # gets faster with size. Left unclamped it is the one shape that forecasts below its own last
    # reading — the under-forecast direction, which is the invisible one.
    projected = cp._projected_cost([(512, 0.40), (2048, 0.20)], 8192)
    assert projected >= 0.20


# ------------------------------------------------------------ the forecast, on degenerate sizes
#
# Both of these are the same edge from opposite ends, and neither was reachable through the tests
# above: every size list in this file grows monotonically from a positive number, which is what a
# real probe looks like and is exactly why the hole survived two fix rounds. `--sizes` accepted any
# comma-separated ints, so both shapes below were CLI-valid input.


def test_forecast_refuses_a_size_it_cannot_extrapolate_from() -> None:
    # A size <= 0 has no multiplier to raise to a power. The forecast used to answer `last_seconds`
    # — a claim of ZERO growth, the most optimistic value available — which disabled the ceiling for
    # the rest of the run rather than merely weakening it. Refusal is the visible direction.
    assert cp._projected_cost([(0, 0.001)], 400) == float("inf")
    assert cp._projected_cost([(-5, 0.001)], 400) == float("inf")


def test_measure_does_not_enter_a_step_it_cannot_forecast(
    advance: Callable[[float], None],
) -> None:
    # End-to-end shape of the same bug: with `[0, 400]` and a genuinely cubic workload, the 400-step
    # ran to completion far past the ceiling because the forecast never looked at 400 at all.
    seen: list[int] = []

    def cubic(n: int) -> None:
        seen.append(n)
        advance(0.001 + 0.0000000010 * max(n, 0) ** 3)

    elapsed = cp.measure(cubic, [0, 400], ceiling=0.02)
    assert 400 not in seen, "ran a step the ceiling could not forecast"
    assert len(elapsed) == 1 and all(e <= 0.02 for e in elapsed)


def test_forecast_survives_a_negative_size_without_raising() -> None:
    # A negative `next_size` against a positive `last_size` makes the `**` base negative, and a
    # negative base to a NON-INTEGRAL power is complex in Python — so this raised `TypeError` for the
    # ordinary case of a measured, noisy exponent while an exponent landing on exactly 2.0 returned
    # normally. Both are pinned, because the integral case is what makes the bug look absent.
    steep = [(100, 0.01), (400, 0.20)]      # exponent ~2.161, non-integral
    exact = [(100, 0.01), (400, 0.16)]      # exponent exactly 2.0
    assert cp._observed_exponent(steep) != cp._observed_exponent(exact)
    assert cp._projected_cost(steep, -50) == float("inf")
    assert cp._projected_cost(exact, -50) == float("inf")


def test_measure_does_not_crash_on_a_negative_size_late_in_the_list() -> None:
    # `measure()` is reached by `assert_growth` (tests/_timing.py) without going through the CLI, so
    # the library layer has to hold on its own — a crash here would take out real guard perf tests.
    elapsed = cp.measure(lambda n: sum(1 for _ in range(max(n, 0))), [100, 400, -50], ceiling=10.0)
    assert len(elapsed) == 2, "the negative size must be refused, not run and not raised on"


@pytest.mark.parametrize(
    "sizes",
    ["0,400", "-5,400", "128,0,512", "400,100", "128,512,512"],
)
def test_main_rejects_a_size_list_it_cannot_measure_growth_across(sizes: str) -> None:
    # The library layer refuses these safely, but a refusal reaches a CLI user as a truncated series
    # and an `indeterminate` verdict — which reads as a property of their PATTERN rather than of
    # their arguments. The boundary says what is actually wrong.
    assert cp.main(["--pattern", "a+b", f"--sizes={sizes}"]) == 2


def test_main_still_accepts_an_ordinary_increasing_size_list() -> None:
    # FP-bait for the two checks above: the validation must reject the degenerate shapes without
    # rejecting the shape every documented invocation uses.
    assert cp.main(["--pattern", "a+b", "--sizes=64,128,256"]) == 0


def test_probe_regex_builds_each_probe_string_once(monkeypatch: pytest.MonkeyPatch) -> None:
    # `prepare` exists to keep the O(size) probe build OUT of the timed region, and it memoizes so
    # the smallest size — prepared once for the warmup and once for its own timed run — is not built
    # twice. Written with `dict.setdefault` that memoization did not happen: Python evaluates the
    # default argument eagerly, so every call rebuilt the string it was about to discard.
    real = cp.build_probe
    built: list[int] = []

    def counting(pattern: str, size: int, shape: str = "inline") -> str:
        built.append(size)
        return cast(str, real(pattern, size, shape))

    monkeypatch.setattr(cp, "build_probe", counting)
    cp.probe_regex(r"a+b", [64, 128, 256], ceiling=10.0)
    assert built == sorted(set(built)), f"a probe string was rebuilt: {built}"


def test_measure_discards_a_warmup_run() -> None:
    # `repeats=1` so this stays a statement about the WARMUP and not about the sampling policy: at
    # the default the smallest size is run once to warm up and then `repeats` times to measure, and
    # separating the two is what keeps this test's failure message true when either changes. The
    # repeat count has its own tests (see "sampling under noise").
    calls: list[int] = []
    cp.measure(calls.append, [5, 10], repeats=1)
    assert calls == [5, 5, 10], "the smallest size runs twice: once untimed to warm up"


def test_measure_warms_up_once_and_then_repeats_at_the_default() -> None:
    # The default's shape, stated where the warmup is stated, so the two cannot drift apart: one
    # untimed warmup at the smallest size, then DEFAULT_REPEATS timed readings per size.
    calls: list[int] = []
    cp.measure(calls.append, [5, 10])
    assert calls == [5] + [5] * cp.DEFAULT_REPEATS + [10] * cp.DEFAULT_REPEATS


# ------------------------------------------------------------------------- probe construction


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        (r"\bto\s+(?P<roles>[\w,\s\"]+?)(?=\busing\b|;|$)", "to "),  # \b dropped, \s+ -> one space
        (r"^\s*FROM\s+.+\s+AS\s+(\S+)\s*$", "FROM "),  # ^ and optional \s* dropped
        (r"(?i)SELECT\s+", "SELECT "),  # inline-flag group contributes no text
        (r"json\.loads\s*\(", "json.loads("),  # escaped literals kept (incl. the `(`); \s* dropped
        (r"[\w]+bar", ""),  # starts with a class we cannot render — no prefix
    ],
)
def test_literal_prefix_renders_what_the_pattern_requires_before_its_first_quantifier(
    pattern: str, expected: str
) -> None:
    assert cp.literal_prefix(pattern) == expected


def test_build_probe_is_prefix_then_filler_then_a_blocking_terminator() -> None:
    probe = cp.build_probe(r"^\s*FROM\s+.+\s+AS\s+(\S+)\s*$", 8)
    assert probe == "FROM " + " " * 8 + "!"


def test_build_probe_reaches_the_ambiguity_it_is_meant_to_measure() -> None:
    # Guards the failure mode that makes a probe silently useless: without a literal prefix the
    # pattern fails at `FROM` and returns instantly, which reads as "linear" — a false clean bill.
    stage = re.compile(r"^\s*FROM\s+.+\s+AS\s+(\S+)\s*$", re.MULTILINE | re.IGNORECASE)
    with_prefix = cp.build_probe(stage.pattern, 512)
    without_prefix = " " * 512 + "!"
    assert cp.measure(lambda _: stage.search(with_prefix), [1, 1])[0] > cp.measure(
        lambda _: stage.search(without_prefix), [1, 1]
    )[0]


def test_infer_multiplier_reads_the_step_from_the_sizes_themselves() -> None:
    assert cp.infer_multiplier([128, 512, 2048, 8192]) == 4
    assert cp.infer_multiplier([300, 600, 1200]) == 2
    assert cp.infer_multiplier([128]) == 0.0


# --------------------------------------------------------------------------------------- CLI


def test_cli_reports_the_rls_pattern_as_quadratic(capsys: pytest.CaptureFixture[str]) -> None:
    # `--pattern`, not `--guard`: the pattern left the guard in #429 (see `_QUADRATIC_REFERENCE`).
    rc = cp.main(["--pattern", _QUADRATIC_REFERENCE.pattern, "--sizes", "128,512,2048"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "quadratic" in out and "cubic" not in out


def test_cli_guard_spec_resolves_to_the_compiled_pattern_and_its_flags() -> None:
    # The `--guard` positive path lost its only test when the CLI test above moved to `--pattern`.
    # What `--guard` adds over `--pattern` is resolution plus the compiled FLAGS (`--pattern` probes
    # with 0), so assert exactly that, with no timing in the way.
    from agentsec.guards.rls_update_privileged_column import _TO_HEAD

    assert cp._resolve_guard_pattern("rls_update_privileged_column:_TO_HEAD") == (
        _TO_HEAD.pattern,
        _TO_HEAD.flags,
    )
    assert _TO_HEAD.flags & re.IGNORECASE


def test_cli_json_mode_is_machine_readable(capsys: pytest.CaptureFixture[str]) -> None:
    import json

    rc = cp.main(["--pattern", r"a+b", "--sizes", "64,128,256", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["multiplier"] == 2
    assert payload["classification"] in {"linear", "quadratic", "cubic-or-worse", "indeterminate"}
    assert payload["aborted"] is False


def test_cli_rejects_a_size_list_too_short_to_form_a_ratio(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cp.main(["--pattern", "a+b", "--sizes", "128"]) == 2
    assert "at least two sizes" in capsys.readouterr().err


def test_cli_rejects_a_guard_spec_that_names_no_pattern() -> None:
    with pytest.raises(SystemExit):
        cp.main(["--guard", "rls_update_privileged_column:_NOT_A_REAL_ATTR"])


# --------------------------------------------------------------- the blank-run probe shape (#697)
# The `inline` probe is a single line, so it structurally cannot surface a blow-up whose mechanism
# is `^` RE-anchoring across many lines. Every test here has its opposite-direction partner, per the
# module docstring: a shape that called everything quadratic would be no better than one that
# called nothing quadratic.

_MULTILINE = re.MULTILINE | re.IGNORECASE
# The shape the sweep converts FROM: `\s*` after `^` matches newlines, so under MULTILINE it
# re-anchors at every blank line and rescans the rest of the run.
_VULNERABLE = r"^\s*USER\s+(\S+)\s*$"
# ...and the shape it converts TO: every whitespace EXCEPT the newline.
_FIXED = r"^[^\S\n]*USER\s+(\S+)\s*$"
# FIVE sizes at a 2x step, not three at 4x. Both lists below were left at three sizes when #759
# swept the rest, and three sizes is exactly two ratios — the case `classify`'s own docstring
# singles out as #758: `statistics.median` of two values is their arithmetic MEAN, so one
# contended reading keeps half its weight and can move the class on its own. Measured under
# `pytest -n auto` on an 8-core box before this change: 1 failure in 5 runs, in
# `test_blank_run_probe_catches_the_anchor_class_the_inline_probe_misses`.
#
# The four-sizes gate in `tests/test_timing_budgets.py` could not see either site, because it
# resolves `assert_growth` call sites and these reach `classify` through a bare `probe_regex`.
# That is the same blind spot #759 named ("one of two call sites left at three ratios-worth") and
# the linear-workload test above was the other one.
#
# Bought on the CHEAP end, exactly as there: the step is halved rather than the range extended, so
# the top reading — the expensive one — stays where it was and only sub-quarter-cost intermediates
# are added.
_BLANK_RUN_SIZES = [1250, 2500, 5000, 10000, 20000]
# The sizes for BOTH linear blank-run partners: the converted pattern, and `_VULNERABLE` with
# MULTILINE off. Either is so fast that at `_BLANK_RUN_SIZES` the readings straddle `NOISE_FLOOR`:
# on a fast host every one sits under it and classifies `indeterminate` (a non-answer, not a pass);
# on a slow one only the top two clear it, and two ratios is the #758 mean-not-median trap (#1156:
# the Windows leg read `[2.92, 2.77]`, exponent 1.51, `quadratic` on a linear workload). These sizes
# put the SMALLEST reading well above the floor (on the Linux devbox at n=50,000: 0.0004s for the
# non-MULTILINE pattern, 0.0012s for the converted one) so "linear" is a real verdict.
#
# Six sizes, not five: five ratios is an odd count whose median survives two contaminated
# readings, where four ratios average the middle two and do not. Measured under 4x CPU
# oversubscription (32 busy loops, 8 cores): five sizes read `quadratic` in 5/150 runs for the
# converted pattern and 3/340 for the non-MULTILINE one; six sizes, 0/150 for either. Bought on the TOP end, the reverse of `_BLANK_RUN_SIZES`, because here the top reading is
# the cheap kind: linear, 0.014s / 0.037s at 1.6M. A smaller bottom size would put the first
# reading within ~2x of the floor, where a faster host drops the step and fails the ratio-count
# guard.
_LINEAR_SIZES = [50_000, 100_000, 200_000, 400_000, 800_000, 1_600_000]


def test_blank_run_probe_is_nothing_but_blank_lines() -> None:
    """No content at all, deliberately. A probe containing a line the pattern MATCHES can hide the
    blow-up: a trailing `\\s*$` absorbs the whole run into that one match and the engine never
    re-anchors inside it. A run with no content cannot be matched, so it cannot be swallowed."""
    probe = cp.build_probe(_VULNERABLE, 32, "blank-run")
    assert probe == "\n" * 32
    assert probe.strip() == ""


def test_inline_probe_shape_is_unchanged_by_the_new_parameter() -> None:
    """Regression guard on the default: `build_probe(pattern, size)` still builds the inline shape."""
    assert cp.build_probe(_VULNERABLE, 8) == cp.build_probe(_VULNERABLE, 8, "inline")
    assert cp.build_probe(r"^\s*FROM\s+.+\s+AS\s+(\S+)\s*$", 8) == "FROM " + " " * 8 + "!"


@pytest.fixture(scope="module")
def _vulnerable_blank_run() -> tuple[list[float], list[int]]:
    """ONE real blank-run measurement of `_VULNERABLE`, shared by the three tests that read it.

    It is the module's only expensive reading (seconds, where everything else is milliseconds),
    and the three tests used to take it three times: once here directly and twice more inside
    `probe_all`, with identical arguments. The verdict is a property of the pattern and the sizes,
    not of which test asked, so one reading answers all three."""
    return cp.probe_regex(_VULNERABLE, _BLANK_RUN_SIZES, flags=_MULTILINE, shape="blank-run")


@pytest.fixture
def _probe_all_reuses_the_blank_run(
    monkeypatch: pytest.MonkeyPatch, _vulnerable_blank_run: tuple[list[float], list[int]],
) -> list[str]:
    """Route `probe_all`'s blank-run call for `_VULNERABLE` to the shared reading; every other
    call (the inline shape, any other pattern) still measures for real. Returns the shapes that
    were served from the cache, so a test can prove the reuse happened rather than assume it."""
    real = cp.probe_regex
    served: list[str] = []

    def probe_regex(pattern: str, sizes: Sequence[int], **kwargs: object) -> tuple[list[float], list[int]]:
        call = (pattern, list(sizes), kwargs.get("flags"), kwargs.get("ceiling", cp.DEFAULT_CEILING),
                kwargs.get("shape"))
        if call == (_VULNERABLE, _BLANK_RUN_SIZES, _MULTILINE, cp.DEFAULT_CEILING, "blank-run"):
            served.append("blank-run")
            return list(_vulnerable_blank_run[0]), list(_vulnerable_blank_run[1])
        # The keyword values pass through untouched; their types are `probe_regex`'s own.
        return real(pattern, sizes, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(cp, "probe_regex", probe_regex)
    return served


@pytest.mark.slow
def test_blank_run_probe_catches_the_anchor_class_the_inline_probe_misses(
    _vulnerable_blank_run: tuple[list[float], list[int]],
) -> None:
    """The direction the shape was added for."""
    elapsed, _ = _vulnerable_blank_run
    ratios = cp.growth_ratios(elapsed)
    assert len(ratios) == 4, f"a discarded step would silently remove the median: {elapsed}"
    assert cp.classify(ratios, cp.infer_multiplier(_BLANK_RUN_SIZES)) == "quadratic"


def test_blank_run_probe_clears_the_converted_pattern() -> None:
    """The opposite direction, and the whole point of the conversion: same pattern, same probe,
    horizontal-only anchor, and the blow-up is gone. Without this partner the shape above would
    pass just as happily against a class that flagged everything."""
    elapsed, _ = cp.probe_regex(_FIXED, _LINEAR_SIZES, flags=_MULTILINE, shape="blank-run")
    ratios = cp.growth_ratios(elapsed)
    assert len(ratios) == len(_LINEAR_SIZES) - 1, f"a discarded step would silently remove the median: {elapsed}"
    assert cp.classify(ratios, cp.infer_multiplier(_LINEAR_SIZES)) == "linear"
    # ...and prove the reading is real rather than a floor artifact, which would classify
    # `indeterminate` on any pattern at all and make the assertion above meaningless.
    assert all(e > cp.NOISE_FLOOR for e in elapsed), f"readings under the noise floor: {elapsed}"


def test_blank_run_probe_needs_multiline_to_mean_anything() -> None:
    """FP-bait on the mechanism itself: without re.MULTILINE, `^` matches only at the string start,
    so there is no re-anchoring and the identical pattern is not a blow-up. A shape that reported
    quadratic here would be measuring something other than what it claims."""
    # At `_LINEAR_SIZES`, not `_BLANK_RUN_SIZES`: without re-anchoring the work collapses to
    # microseconds, and at the quadratic workload's sizes the readings straddle `NOISE_FLOOR` —
    # `indeterminate` (asserting nothing) on a fast host, a two-ratio `quadratic` on a slow one
    # (#1156). Same three guards as the partner above, so a class is actually computed. Putting
    # MULTILINE back makes the first reading take seconds, the forecast stops the run, and the
    # ratio-count guard fails.
    elapsed, _ = cp.probe_regex(_VULNERABLE, _LINEAR_SIZES, flags=re.IGNORECASE, shape="blank-run")
    ratios = cp.growth_ratios(elapsed)
    assert len(ratios) == len(_LINEAR_SIZES) - 1, f"a discarded step would silently remove the median: {elapsed}"
    assert cp.classify(ratios, cp.infer_multiplier(_LINEAR_SIZES)) == "linear"
    assert all(e > cp.NOISE_FLOOR for e in elapsed), f"readings under the noise floor: {elapsed}"


@pytest.mark.slow
def test_probe_all_reports_every_shape(_probe_all_reuses_the_blank_run: list[str]) -> None:
    results = cp.probe_all(_VULNERABLE, _BLANK_RUN_SIZES, flags=_MULTILINE)
    assert _probe_all_reuses_the_blank_run == ["blank-run"]
    assert set(results) == set(cp.PROBE_SHAPES)
    assert results["blank-run"][0] == "quadratic"


@pytest.mark.slow
def test_worst_shape_picks_the_more_severe_classification(
    _probe_all_reuses_the_blank_run: list[str],
) -> None:
    results = cp.probe_all(_VULNERABLE, _BLANK_RUN_SIZES, flags=_MULTILINE)
    assert _probe_all_reuses_the_blank_run == ["blank-run"]
    assert cp.worst_shape(results) == "blank-run"


@pytest.mark.parametrize(
    ("first", "second", "expected"),
    [
        ("linear", "quadratic", "blank-run"),
        ("quadratic", "linear", "inline"),
        ("linear", "cubic-or-worse", "blank-run"),
        # An absence of evidence must not outrank a real reading in either position.
        ("linear", "indeterminate", "inline"),
        ("indeterminate", "linear", "blank-run"),
        ("indeterminate", "quadratic", "blank-run"),
    ],
)
def test_worst_shape_ranks_classes_without_measuring(first: str, second: str, expected: str) -> None:
    results = {"inline": (first, [], []), "blank-run": (second, [], [])}
    assert cp.worst_shape(cast("dict[str, tuple[str, list[float], list[int]]]", results)) == expected


def test_cli_json_reports_every_shape_and_names_the_worst() -> None:
    """#697 changed what the TOP-LEVEL keys mean: they now describe the worst probe shape, not the
    `inline` one unconditionally. The `--json` help promises `shapes.inline` is an exact stand-in
    for the old top-level output, so the per-shape dicts must carry the same shape-level key set."""
    import json
    from contextlib import redirect_stdout
    from io import StringIO

    buf = StringIO()
    with redirect_stdout(buf):
        rc = cp.main(["--pattern", r"a+b", "--sizes", "64,128,256", "--json"])
    payload = json.loads(buf.getvalue())
    assert rc == 0

    assert set(payload["shapes"]) == set(cp.PROBE_SHAPES)
    assert payload["shape"] in cp.PROBE_SHAPES
    # The top level IS one of the per-shape entries, namely the worst one.
    worst = payload["shapes"][payload["shape"]]
    for key in ("classification", "sizes", "elapsed", "ratios", "aborted"):
        assert key in worst, f"per-shape dict missing {key!r}"
        assert payload[key] == worst[key], f"top-level {key!r} does not match the named worst shape"


# ------------------------------------------------------------------- sampling under noise (#758)
#
# The tests above prove the classifier discriminates on a QUIET box. These prove it still does on a
# contended one, which is a different claim and the one #758 falsified. A provably linear workload
# read as `quadratic` on the Windows leg because a single ms-scale reading absorbed a 174ms stall.
#
# The noise is injected through a fake clock rather than by contending for a real CPU, because a
# stopwatch cannot be asked to stall on demand: a test that waits for real contention is exactly the
# flaky gate this is fixing. Every reading below is a number the test chose, so these assertions are
# hardware-independent and identical on every leg.
#
# Both directions, per CLAUDE.md Rule 1. Repeats are a NARROWING of what the gate reacts to, so the
# vulnerable cases (a real quadratic, a real cubic) each carry a test asserting they still fire, and
# specifically that they still fire WITH noise present — a stability fix that quietly bought its
# stability by going blind would pass a test that only ever shows it quiet inputs.


class _FakeClock:
    """A ``perf_counter`` replacement handing out one scripted duration per timed run.

    ``measure`` calls the clock in strict start/end pairs, so each pair consumes one entry and the
    test states exactly what every reading is, including which repeat of which size is the contended
    one. Installed over the probe module's own ``time`` name, so the patch cannot leak into anything
    else that happens to read the clock during the test.
    """

    def __init__(self, durations: Sequence[float]) -> None:
        self._durations = list(durations)
        self._now = 0.0
        self._used = 0
        self._opening = True

    def __call__(self) -> float:
        if self._opening:
            self._opening = False
            return self._now
        self._opening = True
        assert self._used < len(self._durations), (
            f"fake clock ran out after {self._used} readings — the code under test took more "
            f"measurements than the script provides, which is itself the thing to look at"
        )
        self._now += self._durations[self._used]
        self._used += 1
        return self._now

    @property
    def used(self) -> int:
        return self._used


def _with_clock(monkeypatch: pytest.MonkeyPatch, durations: Sequence[float]) -> _FakeClock:
    clock = _FakeClock(durations)
    monkeypatch.setattr(cp, "time", SimpleNamespace(perf_counter=clock))
    return clock


# The #758 series, from the CI failure it was filed on: a linear workload at x4 per step, whose
# LAST reading absorbed a stall. `_HONEST` is what the box would have reported undisturbed.
_HONEST = [0.0017, 0.0068, 0.0272]
_STALL = 0.203


def test_a_single_stalled_reading_misclassifies_a_linear_workload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The bug, pinned. This is the #758 failure reproduced exactly, and it must stay reproducible:
    it is the evidence that `repeats` is load-bearing rather than decorative."""
    _with_clock(monkeypatch, [_HONEST[0], _HONEST[1], _STALL])
    elapsed = cp.measure(lambda _: None, [1000, 4000, 16000], repeats=1)
    assert cp.classify(cp.growth_ratios(elapsed), 4) == "quadratic"


def test_repeats_absorb_the_stall_that_produced_issue_758(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The fix. Same workload, same stall, same size list — the only change is that each size is
    read three times and the minimum kept, because contention can only ever make a reading slower."""
    # The stall lands on the FIRST and LAST repeat, not just the first. With it only on the first,
    # "keep the last reading" recovers the honest value too, so the test would pass against an
    # implementation that had dropped the minimum entirely. Bracketing the honest reading leaves
    # `min` as the only aggregator that can return it (#759 review).
    _with_clock(
        monkeypatch,
        [_HONEST[0]] * 3 + [_HONEST[1]] * 3 + [_STALL, _HONEST[2], _STALL],
    )
    elapsed = cp.measure(lambda _: None, [1000, 4000, 16000], repeats=3)
    assert elapsed == pytest.approx(_HONEST), "the minimum of the repeats is the honest reading"
    assert cp.classify(cp.growth_ratios(elapsed), 4) == "linear"


def test_repeats_keep_the_minimum_wherever_the_stall_lands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stall on the FIRST or MIDDLE sample is the direction that deflates a later ratio, which is
    how a noisy run can hide a real regression rather than invent one. The minimum removes it the
    same way regardless of where it lands."""
    for position in range(3):
        script: list[float] = []
        for i, honest in enumerate(_HONEST):
            readings = [honest] * 3
            if i == position:
                readings[0] = readings[2] = _STALL  # bracket the honest reading; see above
            script.extend(readings)
        monkeypatch.setattr(cp, "time", SimpleNamespace(perf_counter=_FakeClock(script)))
        elapsed = cp.measure(lambda _: None, [1000, 4000, 16000], repeats=3)
        assert elapsed == pytest.approx(_HONEST), f"stall on sample {position} survived"


def test_repeats_do_not_hide_a_real_quadratic(monkeypatch: pytest.MonkeyPatch) -> None:
    """Rule 1, the direction traded against. A genuine n**2 at x2 per step must still be named, and
    must still be named with a stall present — the stall must not be able to launder it into
    `linear` any more than it could launder linear into quadratic."""
    honest = [0.001, 0.004, 0.016, 0.064]  # x4 per x2 step == exponent 2
    script: list[float] = []
    for i, value in enumerate(honest):
        script.extend([0.5, value, 0.5] if i == 3 else [value] * 3)
    _with_clock(monkeypatch, script)
    elapsed = cp.measure(lambda _: None, [300, 600, 1200, 2400], repeats=3)
    # The elapsed series first, then the class. Asserting only the class would let this test pass
    # with `min` swapped for `mean`, `max` or "keep the last reading", because at four sizes the
    # median already absorbs one bad ratio on its own — so a test that stopped here would prove the
    # fourth size works and say nothing about the mechanism its own name claims to pin (#759 review).
    assert elapsed == pytest.approx(honest), "the minimum of the repeats is the honest reading"
    assert cp.classify(cp.growth_ratios(elapsed), 2) == "quadratic"


def test_repeats_do_not_hide_a_real_cubic_when_an_early_sample_stalls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The sharpest version of Rule 1 here, and the reason one plausible fix was rejected.

    Taking the minimum over the RATIOS (rather than over repeated readings of one size) looks far
    more stable than this — it survives a 500x stall on the last sample — and it silently reclassifies
    a genuine cubic as `linear` whenever noise inflates an EARLY sample, because an inflated
    denominator deflates the ratio after it. That is a failure presenting as success (Rule 3) and is
    worse than the bug being fixed. This pins the safe shape: the catastrophic class is still named
    with the stall sitting on an early sample.
    """
    honest = [0.0002, 0.0016, 0.0128, 0.1024]  # x8 per x2 step == exponent 3
    script: list[float] = []
    for i, value in enumerate(honest):
        script.extend([0.05, value, 0.05] if i == 1 else [value] * 3)
    _with_clock(monkeypatch, script)
    elapsed = cp.measure(lambda _: None, [100, 200, 400, 800], repeats=3)
    assert elapsed == pytest.approx(honest), "the minimum of the repeats is the honest reading"
    assert cp.classify(cp.growth_ratios(elapsed), 2) == "cubic-or-worse"


def test_repeats_are_not_spent_on_a_size_too_expensive_for_noise_to_matter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The cost bound. Above `_REPEAT_BELOW` an added stall cannot move the verdict, so the budget
    is not spent there — otherwise this change would multiply the runtime of exactly the slowest
    tests. Two readings, not one: a single INFLATED first reading must not be able to end the
    sampling at its own inflated value, which is the bug this is fixing."""
    calls: list[int] = []
    _with_clock(monkeypatch, [0.3] * 8)
    cp.measure(lambda n: calls.append(n), [10, 20], repeats=3)
    assert len(calls) == 5, f"expected warmup + 2 readings per size, got {len(calls)}: {calls}"


def test_a_runaway_reading_is_not_repeated(monkeypatch: pytest.MonkeyPatch) -> None:
    """A size that blows the ceiling must be paid for ONCE. The ceiling exists to stop a runaway,
    and repeating it `repeats` times over would make the safety measure the expensive part."""
    calls: list[int] = []
    _with_clock(monkeypatch, [2.0, 2.0, 2.0])
    elapsed = cp.measure(lambda n: calls.append(n), [10], ceiling=0.5, repeats=3)
    assert elapsed == pytest.approx([2.0])
    assert len(calls) == 2, f"expected warmup + a single reading, got {len(calls)}"


def test_prepare_runs_before_every_repeat(monkeypatch: pytest.MonkeyPatch) -> None:
    """`prepare` builds the probe input and must stay outside the measurement — including for the
    repeats, or every repeat after the first would measure a workload over an input the previous
    repeat already consumed or mutated."""
    prepared: list[int] = []
    _with_clock(monkeypatch, [0.001] * 4)
    cp.measure(lambda _: None, [10], repeats=3, prepare=prepared.append)
    assert prepared == [10, 10, 10, 10], "one prepare for the warmup and one per repeat"


def test_classify_at_two_ratios_is_the_mean_and_a_third_ratio_is_what_fixes_it() -> None:
    """The trap, pinned so it cannot be reintroduced by someone reading `median` and stopping there.

    `statistics.median` of two values is their arithmetic mean, so at two ratios an outlier keeps
    half its weight and the documented outlier-resistance does not exist. Every `assert_growth` call
    site sat at exactly two ratios when #758 was filed. The gate in `tests/test_timing_budgets.py`
    is what keeps them at four sizes; this states why four is the number.
    """
    assert cp.classify([4.0, 16.0], 4) == "quadratic", "two ratios: the outlier keeps half its weight"
    assert cp.classify([4.0, 4.0, 16.0], 4) == "linear", "three ratios: the outlier is outvoted"
