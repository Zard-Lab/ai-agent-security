#!/usr/bin/env python3
"""Classify a workload's growth SHAPE by ratio, so machine speed cancels out.

Why this exists: an absolute wall-clock threshold cannot separate "a slow machine" from "a real
complexity regression", and in one review round that ambiguity failed in BOTH directions — a
quadratic-but-large regex read as catastrophic because a fixed 10s deadline was crossed on a slow
box (PR #580's claimed "fourth ReDoS site"), and a healthy guard turned ``main`` red on the Windows
CI leg because an 8.0s budget had only 4.3x headroom. A *ratio* between two input sizes is immune to
both: doubling every measurement leaves the ratio unchanged.

The rule this implements is the one the #580 round-4 review used by hand. With each step growing the
input by a multiplier ``m``, the cost ratio between consecutive sizes identifies the complexity
class, because a cost of ``n**k`` grows by ``m**k`` per step::

    ratio ~ m**1  -> linear          (m=4: ~4x)
    ratio ~ m**2  -> quadratic       (m=4: ~16x)  <- the ordinary, bounded profile of a lazy
                                                     quantifier followed by a lookahead
    ratio ~ m**3+ -> cubic-or-worse  (m=4: ~64x)  <- the catastrophic-backtracking class

So classification is done on the measured **exponent** ``log(ratio) / log(m)`` rather than on
distance-to-a-magic-number: it is the same rule, it generalizes to any multiplier, and its bands
stay meaningful when a reading lands between two classes.

Two lessons from the #580 review rounds are encoded here rather than left to be relearned:

1. **Ratios at small n are pure noise** (round-3 addendum: a ratio-based early exit was tried at
   n=8/n=32 and abandoned, because those readings sit in scheduler noise and are indistinguishable
   from linear). Every step whose *baseline* reading is under ``NOISE_FLOOR`` is discarded before
   classifying, so the verdict comes from the TOP of the size sequence where readings are orders of
   magnitude above the floor. Too few surviving steps returns ``"indeterminate"`` — never a guess.
2. **A catastrophic pattern can take minutes at the top size** (``docker_latest_base_tag``'s stage
   matcher: 156s at n=8192). ``re`` cannot be interrupted in-process and Windows has no
   ``signal.alarm``, so the ceiling cannot preempt a running search — it has to stop the sequence
   from *entering* one. It is therefore a FORECAST: before each step, the next size's cost is
   extrapolated from the growth already measured, and the step is skipped if it projects over
   ``--ceiling``. A post-hoc "that took too long" check would have been useless here, because the
   reading that precedes the 156s step is a comfortable 2.5s.

Deliberately self-contained: it must import and run on ``main``, so it shares no code with
``scripts/lint_regex_redos.py`` (which ships only in PR #580). Stdlib only, like everything else here.

Usage::

    # the #580 table, reproducible on any machine: the retired rls_update_privileged_column._TO_CLAUSE
    # (#429 replaced it in the guard with a linear scan; tests/test_complexity_probe.py keeps a copy)
    python scripts/complexity_probe.py --pattern '\\bto\\s+(?P<roles>[\\w,\\s"]+?)(?=\\busing\\b|\\bwith\\s+check\\b|\\bas\\b|;|$)'
    # a compiled guard constant, probed with its own flags
    python scripts/complexity_probe.py --guard rls_update_privileged_column:_TO_HEAD
    # docker_latest_base_tag's stage matcher is inline in `_stage_names`, not a module constant,
    # so it is probed as a literal pattern (and at reduced sizes — it is the catastrophic one):
    python scripts/complexity_probe.py --pattern '^\\s*FROM\\s+.+\\s+AS\\s+(\\S+)\\s*$' --sizes 128,512,2048

    python scripts/complexity_probe.py --pattern '\\bto\\s+([\\w,\\s]+?)(?=\\bas\\b|$)'
    python scripts/complexity_probe.py --pattern '...' --sizes 64,128,256 --json
"""
from __future__ import annotations

import argparse
import importlib
import json
import math
import re
import statistics
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path

# A reading below this is scheduler noise, not a measurement, so the ratio computed from it says
# nothing about complexity — the round-3 lesson above. Steps whose baseline falls below it are
# dropped, which is what pushes classification toward the top of the size sequence.
#
# It sits at 100us rather than the millisecond the round-3 regime would suggest, because that regime
# is not this one: round 3 measured through a SUBPROCESS, where tens of milliseconds of interpreter
# startup swamp the reading being taken. These measurements are in-process. Measured on this box,
# repeated `re.search` timings are stable well below the floor — at n=32 (12.7us) the spread across
# 15 runs was 3% of the median, and at n=64 (81.9us) it was 18%; the occasional 2x scheduling outlier
# that does appear is what the median-of-ratios in `classify` exists to absorb. A floor set at 1ms
# would instead discard the honest small-n readings of a genuinely catastrophic pattern (which is
# fast at small n precisely because it is steep) and report `indeterminate` for the clearest case
# the tool has.
NOISE_FLOOR = 1e-4  # seconds

# Measured exponent bands. Wide on purpose: a contended sample perturbs the exponent far less than
# it perturbs the raw ratio (a 2x timing hiccup moves the exponent by only log(2)/log(4) = 0.5 at
# m=4), and the classes we need to separate sit a full integer apart.
_LINEAR_MAX = 1.5
_QUADRATIC_MAX = 2.5

DEFAULT_SIZES = (128, 512, 2048, 8192)
DEFAULT_CEILING = 10.0  # seconds for any ONE size; see the module docstring on why it is between-sizes

# How many times one size is timed. Only the MINIMUM is kept, because contention noise is ONE-SIDED:
# a lost scheduling slice or a GC pause can only ever make a reading slower, never faster. The
# smallest of a few readings is therefore the least-contaminated estimate of the honest cost, and
# unlike a wider classification band it costs no detection power.
#
# This exists because the ratio design cancels the wrong kind of noise. A uniformly SLOWER machine
# does cancel out of a ratio, which is the property the module was built on. Contention is not a
# constant factor: it ADDS a roughly fixed number of milliseconds to ONE reading, and a ratio
# amplifies that in inverse proportion to how small the readings are. #758 measured the consequence
# on a healthy linear workload whose readings were milliseconds: a 174ms stall on one sample read as
# `quadratic`, while a uniform 10x slowdown of every sample still read `linear`.
#
# Three, not five: on the #758 reproduction (the real workload under 4x CPU oversubscription) three
# readings took a 20-in-25 misclassification rate to 0-in-25, and a synthetic one-sided noise model
# puts min-of-3 at 0.7% against min-of-1's 21%. Five buys another order of magnitude for 67% more
# measurement time, which is not the trade this gate needs.
DEFAULT_REPEATS = 3

# Repeats are only spent where they can change an answer. Above this reading, one measurement is
# taken (two before the budget is abandoned, so a single inflated FIRST reading cannot end the
# sampling early at its own inflated value) and the rest of the budget is not spent.
#
# The arithmetic: an excursion of `q` seconds on an honest reading of `R` inflates that step's ratio
# to `m*(1 + q/R)`, so what matters is the RATIO q/R, not q. In the worst case this module permits
# (two ratios, where `statistics.median` is the mean of both and an outlier keeps half its weight) a
# true linear run stays inside the linear band while `q/R < 2`. At `R = 0.25s` that absorbs a
# half-second stall, roughly 32 Windows scheduling quanta (15.625ms, issue #704). Below it the same
# stall crosses a band boundary: the #758 failure was q=174ms against R=28.7ms, a q/R of 6.
#
# The residual, measured rather than assumed (the #759 review asked for the number): a size whose
# first TWO readings are both independently stalled past this threshold exits early on a minimum
# that is itself inflated. Simulated through this function with the one-sided noise model above,
# that fires on ~4% of runs at the `[1000, 4000, 16000, 64000]` shape and costs 0.04%
# misclassification, because at four sizes `classify`'s median discards the single ratio it
# corrupts. The gap between those two figures is the two halves of the #758 fix doing different
# jobs: repeats make outliers rare, the fourth size makes the survivors harmless. Neither alone.
_REPEAT_BELOW = 0.25  # seconds

# The growth exponent the forecast assumes while no growth has been MEASURED yet. It is the bottom
# of the `cubic-or-worse` band (`_QUADRATIC_MAX`) — the worst class this tool exists to name —
# because the two ways of being wrong here are not symmetric: an over-forecast aborts and says so,
# while an under-forecast disappears into a 156s search that no message ever comes back from
# (CLAUDE.md Rule 3 — a crash beats a clean-looking miss).
#
# Assuming the worst used to be too expensive to do: it truncated healthy sequences into
# `indeterminate`, a fabricated verdict, which is why the assumption was once softened to quadratic
# instead. That trade is no longer necessary. `measure` now answers a guess that projects over the
# ceiling by going and taking a cheap BRIDGE reading (`_bridge`) and re-forecasting from real growth,
# so the conservative direction costs one small measurement rather than a wrong answer.
_UNMEASURED_EXPONENT = 3.0

Classification = str  # "linear" | "quadratic" | "cubic-or-worse" | "indeterminate"

Shape = str  # "inline" | "blank-run"

# Every probe shape a pattern is measured against. A pattern is only as safe as its WORST shape,
# so callers that want a verdict rather than one reading should sweep all of them (`probe_all`).
# `inline` alone is what let the #697 anchor class sit undetected: its probe is a single line, and
# a `^`-re-anchoring blow-up needs many.
PROBE_SHAPES: tuple[Shape, ...] = ("inline", "blank-run")

# Ordering for "which shape produced the worst answer". `indeterminate` ranks BELOW `linear`: it is
# an absence of evidence, so a real `linear` reading from another shape is strictly more informative
# and should win, while any named blow-up outranks both.
_CLASS_SEVERITY: dict[Classification, int] = {
    "indeterminate": -1,
    "linear": 0,
    "quadratic": 1,
    "cubic-or-worse": 2,
}


def measure(
    workload: Callable[[int], object],
    sizes: Sequence[int],
    *,
    ceiling: float = DEFAULT_CEILING,
    prepare: Callable[[int], None] | None = None,
    repeats: int = DEFAULT_REPEATS,
) -> list[float]:
    """Elapsed seconds for ``workload`` at each size, in order, discarding a warmup run.

    Stops early (returning a SHORT list) rather than letting a catastrophic workload run away. The
    warmup is at the smallest size only — it absorbs regex compilation and first-touch page faults,
    and is deliberately untimed. ``prepare`` is called before every timed run (including the warmup
    and any bridge) for setup that must not land inside the measurement, such as building the probe
    string itself; a workload that needs none can omit it.

    **The stop is a forecast, not just a post-mortem.** Checking ``elapsed > ceiling`` only *after* a
    size completes cannot prevent the step that actually blows up: with the default sizes, the docker
    stage matcher reads 2.5s at n=2048 (comfortably under a 10s ceiling), and the next step is the
    155s one this ceiling exists to avoid. So before committing to the next size, its cost is
    projected from the growth already observed and the step is skipped if the projection exceeds the
    ceiling.

    **A forecast made before any growth has been observed is a guess, and a guess is not allowed to
    be the whole decision.** The first forecast of any run has exactly one reading behind it, so
    there is no ratio to extrapolate — and that first forecast is the one governing the dangerous
    step whenever the size list opens with a large jump (``--sizes 128,8192``, or any two-element
    list). Rather than pick a direction to be wrong in, a projection that clears the ceiling only
    under ``_UNMEASURED_EXPONENT`` triggers one cheap intermediate reading (``_bridge``), and the
    step is then decided on measured growth. The bridge is a safety measurement, not data: it is
    taken at a size the caller never asked for and is deliberately absent from the returned series.

    **Each size is timed ``repeats`` times and the MINIMUM is kept.** One reading per size was the
    original design, and it is what made the classification a coin-flip on a contended runner: with
    a single sample there is nothing for an excursion to be outvoted by, and the ratio design does
    not cancel an excursion the way it cancels a slow machine (see ``DEFAULT_REPEATS``). The minimum
    is the right summary rather than the mean or the median because the noise is one-sided. Repeats
    are skipped for readings above ``_REPEAT_BELOW``, where additive noise cannot move the verdict,
    so the cost lands on the cheap sizes where it is affordable and an expensive size costs **at
    most two** readings rather than ``repeats`` of them (two, not one, because the first reading
    alone could be the inflated one — only a size whose first reading already blows the ``ceiling``
    is measured exactly once). ``repeats=1`` restores the original single-sample behavior, which is
    what the tests use to pin the failure this exists to prevent.
    """
    if not sizes:
        return []
    if prepare is not None:
        prepare(sizes[0])
    workload(sizes[0])  # warmup, deliberately untimed
    elapsed: list[float] = []
    # Includes bridge readings, which `elapsed` must not: the returned series has to keep the caller's
    # own constant per-step multiplier for `growth_ratios`/`classify` to read it correctly.
    observations: list[tuple[int, float]] = []
    for i, size in enumerate(sizes):
        if i and _projected_cost(observations, size) > ceiling:
            observations.extend(_bridge(workload, observations, size, ceiling, prepare))
            if _projected_cost(observations, size) > ceiling:
                break
        seconds = math.inf
        for attempt in range(max(1, repeats)):
            reading = _timed_run(workload, size, prepare)
            seconds = min(seconds, reading)
            if reading > ceiling:
                # A runaway must not be run `repeats` times over. The post-hoc ceiling check below
                # still fires on it; this only stops us paying for it more than once.
                break
            if attempt and seconds >= _REPEAT_BELOW:
                # Two readings now agree this size is too expensive for additive noise to matter.
                # `attempt` guards the FIRST reading specifically: an inflated one would otherwise
                # end the sampling at its own inflated value, which is the bug being fixed.
                break
        elapsed.append(seconds)
        observations.append((size, seconds))
        if seconds > ceiling:
            break
    return elapsed


def _timed_run(
    workload: Callable[[int], object], size: int, prepare: Callable[[int], None] | None
) -> float:
    """One timed run of ``workload`` at ``size``, with ``prepare`` kept outside the measurement."""
    if prepare is not None:
        prepare(size)
    start = time.perf_counter()
    workload(size)
    return time.perf_counter() - start


def _projected_cost(observations: Sequence[tuple[int, float]], next_size: int) -> float:
    """Forecast the cost of ``next_size`` from the ``(size, seconds)`` readings already taken.

    Returns 0.0 when there is nothing to extrapolate from, so a missing forecast never blocks a step
    — the post-hoc ceiling check still applies and the caller is no worse off than before.
    """
    if not observations:
        return 0.0
    last_size, last_seconds = observations[-1]
    # A size at or below zero carries no growth information, in either direction: there is no
    # multiplier to raise to a power, and `_bridge_size` cannot split the jump either. The previous
    # answer here was `last_seconds` — a claim of ZERO growth, the single most optimistic value this
    # function can return, which silently disabled the ceiling for the whole rest of the run:
    # `--sizes 0,400` ran a 64s step under a 0.5s ceiling because the forecast never even looked at
    # the 400. Refusing is the direction that is visible when it is wrong (a short series classifies
    # `indeterminate` and says so); proceeding is not (CLAUDE.md Rule 3).
    #
    # This also keeps the exponentiation below total. A negative `next_size` against a positive
    # `last_size` makes the base negative, and a negative base to a NON-INTEGRAL power is `complex`
    # in Python — so `float()` raised `TypeError` for the ordinary case of a measured, noisy
    # exponent, while an exponent that happened to land on exactly 2.0 returned normally. The
    # positivity the old comment claimed "by construction" is now actually established.
    if last_size <= 0 or next_size <= 0:
        return math.inf
    exponent = _observed_exponent(observations)
    if exponent is None:
        exponent = _UNMEASURED_EXPONENT
    # float ** float widens to Any (it can be complex for a negative base); the guard above
    # establishes that both sizes are positive, so the narrowing restates that rather than coercing.
    return float(last_seconds * (next_size / last_size) ** exponent)


def _observed_exponent(observations: Sequence[tuple[int, float]]) -> float | None:
    """The growth exponent implied by the last two readings, or ``None`` when unmeasured.

    Normalizing the observed cost ratio into an exponent is what lets one forecast survive an uneven
    size list. A raw ratio is only transferable to the next step if that step multiplies the input by
    the same amount the measured one did; reused unchanged it is wrong by the difference between the
    two multipliers. With ``--sizes 128,2048,2060`` that error is not subtle — the 16x step measures a
    ~4000x cost ratio, and reapplying it to a 1.006x step projects hours for a step that truly costs
    2.5s, aborting a sequence that was never in danger. The exponent is a property of the *workload*;
    the multiplier belongs to the *size list*, and this keeps them apart.

    ``None`` rather than a number when the readings cannot support one — fewer than two, a
    non-increasing step, or a BASELINE under ``NOISE_FLOOR``. Discarding on the baseline is
    ``growth_ratios``\' rule and it applies here for a sharper reason: there, a ratio built on noise
    produces a wrong verdict; here it produces a wrong verdict the ceiling then *trusts*, which is
    how a guess would launder itself into a measurement.
    """
    if len(observations) < 2:
        return None
    (prev_size, prev_seconds), (last_size, last_seconds) = observations[-2], observations[-1]
    if prev_seconds < NOISE_FLOOR or last_seconds <= 0 or prev_size <= 0:
        return None
    step = last_size / prev_size
    if step <= 1:
        return None
    # Never forecast a GROWING input as getting cheaper. A negative exponent off two above-noise
    # readings is a cache or scheduling artifact, and it is the one shape that would project less
    # than the reading it came from — the under-forecast direction, which is the invisible one.
    return max(_exponent(last_seconds / prev_seconds, step), 0.0)


def _bridge(
    workload: Callable[[int], object],
    observations: Sequence[tuple[int, float]],
    next_size: int,
    ceiling: float,
    prepare: Callable[[int], None] | None,
) -> list[tuple[int, float]]:
    """One cheap intermediate reading, so a refusal rests on measurement instead of an assumption.

    Taken only while ``_observed_exponent`` is ``None`` — the single case where the forecast is a
    guess. Choosing between assuming the benign class (which lets the 156s step through) and assuming
    the catastrophic one (which truncates healthy runs into ``indeterminate``) is a false choice; the
    third option is to spend a bounded fraction of the ceiling finding out which it is.

    Returns ``[]`` — leaving the conservative guess to stand — when there is no room for an
    intermediate size, when even the halfway step forecasts over the ceiling, or when the workload
    refuses the size. That last case is real: a workload may be closed over a probe table keyed on
    exactly the sizes it was handed, and a safety measurement must not be able to turn a bounded
    sequence into a crash.
    """
    if _observed_exponent(observations) is not None or not observations:
        return []
    last_size, last_seconds = observations[-1]
    size = _bridge_size(last_size, next_size)
    if size is None:
        return []
    if last_seconds * (size / last_size) ** _UNMEASURED_EXPONENT > ceiling:
        return []
    try:
        # Single-shot on purpose. The bridge decides whether to SKIP a step; it is not data that
        # reaches `classify`, so spending the repeat budget here would add cost to exactly the case
        # the ceiling exists to keep cheap. A noisy bridge reading can only make the forecast more
        # conservative, which is the direction that fails visibly.
        return [(size, _timed_run(workload, size, prepare))]
    except Exception:
        return []


def _bridge_size(prev: int, nxt: int) -> int | None:
    """The geometric mean of the two sizes — the split that halves the jump in RATIO terms.

    In ratio, not in size, because a step's cost is governed by its multiplier: halving a 64x jump
    into two 8x steps is what keeps the intermediate reading affordable (``8**3`` of the last reading
    rather than ``64**3`` of it) while still landing far enough above it to measure real growth. A
    midpoint in size would be a 32x step — nearly the whole cost of the step being avoided.
    """
    if prev <= 0 or nxt <= prev:
        return None
    size = math.isqrt(prev * nxt)
    return size if prev < size < nxt else None


def growth_ratios(elapsed: Sequence[float]) -> list[float]:
    """Consecutive cost ratios, dropping any step whose BASELINE is below ``NOISE_FLOOR``.

    Dropping on the baseline (the denominator) rather than the numerator is what makes this the
    round-3 lesson and not a re-run of it: a step from a sub-millisecond reading is noise divided by
    noise regardless of how large the numerator got.
    """
    return [
        after / before
        for before, after in zip(elapsed, elapsed[1:], strict=False)
        if before >= NOISE_FLOOR
    ]


def classify(ratios: Sequence[float], multiplier: float) -> Classification:
    """Name the complexity class implied by ``ratios`` at the given size multiplier.

    Uses the MEDIAN ratio, and needs at least two surviving ratios — one ratio is a single
    measurement pair with nothing to cross-check it, and guessing from it is exactly the failure
    this module exists to prevent.

    **Be precise about what the median buys, because an earlier version of this docstring was not.**
    It claimed a single contended sample cannot flip the class. That holds from THREE ratios up,
    where the median genuinely discards an outlier however large. It is false at exactly two:
    ``statistics.median`` of two values is their arithmetic MEAN, so an outlier keeps half its
    weight. Ratios of 4.11 and 29 read as 16.6, an exponent of 2.03, which is the middle of the
    quadratic band — that is #758, on a workload that is provably linear. Every ``assert_growth``
    call site in the repo sat at exactly two ratios when it was filed, so the protection this
    docstring promised was in force nowhere it mattered.

    Two ratios remains the floor here rather than three, deliberately. Refusing to classify would
    turn a dropped step (``growth_ratios`` discards any step whose baseline is under ``NOISE_FLOOR``,
    which a quantized small reading on Windows can trigger) into a hard ``indeterminate`` failure:
    a new flake in place of the old one. The protection is established where it is actionable
    instead — ``measure`` no longer manufactures the outlier (``DEFAULT_REPEATS``), and
    ``tests/test_timing_budgets.py`` requires every ``assert_growth`` call site to pass at least four
    sizes, so the median has three ratios to work with.
    """
    if len(ratios) < 2 or multiplier <= 1:
        return "indeterminate"
    median = statistics.median(ratios)
    if median <= 0:
        return "indeterminate"
    exponent = _exponent(median, multiplier)
    if exponent < _LINEAR_MAX:
        return "linear"
    if exponent < _QUADRATIC_MAX:
        return "quadratic"
    return "cubic-or-worse"


def _exponent(ratio: float, multiplier: float) -> float:
    """The measured growth exponent k, from ``ratio == multiplier ** k``."""
    return math.log(ratio) / math.log(multiplier)


def literal_prefix(pattern: str) -> str:
    """Best-effort literal text that satisfies whatever ``pattern`` requires BEFORE its first
    quantified atom.

    Without it, ``.search()`` never reaches the ambiguity being probed and the workload measures
    nothing (``^\\s*FROM\\s+.+\\s+AS\\s+`` on a probe of bare spaces fails at ``FROM`` and returns
    instantly). Best-effort by design: an unrenderable prefix yields ``""``, which produces a weaker
    probe that under-measures rather than a wrong one that over-measures.
    """
    out: list[str] = []
    i, n = 0, len(pattern)
    while i < n:
        char = pattern[i]
        if char == "^":
            i += 1
            continue
        if char == "\\":
            nxt = pattern[i + 1] if i + 1 < n else ""
            if nxt in "bAZ":  # zero-width anchors contribute no text
                i += 2
                continue
            if nxt == "s":
                quant = pattern[i + 2] if i + 2 < n else ""
                if quant in "*?":  # optional whitespace — contributes nothing
                    i += 3
                    continue
                out.append(" ")
                i += 3 if quant == "+" else 2
                continue
            if nxt in "SwWdD":  # a class we cannot render literally — stop here
                break
            out.append(nxt)  # an escaped literal, e.g. \. or \(
            i += 2
            continue
        if char == "(":
            inline = re.match(r"\(\?[aiLmsux]+\)", pattern[i:])
            if inline:  # an inline-flag group, e.g. (?i) — no text
                i += inline.end()
                continue
            break
        if char.isalnum() or char in " _-/":
            if i + 1 < n and pattern[i + 1] in "*?+{":  # quantified: the ambiguity starts here
                break
            out.append(char)
            i += 1
            continue
        break
    return "".join(out)


def _filler_char(pattern: str, prefix_len: int) -> str:
    """A character the first quantified atom AFTER the literal prefix can consume.

    The probe has to feed the ambiguity the engine will backtrack through; a filler the pattern
    cannot match at all clears the ambiguity fast and under-measures (a false "linear"), which is the
    safe direction to be wrong in.
    """
    tail = pattern[prefix_len:]
    match = re.search(r"\\([swdSWD.])|\[([^\]]+)\]|(\.)", tail)
    if match is None:
        return "a"
    if match.group(1):
        return {"s": " ", "w": "a", "d": "1", "S": "a", "W": " ", "D": "a"}.get(match.group(1), "a")
    if match.group(2):
        body = match.group(2)
        return " " if "\\s" in body else "a"
    return "a"


def build_probe(pattern: str, size: int, shape: Shape = "inline") -> str:
    """A probe string for ``pattern`` at ``size``, in one of two shapes.

    ``inline`` — the literal prefix the pattern demands, then ``size`` filler characters the first
    quantified atom can consume, then a terminator it cannot. The trailing ``"!"`` is what forces
    the engine to exhaust its backtracking before giving up: the classic ReDoS proof-of-concept
    shape. Without it a lazy quantifier stops at the first success and the ambiguity is never
    explored. This is a SINGLE line, so it cannot surface anything that depends on ``^``
    re-anchoring.

    ``blank-run`` — ``size`` blank lines and nothing else (#697). Under ``re.MULTILINE`` a pattern
    of the form ``^\\s*<literal>`` anchors at every line start of a blank run and rescans the
    remainder of the run from each one, which is quadratic in the run length and invisible to the
    ``inline`` shape. agentsec manufactures exactly this input itself:
    ``guards/base.py::join_dockerfile_continuations`` emits one blank line per folded
    ``\\``-continuation to keep line numbers stable.

    The blank-run probe is deliberately EMPTY of content rather than, say, ``"x\\n" + "\\n" * n``.
    A probe that contains a line the pattern MATCHES can hide the very thing being measured: if the
    pattern ends in ``\\s*$``, that match absorbs the whole trailing blank run in one go and the
    engine never re-anchors inside it, reading as linear. That is what made the same
    ``^\\s*FROM...`` pattern measure 0.0004s against a Dockerfile containing a real ``FROM`` line
    and 1.15s against one without (#697 investigation). A run with no content cannot be matched,
    so it cannot be swallowed.
    """
    if shape == "blank-run":
        return "\n" * size
    prefix = literal_prefix(pattern)
    return prefix + _filler_char(pattern, len(prefix)) * size + "!"


def probe_regex(
    pattern: str,
    sizes: Sequence[int] = DEFAULT_SIZES,
    *,
    flags: int = 0,
    ceiling: float = DEFAULT_CEILING,
    shape: Shape = "inline",
) -> tuple[list[float], list[int]]:
    """Measure ``pattern.search()`` against a growing probe. Returns (elapsed, sizes-actually-run)."""
    compiled = re.compile(pattern, flags)
    probes: dict[int, str] = {}

    def prepare(size: int) -> None:
        # Building the probe is itself O(size), so it is handed to `measure` as setup rather than
        # done inside `workload` — a string build counted as part of the pattern's own cost would
        # add a linear term to every reading and flatten the exponent being measured. Sizes are not
        # known up front any more: `measure` may ask for a bridge size the caller never listed.
        if size not in probes:  # NOT setdefault: it evaluates the O(size) build on every call
            probes[size] = build_probe(pattern, size, shape)

    def workload(size: int) -> object:
        # `finditer`, not `search`, for the blank-run shape: the blow-up is `^` RE-anchoring at
        # each line start, and `search` returns at the first match, which on some patterns is
        # before the run is ever re-entered. Draining the iterator measures the whole scan.
        if shape == "blank-run":
            return [None for _ in compiled.finditer(probes[size])]
        return compiled.search(probes[size])

    elapsed = measure(workload, sizes, ceiling=ceiling, prepare=prepare)
    return elapsed, list(sizes[: len(elapsed)])


def probe_all(
    pattern: str,
    sizes: Sequence[int] = DEFAULT_SIZES,
    *,
    flags: int = 0,
    ceiling: float = DEFAULT_CEILING,
    multiplier: float | None = None,
) -> dict[Shape, tuple[Classification, list[float], list[int]]]:
    """Measure ``pattern`` against EVERY probe shape. Returns {shape: (verdict, elapsed, ran)}.

    A pattern is only as safe as its worst shape, and the shapes catch disjoint failure modes, so
    a single-shape answer is not a verdict about the pattern (#697).
    """
    step = multiplier if multiplier is not None else infer_multiplier(sizes)
    out: dict[Shape, tuple[Classification, list[float], list[int]]] = {}
    for shape in PROBE_SHAPES:
        elapsed, ran = probe_regex(pattern, sizes, flags=flags, ceiling=ceiling, shape=shape)
        out[shape] = (classify(growth_ratios(elapsed), step), elapsed, ran)
    return out


def worst_shape(results: dict[Shape, tuple[Classification, list[float], list[int]]]) -> Shape:
    """The shape that produced the most severe classification (ties: first in `PROBE_SHAPES`)."""
    return max(
        results,
        key=lambda s: (_CLASS_SEVERITY.get(results[s][0], -1), -list(PROBE_SHAPES).index(s)),
    )


def infer_multiplier(sizes: Sequence[int]) -> float:
    """The per-step size multiplier, taken from the sizes themselves.

    Derived rather than declared: a ``--multiplier`` that silently disagrees with ``--sizes`` would
    mislabel every class it produced, and there is no way for the caller to notice.
    """
    if len(sizes) < 2:
        return 0.0
    steps = [b / a for a, b in zip(sizes, sizes[1:], strict=False) if a > 0]
    return statistics.median(steps) if steps else 0.0


def _resolve_guard_pattern(spec: str) -> tuple[str, int]:
    """Resolve ``module:attr`` to a compiled guard pattern's ``(pattern, flags)``.

    ``attr`` may be a ``re.Pattern`` constant or a zero-argument callable returning one, so a
    pattern that lives inline inside a function can be exposed for probing without being hoisted.
    """
    module_name, _, attr = spec.partition(":")
    if not attr:
        raise SystemExit(f"--guard needs MODULE:ATTR, got {spec!r}")
    # Run directly (`python scripts/complexity_probe.py`) sys.path[0] is scripts/, not the repo
    # root, so `agentsec` would not import. Harmless when agentsec is already installed.
    repo_root = str(Path(__file__).resolve().parents[1])
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    module = importlib.import_module(f"agentsec.guards.{module_name}")
    obj = getattr(module, attr, None)
    if obj is None:
        raise SystemExit(f"{module_name} has no attribute {attr!r}")
    if callable(obj) and not isinstance(obj, re.Pattern):
        obj = obj()
    if not isinstance(obj, re.Pattern):
        raise SystemExit(f"{spec} is {type(obj).__name__}, not a compiled regex")
    return obj.pattern, obj.flags


def format_report(
    label: str,
    sizes: Sequence[int],
    elapsed: Sequence[float],
    verdict: Classification,
    multiplier: float,
) -> str:
    """One line per run, in the shape the #580 review reported it.

    ``sizes`` is what was REQUESTED, not what ran — passing the truncated list would make the
    aborted notice unreachable, and a probe that silently drops the sizes you asked for while
    printing a confident verdict is the "failure that presents as success" shape.
    """
    steps = " | ".join(
        f"n={size} {seconds:.4f}s"
        + (f" ({seconds / elapsed[i - 1]:.1f}x)" if i and elapsed[i - 1] > 0 else "")
        for i, (size, seconds) in enumerate(zip(sizes, elapsed, strict=False))
    )
    skipped = [str(n) for n in sizes[len(elapsed) :]]
    aborted = f" [stopped before n={','.join(skipped)}: projected over the ceiling]" if skipped else ""
    return f"{label}\n  {steps}\n  -> {verdict} (x{multiplier:g} per step){aborted}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Classify a regex's growth shape by ratio (machine-speed independent).",
    )
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--pattern", help="a regex pattern string to probe")
    src.add_argument("--guard", help="MODULE:ATTR of a compiled pattern in agentsec/guards/")
    ap.add_argument(
        "--sizes",
        default=",".join(str(s) for s in DEFAULT_SIZES),
        help=(
            f"comma-separated probe sizes (default: {','.join(str(s) for s in DEFAULT_SIZES)}). "
            "Three or more are needed for a VERDICT — `classify` wants two surviving ratios and "
            "refuses to name a class from one. Two is accepted and safe, but reports "
            "`indeterminate` by construction."
        ),
    )
    ap.add_argument(
        "--multiplier",
        type=float,
        default=None,
        help="per-step size multiplier (default: inferred from --sizes)",
    )
    ap.add_argument(
        "--ceiling",
        type=float,
        default=DEFAULT_CEILING,
        help=(
            f"abandon the sequence once one size exceeds this many seconds (default: "
            f"{DEFAULT_CEILING:g}). Enforced as a FORECAST before each step, not as a timeout "
            "during one: `re` cannot be interrupted in-process, so a step that starts is a step "
            "that finishes."
        ),
    )
    ap.add_argument(
        "--json",
        action="store_true",
        help=(
            "emit machine-readable JSON. NOTE (changed in #697): the top-level `classification` / "
            "`elapsed` / `sizes` / `aborted` keys now describe the WORST probe shape, named by the "
            "new `shape` key, not the `inline` shape unconditionally. Per-shape readings are under "
            "`shapes`, so `shapes.inline` reproduces the old top-level values exactly."
        ),
    )
    args = ap.parse_args(argv)

    try:
        sizes = [int(s) for s in args.sizes.split(",") if s.strip()]
    except ValueError:
        print(f"--sizes must be comma-separated integers, got {args.sizes!r}", file=sys.stderr)
        return 2
    if len(sizes) < 2:
        print("--sizes needs at least two sizes to form a ratio (three to reach a verdict)", file=sys.stderr)
        return 2
    # The library layer refuses to forecast across a non-positive or non-increasing step, which keeps
    # `measure()` safe for every caller (`assert_growth` in tests/_timing.py reaches it without going
    # through this function at all). But a refusal presents to a CLI user as a truncated series and an
    # `indeterminate` verdict, which reads like a property of their PATTERN rather than of their
    # arguments. Say what is actually wrong, here, where the arguments are.
    if any(size <= 0 for size in sizes):
        print(f"--sizes must all be positive, got {sizes} — a size is a probe length in characters",
              file=sys.stderr)
        return 2
    if any(nxt <= prev for prev, nxt in zip(sizes, sizes[1:], strict=False)):
        print(f"--sizes must increase, got {sizes} — growth is measured BETWEEN sizes, so a step that "
              "does not grow the input has nothing to report", file=sys.stderr)
        return 2

    if args.guard:
        pattern, flags = _resolve_guard_pattern(args.guard)
        label = args.guard
    else:
        pattern, flags, label = args.pattern, 0, args.pattern

    multiplier = args.multiplier if args.multiplier is not None else infer_multiplier(sizes)
    # Every shape, then report the worst: the shapes catch disjoint failure modes and a pattern is
    # only as safe as its worst one (#697).
    results = probe_all(pattern, sizes, flags=flags, ceiling=args.ceiling, multiplier=multiplier)
    worst = worst_shape(results)
    verdict, elapsed, ran = results[worst]

    if args.json:
        print(
            json.dumps(
                {
                    "label": label,
                    "pattern": pattern,
                    "sizes": ran,
                    "elapsed": elapsed,
                    "ratios": growth_ratios(elapsed),
                    "multiplier": multiplier,
                    "classification": verdict,
                    "aborted": len(elapsed) < len(sizes),
                    "shape": worst,
                    # Per-shape readings. Carries the SAME key set as the top level (including
                    # `aborted`) so `shapes.inline` is an exact stand-in for the pre-#697 top-level
                    # output, which is what the --json help promises.
                    "shapes": {
                        s: {
                            "classification": c,
                            "sizes": r,
                            "elapsed": e,
                            "ratios": growth_ratios(e),
                            "aborted": len(e) < len(sizes),
                        }
                        for s, (c, e, r) in results.items()
                    },
                },
                indent=2,
            )
        )
    else:
        for shape in PROBE_SHAPES:
            shape_verdict, shape_elapsed, _ = results[shape]
            marker = "  <- worst" if shape == worst else ""
            print(format_report(f"{label} [{shape}]", sizes, shape_elapsed, shape_verdict, multiplier) + marker)
    return 0


if __name__ == "__main__":
    # Importable from tests via importlib (it is in scripts/, not a package) — see
    # tests/test_complexity_probe.py, which mirrors tests/test_doc_counts.py's loader.
    raise SystemExit(main())
