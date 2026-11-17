"""Shared wall-clock budget rules for the perf-regression tests.

Underscore-prefixed so pytest does not collect it as a test module; the gate that enforces the rule
below lives in ``tests/test_timing_budgets.py``.

**The rule: a wall-clock budget must clear ``MIN_HEADROOM`` times its measured healthy value, and
must still sit below the regression it exists to catch.** Both halves matter and they pull in
opposite directions, which is the point — a budget raised until it stops flaking has usually been
raised past the bug it was watching for, and nothing says so.

This exists because an absolute threshold cannot distinguish a slow machine from a real complexity
regression, and in one review round the ambiguity bit in both directions:

- **False positive.** ``test_policy_rls_disabled_many_findings_bounded_time`` turned ``main`` red on
  a docs-only commit. Healthy 1.82s against an 8.0s budget is 4.4x headroom, and the Windows CI leg
  alone runs 2.2x-3.2x slower than linux (measured and recorded in the `validate-windows`
  `timeout-minutes` comment in ``.github/workflows/ci.yml``), before any GitHub-hosted runner
  contention on top.
- **False negative.** PR #580's fixed 10s ReDoS deadline confirmed a merely-quadratic pattern as
  catastrophic on slow hardware, which would have sent someone to rewrite a guard pattern that is
  not vulnerable.

Where the healthy-to-regression window is wide (``_C673_BUDGET``: 0.07s healthy, 30.8s regression,
a 400x window) an absolute budget is comfortable. Where it is narrow, prefer a **growth-ratio**
assertion via ``assert_growth`` — machine speed cancels out of a ratio entirely — and keep the
absolute budget as a backstop so a true hang still fails loudly instead of running forever.
"""

from __future__ import annotations

import importlib.util
import re
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from statistics import median
from typing import cast

# The growth-ratio primitives live in scripts/ (dev tooling, deliberately not shipped inside
# agentsec/ where the self-audit and canary machinery would scan them). Loaded the same way
# tests/test_doc_counts.py loads scripts/doc_counts.py.
_PROBE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "complexity_probe.py"
_spec = importlib.util.spec_from_file_location("complexity_probe", _PROBE_PATH)
assert _spec is not None and _spec.loader is not None
_probe = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("complexity_probe", _probe)
_spec.loader.exec_module(_probe)


# The Windows CI leg runs the pytest step 2.2x-3.2x slower than the linux runner (mean 2.7x over
# five runs) — measured and recorded in the `validate-windows` `timeout-minutes` comment in
# .github/workflows/ci.yml. (Cited by CONTENT, not by line: three citations of this measurement
# all said `ci.yml:222` and all three had drifted onto an unrelated step by #770. The drift gate
# is `test_the_cited_windows_slowdown_measurement_still_exists`.) A budget has to clear that
# worst case AND leave room for GitHub-hosted runner contention stacked on top of it, which is the
# combination that turned `main` red on 2026-08-22: a 4.4x-headroom budget met a 3.2x-slower box and
# a 1.82s workload arrived at 9.12s against an 8.0s budget.
#
# 10x is 3.2x for Windows with a further ~3x for contention and for the healthy value drifting up as
# the code under test grows. It is deliberately a round number: the honest precision here is "an
# order of magnitude", not a second decimal place.
MIN_HEADROOM = 10.0


@dataclass(frozen=True)
class TimingBudget:
    """An absolute wall-clock budget, carrying the two measurements that justify it.

    ``measured`` and ``regression`` are what make the budget auditable rather than a magic number:
    together they say what the budget is between, and ``tests/test_timing_budgets.py`` asserts it
    actually sits there. Record real measurements only — a guessed ``regression`` would make the
    gate assert a fiction.
    """

    name: str
    seconds: float
    """The asserted ceiling."""
    measured: float
    """Healthy elapsed on a dev box — the value ``seconds`` must clear by ``MIN_HEADROOM``."""
    regression: float
    """Elapsed WITH the bug this guards — the value ``seconds`` must stay under, or the budget has
    been raised past the thing it was watching for."""
    why: str

    @property
    def headroom(self) -> float:
        return self.seconds / self.measured if self.measured > 0 else float("inf")

    @property
    def window(self) -> float:
        """How far apart healthy and broken are. A narrow window wants ``assert_growth`` instead."""
        return self.regression / self.measured if self.measured > 0 else float("inf")


    @property
    def limit(self) -> float:
        """Uniform name for the asserted ceiling, so the gate can treat both budget kinds alike."""
        return self.seconds


# --------------------------------------------------------------------------- normalized cost
#
# A growth ratio is blind to a CONSTANT-factor slowdown, by construction: if every reading doubles,
# every ratio is unchanged. That is the property that makes it immune to a slow machine, and it is
# also a real hole — an implementation that does 5x the work per item but stays O(n) sails through
# `assert_growth`, and cannot be caught by an absolute budget either, because any budget with
# MIN_HEADROOM over a 1.82s baseline sits at 18.2s or higher and only trips at ~11x.
#
# The fix is to divide out machine speed instead of tolerating it. A fixed reference workload is
# measured in the same process, and cost is expressed in units of it. Measured on this box: the
# reference is stable to 2% across repeated runs, and the resulting normalized cost per finding to
# 5.6% — against a raw wall-clock reading that carries the full 2.2x-3.2x Windows spread plus
# contention. So a 3x threshold here is a far tighter net than 11x on the clock, and safer.
#
# Honesty about the limit: cross-machine stability is REASONED, not measured (one box was available).
# The reference is deliberately the same character as the work it normalizes — regex scanning over a
# string, not an arithmetic loop — so the two should track together across machines. The 3x headroom
# is sized to absorb a good deal of skew if they do not.
_CALIBRATION_TEXT = "create policy p on public.t for select using (true);\n" * 400
_CALIBRATION_RX = re.compile(r"create\s+policy\b", re.IGNORECASE)

NORMALIZED_MIN_HEADROOM = 3.0


def calibration_seconds(samples: int = 5) -> float:
    """This machine's speed, as seconds for a fixed reference scan. Median of ``samples`` runs."""
    _CALIBRATION_RX.findall(_CALIBRATION_TEXT)  # warm
    return median(
        [_timed(lambda: _CALIBRATION_RX.findall(_CALIBRATION_TEXT)) for _ in range(samples)]
    )


def _timed(fn: Callable[[], object]) -> float:
    start = time.perf_counter()
    fn()
    return time.perf_counter() - start


@dataclass(frozen=True)
class NormalizedCostBudget:
    """A per-item cost ceiling in calibration units — the constant-factor half of the rule.

    Same two-measurement discipline as ``TimingBudget``, and gated by the same tests; only the unit
    differs, which is why the threshold can be tight without being flaky.
    """

    name: str
    units_per_item: float
    """The asserted ceiling, in reference-workload units per item."""
    measured: float
    """Healthy units per item."""
    regression: float
    """Units per item WITH the bug this guards."""
    why: str

    @property
    def limit(self) -> float:
        return self.units_per_item

    @property
    def headroom(self) -> float:
        return self.limit / self.measured if self.measured > 0 else float("inf")

    @property
    def window(self) -> float:
        return self.regression / self.measured if self.measured > 0 else float("inf")


ALL_NORMALIZED: list[NormalizedCostBudget] = []


def register_normalized(budget: NormalizedCostBudget) -> NormalizedCostBudget:
    ALL_NORMALIZED.append(budget)
    return budget


def assert_normalized_cost(
    elapsed: float, items: int, budget: NormalizedCostBudget, *, calibration: float | None = None
) -> float:
    """Assert per-item cost, with this machine's speed divided out. Returns the measured cost."""
    unit = calibration if calibration is not None else calibration_seconds()
    assert unit > 0 and items > 0, "calibration and item count must be positive"
    cost = elapsed / unit / items
    assert cost < budget.units_per_item, (
        f"{budget.name}: {cost:.3f} calibration-units per item against a "
        f"{budget.units_per_item:.3f} ceiling (healthy is {budget.measured:.3f}, "
        f"{cost / budget.measured:.1f}x) — {budget.why}"
    )
    return cost


ALL_BUDGETS: list[TimingBudget] = []
"""Every registered budget, mirroring ``registry.py::ALL_GUARDS``.

A budget that is not in here is invisible to the headroom gate, so
``test_new_wall_clock_assertions_are_registered`` separately fails any NEW bare ``assert elapsed <``
that has not been registered or explicitly grandfathered.
"""


def register(budget: TimingBudget) -> TimingBudget:
    """Add a budget to the gate and return it, so a call site can be a single assignment."""
    ALL_BUDGETS.append(budget)
    return budget


def assert_within(elapsed: float, budget: TimingBudget, detail: str = "") -> None:
    """Assert ``elapsed`` is inside ``budget``, reporting the healthy value for comparison.

    ``detail`` names the specific scenario when one budget is shared by several tests — without it
    six call sites all fail with the same sentence and the failure output stops saying which input
    shape actually regressed.
    """
    assert elapsed < budget.seconds, (
        f"{budget.name}: took {elapsed:.2f}s against a {budget.seconds:.1f}s budget "
        f"(healthy is {budget.measured:.2f}s) — {detail or budget.why}"
    )


def assert_growth(
    workload: Callable[[int], object],
    sizes: Sequence[int],
    *,
    expected: str,
    multiplier: float | None = None,
    ceiling: float = 60.0,
) -> list[float]:
    """Assert the workload's measured growth CLASS, not its wall-clock time.

    The machine-speed-independent half of the rule: doubling every reading leaves the ratios between
    them unchanged, so a SLOW runner cannot manufacture a failure here the way it can against an
    absolute budget. Returns the elapsed readings so the caller can additionally apply a backstop
    budget.

    **A slow runner and a CONTENDED one are not the same thing, and this docstring used to say they
    were** ("a slow or contended runner cannot manufacture a failure here"). A slow machine is a
    constant factor and cancels out of a ratio exactly as claimed. Contention is not a factor at all:
    a lost scheduling slice ADDS a roughly fixed number of milliseconds to one reading, and a ratio
    amplifies that in inverse proportion to the size of the readings. #758 is what that costs — a
    provably linear workload read as `quadratic` on the Windows leg because one ms-scale sample
    absorbed a 174ms stall, while a uniform 10x slowdown of every sample still read `linear`.

    So two conditions, both now enforced rather than assumed. `measure` takes several readings per
    size and keeps the minimum, because the noise is one-sided (`complexity_probe.DEFAULT_REPEATS`).
    And **pass at least four sizes**: `classify`'s median only discards an outlier from three ratios
    up, and `tests/test_timing_budgets.py` fails a call site that passes fewer.
    """
    step = multiplier if multiplier is not None else cast(float, _probe.infer_multiplier(sizes))
    elapsed = cast(list[float], _probe.measure(workload, sizes, ceiling=ceiling))
    ratios = cast(list[float], _probe.growth_ratios(elapsed))
    verdict = cast(str, _probe.classify(ratios, step))
    assert verdict == expected, (
        f"expected {expected} growth, measured {verdict} — "
        f"sizes={list(sizes)} elapsed={[round(e, 3) for e in elapsed]} "
        f"ratios={[round(r, 2) for r in ratios]} (x{step:g} per step)"
    )
    return elapsed


def classify(ratios: Sequence[float], multiplier: float) -> str:
    """Re-export of the probe's classifier, for tests that measure their own timings."""
    return cast(str, _probe.classify(ratios, multiplier))


def growth_ratios(elapsed: Sequence[float]) -> list[float]:
    """Re-export of the probe's ratio helper."""
    return cast(list[float], _probe.growth_ratios(elapsed))

