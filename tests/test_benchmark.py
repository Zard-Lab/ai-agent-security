"""Guard precision/recall benchmark (measure quality, don't just assert it).

Runs each guard over its labeled corpus (benchmark_corpus.py), tallies
true/false positives and negatives, and computes precision (low false alarms) and
recall (low misses) per guard. Two gates:

  * `test_benchmark_no_misclassification` — on the curated corpus every case is
    classified correctly (precision == recall == 1.0). A new guard / a regression
    that introduces a false positive or a miss fails here with the exact case.
  * `test_benchmark_report_renders` — the markdown report renders (used by
    `python -m tests.test_benchmark` to print the scorecard).

The corpus is the ground-truth; extend it to raise confidence. Unlike the canary
(one planted case per guard, liveness only), this measures the FP/FN *rate*.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.registry import ALL_GUARDS
from tests.benchmark_corpus import CORPUS

_GUARDS = {g.id: g for g in ALL_GUARDS}

# A broad "everything" profile so every guard's applies() is satisfied; each case
# is a single file under its own dir, so guards don't cross-contaminate.
_FEATURES = {
    "python", "fastapi", "llm", "supabase", "postgres", "sql", "frontend", "payments", "docker", "rls",
}


def _profile(root: Path) -> StackProfile:
    p = StackProfile(root=root)
    p.features = set(_FEATURES)
    p.python_dirs = ["."]
    p.frontend_dir = "."
    p.sql_dir = "."
    return p


def _fires(guard_id: str, root: Path) -> bool:
    guard = _GUARDS[guard_id]
    return len(guard.run(root, _profile(root))) > 0


@dataclass(frozen=True)
class Score:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 1.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 1.0


def measure(tmp_root: Path) -> dict[str, Score]:
    """Run every corpus case in its own dir; return a per-guard Score."""
    out: dict[str, Score] = {}
    for gid, cases in CORPUS.items():
        if gid not in _GUARDS:
            continue
        tp = fp = fn = tn = 0
        for i, c in enumerate(cases):
            d = tmp_root / gid / str(i)
            d.mkdir(parents=True, exist_ok=True)
            (d / c.filename).write_text(c.content, encoding="utf-8")
            fired = _fires(gid, d)
            if c.should_fire and fired:
                tp += 1
            elif c.should_fire and not fired:
                fn += 1
            elif not c.should_fire and fired:
                fp += 1
            else:
                tn += 1
        out[gid] = Score(tp, fp, fn, tn)
    return out


def render(scores: dict[str, Score]) -> str:
    lines = ["# Guard precision/recall benchmark", "", "| guard | cases | precision | recall | FP | FN |", "|---|---|---|---|---|---|"]
    tp = fp = fn = tn = 0
    for gid in sorted(scores):
        s = scores[gid]
        tp, fp, fn, tn = tp + s.tp, fp + s.fp, fn + s.fn, tn + s.tn
        n = s.tp + s.fp + s.fn + s.tn
        lines.append(f"| {gid} | {n} | {s.precision:.0%} | {s.recall:.0%} | {s.fp} | {s.fn} |")
    overall = Score(tp, fp, fn, tn)
    lines.append(f"| **overall** | {tp+fp+fn+tn} | **{overall.precision:.0%}** | **{overall.recall:.0%}** | {fp} | {fn} |")
    return "\n".join(lines) + "\n"


def test_benchmark_no_misclassification(tmp_path: Path) -> None:
    scores = measure(tmp_path)
    assert scores, "corpus produced no measurable guards"
    bad = {gid: s for gid, s in scores.items() if s.fp or s.fn}
    assert not bad, f"false positives/negatives on the curated corpus: {bad}\n\n{render(scores)}"


def test_benchmark_report_renders(tmp_path: Path) -> None:
    md = render(measure(tmp_path))
    assert "precision/recall" in md and "overall" in md


if __name__ == "__main__":  # `python -m tests.test_benchmark` prints the scorecard
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        print(render(measure(Path(d))))
