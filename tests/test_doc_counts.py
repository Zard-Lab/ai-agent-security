"""Unit tests for scripts/doc_counts.py + a scalar drift guard for the count-bearing docs.

The drift guard is the mirror of tests/test_readme_facts.py: it fails CI when the four scalar facts
(guards, runners, checklist version, item count) go stale in ROADMAP / user-guide / the infographics /
the coverage-dashboard scalar lines — so a guard or checklist change that forgets to refresh them is
caught. The per-section table is deliberately NOT gated (too granular; the /refresh-doc-counts skill
owns it).
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import _exec_guarded

_REPO = Path(__file__).resolve().parents[1]
_SCRIPT = _REPO / "scripts" / "doc_counts.py"
_spec = importlib.util.spec_from_file_location("doc_counts", _SCRIPT)
assert _spec is not None and _spec.loader is not None
dc = importlib.util.module_from_spec(_spec)
sys.modules["doc_counts"] = dc  # register before exec so @dataclass can resolve cls.__module__
_exec_guarded(_spec.loader, dc, "doc_counts.py")


# --------------------------------------------------------------------------- ground truth
def test_live_counts_match_registry_and_checklist() -> None:
    from agentsec.checklist import load_checklist
    from agentsec.registry import ALL_GUARDS, ALL_RUNNERS

    c = dc.live_counts()
    cl = load_checklist()
    assert c.guards == len(ALL_GUARDS)
    assert c.runners == len(ALL_RUNNERS)
    assert c.version == cl.version
    assert c.items == len(cl.items)


def test_full_registry_rollup_sums_to_all_items_with_no_na() -> None:
    from agentsec.checklist import load_checklist

    c = dc.live_counts()
    # every item is covered/partial/manual — na is 0 by construction (stack-agnostic)
    assert c.covered + c.partial + c.manual == c.items == len(load_checklist().items)
    assert sum(v[3] for v in c.sections.values()) == c.items
    for auto, rev, man, tot, _ in c.sections.values():
        assert auto + rev + man == tot


# --------------------------------------------------------------------------- table renderer
def _table_rows() -> list[str]:
    text = (_REPO / "wiki" / "coverage-dashboard.md").read_text(encoding="utf-8")
    lines = text.split("\n")
    start = next(i for i, ln in enumerate(lines) if ln.strip() == "```")
    end = next(i for i, ln in enumerate(lines[start + 1:], start + 1) if ln.strip() == "```")
    return [ln for ln in lines[start + 1:end] if ln.startswith("§")]


def test_render_row_is_byte_identical_to_the_live_table() -> None:
    # Every current row must round-trip through the renderer unchanged (fixed-column alignment +
    # preserved label/annotation). This is the guarantee that a refresh can't misalign a row.
    for line in _table_rows():
        m = dc._ROW.match(line)
        assert m, f"row did not parse: {line!r}"
        # re-derive the numbers straight from the row and re-render
        nums = re.findall(r"\d+", line.split("[")[0])
        # nums may lead with the section number (e.g. §12) — take the last four before the bar
        auto, rev, man, tot = (int(x) for x in nums[-4:])
        pct = int(re.search(r"(\d+)%", line).group(1))  # type: ignore[union-attr]
        rebuilt = dc.render_row(m.group("label"), auto, rev, man, tot, pct, m.group("annot"))
        assert rebuilt == line, f"\n orig: {line!r}\n new : {rebuilt!r}"


def test_bar_uses_round_pct_over_ten() -> None:
    assert dc._bar(0) == "." * 10
    assert dc._bar(100) == "#" * 10
    assert dc._bar(92) == "#" * 9 + "."       # round(9.2) = 9
    assert dc._bar(55) == "#" * 6 + "." * 4   # round(5.5) = 6 (banker's → even)


def test_table_sums_to_the_totals_line() -> None:
    c = dc.live_counts()
    auto = rev = man = 0
    for line in _table_rows():
        nums = re.findall(r"\d+", line.split("[")[0])[-4:]
        auto += int(nums[0])
        rev += int(nums[1])
        man += int(nums[2])
    assert (auto, rev, man) == (c.covered, c.partial, c.manual)


# --------------------------------------------------------------------------- patch fns are pure + idempotent
def test_patches_are_idempotent_and_hit_live_values() -> None:
    c = dc.live_counts()
    fixtures = {
        dc.patch_roadmap: "**Baseline:** `main` is **v0.1.0, 9 checklist items, 3 guards, 2 runners**. rest",
        dc.patch_user_guide: "The checklist (7 items, versioned) rendered as a table.",
        dc.patch_infographic: "<h4>3 Guards &amp; 9-Item Checklist</h4> running 3 static guards; "
                              "each of the 3 guards; <h4>3 Dependency-Free Static Guards</h4>; "
                              "supplemented by 2 optional integrations like Bandit.",
    }
    for fn, text in fixtures.items():
        once = fn(text, c)
        assert fn(once, c) == once, f"{fn.__name__} not idempotent"
        assert str(c.guards) in once or str(c.items) in once


def test_infographic_patch_covers_the_runner_count() -> None:
    # Regression: the "N optional integrations" sentence is a runner count and must be refreshed
    # (it was missed once, so `--check` said OK while a stale count sat on disk).
    c = dc.live_counts()
    out = dc.patch_infographic("supplemented by 7 optional integrations like Bandit, Semgrep.", c)
    assert out == f"supplemented by {c.runners} optional integrations like Bandit, Semgrep."


def test_render_row_raises_on_column_overflow() -> None:
    import pytest
    with pytest.raises(ValueError, match="overflow"):
        # a label that fills the field so a multi-digit count can't fit before its end column
        dc.render_row("§99 " + "x" * 60, 999, 0, 0, 0, 0)


def test_roadmap_patch_writes_all_four_scalars() -> None:
    c = dc.live_counts()
    out = dc.patch_roadmap("is **v9.9.9, 1 checklist items, 2 guards, 3 runners**", c)
    assert out == f"is **v{c.version}, {c.items} checklist items, {c.guards} guards, {c.runners} runners**"


# --------------------------------------------------------------------------- the durable drift guard
# `test_docs_have_no_scalar_count_drift` lives in the maintainers' private test module: it reads a file this repository does
# not publish.


# --------------------------------------------------------------------------- the narrative drift net
def test_docs_have_no_narrative_count_drift() -> None:
    # The "prose never carries live counts" doctrine (docs/README.md): no live doc may hard-code a
    # guard/item/runner count that disagrees with the registry. To fix a failure, either EDIT the
    # prose to remove the count (link to the ROADMAP baseline line / README instead), or, for a
    # genuinely historical line, append a trailing `<!-- stale-ok -->` marker to waive it.
    hits = dc.narrative_drift(dc.live_counts())
    assert not hits, "narrative count drift (de-numberize the prose, or add `<!-- stale-ok -->`):\n" + \
        "\n".join(hits)


# Returns a dc.Counts; annotated `object` because `dc` is an importlib-loaded module, so a precise
# `dc.Counts` annotation is not a resolvable type form for the type-checkers (reportInvalidTypeForm).
def _counts(guards: int = 3, items: int = 7, runners: int = 2) -> object:
    return dc.Counts(
        guards=guards, runners=runners, version="9.9.9", items=items,
        covered=1, partial=1, manual=items - 2, pct=14, sections={},
    )


def test_narrative_drift_detects_waives_and_excludes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Drive narrative_drift over a throwaway tree (monkeypatch ROOT) to prove: it flags a mismatched
    # count, stays silent on a matching one, honours the `<!-- stale-ok -->` waiver, and skips the
    # excluded homes (append-only records + the per-guard design docs, now under wiki/guards/).
    kn = tmp_path / "docs" / "knowledge"
    kn.mkdir(parents=True)
    (kn / "live.md").write_text(
        "The tool ships 3 guards.\n"          # matches live (3) → silent
        "An old note said 5 guards once.\n"   # mismatch → FLAGGED
        "Historically 9 guards shipped. <!-- stale-ok -->\n",  # mismatch but waived → silent
        encoding="utf-8",
    )
    (tmp_path / "docs" / "archive").mkdir(parents=True)
    (tmp_path / "docs" / "archive" / "old.md").write_text("had 5 guards.\n", encoding="utf-8")  # excluded dir
    (tmp_path / "wiki").mkdir()
    (tmp_path / "wiki" / "coverage-dashboard.md").write_text("live: 3 guards.\n", encoding="utf-8")  # scanned, matches
    # The guard-design docs moved to wiki/guards/ (RFC Proposal 3). wiki/** IS scanned, so the
    # exclusion had to move with them or 259 docs full of fixed-window "N guards" prose would all
    # start tripping this check. Both halves are pinned: excluded here...
    (tmp_path / "wiki" / "guards").mkdir()
    (tmp_path / "wiki" / "guards" / "foo.md").write_text("5 guards in the fixed window.\n", encoding="utf-8")
    # ...and NOT excluded at the old path, because docs/knowledge/ is now private process docs
    # only, which are ordinary live prose subject to the no-live-counts rule.
    #
    # The count here MUST mismatch the live count (3). An earlier version of this fixture used
    # "3 guards", which produces zero hits whether the file is scanned or excluded -- so the
    # assertion below held against the exact regression it exists to catch, and proved nothing
    # (#618 review, M1). Measured with "7 guards": 2 hits scanned, 1 hit if the old exclusion
    # comes back.
    (kn / "guard-design-foo.md").write_text("A stale note claims 7 guards.\n", encoding="utf-8")

    monkeypatch.setattr(dc, "ROOT", tmp_path)
    hits = dc.narrative_drift(_counts())

    # Order-independent: hits come back sorted by path, which is not the order they are written
    # above, and pinning an index here would make the test brittle for no benefit.
    assert len(hits) == 2, hits
    joined = "\n".join(hits)
    assert "docs/knowledge/live.md:2: found '5 guards', live is 3" in joined
    # the old-path doc is SCANNED, so its stale count is flagged like any other live prose
    assert "docs/knowledge/guard-design-foo.md:1: found '7 guards', live is 3" in joined


def test_narrative_drift_tolerates_non_utf8_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A stray non-UTF-8 byte in a scanned doc must not crash the check (errors="ignore"): the read
    # still succeeds and the count on the line is still caught.
    kn = tmp_path / "docs" / "knowledge"
    kn.mkdir(parents=True)
    (kn / "bad.md").write_bytes(b"intro line\n\xff\xfe a stale 5 guards claim\n")
    monkeypatch.setattr(dc, "ROOT", tmp_path)

    hits = dc.narrative_drift(_counts())  # live guards=3

    assert len(hits) == 1, hits
    assert "found '5 guards', live is 3" in hits[0]


# --------------------------------------------------------------------------- cross-platform stdout
def test_write_summary_is_windows_safe(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Regression (#414 review): the --write summary line must be encodable under cp1252, the default
    # Windows console codepage. A U+2192 arrow ("→") raised UnicodeEncodeError there, crashing --write
    # from a Windows shell. Monkeypatch write() so no docs are touched — we only need the print to fire.
    monkeypatch.setattr(dc, "write", lambda _c: [])
    rc = dc.main(["--write"])
    assert rc == 0
    out = capsys.readouterr().out
    out.encode("cp1252")  # raises UnicodeEncodeError if a non-cp1252 char sneaks back into the print


# --------------------------------------------------------------------------- the sys.path trap
# Issue #511. This script has TWO notions of "this repo": ROOT (filesystem, governs every doc it
# reads and writes) and `import agentsec` (sys.path, governs every number it reports). If those
# resolve to different checkouts it reports — and with --write, stamps — one tree's docs using
# another tree's counts, then exits 0. Two mechanisms keep them equal: the sys.path insert and the
# assertion after it. These tests pin one each, and both are written so that removing the mechanism
# they pin produces the REAL failure (a confident wrong number), not merely a crash.
_FAKE_GUARDS, _FAKE_RUNNERS, _FAKE_VERSION, _FAKE_ITEMS = 9, 3, "0.0.0-fake", 2


def _fake_checkout(tmp_path: Path) -> Path:
    """A second 'checkout' complete enough for live_counts() to succeed with WRONG numbers.

    Deliberately not a bare stub: if it were missing submodules the script would die with
    ModuleNotFoundError, and a test that only proves "it crashes" would not prove the thing that
    matters, which is that it never quietly reports these numbers as if they were ours.
    """
    pkg = tmp_path / "other-checkout" / "agentsec"
    (pkg / "checklist").mkdir(parents=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "console.py").write_text(
        "def force_utf8_stdio() -> None:\n    return None\n", encoding="utf-8"
    )
    (pkg / "registry.py").write_text(
        f"ALL_GUARDS = [None] * {_FAKE_GUARDS}\nALL_RUNNERS = [None] * {_FAKE_RUNNERS}\n",
        encoding="utf-8",
    )
    (pkg / "checklist" / "__init__.py").write_text(
        "class _Item:\n"
        "    def __init__(self, section, status):\n"
        "        self.section, self.status = section, status\n"
        "class _Checklist:\n"
        f"    version = {_FAKE_VERSION!r}\n"
        "    items = [_Item('1', 'covered'), _Item('2', 'manual')]\n"
        "def load_checklist():\n"
        "    return _Checklist()\n",
        encoding="utf-8",
    )
    return pkg.parent


def _clean_env(**extra: str) -> dict[str, str]:
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env.update(extra)
    return env


def test_agentsec_resolves_to_this_checkout() -> None:
    # The FP-bait direction (CLAUDE.md rule 1): this change is a NARROWING — the script now refuses
    # in a case where it used to proceed — so the ordinary path must be proven still to work.
    import agentsec

    assert Path(agentsec.__file__).resolve().parent == _REPO / "agentsec"
    assert dc.ROOT == _REPO


def test_script_prefers_this_checkout_over_one_on_pythonpath(tmp_path: Path) -> None:
    # Pins the sys.path INSERT. Run from a foreign cwd with a second checkout on PYTHONPATH: the
    # insert puts ROOT at position 0, so OUR numbers must win. Delete the insert and PYTHONPATH
    # wins instead — the script then prints 9 guards / 3 runners / v0.0.0-fake and exits 0, which
    # is exactly the silent wrong answer #511 was filed about.
    from agentsec.checklist import load_checklist
    from agentsec.registry import ALL_GUARDS, ALL_RUNNERS

    proc = subprocess.run(
        [sys.executable, str(_SCRIPT), "--json"],
        cwd=str(tmp_path), env=_clean_env(PYTHONPATH=str(_fake_checkout(tmp_path))),
        capture_output=True, text=True, encoding="utf-8", timeout=120,
    )

    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    cl = load_checklist()
    assert payload["guards"] == len(ALL_GUARDS) != _FAKE_GUARDS
    assert payload["runners"] == len(ALL_RUNNERS) != _FAKE_RUNNERS
    assert payload["items"] == len(cl.items) != _FAKE_ITEMS
    assert payload["version"] == cl.version != _FAKE_VERSION


def test_script_refuses_when_agentsec_is_another_checkout(tmp_path: Path) -> None:
    # Pins the ASSERTION, the half the insert cannot cover. sys.path governs resolution, never
    # RE-resolution: once `agentsec` is cached in sys.modules the script's own insert is a no-op
    # and live_counts() reads the cached package. Not hypothetical — tests/conftest.py imports
    # agentsec at module scope, and pytest imports conftest before this file is exec'd in-process.
    # Driven in a SUBPROCESS on purpose: importing a second `agentsec` into the pytest process
    # would poison every other test in the session.
    fake = _fake_checkout(tmp_path)
    driver = tmp_path / "driver.py"
    driver.write_text(
        "import importlib.util, sys\n"
        f"sys.path.insert(0, {str(fake)!r})\n"
        "import agentsec  # the other checkout wins: imported FIRST, cached in sys.modules\n"
        f"spec = importlib.util.spec_from_file_location('doc_counts', {str(_SCRIPT)!r})\n"
        "mod = importlib.util.module_from_spec(spec)\n"
        "sys.modules['doc_counts'] = mod\n"
        "spec.loader.exec_module(mod)\n"
        "c = mod.live_counts()\n"
        "print('NO REFUSAL:', c.guards, c.runners, c.version)\n",
        encoding="utf-8",
    )
    proc = subprocess.run(
        [sys.executable, str(driver)],
        cwd=str(tmp_path), env=_clean_env(), capture_output=True, text=True,
        encoding="utf-8", timeout=120,
    )

    assert proc.returncode == 2, f"expected a loud refusal, got rc={proc.returncode}\n{proc.stdout}"
    assert "refusing to run" in proc.stderr
    # The point of the guard: the other tree's numbers must never be printed as if they were ours.
    assert "NO REFUSAL" not in proc.stdout
    assert _FAKE_VERSION not in proc.stdout
