"""Unit tests for agentsec/corpus.py — no real git clones, no real GitHub API calls."""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import stat
import sys
from collections.abc import Callable
from datetime import date
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agentsec.cli import main
from agentsec.corpus import (
    _FP_OUTLIER_EXCLUDED_REPOS,
    SEED_REPOS,
    CorpusReport,
    FpCandidate,
    GapCandidate,
    RepoScan,
    analyze_fps,
    analyze_gaps,
    corpus_scan,
    outlier_excluded_repos,
    report_to_json,
    report_to_markdown,
    report_to_terminal,
    scan_repo,
)
from agentsec.findings import Finding
from tests.conftest import mkprofile

_TODAY = date(2026, 6, 25)


def _scan(
    url: str = "https://github.com/example/repo",
    features: list[str] | None = None,
    findings: list[Finding] | None = None,
    ran: list[str] | None = None,
    skipped: list[str] | None = None,
    error: str = "",
) -> RepoScan:
    return RepoScan(
        url=url,
        features=features or ["python", "fastapi", "llm"],
        stack_summary="python+fastapi+llm",
        findings=findings or [],
        ran=ran or [],
        skipped=skipped or [],
        error=error,
    )


def _finding(guard_id: str, location: str = "app/main.py:10") -> Finding:
    return Finding(check_id=guard_id, severity="high", title=f"Finding from {guard_id}", location=location)


# ---------------------------------------------------------------------------
# FP analysis
# ---------------------------------------------------------------------------

def test_fp_analysis_detects_high_ratio() -> None:
    guard = "cors-wildcard"
    scans = [
        _scan(url=f"https://example.com/{i}", ran=[guard], findings=[_finding(guard)])
        for i in range(8)
    ] + [
        _scan(url=f"https://example.com/clean/{i}", ran=[guard], findings=[])
        for i in range(2)
    ]
    result = analyze_fps(scans, threshold=0.5, min_repos=3)
    assert any(c.guard_id == guard for c in result)
    cand = next(c for c in result if c.guard_id == guard)
    assert cand.fired_ratio == pytest.approx(0.8)


def test_fp_analysis_ignores_low_sample() -> None:
    guard = "cors-wildcard"
    scans = [
        _scan(url=f"https://example.com/{i}", ran=[guard], findings=[_finding(guard)])
        for i in range(2)
    ]
    result = analyze_fps(scans, threshold=0.5, min_repos=3)
    assert not any(c.guard_id == guard for c in result)


def test_fp_analysis_skips_errored_scans() -> None:
    guard = "cors-wildcard"
    good = [_scan(url=f"https://example.com/{i}", ran=[guard], findings=[_finding(guard)]) for i in range(3)]
    bad = [_scan(url="https://example.com/bad", ran=[guard], findings=[_finding(guard)], error="clone-failed")]
    result = analyze_fps(good + bad, threshold=0.5, min_repos=3)
    cand = next((c for c in result if c.guard_id == guard), None)
    if cand:
        assert "https://example.com/bad" not in cand.repos_applicable


def test_fp_analysis_collects_sample_locations() -> None:
    guard = "cors-wildcard"
    scans = [
        _scan(
            url=f"https://example.com/{i}",
            ran=[guard],
            findings=[_finding(guard, location=f"app/main.py:{i}")],
        )
        for i in range(6)
    ]
    result = analyze_fps(scans, threshold=0.0, min_repos=3)
    cand = next((c for c in result if c.guard_id == guard), None)
    assert cand is not None
    assert len(cand.fp_sample_locations) <= 5


def _findings(guard_id: str, n: int) -> list[Finding]:
    return [_finding(guard_id, location=f"app/routes/r{i}.py:{i}") for i in range(n)]


def test_fp_analysis_flags_single_repo_over_fire_outlier() -> None:
    # A guard that blows up on ONE repo (8 findings) and fires 0-1 on the others is invisible to the
    # prevalence signal (needs >50% across >=3 repos) but must surface as an over-fire outlier (#8b).
    guard = "auth-dependency-not-applied"
    scans = [_scan(url="https://example.com/spike", ran=[guard], findings=_findings(guard, 8))] + [
        _scan(url=f"https://example.com/clean/{i}", ran=[guard], findings=[]) for i in range(4)
    ]
    result = analyze_fps(scans, threshold=0.5, min_repos=3)
    cand = next((c for c in result if c.guard_id == guard), None)
    assert cand is not None and cand.outlier is True
    assert cand.max_repo_findings == 8
    assert cand.fired_ratio == pytest.approx(0.2)  # 1/5 repos — below the prevalence threshold


def test_fp_outlier_needs_absolute_floor() -> None:
    # A small spike (2 on one repo, 0 elsewhere) clears the multiple but not the count floor → silent.
    guard = "cors-wildcard"
    scans = [_scan(url="https://example.com/spike", ran=[guard], findings=_findings(guard, 2))] + [
        _scan(url=f"https://example.com/clean/{i}", ran=[guard], findings=[]) for i in range(3)
    ]
    assert not any(c.guard_id == guard for c in analyze_fps(scans, outlier_min_count=5))


def test_fp_outlier_needs_concentration_not_uniform() -> None:
    # Two repos each firing 6 (uniform, not concentrated) is not a single-repo outlier — the peak is
    # not >= 3x the next repo. (It also stays under the prevalence threshold at 2/5 repos.)
    #
    # The two repos deliberately carry DIFFERENT amounts of unrelated noise, so their shares differ
    # (6/10 = 0.60 vs 6/12 = 0.50) and the size-normalization filter would PASS this fixture. That
    # makes the concentration check the only thing suppressing it, which is what this test is for:
    # with equal shares, either mechanism alone suppressed the candidate and deleting the
    # concentration check left this test green (#476 re-gate M1). The noise counts are kept close
    # (4 vs 6) so the noise guard does not trip the outlier signal on its own and muddy the fixture.
    guard = "cors-wildcard"
    noise = "weak-crypto"
    scans = [
        _scan(url="https://example.com/a", ran=[guard, noise],
              findings=_findings(guard, 6) + _findings(noise, 4)),
        _scan(url="https://example.com/b", ran=[guard, noise],
              findings=_findings(guard, 6) + _findings(noise, 6)),
    ] + [_scan(url=f"https://example.com/clean/{i}", ran=[guard], findings=[]) for i in range(3)]
    assert not any(c.guard_id == guard for c in analyze_fps(scans, threshold=0.5, min_repos=3))


def test_fp_outlier_needs_a_comparison_basis(tmp_path: Path) -> None:
    # #476 review: with a SINGLE applicable repo there is nothing to compare against, so the
    # concentration test degenerates to the absolute floor alone (`peak >= 5`) and reports a
    # correctly-working guard on the only repo it applies to. Two distinct repos are required.
    guard = "cors-wildcard"
    one = [_scan(url="https://example.com/only", ran=[guard], findings=_findings(guard, 9))]
    assert not any(c.guard_id == guard for c in analyze_fps(one))
    # ...and adding a real second repo restores the signal.
    two = one + [_scan(url="https://example.com/other", ran=[guard], findings=[])]
    assert any(c.guard_id == guard and c.outlier for c in analyze_fps(two))


def test_fp_duplicate_repo_entry_does_not_kill_the_outlier_signal() -> None:
    # #476 review: the same URL scanned twice made the repo its own comparison basis
    # (`peak == rest_peak`), so the concentration test could never pass — a duplicate entry
    # silently cancelled the signal. Scans are deduped by URL before either signal runs.
    guard = "cors-wildcard"
    spike = _scan(url="https://example.com/spike", ran=[guard], findings=_findings(guard, 9))
    dupe = _scan(url="https://example.com/spike", ran=[guard], findings=_findings(guard, 9))
    other = _scan(url="https://example.com/other", ran=[guard], findings=[])
    assert any(c.guard_id == guard and c.outlier for c in analyze_fps([spike, dupe, other]))


def test_fp_outlier_excludes_a_deliberately_vulnerable_recall_repo() -> None:
    # M3: a deliberately-vulnerable, small/dense recall-canary repo would otherwise
    # become the outlier spike on its own real vulnerabilities, misreading them as FP candidates.
    # Verified empirically against a real scoped corpus-scan before this fix (not assumed): two
    # guards on the real damn-vulnerable-MCP-server outlier-flagged with 100% of their findings
    # from that one repo's own fixtures. An excluded repo must not become the spike, and must not
    # even count as comparison basis for an ordinary repo's own spike.
    guard = "command-injection"
    excluded_url = next(iter(_FP_OUTLIER_EXCLUDED_REPOS))
    vulnerable = _scan(url=excluded_url, ran=[guard], findings=_findings(guard, 20))
    clean = [_scan(url=f"https://example.com/clean/{i}", ran=[guard], findings=[]) for i in range(3)]
    # Excluded alone with only clean repos: no comparison basis survives filtering -> silent,
    # not "flag the excluded repo anyway" and not "crash on an empty comparison set".
    assert not any(c.guard_id == guard for c in analyze_fps([vulnerable, *clean]))

    # An ordinary repo's own real spike must still surface normally even with the excluded repo
    # also present and also firing heavily -- its presence must not suppress a genuine signal
    # elsewhere, only decline to BE that signal itself.
    ordinary_spike = _scan(url="https://example.com/spike", ran=[guard], findings=_findings(guard, 9))
    ordinary_others = [_scan(url=f"https://example.com/other/{i}", ran=[guard], findings=[]) for i in range(2)]
    result = analyze_fps([vulnerable, ordinary_spike, *ordinary_others])
    cand = next((c for c in result if c.guard_id == guard), None)
    assert cand is not None and cand.outlier is True
    assert excluded_url not in cand.repos_applicable
    assert cand.max_repo_findings == 9  # the ordinary repo's own count, not the excluded repo's 20


@pytest.mark.parametrize(
    "respell",
    [
        lambda url: url,
        lambda url: url + ".git",
        lambda url: url + "/",
        lambda url: url.replace("harishsg993010", "HarishSG993010"),
        lambda url: url.replace("https://", "http://"),
    ],
    ids=["as-is", "trailing-.git", "trailing-slash", "owner-case", "http-scheme"],
)
def test_fp_outlier_exclusion_survives_url_respelling(respell: Callable[[str], str]) -> None:
    # Review H1: an exact string match on `_FP_OUTLIER_EXCLUDED_REPOS` let any other spelling of
    # the same excluded repo silently bypass the exclusion -- including the exact spelling (a
    # trailing `.git`) that discover_repos' own GitHub search `clone_url` produces for this repo
    # if it's ever auto-discovered rather than seeded. All five spellings below must still be
    # excluded from the outlier signal.
    guard = "command-injection"
    excluded_url = next(iter(_FP_OUTLIER_EXCLUDED_REPOS))
    vulnerable = _scan(url=respell(excluded_url), ran=[guard], findings=_findings(guard, 20))
    clean = [_scan(url=f"https://example.com/clean/{i}", ran=[guard], findings=[]) for i in range(3)]
    assert not any(c.guard_id == guard for c in analyze_fps([vulnerable, *clean]))


def test_fp_outlier_excluded_repos_is_a_subset_of_seed_repos() -> None:
    # Review M2: the exclusion set must only ever name a real SEED_REPOS entry, so it can't
    # silently drift from the actual seed repo it's meant to exclude.
    assert set(SEED_REPOS) >= _FP_OUTLIER_EXCLUDED_REPOS



def test_fp_outlier_exclusion_is_disclosed_in_the_report_only_when_present() -> None:
    # Round-1 review M1: the exclusion used to be silent, so the excluded repo read as "not
    # applicable" in fp-candidates.json and nothing said why. Both directions: a scan that holds
    # the recall repo (under the discovery spelling, with `.git`) names it in the report JSON, the
    # markdown and the terminal summary; a scan without it says nothing.
    guard = "command-injection"
    excluded = next(iter(_FP_OUTLIER_EXCLUDED_REPOS)) + ".git"
    ordinary = [_scan(url=f"https://example.com/r/{i}", ran=[guard], findings=[]) for i in range(3)]
    with_recall = [_scan(url=excluded, ran=[guard], findings=_findings(guard, 20)), *ordinary]
    assert outlier_excluded_repos(with_recall) == [excluded]
    assert outlier_excluded_repos(ordinary) == []
    # A recall repo whose scan errored (clone failure, stack mismatch) counted for nothing, so it
    # must not be reported as excluded-but-still-counted.
    errored = _scan(url=excluded, ran=[], findings=[], error="clone failed")
    assert outlier_excluded_repos([errored, *ordinary]) == []

    def _report(scans: list[RepoScan]) -> CorpusReport:
        return CorpusReport(
            scanned=scans, fp_candidates=analyze_fps(scans), gap_candidates=[], run_date="2026-10-27",
            corpus_size=len(scans), stack_match_count=len(scans),
            outlier_excluded_repos=outlier_excluded_repos(scans),
        )

    disclosed = _report(with_recall)
    assert json.loads(report_to_json(disclosed))["outlier_excluded_repos"] == [excluded]
    assert "outlier signal excludes 1 deliberately-vulnerable recall repo" in report_to_markdown(disclosed)
    assert f"outlier signal excludes 1 recall repo: {excluded}" in report_to_terminal(disclosed)

    silent = _report(ordinary)
    assert json.loads(report_to_json(silent))["outlier_excluded_repos"] == []
    assert "recall repo" not in report_to_markdown(silent)
    assert "recall repo" not in report_to_terminal(silent)

def test_fp_outlier_is_size_normalized() -> None:
    # #476 review: raw counts scale with repo size, so the biggest repo tops the peak on nearly
    # every guard. A guard firing 20x on a repo with 10x of everything is PROPORTIONATE and must
    # not surface, even though 20 >= 3 x 2 clears the raw multiple.
    guard = "cors-wildcard"
    big = _scan(
        url="https://example.com/big", ran=[guard],
        findings=_findings(guard, 20) + _findings("other-guard", 200),
    )
    small = _scan(
        url="https://example.com/small", ran=[guard],
        findings=_findings(guard, 2) + _findings("other-guard", 20),
    )
    assert not any(c.guard_id == guard and c.outlier for c in analyze_fps([big, small]))
    # Held at the SAME repo size, the guard IS an outsized share on `big` (20/220 vs 2/220), so
    # the spike is real and still surfaces — the normalization removes the size artifact, not the
    # signal.
    same_size = _scan(
        url="https://example.com/same-size", ran=[guard],
        findings=_findings(guard, 2) + _findings("other-guard", 218),
    )
    assert any(c.guard_id == guard and c.outlier for c in analyze_fps([big, same_size]))


def test_fp_prevalence_candidate_not_duplicated_as_outlier() -> None:
    # A guard already surfaced by prevalence (fires on all 4 repos, one of them a spike) appears once,
    # tagged as prevalence (outlier=False) but still carrying the peak-per-repo magnitude.
    #
    # The spike repo carries a strictly larger SHARE than the others (9/10 = 0.90 vs 1/10 = 0.10), so
    # it clears the size-normalization filter and would be re-emitted as an outlier if the
    # `seen_guards` gate were removed. With equal shares that filter suppressed the second emission
    # by itself and deleting the dedup gate left this test green (#476 re-gate M2).
    guard = "cors-wildcard"
    noise = "weak-crypto"
    scans = [
        _scan(url="https://example.com/spike", ran=[guard, noise],
              findings=_findings(guard, 9) + _findings(noise, 1)),
    ] + [
        _scan(url=f"https://example.com/f/{i}", ran=[guard, noise],
              findings=_findings(guard, 1) + _findings(noise, 9)) for i in range(3)
    ]
    result = [c for c in analyze_fps(scans, threshold=0.5, min_repos=3) if c.guard_id == guard]
    assert len(result) == 1
    assert result[0].outlier is False and result[0].max_repo_findings == 9


# ---------------------------------------------------------------------------
# Gap analysis
# ---------------------------------------------------------------------------

def test_gap_analysis_finds_manual_items() -> None:
    scans = [_scan(features=["python", "fastapi", "llm"])]
    result = analyze_gaps(scans)
    assert len(result) > 0
    for g in result:
        assert g.repos_affected >= 1
        assert isinstance(g.stacks_seen, list)
        assert isinstance(g.applies_when, list)
        assert isinstance(g.standards, list)


def test_gap_analysis_skips_errored_scans() -> None:
    bad = _scan(error="clone-failed")
    result = analyze_gaps([bad])
    assert all(g.repos_affected == 0 for g in result)


def test_gap_candidate_carries_full_metadata() -> None:
    scans = [_scan(features=["python", "fastapi", "llm"])]
    result = analyze_gaps(scans)
    for g in result:
        assert isinstance(g.item_id, str)
        assert isinstance(g.item_title, str)
        assert isinstance(g.atlas_techniques, list)
        assert isinstance(g.cwe, (str, type(None)))


def test_gap_candidate_stacks_seen_is_list_of_lists() -> None:
    scans = [
        _scan(url="https://example.com/1", features=["python", "fastapi", "llm"]),
        _scan(url="https://example.com/2", features=["python", "fastapi", "llm", "supabase"]),
    ]
    result = analyze_gaps(scans)
    for g in result:
        assert isinstance(g.stacks_seen, list)
        for entry in g.stacks_seen:
            assert isinstance(entry, list)
            assert all(isinstance(f, str) for f in entry)


def test_gap_analysis_skips_na_items() -> None:
    # scan with NO llm feature — LLM-specific items should not appear
    scans = [_scan(features=["python", "docker", "postgres"])]
    result = analyze_gaps(scans)
    llm_only = [g for g in result if "llm" in g.applies_when and len(g.applies_when) == 1]
    assert len(llm_only) == 0


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def test_report_to_json_is_serializable() -> None:
    report = CorpusReport(
        scanned=[_scan()],
        fp_candidates=[],
        gap_candidates=[],
        run_date="2026-06-25",
        corpus_size=1,
        stack_match_count=1,
    )
    raw = report_to_json(report)
    parsed = json.loads(raw)
    assert parsed["run_date"] == "2026-06-25"
    assert isinstance(parsed["scanned"], list)


# ---------------------------------------------------------------------------
# scan_repo error handling
# ---------------------------------------------------------------------------

def test_scan_repo_captures_detect_error(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    result = scan_repo("https://example.com/repo", empty, _TODAY)
    # empty dir may or may not raise in detect — if it raises, error is set
    assert isinstance(result, RepoScan)
    assert isinstance(result.error, str)


def test_scan_repo_with_non_utf8_config_is_scanned_not_audit_failed(tmp_path: Path) -> None:
    # #961 round-1 L2: a SCANNED repo (not the CWD) with an un-decodable config landed as
    # `audit-failed: 'utf-8' codec ...` with every finding dropped; it is now scanned with defaults.
    repo = tmp_path / "repo"
    (repo / ".agentsec").mkdir(parents=True)
    (repo / ".agentsec" / "config.json").write_bytes('{"archive_paths": true}'.encode("utf-16"))
    (repo / "requirements.txt").write_text("fastapi\n", encoding="utf-8")
    result = scan_repo("https://example.com/repo", repo, _TODAY, min_features=0)
    assert result.error == ""
    assert result.ran


def _corpus_scan_one_local_repo(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], config: bytes | None
) -> list[str]:
    """Run `corpus_scan` over one local repo (optionally with a `.agentsec/config.json`), cloned by
    copying it, and return the stderr lines."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "requirements.txt").write_text("fastapi\n", encoding="utf-8")
    if config is not None:
        (src / ".agentsec").mkdir()
        (src / ".agentsec" / "config.json").write_bytes(config)

    def _copy_clone(url: str, dest: Path) -> bool:
        shutil.copytree(url, dest)
        return True

    with patch("agentsec.corpus.clone_repo", side_effect=_copy_clone), \
         patch("agentsec.corpus.evict_stale_cache", return_value=0):
        corpus_scan(
            repos=[str(src)], count=0, today=_TODAY, tier=0,
            include_seeds=False, min_features=0, cache_root=tmp_path / "cache",
        )
    return capsys.readouterr().err.splitlines()


def test_corpus_scan_keeps_the_progress_line_whole_when_a_repo_warns(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # #961 round-2 M1: the loop leaves `[i/total] name` open while the repo scans, so the config
    # loader's warning split it and orphaned the result from its repo. The traded-against direction:
    # the warning is held back, NOT swallowed, and it prints under the completed line.
    lines = _corpus_scan_one_local_repo(tmp_path, capsys, '{"archive_paths": true}'.encode("utf-16"))
    progress = next(i for i, ln in enumerate(lines) if ln.startswith("  [1/1]"))
    assert "✓" in lines[progress]
    assert "warning" not in lines[progress]
    held = [ln for ln in lines[progress + 1:] if "warning: ignoring" in ln]
    assert len(held) == 1  # printed once, not once per flush path (#961 round-3)
    assert held[0].startswith("      warning: ignoring") and "not UTF-8 text" in held[0]


def test_corpus_scan_interrupted_mid_scan_still_prints_what_was_held(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # #961 round-3 M1: a BaseException out of `scan_repo` (a Ctrl+C; a guard worker that fails to
    # start, which `guard_worker` lets propagate on purpose) unwound past the loop's flush, so the
    # held warnings were discarded rather than delayed. They must print, on their own line, before
    # the interrupt propagates.
    src = tmp_path / "src"
    src.mkdir()

    def _warn_then_interrupt(*_a: object, **_k: object) -> RepoScan:
        print("warning: ignoring the config (not UTF-8 text)", file=sys.stderr)
        raise KeyboardInterrupt

    with patch("agentsec.corpus.clone_repo", side_effect=_fake_clone), \
         patch("agentsec.corpus.scan_repo", side_effect=_warn_then_interrupt), \
         patch("agentsec.corpus.evict_stale_cache", return_value=0), \
         pytest.raises(KeyboardInterrupt):
        corpus_scan(
            repos=[str(src)], count=0, today=_TODAY, tier=0,
            include_seeds=False, cache_root=tmp_path / "cache",
        )
    lines = capsys.readouterr().err.splitlines()
    progress = next(i for i, ln in enumerate(lines) if ln.startswith("  [1/1]"))
    assert "warning" not in lines[progress]
    assert lines[progress + 1:] == ["      warning: ignoring the config (not UTF-8 text)"]


def test_corpus_scan_prints_nothing_extra_for_a_quiet_repo(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # FP-bait for the hold-back above: a repo whose scan prints nothing adds no lines under its own.
    lines = _corpus_scan_one_local_repo(tmp_path, capsys, b'{"archive_paths": ["old"]}')
    progress = next(i for i, ln in enumerate(lines) if ln.startswith("  [1/1]"))
    assert "✓" in lines[progress]
    assert lines[progress + 1:] == []


def test_scan_repo_captures_stack_mismatch(tmp_path: Path) -> None:
    # create a minimal dir with just one detectable feature
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("fastapi\n", encoding="utf-8")

    with patch("agentsec.corpus.detect") as mock_detect:
        profile = MagicMock()
        profile.features = {"python"}   # only 1 feature < min_features=3
        profile.summary.return_value = "python"
        mock_detect.return_value = profile

        result = scan_repo("https://example.com/repo", repo, _TODAY, min_features=3)

    assert "stack-mismatch" in result.error
    assert result.findings == []
    assert result.ran == []


# ---------------------------------------------------------------------------
# clone_repo_cached — persistent local clone cache
# ---------------------------------------------------------------------------

def _fake_clone(url: str, dest: Path) -> bool:
    """A `clone_repo` stand-in that actually creates a directory, unlike a bare mock returning
    True/False — needed here since the caching logic itself checks `dest.is_dir()`."""
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "marker.txt").write_text(url, encoding="utf-8")
    return True


def test_clone_repo_cached_first_call_clones_and_writes_marker(tmp_path: Path) -> None:
    from agentsec.corpus import _CACHE_MARKER, clone_repo_cached

    with patch("agentsec.corpus.clone_repo", side_effect=_fake_clone) as mock_clone:
        dest, status = clone_repo_cached("https://github.com/a/b", cache_root=tmp_path)

    assert status == "cloned"
    assert mock_clone.call_count == 1
    assert (dest / _CACHE_MARKER).is_file()


def test_clone_repo_cached_second_call_within_max_age_reuses_no_clone(tmp_path: Path) -> None:
    from agentsec.corpus import clone_repo_cached

    with patch("agentsec.corpus.clone_repo", side_effect=_fake_clone) as mock_clone:
        clone_repo_cached("https://github.com/a/b", cache_root=tmp_path, max_age_hours=168)
        dest, status = clone_repo_cached(
            "https://github.com/a/b", cache_root=tmp_path, max_age_hours=168,
        )

    assert status == "hit"
    assert mock_clone.call_count == 1  # only the FIRST call actually cloned


def test_clone_repo_cached_force_refresh_always_reclones(tmp_path: Path) -> None:
    from agentsec.corpus import clone_repo_cached

    with patch("agentsec.corpus.clone_repo", side_effect=_fake_clone) as mock_clone:
        clone_repo_cached("https://github.com/a/b", cache_root=tmp_path, max_age_hours=168)
        dest, status = clone_repo_cached(
            "https://github.com/a/b", cache_root=tmp_path, max_age_hours=168, force_refresh=True,
        )

    assert status == "cloned"
    assert mock_clone.call_count == 2


def test_clone_repo_cached_stale_marker_reclones(tmp_path: Path) -> None:
    from agentsec.corpus import _CACHE_MARKER, _cache_key, clone_repo_cached

    with patch("agentsec.corpus.clone_repo", side_effect=_fake_clone) as mock_clone:
        dest, _ = clone_repo_cached("https://github.com/a/b", cache_root=tmp_path, max_age_hours=168)
        # backdate the marker past the max age instead of waiting real time
        (dest / _CACHE_MARKER).write_text("2020-01-01T00:00:00+00:00", encoding="utf-8")
        dest2, status = clone_repo_cached(
            "https://github.com/a/b", cache_root=tmp_path, max_age_hours=168,
        )

    assert dest2 == tmp_path / _cache_key("https://github.com/a/b")
    assert status == "cloned"
    assert mock_clone.call_count == 2


def test_rmtree_robust_retries_then_succeeds(tmp_path: Path) -> None:
    """a delete that fails once (a just-killed subprocess briefly holding a file
    lock on Windows) must not be treated as permanent -- a short retry should recover it."""
    from agentsec.corpus import _rmtree_robust

    target = tmp_path / "locked"
    target.mkdir()
    (target / "file.txt").write_text("x", encoding="utf-8")

    calls = {"n": 0}
    real_rmtree = shutil.rmtree

    def _flaky_rmtree(path: Path, **kwargs: object) -> None:
        calls["n"] += 1
        if calls["n"] < 3:
            return  # simulate the lock still being held -- delete silently does nothing
        real_rmtree(path, ignore_errors=True)

    with (
        patch("agentsec.corpus.shutil.rmtree", side_effect=_flaky_rmtree),
        patch("agentsec.corpus.time.sleep"),
    ):
        result = _rmtree_robust(target, retries=5, delay_seconds=0)

    assert result is True
    assert not target.exists()
    assert calls["n"] == 3


def test_rmtree_robust_gives_up_after_persistent_failure(tmp_path: Path) -> None:
    """If the delete never succeeds (a real, non-transient problem), report that honestly
    instead of the old `ignore_errors=True` behavior of silently pretending it worked."""
    from agentsec.corpus import _rmtree_robust

    target = tmp_path / "stuck"
    target.mkdir()
    (target / "file.txt").write_text("x", encoding="utf-8")

    with patch("agentsec.corpus.shutil.rmtree"), patch("agentsec.corpus.time.sleep"):
        result = _rmtree_robust(target, retries=3, delay_seconds=0)

    assert result is False
    assert target.exists()  # never actually deleted -- not silently swallowed


def test_rmtree_robust_clears_a_state_dependent_readonly_file(tmp_path: Path) -> None:
    """Medium 4 (reopen review): a READ-ONLY file (e.g. git leaves its
    `.git/objects/pack/*.pack` files read-only) fails `shutil.rmtree` identically on every
    retry -- it's a STATE problem, not a TIMING one, so a bare re-issued
    `ignore_errors=True` rmtree can never recover it no matter how many times the loop runs.
    The real (unmocked) `_rmtree_robust` must clear the read-only bit and retry the removal,
    not just give up."""
    from agentsec.corpus import _rmtree_robust

    target = tmp_path / "readonly-leftover"
    target.mkdir()
    ro_file = target / "pack-abc123.pack"
    ro_file.write_text("git pack data", encoding="utf-8")
    ro_file.chmod(stat.S_IREAD)  # read-only -- what a real git leftover's pack files look like

    result = _rmtree_robust(target, retries=1, delay_seconds=0)

    assert result is True
    assert not target.exists()


def test_clear_readonly_and_retry_survives_a_func_that_rejects_the_call(tmp_path: Path) -> None:
    """Round-2 Critical 1: `shutil.rmtree`'s fd-based POSIX implementation can hand the
    `onexc` hook `func=os.open` -- which needs 2 positional args, not 1 -- when a directory it is
    trying to open has become unreadable from an EARLIER attempt's own chmod. The old hook's
    `except OSError` did not catch the resulting `TypeError`, so it escaped the hook, escaped
    `_rmtree_robust`, and took down the whole corpus-scan run. The hook must swallow it, not the
    caller."""
    from agentsec.corpus import _clear_readonly_and_retry

    target = tmp_path / "leftover"
    target.mkdir()

    def _rejects_one_arg(path: str) -> None:
        raise TypeError("open() missing required argument 'flags' (pos 2)")

    _clear_readonly_and_retry(_rejects_one_arg, str(target), PermissionError("denied"))  # must not raise


def test_clear_readonly_and_retry_adds_write_bit_without_stripping_other_bits(tmp_path: Path) -> None:
    """Round-2 Critical 1: the old hook ASSIGNED `stat.S_IWRITE` outright (0o200), which
    on POSIX clears every OTHER bit too -- on a directory that strips read AND execute, making it
    untraversable on the very next retry attempt (the crash `test_clear_readonly_and_retry_survives_
    a_func_that_rejects_the_call` above pins). The fix must ADD the write bit -- and execute, for a
    directory -- onto the EXISTING mode instead of overwriting it."""
    from agentsec.corpus import _clear_readonly_and_retry

    target = tmp_path / "dir"
    target.mkdir()
    target.chmod(stat.S_IREAD)  # read-only: no write, no execute

    calls: list[str] = []
    _clear_readonly_and_retry(calls.append, str(target), OSError("denied"))

    mode = stat.S_IMODE(os.stat(target).st_mode)
    assert mode & stat.S_IWUSR, "write bit must be added back"
    assert mode & stat.S_IXUSR, "execute bit must be added back for a directory"
    assert calls == [str(target)]  # func was still invoked with the retry


def test_clear_readonly_and_retry_does_not_add_execute_to_a_plain_file(tmp_path: Path) -> None:
    """The execute-bit fix above is directory-only -- adding it unconditionally would leave a
    plain read-only FILE executable, which is not this fix's job and not what the shipped hook
    (a read-only file, e.g. a git pack file) ever needed."""
    from agentsec.corpus import _clear_readonly_and_retry

    target = tmp_path / "file.txt"
    target.write_text("x", encoding="utf-8")
    target.chmod(stat.S_IREAD)

    _clear_readonly_and_retry(lambda p: None, str(target), OSError("denied"))

    mode = stat.S_IMODE(os.stat(target).st_mode)
    assert mode & stat.S_IWUSR, "write bit must still be added back"
    assert not mode & stat.S_IXUSR, "a plain file must not gain the execute bit"


def test_clone_repo_cached_failed_clone_with_uncleanable_leftover_returns_stuck(tmp_path: Path) -> None:
    """Round-2 Critical 2: when `clone_repo` fails AND the subsequent cleanup of the
    corrupted partial checkout ALSO fails, the return value used to be dropped and this path fell
    through to "cloned" anyway -- the same one-bit collision the pre-existing-leftover branch
    already guards against (see `test_clone_repo_cached_does_not_clone_into_a_leftover_it_could_not_clear`
    below), just on its sibling code path. A caller that sees "cloned" hands `dest` straight to
    `scan_repo()`; the corrupted leftover must instead come back as "stuck"."""
    from agentsec.corpus import clone_repo_cached

    def _partial_clone(url: str, dest: Path) -> bool:
        (dest / ".git").mkdir(parents=True, exist_ok=True)
        return False

    with (
        patch("agentsec.corpus.clone_repo", side_effect=_partial_clone),
        patch("agentsec.corpus._rmtree_robust", return_value=False),  # cleanup ALSO fails
    ):
        dest, status = clone_repo_cached("https://github.com/a/b", cache_root=tmp_path)

    assert status == "stuck"


def test_clone_repo_cached_does_not_clone_into_a_leftover_it_could_not_clear(tmp_path: Path) -> None:
    """the actual root cause: a corrupted leftover half-clone that can't be deleted
    must never be handed to `clone_repo` -- git refuses a non-empty destination, so that
    would just fail instantly and silently re-create the exact same permanently-stuck cache
    entry on every future run instead of ever getting a clean retry.

    This only pins `clone_repo_cached`'s OWN return value. A later fix reopened because a prior
    fix stopped here: the low-level function correctly refuses to re-clone, but nothing made
    its `status == "stuck"` distinct from an ordinary "cloned" attempt to the CALLER -- which
    is what actually let the corrupted leftover reach `scan_repo()` again. See
    `test_corpus_scan_stuck_cache_leftover_is_not_treated_as_a_cache_hit` below for the
    caller-visible half of this regression."""
    from agentsec.corpus import _cache_key, clone_repo_cached

    dest = tmp_path / _cache_key("https://github.com/a/b")
    dest.mkdir(parents=True)
    (dest / "partial.git").write_text("leftover", encoding="utf-8")

    with (
        patch("agentsec.corpus.shutil.rmtree"),
        patch("agentsec.corpus.time.sleep"),
        patch("agentsec.corpus.clone_repo") as mock_clone,
    ):
        result_dest, status = clone_repo_cached("https://github.com/a/b", cache_root=tmp_path)

    assert status == "stuck"
    mock_clone.assert_not_called()
    assert result_dest == dest
    assert (dest / "partial.git").exists()  # untouched, not silently clobbered either


def test_corpus_scan_stuck_cache_leftover_is_not_treated_as_a_cache_hit(tmp_path: Path) -> None:
    """the reopen (Dean Prichard review, Critical 1): the CALLER must not treat a leftover
    `clone_repo_cached` could not clear as a valid cache hit. Before this fix, the caller
    re-derived "is this usable?" from `dest.is_dir() and any(dest.iterdir())` -- which reads a
    corrupted, non-empty leftover as indistinguishable from a genuinely successful clone -- so
    the corrupted directory was handed straight to `scan_repo()` and the run reported it as a
    clean, findingless success. That is the literal original bug's symptom (0 features
    matched, no error surfaced) and is what the sibling unit test above cannot catch, because it
    only asserts `clone_repo_cached`'s return value, never what `corpus_scan` DOES with it.

    Confirmed non-vacuous against the code as it stood before this fix: `scan_repo` was called
    with the corrupted leftover, and `scan.error` was empty ("" -- an unremarkable, invisible
    skip, per Critical 2)."""
    from agentsec.corpus import _cache_key

    url = "https://github.com/a/b"
    dest = tmp_path / _cache_key(url)
    dest.mkdir(parents=True)
    (dest / "partial.git").write_text("leftover corrupted half-clone", encoding="utf-8")

    with (
        patch("agentsec.corpus.discover_repos", return_value=[]),
        patch("agentsec.corpus._rmtree_robust", return_value=False),  # genuinely can't clear it
        patch("agentsec.corpus.scan_repo") as mock_scan_repo,
        patch("agentsec.corpus.evict_stale_cache", return_value=0),
    ):
        report = corpus_scan(
            repos=[url], count=0, today=_TODAY, tier=1,
            include_seeds=False, cache_root=tmp_path,
        )

    # Critical 1: never handed the corrupted leftover to the real scanner as if it were valid.
    mock_scan_repo.assert_not_called()
    scan = report.scanned[0]
    # Critical 2: surfaced distinctly, not an ordinary/invisible skip.
    assert scan.error, "a stuck leftover must not present as a silent, unremarkable success"
    assert "clone-failed" not in scan.error  # distinct from the ordinary clone-failed skip
    assert scan.findings == []


def test_evict_stale_cache_removes_old_and_keeps_fresh(tmp_path: Path) -> None:
    from agentsec.corpus import _CACHE_MARKER, _cache_key, clone_repo_cached, evict_stale_cache

    with patch("agentsec.corpus.clone_repo", side_effect=_fake_clone):
        clone_repo_cached("https://github.com/a/fresh", cache_root=tmp_path)
        clone_repo_cached("https://github.com/a/old", cache_root=tmp_path)

    old_dir = tmp_path / _cache_key("https://github.com/a/old")
    (old_dir / _CACHE_MARKER).write_text("2020-01-01T00:00:00+00:00", encoding="utf-8")

    removed = evict_stale_cache(cache_root=tmp_path, evict_after_hours=720)

    assert removed == 1
    assert not old_dir.is_dir()
    assert (tmp_path / _cache_key("https://github.com/a/fresh")).is_dir()


def test_evict_stale_cache_removes_corrupt_marker_entry(tmp_path: Path) -> None:
    from agentsec.corpus import _CACHE_MARKER, _cache_key, clone_repo_cached, evict_stale_cache

    with patch("agentsec.corpus.clone_repo", side_effect=_fake_clone):
        clone_repo_cached("https://github.com/a/b", cache_root=tmp_path)

    entry = tmp_path / _cache_key("https://github.com/a/b")
    (entry / _CACHE_MARKER).write_text("not-a-timestamp", encoding="utf-8")

    assert evict_stale_cache(cache_root=tmp_path) == 1
    assert not entry.is_dir()


def test_evict_stale_cache_missing_root_is_noop(tmp_path: Path) -> None:
    from agentsec.corpus import evict_stale_cache

    assert evict_stale_cache(cache_root=tmp_path / "does-not-exist") == 0


def test_evict_stale_cache_ignores_stray_file_in_root(tmp_path: Path) -> None:
    # A non-directory entry directly under the cache root must be left untouched.
    from agentsec.corpus import evict_stale_cache

    stray = tmp_path / "not-a-cache-dir.txt"
    stray.write_text("hello", encoding="utf-8")

    assert evict_stale_cache(cache_root=tmp_path) == 0
    assert stray.is_file()


def test_clone_repo_cached_failed_clone_returns_uncached(tmp_path: Path) -> None:
    from agentsec.corpus import clone_repo_cached

    with patch("agentsec.corpus.clone_repo", return_value=False):
        dest, status = clone_repo_cached("https://github.com/a/b", cache_root=tmp_path)

    assert status == "cloned"
    assert not dest.is_dir()  # nothing written, no marker -> caller treats as clone-failed


def test_clone_repo_cached_partial_clone_is_cleaned_up(tmp_path: Path) -> None:
    """A clone killed mid-transfer (e.g. by the `timeout=120` in `clone_repo`) can leave a
    non-empty partial checkout behind even though `clone_repo` reports failure. Regression test
    for the mislabel where the caller's `dest.is_dir() and any(dest.iterdir())` cache-hit check
    saw the leftover partial dir and treated a failed clone as a successful one."""
    from agentsec.corpus import clone_repo_cached

    def _partial_clone(url: str, dest: Path) -> bool:
        (dest / ".git").mkdir(parents=True, exist_ok=True)
        return False

    with patch("agentsec.corpus.clone_repo", side_effect=_partial_clone):
        dest, status = clone_repo_cached("https://github.com/a/b", cache_root=tmp_path)

    assert status == "cloned"
    assert not dest.is_dir()  # partial checkout must be wiped, not left for the caller to misread


def test_cache_key_is_filesystem_safe_and_distinct() -> None:
    from agentsec.corpus import _cache_key

    a = _cache_key("https://github.com/fastapi/fastapi")
    b = _cache_key("https://github.com/tiangolo/full-stack-fastapi-template")
    assert a != b
    assert all(c.isalnum() or c == "-" for c in a)
    assert all(c.isalnum() or c == "-" for c in b)


def test_cache_key_distinguishes_slash_and_hyphen_paths() -> None:
    """`foo/bar` and `foo-bar` (and `some_org/repo` vs `some-org/repo`) must not collapse onto the
    same slug -- the regex-only key mapped all of `/-_.` to `-`, colliding distinct repo URLs."""
    from agentsec.corpus import _cache_key

    assert _cache_key("https://github.com/foo/bar") != _cache_key("https://github.com/foo-bar")
    assert _cache_key("https://github.com/some_org/repo") != _cache_key(
        "https://github.com/some-org/repo",
    )


def test_corpus_scan_use_cache_false_never_touches_the_cache(tmp_path: Path) -> None:
    # use_cache=False (--fresh-corpus) must go through the tempdir path — no clone_repo_cached,
    # and no eviction pass over the persistent cache either.
    with patch("agentsec.corpus.discover_repos", return_value=[]), \
         patch("agentsec.corpus.clone_repo_cached") as mock_cached, \
         patch("agentsec.corpus.evict_stale_cache") as mock_evict, \
         patch("agentsec.corpus.clone_repo", return_value=False):
        corpus_scan(
            repos=["https://github.com/a/b"], count=0, today=_TODAY, tier=1,
            use_cache=False, max_repos=1,
        )
    mock_cached.assert_not_called()
    mock_evict.assert_not_called()


def test_corpus_scan_use_cache_true_runs_eviction_with_the_given_root(tmp_path: Path) -> None:
    # The corpus_scan -> evict_stale_cache wiring itself: eviction runs once when use_cache=True,
    # and the caller's cache_root is threaded through (not the real machine-global cache root).
    with patch("agentsec.corpus.discover_repos", return_value=[]), \
         patch("agentsec.corpus.evict_stale_cache", return_value=0) as mock_evict, \
         patch("agentsec.corpus.clone_repo", return_value=False):
        corpus_scan(
            repos=["https://github.com/a/b"], count=0, today=_TODAY, tier=1,
            use_cache=True, max_repos=1, cache_root=tmp_path,
        )
    mock_evict.assert_called_once()
    assert mock_evict.call_args.args[0] == tmp_path


def test_corpus_scan_eviction_failure_does_not_abort_the_run(tmp_path: Path) -> None:
    # A cache-eviction hiccup must never propagate out of corpus_scan (never-raises contract).
    with patch("agentsec.corpus.discover_repos", return_value=[]), \
         patch("agentsec.corpus.evict_stale_cache", side_effect=PermissionError("boom")), \
         patch("agentsec.corpus.clone_repo", return_value=False):
        report = corpus_scan(
            repos=["https://github.com/a/b"], count=0, today=_TODAY, tier=1,
            use_cache=True, max_repos=1, cache_root=tmp_path,
        )
    assert report.corpus_size == 1  # run completed despite the eviction blow-up


# ---------------------------------------------------------------------------
# SEED_REPOS shape + corpus_scan cost cap
# ---------------------------------------------------------------------------

def test_seed_repos_well_formed() -> None:
    pat = re.compile(r"^https://github\.com/[^/]+/[^/]+$")
    assert SEED_REPOS, "seed list must not be empty"
    assert len(SEED_REPOS) == len(set(SEED_REPOS)), "seed list has duplicates"
    for url in SEED_REPOS:
        assert pat.match(url), f"malformed seed URL: {url!r}"
        assert not url.endswith("/"), f"trailing slash: {url!r}"
        assert not url.endswith(".git"), f"explicit .git suffix: {url!r}"


# The org that gates the one access-gated repo SEED_REPOS used to carry. SEED_REPOS ships in the
# wheel, so a private repo's URL there is published to PyPI (pypi-release plan, P1.4).
_ACCESS_GATED_ORGS = ("dynamous-community",)


def _access_gated(urls: list[str]) -> list[str]:
    # GitHub org names are case-insensitive, so compare lowercased.
    return [u for u in urls if u.split("/")[3].lower() in _ACCESS_GATED_ORGS]


def test_seed_repos_name_no_access_gated_repo() -> None:
    leaked = _access_gated(list(SEED_REPOS))
    assert not leaked, f"SEED_REPOS ships in the wheel; drop the access-gated repo(s): {leaked}"


def test_access_gated_seed_check_fires() -> None:
    """Rule 1 control: the helper the gate uses must flag a gated URL in any case, not pass on any list."""
    seeds = ["https://github.com/hashicorp/vault", "https://github.com/Dynamous-Community/some-repo"]
    assert _access_gated(seeds) == [seeds[1]]


# ---------------------------------------------------------------------------
# Private/local repo scanning: is_local_repo, --no-seeds, offline gate
# ---------------------------------------------------------------------------

def test_is_local_repo(tmp_path: Path) -> None:
    from agentsec.corpus import is_local_repo
    assert is_local_repo(str(tmp_path)) is True             # an existing directory
    # BOTH `file://` spellings, deliberately. `f"file://{tmp_path}"` is the one a Windows dev pastes:
    # on Windows it yields `file://C:\Users\...`, which parks the DRIVE in the authority slot — the
    # only construction in the suite that produces that shape, and the platform-specific behaviour
    # `_is_windows_drive_authority` exists to pin (see the drive tests below). `as_uri()` yields the
    # RFC 8089 form `file:///...` on both platforms, so it can never produce it. Asserting only
    # `as_uri()` would make the test pass by testing an easier input (#477 review, H2).
    assert is_local_repo(f"file://{tmp_path}") is True      # native spelling (Windows: drive authority)
    assert is_local_repo(tmp_path.as_uri()) is True         # RFC 8089 spelling, both platforms
    assert is_local_repo("https://github.com/a/b") is False  # remote clone URL
    assert is_local_repo("git@github.com:a/b.git") is False  # ssh clone URL
    assert is_local_repo(str(tmp_path / "does-not-exist")) is False  # non-existent path


def test_corpus_scan_no_seeds_scans_only_given_repos(tmp_path: Path) -> None:
    # include_seeds=False → scan EXACTLY the given repos; the public SEED_REPOS are not cloned.
    with patch("agentsec.corpus.discover_repos", return_value=[]), \
         patch("agentsec.corpus.clone_repo", side_effect=_fake_clone), \
         patch("agentsec.corpus.evict_stale_cache", return_value=0):
        report = corpus_scan(
            repos=[str(tmp_path)], count=0, today=_TODAY, tier=0,
            include_seeds=False, cache_root=tmp_path,
        )
    scanned = {s.url for s in report.scanned}
    # exactly the one given repo attempted — no seeds mixed in.
    assert report.corpus_size == 1
    assert scanned == {str(tmp_path)}
    assert not (scanned & set(SEED_REPOS))


def test_corpus_scan_include_seeds_true_includes_seeds(tmp_path: Path) -> None:
    # Default include_seeds=True → the curated public seed list is prepended to the explicit repos.
    with patch("agentsec.corpus.discover_repos", return_value=[]), \
         patch("agentsec.corpus.clone_repo_cached", side_effect=lambda url, **kw: (tmp_path, "cloned")), \
         patch("agentsec.corpus.clone_repo", side_effect=_fake_clone), \
         patch("agentsec.corpus.scan_repo", side_effect=lambda url, *a, **k: _scan(url=url)), \
         patch("agentsec.corpus.evict_stale_cache", return_value=0):
        report = corpus_scan(
            repos=["https://github.com/x/y"], count=0, today=_TODAY, tier=1,
            include_seeds=True, cache_root=tmp_path,
        )
    assert report.corpus_size == len(SEED_REPOS) + 1


def test_corpus_scan_local_repo_bypasses_cache(tmp_path: Path) -> None:
    # A local-path repo must clone fresh (clone_repo), never via the age-based clone_repo_cached,
    # even when use_cache=True — so a live local repo is never served from a stale 7-day cache entry.
    # NOT "at its current state": the fresh path is still a `git clone --depth 1`, so what gets
    # scanned is the COMMITTED HEAD. Uncommitted working-tree changes are not scanned (#466 gate
    # measured this end-to-end; CLAUDE.md carried the same wrong claim and was corrected with it).
    with patch("agentsec.corpus.discover_repos", return_value=[]), \
         patch("agentsec.corpus.clone_repo_cached") as mock_cached, \
         patch("agentsec.corpus.clone_repo", side_effect=_fake_clone) as mock_fresh, \
         patch("agentsec.corpus.evict_stale_cache", return_value=0):
        corpus_scan(
            repos=[str(tmp_path)], count=0, today=_TODAY, tier=0,
            include_seeds=False, use_cache=True, cache_root=tmp_path,
        )
    mock_cached.assert_not_called()
    mock_fresh.assert_called_once()


def test_corpus_scan_refuses_remote_clone_at_tier0(tmp_path: Path) -> None:
    # Egress safety / defense-in-depth (PR #466 review, Medium): corpus_scan itself must refuse a
    # REMOTE clone at Tier 0 — independent of the CLI gate — never shelling out to git clone. It
    # records error="tier0-network-required" instead. A local repo in the same run is unaffected.
    with patch("agentsec.corpus.discover_repos", return_value=[]), \
         patch("agentsec.corpus.clone_repo_cached") as mock_cached, \
         patch("agentsec.corpus.clone_repo", side_effect=_fake_clone) as mock_clone, \
         patch("agentsec.corpus.evict_stale_cache", return_value=0):
        report = corpus_scan(
            repos=["https://github.com/x/y", str(tmp_path)], count=0, today=_TODAY, tier=0,
            include_seeds=False, cache_root=tmp_path,
        )
    by_url = {s.url: s for s in report.scanned}
    assert by_url["https://github.com/x/y"].error == "tier0-network-required"
    mock_cached.assert_not_called()  # never reached the cached-clone path for the remote repo
    # the remote repo was NOT cloned; only the local repo went through clone_repo
    assert all("github.com" not in c.args[0] for c in mock_clone.call_args_list)


def test_corpus_scan_cli_no_seeds_without_repos_errors(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["corpus-scan", "--no-seeds"])
    assert rc == 2
    assert "nothing to scan" in capsys.readouterr().err


# --- backlog #8d: is_url_like + typo'd-local-path detection ---

def test_is_url_like() -> None:
    # The predicate the typo gate needs: "is this NOT a plain filesystem path?". Its predecessor
    # `is_remote_url` answered a different question (`https?|ssh|git://` + scp only), so everything
    # in between was reported to the user as a missing local path (#477 review, M1).
    from agentsec.corpus import is_url_like
    assert is_url_like("https://github.com/a/b") is True
    assert is_url_like("http://example.com/a/b") is True
    assert is_url_like("ssh://git@host/a/b") is True
    assert is_url_like("git://host/a/b") is True
    assert is_url_like("git@github.com:a/b.git") is True     # scp-like
    assert is_url_like("/home/x/repo") is False              # local abs path
    assert is_url_like("../repo") is False                   # local relative path
    assert is_url_like("C:\\Users\\me\\repo") is False        # Windows drive path
    assert is_url_like("node_modules/@scope/pkg") is False    # an `@` is not an scp URL
    assert is_url_like("/home/user@corp/repo") is False
    assert is_url_like("file:/tmp/x") is True                 # RFC 8089's minimal no-authority form
    assert is_url_like("file:///home/x/repo") is True         # local, but still not a PLAIN path


def test_is_url_like_covers_every_authority_bearing_spelling() -> None:
    # THE regression this predicate exists for. Each of these is url-like and NOT local, so the
    # typo gate must pass it through to the tier gate rather than call it a missing local path.
    # `is_remote_url` answered False to every one of them.
    from agentsec.corpus import is_local_repo, is_url_like
    for url in (
        "file://198.51.100.7/share/repo",     # file:// with a remote authority
        "file://fileserver/share/repo",
        "\\\\evil.example.com\\share\\repo",  # UNC, Explorer spelling
        "//evil.example.com/share/repo",      # UNC, forward slashes
        "/\\evil.example.com\\share\\repo",   # UNC, mixed separators
        "FILE://198.51.100.7/share/repo",     # uppercase scheme (git accepts it)
        "HTTPS://github.com/a/b",
        "SSH://git@host/a/b",
    ):
        assert is_url_like(url) is True, url
        assert is_local_repo(url) is False, url    # ...and it is genuinely not local, so it routes


def test_is_url_like_reads_a_one_letter_scheme_as_a_drive_exactly_like_is_local_repo() -> None:
    # `C://repo` is a Windows drive path, not a URL — no registered URI scheme is one letter, and
    # `is_local_repo` already reads it that way. The two predicates gate the same string, so a
    # disagreement here is a third bucket reopening.
    from agentsec.corpus import is_url_like
    assert is_url_like("C://repo") is False
    assert is_url_like("c:/repo") is False


def test_corpus_scan_cli_missing_local_path_errors_clearly(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A typo'd local path (no clone-URL scheme, not an existing dir) must be caught as "not found"
    # rather than misclassified as a remote repo → confusing tier-1 / clone-failed error (backlog #8d).
    typo = str(tmp_path / "does-not-exist")
    rc = main(["corpus-scan", "--no-seeds", "--repos", typo, "--network", "tier0"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "local repo path(s) not found" in err and typo in err
    assert "needs network tier 1" not in err  # not misread as remote


def test_corpus_scan_cli_url_like_entries_reach_the_tier_gate_not_the_typo_gate(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # FALSE-POSITIVE guard for the typo gate — the traded-against direction of a NARROWING change.
    # Every one of these carries an authority, so none is a "missing local path"; the contract is
    # the tier gate's graceful `rc=0` + "needs network tier 1". Under the `not is_remote_url(...)`
    # test these aborted the whole run with rc=2 and the factually wrong "local repo path(s) not
    # found: file://198.51.100.7/share/repo" (#477 review, M1).
    for url in (
        "file://198.51.100.7/share/repo",
        "file://fileserver/share/repo",
        "\\\\evil.example.com\\share\\repo",
        "//evil.example.com/share/repo",
        "/\\evil.example.com\\share\\repo",
        "FILE://198.51.100.7/share/repo",     # uppercase schemes are legal and git accepts them
        "HTTPS://github.com/x/y",
    ):
        with patch("agentsec.corpus.discover_repos", return_value=[]), \
             patch("agentsec.corpus.clone_repo", side_effect=_fake_clone) as mock_clone, \
             patch("agentsec.corpus.evict_stale_cache", return_value=0):
            rc = main([
                "corpus-scan", "--no-seeds", "--repos", url,
                "--network", "tier0", "--out", str(tmp_path / "out"),
            ])
        err = capsys.readouterr().err
        assert rc == 0, url
        assert "needs network tier 1" in err, url
        assert "local repo path(s) not found" not in err, url
        mock_clone.assert_not_called()


# --- #477 review L3: "exists but isn't a git repo" is the other likely user error ---

def test_local_entry_is_not_a_git_repo(tmp_path: Path) -> None:
    from agentsec.corpus import local_entry_is_not_a_git_repo
    plain = tmp_path / "app"
    plain.mkdir()
    assert local_entry_is_not_a_git_repo(str(plain)) is True
    assert local_entry_is_not_a_git_repo(plain.as_uri()) is True     # same answer via file://

    # FALSE-POSITIVE direction, and the reason this only warns: every shape git can actually clone
    # must answer False, or a diagnosis would be refusing a run that would have worked.
    work = tmp_path / "work"
    (work / ".git").mkdir(parents=True)
    assert local_entry_is_not_a_git_repo(str(work)) is False
    linked = tmp_path / "linked"                                     # worktree / submodule: .git FILE
    linked.mkdir()
    (linked / ".git").write_text("gitdir: ../real/.git\n", encoding="utf-8")
    assert local_entry_is_not_a_git_repo(str(linked)) is False
    bare = tmp_path / "bare.git"                                     # bare repo: no .git at all
    (bare / "objects").mkdir(parents=True)
    (bare / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    assert local_entry_is_not_a_git_repo(str(bare)) is False

    # Not a local entry at all → never diagnosed (the typo gate owns the non-existent case).
    assert local_entry_is_not_a_git_repo("https://github.com/a/b") is False
    assert local_entry_is_not_a_git_repo(str(tmp_path / "does-not-exist")) is False


def test_corpus_scan_cli_non_git_directory_warns_and_still_runs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # `--repos <app dir>` used to surface only as an opaque `clone-failed` row. It warns now — but
    # it must NOT become an rc=2 like the typo gate: recognising a repo from its on-disk layout is a
    # heuristic, and a heuristic must never fail a run git would have completed.
    plain = tmp_path / "app"
    plain.mkdir()
    out = tmp_path / "out"
    with patch("agentsec.corpus.discover_repos", return_value=[]), \
         patch("agentsec.corpus.clone_repo", side_effect=_fake_clone), \
         patch("agentsec.corpus.evict_stale_cache", return_value=0):
        rc = main([
            "corpus-scan", "--no-seeds", "--repos", str(plain),
            "--network", "tier0", "--out", str(out),
        ])
    err = capsys.readouterr().err
    assert rc == 0
    assert "not a git repository" in err and str(plain) in err
    assert (out / "corpus-report.json").exists()   # the run still happened


# --- backlog #8c: raw_scan_name disambiguates local paths ---

def test_raw_scan_name_remote_is_org_repo(tmp_path: Path) -> None:
    from agentsec.corpus import raw_scan_name
    assert raw_scan_name("https://github.com/org/repo") == "org-repo"
    assert raw_scan_name("https://github.com/org/repo.git") == "org-repo"


def test_raw_scan_name_local_paths_sharing_segments_do_not_collide(tmp_path: Path) -> None:
    # Two distinct checkouts whose LAST TWO segments are identical (`project/backend`) — the base
    # name collides, so only the abs-path hash keeps their raw/*.json apart (backlog #8c).
    a = tmp_path / "x" / "project" / "backend"
    b = tmp_path / "y" / "project" / "backend"
    a.mkdir(parents=True)
    b.mkdir(parents=True)
    from agentsec.corpus import raw_scan_name
    na, nb = raw_scan_name(str(a)), raw_scan_name(str(b))
    assert na != nb
    assert na.startswith("project-backend-") and nb.startswith("project-backend-")  # base + abs hash


# --- #477 review M2/M3/M4: raw-dump names must be portable, canonical and collision-free ---

def test_raw_scan_name_is_a_legal_filename_on_every_platform() -> None:
    # PORTABILITY, both naming branches. `corpus-scan.yml` does `git add -f corpus-out/`, and a path
    # containing `:` cannot be checked out by git on Windows at all (`error: invalid path`); NTFS
    # reads `:` as the alternate-data-stream separator, so `raw/git@github.com:org-repo.json`
    # becomes a visible 0-byte `git@github.com` holding an invisible stream — and EVERY scp URL from
    # that host lands on that one file. `|` (the legacy bar drive form) is illegal there too.
    from agentsec.corpus import raw_scan_name
    illegal = set('<>:"/\\|?*')
    for url in (
        "git@github.com:org/repo.git",        # scp form — the `git@host:` prefix carried a colon
        "git@gitlab.example.com:group/sub.git",
        "ssh://git@host/a/b",
        "https://github.com/org/repo",
        "file:///tmp",                        # single-segment file:// — used to yield `file:-tmp-…`
        "file:///repo",
        "file://localhost/tmp",
        "file:///C|/path",                    # RFC 8089 E.2 legacy bar form
    ):
        name = raw_scan_name(url)
        assert not (set(name) & illegal), f"{url!r} → {name!r} is not a portable filename"
        assert name and not name.startswith("-") and not name.endswith("-"), (url, name)


def test_raw_scan_name_scp_urls_from_one_host_do_not_collide() -> None:
    # The colon meant every scp URL from one host shared a visible NTFS filename. Stripping the
    # `user@host:` prefix also makes the scp and https spellings of one repo agree.
    from agentsec.corpus import raw_scan_name
    a = raw_scan_name("git@github.com:org/repo.git")
    b = raw_scan_name("git@github.com:otherorg/other.git")
    assert (a, b) == ("org-repo", "otherorg-other")
    assert a == raw_scan_name("https://github.com/org/repo")   # same repo, same dump name


def test_raw_scan_name_local_file_url_matches_the_plain_path_and_is_cwd_independent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # `raw_scan_name` used to hand a `file://` URL straight to `Path(...)`, so `file:///tmp`
    # "resolved" to the literal `<cwd>/file:/tmp`: a colon in the name, a hash over a path that does
    # not exist, and a DIFFERENT dump name for the same repo depending on the directory the scan was
    # run from — the docstring's "hash of the resolved absolute path" was simply false (#477 M3).
    from agentsec.corpus import raw_scan_name
    repo = tmp_path / "demo" / "repoA"
    repo.mkdir(parents=True)
    plain = raw_scan_name(str(repo))
    assert plain.startswith("demo-repoA-")
    assert raw_scan_name(str(repo) + "/") == plain
    assert raw_scan_name(repo.as_uri()) == plain
    # `file://localhost/…` is the same machine per RFC 8089 §2, so it is the same repo.
    assert raw_scan_name(repo.as_uri().replace("file://", "file://localhost", 1)) == plain
    monkeypatch.chdir(tmp_path)
    assert raw_scan_name(repo.as_uri()) == plain


def test_file_url_to_path_handles_every_drive_spelling_on_both_platforms(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # `_file_url_to_path` is `url2pathname` reimplemented (urllib.request is the egress module and
    # test_net_sandbox.py pins net.py as the only importer of it), so its platform-dispatched leg
    # needs pinning from Linux CI too — otherwise the whole Windows half of the naming fix is
    # asserted nowhere, which is the H2 mistake repeated one layer down.
    from agentsec import corpus

    # Patched via the directly-imported `os` module (the same singleton `corpus.py` itself sees
    # through its own `import os` -- `sys.modules` guarantees one shared object), not `corpus.os`:
    # mypy --strict flags attribute access through a module for a name that module merely imports
    # rather than defines/re-exports, and the effect on `corpus._file_url_to_path`'s `os.name` read
    # is identical either way.
    monkeypatch.setattr(os, "name", "nt")
    assert corpus._file_url_to_path("file:///C:/Users/me/repo") == "C:/Users/me/repo"
    assert corpus._file_url_to_path("file:///C|/path") == "C:/path"          # RFC 8089 E.2 bar form
    assert corpus._file_url_to_path("file://C:/repo") == "C:/repo"           # drive in the authority
    assert corpus._file_url_to_path("file://C:\\Users\\me\\repo") == "C:\\Users\\me\\repo"
    assert corpus._file_url_to_path("file://localhost/C:/repo") == "C:/repo"
    assert corpus._file_url_to_path("file:///srv/repo") == "/srv/repo"       # no drive → untouched

    monkeypatch.setattr(os, "name", "posix")
    # On POSIX `/C:/…` IS a legal absolute path (a directory literally named `C:`), so the leading
    # slash stays — url2pathname is platform-dispatched for exactly this reason.
    assert corpus._file_url_to_path("file:///C:/Users/me/repo") == "/C:/Users/me/repo"
    assert corpus._file_url_to_path("file:///srv/repo") == "/srv/repo"
    assert corpus._file_url_to_path("file:///tmp/my%20repo") == "/tmp/my repo"   # percent-decoded
    assert corpus._file_url_to_path("file:/tmp/x") == "/tmp/x"                   # minimal form


def test_unique_raw_scan_names_disambiguates_a_residual_stem_collision() -> None:
    # Last line of defence for "N scanned rows ⇒ N files in raw/". The remote stem is only the last
    # two path segments, so two hosts can still produce one name; the common case keeps its plain
    # name and the loser is disambiguated rather than silently overwriting the winner's dump.
    from agentsec.corpus import unique_raw_scan_names
    names = unique_raw_scan_names(["https://github.com/org/repo", "https://gitlab.com/org/repo"])
    assert names[0] == "org-repo"
    assert len(set(names)) == 2


def test_corpus_scan_dedupes_one_repo_spelled_three_ways(tmp_path: Path) -> None:
    # M4's root cause: `corpus_scan` deduped on the RAW STRING while `raw_scan_name` named by the
    # RESOLVED PATH, so `/r`, `/r/` and `file:///r` were three rows (each cloned and scanned, three
    # times over) that named onto two files. Dedupe now uses the same key the naming does.
    repo = tmp_path / "demo" / "repoA"
    repo.mkdir(parents=True)
    with patch("agentsec.corpus.discover_repos", return_value=[]), \
         patch("agentsec.corpus.clone_repo", side_effect=_fake_clone) as mock_clone, \
         patch("agentsec.corpus.evict_stale_cache", return_value=0):
        report = corpus_scan(
            repos=[str(repo), str(repo) + "/", repo.as_uri()], count=0, today=_TODAY, tier=0,
            include_seeds=False, cache_root=tmp_path,
        )
    assert report.corpus_size == 1
    assert [s.url for s in report.scanned] == [str(repo)]   # the FIRST spelling is what's reported
    assert mock_clone.call_count == 1                       # ...and it was scanned exactly once


def test_corpus_scan_dedupe_does_not_collapse_distinct_local_repos(tmp_path: Path) -> None:
    # FALSE-POSITIVE guard for the dedupe narrowing: two different checkouts that share their last
    # two segments are two repos and must both be scanned.
    a = tmp_path / "x" / "project" / "backend"
    b = tmp_path / "y" / "project" / "backend"
    a.mkdir(parents=True)
    b.mkdir(parents=True)
    with patch("agentsec.corpus.discover_repos", return_value=[]), \
         patch("agentsec.corpus.clone_repo", side_effect=_fake_clone), \
         patch("agentsec.corpus.evict_stale_cache", return_value=0):
        report = corpus_scan(
            repos=[str(a), str(b)], count=0, today=_TODAY, tier=0,
            include_seeds=False, cache_root=tmp_path,
        )
    assert report.corpus_size == 2
    assert {s.url for s in report.scanned} == {str(a), str(b)}


def test_corpus_scan_cli_report_row_count_equals_raw_dump_count(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The end-to-end invariant, at the CLI where it actually broke: the report claimed 3 scanned
    # repos and `raw/` held 2 files — a silent overwrite with exit 0 and no warning.
    repo = tmp_path / "demo" / "repoA"
    repo.mkdir(parents=True)
    out = tmp_path / "out"
    with patch("agentsec.corpus.discover_repos", return_value=[]), \
         patch("agentsec.corpus.clone_repo", side_effect=_fake_clone), \
         patch("agentsec.corpus.evict_stale_cache", return_value=0):
        rc = main([
            "corpus-scan", "--no-seeds",
            "--repos", str(repo), str(repo) + "/", repo.as_uri(),
            "--network", "tier0", "--out", str(out),
        ])
    assert rc == 0
    report = json.loads((out / "corpus-report.json").read_text(encoding="utf-8"))
    assert len(report["scanned"]) == len(list((out / "raw").glob("*.json"))) == 1


def test_corpus_scan_cli_offline_local_run_is_not_network_gated(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The key feature: `--no-seeds` over a local path runs OFFLINE (Tier 0) — it must NOT no-op with
    # the "needs network tier 1" message, and must produce a report.
    out = tmp_path / "out"
    with patch("agentsec.corpus.discover_repos", return_value=[]), \
         patch("agentsec.corpus.clone_repo", side_effect=_fake_clone), \
         patch("agentsec.corpus.evict_stale_cache", return_value=0):
        rc = main([
            "corpus-scan", "--no-seeds", "--repos", str(tmp_path),
            "--network", "tier0", "--out", str(out),
        ])
    err = capsys.readouterr().err
    assert rc == 0
    assert "needs network tier 1" not in err
    assert (out / "corpus-report.json").exists()


def test_corpus_scan_cli_with_non_utf8_config_in_cwd_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # #513, the issue's measured path: corpus-scan reads `.agentsec/config.json` from the CWD before
    # any clone, and an un-decodable one tracebacked the whole run.
    cfg = tmp_path / ".agentsec" / "config.json"
    cfg.parent.mkdir()
    cfg.write_bytes(b'{"archive_paths": ["caf\xe9"]}')
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "out"
    with patch("agentsec.corpus.discover_repos", return_value=[]), \
         patch("agentsec.corpus.clone_repo", side_effect=_fake_clone), \
         patch("agentsec.corpus.evict_stale_cache", return_value=0):
        rc = main([
            "corpus-scan", "--no-seeds", "--repos", str(tmp_path),
            "--network", "tier0", "--out", str(out),
        ])
    assert rc == 0
    assert "Traceback" not in capsys.readouterr().err
    assert (out / "corpus-report.json").exists()


def test_corpus_scan_cli_mixed_local_and_remote_repos_is_network_gated(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Egress-safety (PR #466 review): a --no-seeds run mixing a LOCAL path with a REMOTE URL still
    # needs network (the remote clone egresses), so at tier0 it MUST refuse — never silently clone
    # the remote repo offline.
    with patch("agentsec.corpus.discover_repos", return_value=[]), \
         patch("agentsec.corpus.clone_repo", side_effect=_fake_clone) as mock_clone, \
         patch("agentsec.corpus.evict_stale_cache", return_value=0):
        rc = main([
            "corpus-scan", "--no-seeds",
            "--repos", str(tmp_path), "https://github.com/x/y",
            "--network", "tier0", "--out", str(tmp_path / "out"),
        ])
    err = capsys.readouterr().err
    assert rc == 0
    assert "needs network tier 1" in err
    mock_clone.assert_not_called()  # refused before any clone


def test_corpus_scan_cli_repos_file_keeps_hash_in_path(tmp_path: Path) -> None:
    # A '#' inside a path (no preceding whitespace) is part of the path, not a comment; an inline
    # comment (whitespace + '#') is still stripped. (PR #466 review.)
    hashed = tmp_path / "repo#2"
    hashed.mkdir()
    repos_file = tmp_path / "repos.txt"
    repos_file.write_text(f"{hashed}  # inline comment\n", encoding="utf-8")
    out = tmp_path / "out"
    with patch("agentsec.corpus.discover_repos", return_value=[]), \
         patch("agentsec.corpus.clone_repo", side_effect=_fake_clone), \
         patch("agentsec.corpus.evict_stale_cache", return_value=0):
        rc = main([
            "corpus-scan", "--no-seeds", "--repos-file", str(repos_file),
            "--network", "tier0", "--out", str(out),
        ])
    assert rc == 0
    report = json.loads((out / "corpus-report.json").read_text(encoding="utf-8"))
    assert [s["url"] for s in report["scanned"]] == [str(hashed)]


def test_corpus_scan_cli_repos_file_merges_entries(tmp_path: Path) -> None:
    # --repos-file lines (with # comments + blanks ignored) are merged into the scan set.
    repos_file = tmp_path / "private-repos.txt"
    repos_file.write_text(
        f"# our private app corpus\n{tmp_path}\n\n  # a comment line\n", encoding="utf-8"
    )
    out = tmp_path / "out"
    with patch("agentsec.corpus.discover_repos", return_value=[]), \
         patch("agentsec.corpus.clone_repo", side_effect=_fake_clone), \
         patch("agentsec.corpus.evict_stale_cache", return_value=0):
        rc = main([
            "corpus-scan", "--no-seeds", "--repos-file", str(repos_file),
            "--network", "tier0", "--out", str(out),
        ])
    assert rc == 0
    report = json.loads((out / "corpus-report.json").read_text(encoding="utf-8"))
    assert report["corpus_size"] == 1


def test_corpus_scan_caps_total_and_prioritizes_seeds() -> None:
    # No network: discovery returns fakes, every clone "fails" (records a clone-failed RepoScan).
    # Cap = seeds + 1, so the assertions below prove seed priority *and* exactly one leftover
    # discovery slot — tied to len(SEED_REPOS) rather than a literal so growing the seed list
    # doesn't silently desync this from test_corpus_scan_unbounded_includes_all below.
    cap = len(SEED_REPOS) + 1
    discovered = [f"https://github.com/disc/r{i}" for i in range(10)]
    with patch("agentsec.corpus.discover_repos", return_value=discovered), \
         patch("agentsec.corpus.clone_repo", return_value=False):
        report = corpus_scan(repos=None, count=10, today=_TODAY, tier=1, max_repos=cap)

    assert report.corpus_size == cap
    scanned_urls = {s.url for s in report.scanned}
    # the full curated seed baseline survives the cap...
    assert set(SEED_REPOS) <= scanned_urls
    # ...and exactly the cap-minus-seeds discovered tail is kept.
    kept_discovered = [u for u in scanned_urls if u.startswith("https://github.com/disc/")]
    assert len(kept_discovered) == cap - len(SEED_REPOS)


def test_corpus_scan_unbounded_includes_all() -> None:
    discovered = [f"https://github.com/disc/r{i}" for i in range(10)]
    with patch("agentsec.corpus.discover_repos", return_value=discovered), \
         patch("agentsec.corpus.clone_repo", return_value=False):
        report = corpus_scan(repos=None, count=10, today=_TODAY, tier=1, max_repos=None)

    assert report.corpus_size == len(SEED_REPOS) + 10


# `test_corpus_scan_workflow_cap_tracks_seed_count` lives in the maintainers' private test module: it reads a file this repository does
# not publish.


def test_scan_repo_runs_no_external_scanners() -> None:
    """corpus-scan is guards-only: scan_repo() must call audit(run_scanners=False), so no Runner
    (e.g. go-osv-hygiene) ever executes in a corpus run (review #678, Finding 4). A future flip to
    run_scanners=True would silently make the weekly job shell out to every scanner binary."""
    prof = mkprofile(Path("/fake/repo"), features={"go", "docker", "javascript"})
    fake_result = MagicMock(
        findings=[], ran=["go-sql-injection"], skipped=[],
        guards_budget_exceeded=[], guards_unbudgeted=[],
    )
    with patch("agentsec.corpus.detect", return_value=prof), \
         patch("agentsec.corpus.audit", return_value=fake_result) as audit_mock:
        scan_repo("https://github.com/x/y", Path("/fake/repo"), today=_TODAY)

    audit_mock.assert_called_once()
    assert audit_mock.call_args.kwargs.get("run_scanners") is False, (
        "scan_repo must call audit(run_scanners=False) — corpus-scan never runs external scanners"
    )


# ---------------------------------------------------------------------------
# discover_repos
# ---------------------------------------------------------------------------

def test_discover_repos_parses_github_response() -> None:
    fixture = {
        "items": [
            {"clone_url": "https://github.com/example/alpha"},
            {"clone_url": "https://github.com/example/beta"},
            {"clone_url": "https://github.com/example/gamma"},
        ]
    }
    # discovery is a Tier-1 net.get; it returns raw bytes
    with patch("agentsec.corpus.net.get", return_value=json.dumps(fixture).encode()) as mock_get:
        from agentsec.corpus import discover_repos
        result = discover_repos(count=2, tier=1, token="gh_fake")

    assert len(result) == 2
    assert all(r.startswith("https://github.com/") for r in result)
    # the auth token is forwarded through the chokepoint's headers
    assert mock_get.call_args.kwargs["headers"]["Authorization"] == "Bearer gh_fake"
    assert mock_get.call_args.kwargs["tier_required"] == 1


def test_gh_search_queries_length_is_pinned() -> None:
    """Dean's review, PR #913 review (MEDIUM): nothing pinned the query-list length, so a
    silent future deletion (or an addition nobody meant to widen sampling with) would pass
    every existing test unnoticed. Bump this deliberately when the list changes; that's the
    point of a pin.

    Scope, per the re-review (M-2): this pins CONTENT only. A length assert cannot detect
    unreachability — a 6th query turns it red, the author bumps 5 → 6, and the new query is as
    unreachable as before. Reachability is
    `test_discover_repos_samples_every_query_at_the_cli_default`'s job, and that one scales to
    a 6th query for free."""
    from agentsec.corpus import _GH_SEARCH_QUERIES

    assert len(_GH_SEARCH_QUERIES) == 5
    assert "topic:mcp-server+stars:%3E10" in _GH_SEARCH_QUERIES
    assert "nextjs+in:readme+language:typescript+stars:%3E500" in _GH_SEARCH_QUERIES


def _fake_search(calls: list[str], per_page: int = 30) -> Callable[..., bytes]:
    """A GitHub-search stub shaped like the real endpoint: `per_page` distinct repos per page.

    The page size is the load-bearing part. An earlier version of the reachability test below
    returned ONE item per call, which let a query-monopolizing loop look fair — the guard has
    to hold at the page size GitHub actually serves (hard-coded `per_page=30` in corpus.py).
    """

    def _get(url: str, **kwargs: object) -> bytes:
        calls.append(url)
        n = len(calls)
        items = [{"clone_url": f"https://github.com/call{n}/repo{i}"} for i in range(per_page)]
        return json.dumps({"items": items}).encode()

    return _get


# count=10 is the shipped default in BOTH places it is configured (cli.py `--count` and
# .github/workflows/corpus-scan.yml), so it is the value the routine pass actually runs with.
# 7 and 12 are the awkward counts that discriminate a floor cap from a ceil one: with
# ceil(count / 5) a query may take 2-3 per round, four queries eat the whole budget, and the
# fifth never runs. 5 == len(queries) is the exact boundary of the guarantee.
@pytest.mark.parametrize("count", [5, 7, 10, 12, 30])
def test_discover_repos_samples_every_query_at_the_cli_default(
    monkeypatch: pytest.MonkeyPatch, count: int,
) -> None:
    """Regression (PR #913 re-review, H-1/H-2): every query is sampled whenever
    `count >= len(_GH_SEARCH_QUERIES)`.

    The original bug: `discover_repos` drained query #1's first page until `count` was met,
    then broke out of the round — so at the shipped default exactly ONE search call fired and
    the mcp-server/Next.js queries added to widen sampling were unreachable below count=91/121.
    Rotating pages alone did not fix it (30 items arrive in hand per page); capping what one
    query may take per round is what does.
    """
    from agentsec.corpus import _GH_SEARCH_QUERIES, discover_repos

    calls: list[str] = []
    monkeypatch.setattr("agentsec.corpus.net.get", _fake_search(calls))

    result = discover_repos(count=count, tier=1, token="gh_fake")

    queried = {q for q in _GH_SEARCH_QUERIES if any(f"q={q}&" in c for c in calls)}
    assert queried == set(_GH_SEARCH_QUERIES), (
        f"not sampled at count={count}: missing {set(_GH_SEARCH_QUERIES) - queried}"
    )
    # The other direction (CLAUDE.md Rule 1): spreading the budget must not change the
    # contract -- still exactly `count` repos, still deduped.
    assert len(result) == count
    assert len(set(result)) == count


def test_discover_repos_below_query_count_is_bounded_by_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """FP-bait for the widening above: when `count` is SMALLER than the query list, `count`
    still binds. The run takes one repo from each of the first `count` queries and stops — it
    does NOT keep going to give all five queries a turn, and it does not return more than
    asked.

    Scope note, corrected on the round-3 review: an earlier version of this docstring called
    the `max(1, ...)` in the per-round cap decorative, on the strength of a fixture where every
    page's first item was fresh. That is the only shape it holds for, and it is NOT safe to
    remove. See `test_discover_repos_cap_floor_survives_a_stale_first_item` below for the
    measured counterexample."""
    from agentsec.corpus import _GH_SEARCH_QUERIES, discover_repos

    count = 2
    assert count < len(_GH_SEARCH_QUERIES), "fixture assumes count below the query-list length"

    calls: list[str] = []
    monkeypatch.setattr("agentsec.corpus.net.get", _fake_search(calls))

    result = discover_repos(count=count, tier=1, token="gh_fake")

    assert len(result) == count
    assert len(calls) == count, f"spent {len(calls)} search calls for {count} repos"


# A page whose FIRST entry contributes nothing: either already seen (search ties re-ranking
# between page fetches, or cross-query overlap) or missing `clone_url` (a repo deleted between
# index and fetch). Both are ordinary live-API shapes, not contrivances.
@pytest.mark.parametrize("stale", ["duplicate", "no_clone_url"])
def test_discover_repos_cap_floor_survives_a_stale_first_item(
    monkeypatch: pytest.MonkeyPatch, stale: str,
) -> None:
    """Regression (PR #913 round-3 review, M-1): the `max(1, ...)` floor on the per-round cap
    is load-bearing, and this is the case that proves it.

    Below `count == len(_GH_SEARCH_QUERIES)` the cap floor-divides to 0. The cap is checked
    after the add, so with an all-fresh page `took` is already 1 and `took >= 0` is harmless —
    which is exactly why an all-fresh fixture reports the floor as decorative. Let the FIRST
    entry on the page contribute nothing and `took` is still 0 at the check, `0 >= 0` fires
    before the rest of the page is read, nothing is collected, `pages[query]` increments, and
    the same page shape repeats forever.

    Measured with the floor removed: >2000 calls and no termination at count 2/3/4. The stub
    below raises past a call ceiling so that regression surfaces as a fast failure instead of
    hanging the suite (assert the artifact, not the exit code — CLAUDE.md Rule 3).
    """
    from agentsec.corpus import discover_repos

    ceiling = 50
    calls: list[str] = []

    def _fake_get(url: str, **kwargs: object) -> bytes:
        calls.append(url)
        if len(calls) > ceiling:
            raise AssertionError(
                f"discover_repos made >{ceiling} search calls for count=3 — the per-round cap "
                "floor is gone and a stale first entry is starving every query"
            )
        n = len(calls)
        head = (
            {"clone_url": "https://github.com/already/seen"} if stale == "duplicate"
            else {"name": "deleted-between-index-and-fetch"}
        )
        rest = [{"clone_url": f"https://github.com/call{n}/repo{i}"} for i in range(29)]
        return json.dumps({"items": [head, *rest]}).encode()

    monkeypatch.setattr("agentsec.corpus.net.get", _fake_get)

    result = discover_repos(count=3, tier=1, token="gh_fake")

    assert len(result) == 3, f"under-collected: got {len(result)} of 3"
    assert len(set(result)) == 3


# ---------------------------------------------------------------------------
# report_to_terminal
# ---------------------------------------------------------------------------

def _fp_candidate(guard_id: str, fired: int, applicable: int) -> FpCandidate:
    return FpCandidate(
        guard_id=guard_id,
        fired_ratio=fired / applicable,
        repos_fired=[f"https://example.com/fired/{j}" for j in range(fired)],
        repos_applicable=[f"https://example.com/all/{j}" for j in range(applicable)],
        sample_finding=_finding(guard_id),
        fp_sample_locations=["app/main.py:10"],
    )


def _gap_candidate(item_id: str, severity: str, repos: int) -> GapCandidate:
    return GapCandidate(
        item_id=item_id,
        item_title=f"No check for {item_id}",
        item_severity=severity,
        item_section="section-4",
        applies_when=["llm"],
        standards=[],
        cwe=None,
        atlas_techniques=[],
        repos_affected=repos,
        stacks_seen=[["python", "fastapi", "llm"]] * repos,
    )


def _corpus_report(
    fp_candidates: list[FpCandidate] | None = None,
    gap_candidates: list[GapCandidate] | None = None,
    run_date: str = "2026-06-26",
    corpus_size: int = 5,
    stack_match_count: int = 4,
) -> CorpusReport:
    return CorpusReport(
        scanned=[],
        fp_candidates=fp_candidates or [],
        gap_candidates=gap_candidates or [],
        run_date=run_date,
        corpus_size=corpus_size,
        stack_match_count=stack_match_count,
    )


def test_report_to_terminal_header_contains_date_and_counts() -> None:
    report = _corpus_report(run_date="2026-06-26", corpus_size=5, stack_match_count=4)
    out = report_to_terminal(report)
    assert "2026-06-26" in out
    assert "4/5" in out


def test_report_to_terminal_fp_shown_with_guard_id_and_title() -> None:
    fp = _fp_candidate("cors-wildcard", fired=4, applicable=4)
    report = _corpus_report(fp_candidates=[fp])
    out = report_to_terminal(report)
    assert "cors-wildcard" in out
    assert "Finding from cors-wildcard" in out
    assert "100%" in out


def test_report_to_terminal_gap_shown_with_severity_and_item_id() -> None:
    gap = _gap_candidate("4-inter-agent-auth", "high", repos=3)
    report = _corpus_report(gap_candidates=[gap])
    out = report_to_terminal(report)
    assert "4-inter-agent-auth" in out
    assert "No check for 4-inter-agent-auth" in out
    assert "HIGH" in out


def test_report_to_terminal_no_candidates_shows_clean_message() -> None:
    report = _corpus_report()
    out = report_to_terminal(report)
    assert "patterns look tight" in out
    assert "No undetected risks" in out


def test_report_to_terminal_truncates_fp_at_five() -> None:
    fps = [_fp_candidate(f"guard-{j}", fired=3, applicable=4) for j in range(7)]
    report = _corpus_report(fp_candidates=fps)
    out = report_to_terminal(report)
    assert "and 2 more" in out
    # only 5 guards shown by name
    shown = sum(1 for j in range(7) if f"guard-{j}" in out)
    assert shown == 5


def test_discover_repos_refused_at_tier0_yields_seeds_fallback() -> None:
    """DO_NOT_TRACK / tier 0 → net.get raises EgressRefused → discovery returns [] (no crash)."""
    from agentsec import net

    with patch("agentsec.corpus.net.get", side_effect=net.EgressRefused("tier 0")):
        from agentsec.corpus import discover_repos
        result = discover_repos(count=5, tier=0, token="")

    assert result == []


# ---------------------------------------------------------------------------
# CLI output switch — non-TTY (the weekly workflow) must keep the markdown path
# ---------------------------------------------------------------------------

class _FakeStdout(io.StringIO):
    """A StringIO with a controllable isatty(), to drive the corpus-scan output switch."""

    def __init__(self, tty: bool) -> None:
        super().__init__()
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


def _run_corpus_scan(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, tty: bool,
                     report: CorpusReport) -> str:
    """Run `agentsec corpus-scan` with the network scan stubbed and a controlled isatty()."""
    monkeypatch.setattr("agentsec.corpus.corpus_scan", lambda **kw: report)
    buf = _FakeStdout(tty)
    with contextlib.redirect_stdout(buf):
        rc = main(["corpus-scan", "--repos", "https://github.com/x/y", "--out", str(tmp_path)])
    assert rc == 0
    return buf.getvalue()


def test_corpus_scan_non_tty_emits_markdown(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Non-TTY is the weekly workflow's path: raw markdown + 'Output written', not the summary."""
    report = _corpus_report(fp_candidates=[_fp_candidate("cors-wildcard", 4, 4)])
    out = _run_corpus_scan(monkeypatch, tmp_path, tty=False, report=report)
    assert "### FP Candidates" in out          # the markdown body
    assert "Output written to" in out
    assert "─" not in out                       # the TTY summary's box-rule is absent (markdown has none)


def test_corpus_scan_tty_emits_summary(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """TTY: the human summary, and not the raw markdown / 'Output written' lines."""
    report = _corpus_report(fp_candidates=[_fp_candidate("cors-wildcard", 4, 4)])
    out = _run_corpus_scan(monkeypatch, tmp_path, tty=True, report=report)
    assert "Corpus Scan —" in out              # the summary header
    assert "─" in out                           # the summary's box-rule
    assert "cors-wildcard" in out
    assert "Output written to" not in out
    assert "### FP Candidates" not in out       # markdown body must be absent


def test_is_local_repo_rejects_a_file_url_with_a_remote_authority() -> None:
    # Regression (#466 review): every `file://` URL was treated as local, so
    # `--repos file://198.51.100.7/share/repo --network tier0` recorded no EgressOp and the
    # manifest printed "TIER 0 — offline; nothing leaves your machine" while git resolved the
    # UNC path off-machine. The defence-in-depth gate downstream asks this same predicate, so it
    # passed the URL through too. RFC 8089: only an empty authority or `localhost` is local.
    from agentsec.corpus import is_local_repo

    assert is_local_repo("file:///home/user/repo") is True
    assert is_local_repo("file://localhost/srv/repo") is True
    assert is_local_repo("file://198.51.100.7/share/repo") is False
    assert is_local_repo("file://fileserver.corp/share/repo") is False
    # the scheme comparison is case-insensitive, so an uppercase spelling cannot slip past
    assert is_local_repo("FILE://198.51.100.7/share/repo") is False


def test_is_local_repo_rejects_a_scheme_less_unc_path() -> None:
    # The gap the `file://` carve-out left open: `\\host\share\repo` (literally what Windows
    # Explorer's address bar produces for a network location) and its `//host/share/repo` spelling
    # carry an authority with NO scheme, so they fell through to `Path(url).is_dir()`. On Windows
    # that is real SMB/NetBIOS resolution performed as a side effect of mere CLASSIFICATION, which
    # `cli.py` runs before `net.resolve_tier` decides the run is offline. Inert on POSIX, so the
    # harm is Windows-specific; the rule is uniform so the Tier 0 claim does not depend on the OS.
    from agentsec.corpus import is_local_repo

    assert is_local_repo("\\\\evil.example.com\\share\\repo") is False
    assert is_local_repo("//evil.example.com/share/repo") is False
    assert is_local_repo("\\/evil.example.com/share/repo") is False   # Win32 honours mixed seps
    assert is_local_repo("/\\evil.example.com\\share\\repo") is False
    assert is_local_repo("  //evil.example.com/share") is False       # leading whitespace
    # A single leading separator is an ordinary absolute path, never an authority.
    assert is_local_repo("/definitely/not/a/real/directory/xyz") is False  # remote-by-absence only


def test_is_local_repo_never_touches_the_filesystem_for_an_authority() -> None:
    # The INVARIANT's second half: classification must be a pure string computation for anything
    # carrying an authority, because it runs BEFORE the tier gate (cli.py computes `needs_network`
    # from it to pick the default tier). Any probe here is unrecorded egress. Proven by making the
    # filesystem probe explode: a correct implementation never reaches it.
    import agentsec.corpus as corpus

    def boom(*_a: object, **_k: object) -> None:
        raise AssertionError("classification probed the filesystem for an authority-bearing URL")

    with patch.object(corpus, "Path", boom):
        for url in (
            "\\\\evil.example.com\\share\\repo",
            "//evil.example.com/share/repo",
            "file://198.51.100.7/share/repo",
            "file:////evil.example.com/share/repo",
            "https://github.com/a/b",
            "ssh://git@evil.example.com/x",
            "file://C:@evil.example.com/x",
            "file://C|/path",
        ):
            assert corpus.is_local_repo(url) is False
        # a Windows drive authority answers LOCAL from the string alone, also without probing
        for local in ("file://C:/repo", "file://C:\\Users\\dev\\repo", "file://C:"):
            assert corpus.is_local_repo(local) is True


def test_is_local_repo_authority_check_is_case_insensitive() -> None:
    # The authority used to be sliced out of the ORIGINAL (non-lowered) string while only the
    # scheme token was compared case-insensitively, so `file://LOCALHOST/srv/repo` was called
    # REMOTE while `FILE://localhost/srv/repo` was called LOCAL. Parsing the whole URL once through
    # urllib makes the two spellings agree (`SplitResult.hostname` is already lower-cased).
    from agentsec.corpus import is_local_repo

    assert is_local_repo("file://LOCALHOST/srv/repo") is True
    assert is_local_repo("FILE://localhost/srv/repo") is True
    assert is_local_repo("FiLe://LocalHost/srv/repo") is True


def test_is_local_repo_rejects_an_authority_smuggled_through_the_path() -> None:
    # An empty/`localhost` authority is not enough on its own: the PATH can carry a UNC authority,
    # including percent-encoded, and git decodes it. Found by attacking the first cut of this fix.
    from agentsec.corpus import is_local_repo

    assert is_local_repo("file:////evil.example.com/share/repo") is False
    assert is_local_repo("file://localhost//evil.example.com/share/repo") is False
    assert is_local_repo("file:///%5C%5Cevil.example.com%5Cshare") is False
    assert is_local_repo("file:///%2F%2Fevil.example.com%2Fshare") is False
    # `urlsplit` silently DELETES tab/CR/LF (the WHATWG mitigation) and would parse this as host
    # `localhost`; git keeps the raw host and resolves it off-machine. Refuse rather than guess.
    assert is_local_repo("file://loca\nlhost/x") is False
    assert is_local_repo("file://loca\tlhost/x") is False
    # userinfo and a port are not the RFC 8089 local form
    assert is_local_repo("file://user@evil.example.com/share/repo") is False
    assert is_local_repo("file://localhost@evil.example.com/x") is False
    assert is_local_repo("file://evil.example.com:445/share") is False
    # a trailing-dot / percent-encoded / punycode host is not `localhost`
    assert is_local_repo("file://localhost./srv/repo") is False
    assert is_local_repo("file://%6Cocalhost/srv/repo") is False


def test_is_local_repo_loopback_literals_are_remote_by_deliberate_choice() -> None:
    # DOCUMENTED DECISION, not an accident. RFC 8089 §2 lists only the empty authority and
    # `localhost`. On POSIX git ignores a file:// authority entirely (so these do clone locally),
    # but on Windows git rewrites `file://127.0.0.1/share` to `\\127.0.0.1\share`, a real trip
    # through the SMB stack. One uniform, fail-safe answer: an offline run gets a visible
    # "needs network tier 1" message instead of a silently broken Tier 0 promise.
    from agentsec.corpus import is_local_repo

    assert is_local_repo("file://127.0.0.1/repo") is False
    assert is_local_repo("file://[::1]/repo") is False


def test_is_local_repo_windows_drive_in_the_authority_slot_is_local() -> None:
    # Windows CI regression: `f"file://{tmp_path}"` yields `file://C:\Users\...\pytest-of-...`, so
    # the DRIVE lands in the authority slot and classified REMOTE, making `--repos file://C:\path`
    # unusable on the very platform this feature exists for. It failed safe, but it was a break.
    # `urlsplit` ends the authority at the first `/`, so the two native spellings land differently:
    # the forward-slash form leaves `C:`, the backslash form leaves the WHOLE path, because a
    # backslash is not a urlsplit delimiter. Both are LOCAL. Pure string logic, so this test is
    # meaningful on every platform, not just Windows.
    from agentsec.corpus import is_local_repo

    assert is_local_repo("file://C:\\Users\\dev\\repo") is True
    assert is_local_repo("file://C:/repo") is True
    assert is_local_repo("file://c:/repo") is True          # lower-case drive letter
    assert is_local_repo("file://Z:\\srv\\repo") is True
    assert is_local_repo("file://C:") is True               # bare drive
    assert is_local_repo("file://C:\\") is True


def test_is_local_repo_drive_rule_is_not_an_authority_bypass() -> None:
    # Loosening the AUTHORITY rule is exactly where a bypass would reappear, so the drive reading
    # must account for the ENTIRE authority. A host sitting after the colon is not a drive.
    from agentsec.corpus import is_local_repo

    assert is_local_repo("file://C:@evil.example.com/x") is False    # remainder is not `\`-rooted
    assert is_local_repo("file://C:evil.example.com/x") is False     # no separator after the drive
    assert is_local_repo("file://CC:/path") is False                 # two letters is not a drive
    assert is_local_repo("file://1:/path") is False                  # a digit is not a drive
    assert is_local_repo("file://\u0421:/path") is False             # Cyrillic homoglyph drive
    assert is_local_repo("file://evil.example.com:445/share") is False
    # The shared path test still guards the drive branch, so a UNC smuggled into the PATH after a
    # legitimate drive authority is still REMOTE.
    assert is_local_repo("file://C://@evil.example.com/x") is False


def test_is_local_repo_drive_anchored_paths_containing_at_signs_stay_local() -> None:
    # Deliberately NOT tightened. These look alarming but are drive-anchored from character 0, so
    # Win32 can never read them as UNC: the `@` and `:` sit inside a PATH, not an authority, and no
    # host is reachable. Rejecting `@` here would break `C:\...\node_modules\@scope\pkg`, which is
    # on every Windows dev box with a JS repo, for zero security gain.
    from agentsec.corpus import is_local_repo

    assert is_local_repo("file://C:/@evil.example.com/x") is True
    assert is_local_repo("file://C:\\x@evil.example.com:445/y") is True
    assert is_local_repo("file://C:\\Users\\dev\\node_modules\\@scope\\pkg") is True


def test_is_local_repo_legacy_bar_drive_form() -> None:
    # DOCUMENTED DECISION. RFC 8089 Appendix E.2 documents the legacy bar only in the PATH
    # (`file:///c|/path`), which has an empty authority and is LOCAL. The bar in the AUTHORITY slot
    # is not a documented form, and `|` is legal in neither a host name nor a Win32 path, so it is
    # malformed under both readings and stays REMOTE. When loosening the load-bearing authority
    # rule, support only the one spelling Windows and git actually accept.
    from agentsec.corpus import is_local_repo

    assert is_local_repo("file:///C|/path") is True     # bar in the path, RFC 8089 E.2
    assert is_local_repo("file://C|/path") is False     # bar in the authority


def test_is_local_repo_keeps_plain_local_paths_local(tmp_path: Path) -> None:
    # The fix must not turn genuine local repos into remote ones (the false-negative direction).
    from agentsec.corpus import is_local_repo

    assert is_local_repo(str(tmp_path)) is True
    assert is_local_repo(str(tmp_path) + "/") is True
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    assert is_local_repo(f"{tmp_path}//a/b") is True   # a doubled separator INSIDE the path is fine
    assert is_local_repo(f"file://{tmp_path}") is True
    assert is_local_repo("file:/tmp") is True          # RFC 8089's minimal no-authority form


def test_corpus_scan_cli_repos_file_strips_a_utf8_bom(tmp_path: Path) -> None:
    # Regression (#477): `--repos-file` was read as `utf-8`, so a file saved by Notepad (the
    # likeliest way a Windows user hands over a repo list) carries a BOM that lands on the FIRST
    # entry as an invisible U+FEFF and makes that path fail to resolve. The fix reads `utf-8-sig`
    # and had NO test, so a future "explicit utf-8 everywhere" cleanup would regress it silently.
    first = tmp_path / "first-repo"
    first.mkdir()
    second = tmp_path / "second-repo"
    second.mkdir()
    repos_file = tmp_path / "repos.txt"
    repos_file.write_text(f"﻿{first}\n{second}\n", encoding="utf-8")
    # the BOM really is on the wire, not silently dropped by the writer
    assert repos_file.read_bytes().startswith(b"\xef\xbb\xbf")

    out = tmp_path / "out"
    with patch("agentsec.corpus.discover_repos", return_value=[]), \
         patch("agentsec.corpus.clone_repo", side_effect=_fake_clone), \
         patch("agentsec.corpus.evict_stale_cache", return_value=0):
        rc = main([
            "corpus-scan", "--no-seeds", "--repos-file", str(repos_file),
            "--network", "tier0", "--out", str(out),
        ])

    assert rc == 0
    report = json.loads((out / "corpus-report.json").read_text(encoding="utf-8"))
    # the BOM'd first entry resolved as a LOCAL path, so the run stayed offline and scanned both
    assert [s["url"] for s in report["scanned"]] == [str(first), str(second)]
    assert all(s["error"] != "tier0-network-required" for s in report["scanned"])


@pytest.mark.parametrize(
    "encoding, raw",
    [
        ("utf-16", None),                      # Notepad's "Unicode" save — the reachable case
        ("latin-1", "café-repo".encode("latin-1")),   # any non-UTF-8 byte
    ],
)
def test_corpus_scan_cli_repos_file_that_is_not_utf8_exits_cleanly(
    tmp_path: Path, encoding: str, raw: bytes | None, capsys: pytest.CaptureFixture[str]
) -> None:
    # Regression (#466 gate): `--repos-file` is read with `read_text(encoding="utf-8-sig")`, and the
    # only handler was `except OSError`. `UnicodeDecodeError` is a ValueError, NOT an OSError, so an
    # un-decodable file crashed the CLI with a traceback instead of exiting 2 with a message.
    #
    # It is reachable for exactly the reason the BOM comment above exists: Notepad is the likeliest
    # source of a hand-written repo list, and its "Unicode" option writes UTF-16LE, not UTF-8. So the
    # editor that motivates `utf-8-sig` is the same one that produces the file this arm catches.
    repos_file = tmp_path / "repos.txt"
    if raw is not None:
        repos_file.write_bytes(raw)
    else:
        repos_file.write_text(str(tmp_path / "some-repo"), encoding=encoding)
    # the file really is un-decodable as UTF-8 (guards against the writer normalising it)
    with pytest.raises(UnicodeDecodeError):
        repos_file.read_text(encoding="utf-8-sig")

    rc = main([
        "corpus-scan", "--no-seeds", "--repos-file", str(repos_file),
        "--network", "tier0", "--out", str(tmp_path / "out"),
    ])

    assert rc == 2
    err = capsys.readouterr().err
    assert "not UTF-8" in err
    assert "Traceback" not in err


def test_corpus_scan_cli_file_url_with_remote_authority_is_network_gated(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The CLI-level proof for THIS round of the fix (the sibling `42b48f58` got one for a plain
    # https remote, this one did not). A `file://` URL with a remote authority is egress, so a
    # tier0 run must refuse at the gate and never reach `clone_repo`.
    with patch("agentsec.corpus.discover_repos", return_value=[]), \
         patch("agentsec.corpus.clone_repo", side_effect=_fake_clone) as mock_clone, \
         patch("agentsec.corpus.evict_stale_cache", return_value=0):
        rc = main([
            "corpus-scan", "--no-seeds",
            "--repos", "file://198.51.100.7/share/repo",
            "--network", "tier0", "--out", str(tmp_path / "out"),
        ])

    err = capsys.readouterr().err
    assert rc == 0
    assert "needs network tier 1" in err
    mock_clone.assert_not_called()


def test_corpus_scan_cli_unc_path_is_network_gated(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Same gate for the scheme-less spelling this fix closes. `clone_repo` must never be called,
    # because on Windows the classification alone would already have hit the SMB stack.
    for url in ("\\\\evil.example.com\\share\\repo", "//evil.example.com/share/repo"):
        with patch("agentsec.corpus.discover_repos", return_value=[]), \
             patch("agentsec.corpus.clone_repo", side_effect=_fake_clone) as mock_clone, \
             patch("agentsec.corpus.evict_stale_cache", return_value=0):
            rc = main([
                "corpus-scan", "--no-seeds", "--repos", url,
                "--network", "tier0", "--out", str(tmp_path / "out"),
            ])

        err = capsys.readouterr().err
        assert rc == 0, url
        assert "needs network tier 1" in err, url
        mock_clone.assert_not_called()


# `test_documented_private_repos_file_is_gitignored` lives in the maintainers' private test module: it reads a file this repository does
# not publish.
