"""FIRST.org EPSS enrichment — per-CVE fetch/cache + the stamp/boost (a re-ranking, never a drop)."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from agentsec import epss
from agentsec.findings import Finding
from agentsec.prioritize import priority_rank

NOW = datetime(2026, 6, 24, tzinfo=UTC)


def _resp(*rows: tuple[str, float]) -> bytes:
    return json.dumps({
        "status": "OK", "status-code": 200,
        "data": [{"cve": cve, "epss": f"{score:.9f}", "percentile": "0.5", "date": "2026-06-24"} for cve, score in rows],
    }).encode()


def _fetch_ok(*, cve_batch, tier, manifest=None):
    return _resp(*[(cve, 0.42) for cve in cve_batch])


def test_cves_in_findings_extracts_from_rule_and_message() -> None:
    f1 = Finding(check_id="pip-audit", severity="high", title="t", rule="CVE-2025-68664")
    f2 = Finding(check_id="dep", severity="high", title="t", message="affected by cve-2026-12345 too")
    assert epss.cves_in_findings([f1, f2]) == {"CVE-2025-68664", "CVE-2026-12345"}


def test_fetch_parses_batch(tmp_path: Path) -> None:
    def fetch(*, cve_batch, tier, manifest=None):
        return _resp(("CVE-2025-68664", 0.91234), ("CVE-2026-12345", 0.001))

    scores = epss.fetch_epss({"CVE-2025-68664", "CVE-2026-12345"}, tier=1, now=NOW, cache_dir=tmp_path, fetch=fetch)
    assert scores == {"CVE-2025-68664": 0.91234, "CVE-2026-12345": 0.001}


def test_empty_cve_set_short_circuits_with_no_fetch(tmp_path: Path) -> None:
    calls = {"n": 0}

    def fetch(*, cve_batch, tier, manifest=None):
        calls["n"] += 1
        return _resp()

    assert epss.fetch_epss(set(), tier=1, now=NOW, cache_dir=tmp_path, fetch=fetch) == {}
    assert calls["n"] == 0


def test_fetch_uses_24h_cache_per_cve(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def counting_fetch(*, cve_batch, tier, manifest=None):
        calls.append(list(cve_batch))
        return _resp(*[(c, 0.5) for c in cve_batch])

    epss.fetch_epss({"CVE-2025-68664"}, tier=1, now=NOW, cache_dir=tmp_path, fetch=counting_fetch)
    epss.fetch_epss({"CVE-2025-68664"}, tier=1, now=NOW + timedelta(hours=23), cache_dir=tmp_path, fetch=counting_fetch)
    assert len(calls) == 1                                     # 2nd call served from cache
    epss.fetch_epss({"CVE-2025-68664"}, tier=1, now=NOW + timedelta(hours=25), cache_dir=tmp_path, fetch=counting_fetch)
    assert len(calls) == 2                                     # past TTL -> re-fetch


def test_fetch_only_queries_missing_cves(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def counting_fetch(*, cve_batch, tier, manifest=None):
        calls.append(list(cve_batch))
        return _resp(*[(c, 0.5) for c in cve_batch])

    epss.fetch_epss({"CVE-2025-68664"}, tier=1, now=NOW, cache_dir=tmp_path, fetch=counting_fetch)
    scores = epss.fetch_epss(
        {"CVE-2025-68664", "CVE-2026-99999"}, tier=1, now=NOW + timedelta(hours=1),
        cache_dir=tmp_path, fetch=counting_fetch,
    )
    assert calls[1] == ["CVE-2026-99999"]                      # only the new one was fetched
    assert scores == {"CVE-2025-68664": 0.5, "CVE-2026-99999": 0.5}


def test_fetch_batches_large_cve_sets(tmp_path: Path) -> None:
    cve_ids = {f"CVE-2026-{i:05d}" for i in range(150)}
    calls: list[int] = []

    def counting_fetch(*, cve_batch, tier, manifest=None):
        calls.append(len(cve_batch))
        return _resp(*[(c, 0.5) for c in cve_batch])

    scores = epss.fetch_epss(cve_ids, tier=1, now=NOW, cache_dir=tmp_path, fetch=counting_fetch)
    assert sorted(calls) == [50, 100]                          # 150 CVEs -> two batches of <=100
    assert len(scores) == 150


def test_fetch_degrades_to_cached_subset_on_failure(tmp_path: Path) -> None:
    epss.fetch_epss({"CVE-2025-68664"}, tier=1, now=NOW, cache_dir=tmp_path, fetch=_fetch_ok)

    def boom(*, cve_batch, tier, manifest=None):
        raise OSError("offline")

    # the already-cached CVE survives; the new one is silently dropped (never raises)
    scores = epss.fetch_epss(
        {"CVE-2025-68664", "CVE-2026-99999"}, tier=1, now=NOW + timedelta(hours=1),
        cache_dir=tmp_path, fetch=boom,
    )
    assert scores == {"CVE-2025-68664": 0.42}


def test_fetch_refused_below_tier_degrades_to_empty(tmp_path: Path) -> None:
    # the real default fetch at tier 0 -> net.get refuses -> degrade (no audit break)
    assert epss.fetch_epss({"CVE-2025-68664"}, tier=0, now=NOW, cache_dir=tmp_path) == {}


def test_stamp_marks_findings_with_highest_scored_cve() -> None:
    f_single = Finding(check_id="pip-audit", severity="high", title="v", rule="CVE-2025-68664")
    f_multi = Finding(check_id="dep", severity="high", title="x", message="CVE-2025-68664 and CVE-2026-12345")
    f_no = Finding(check_id="dep", severity="high", title="y", rule="CVE-2099-0001")
    n = epss.stamp_epss([f_single, f_multi, f_no], {"CVE-2025-68664": 0.3, "CVE-2026-12345": 0.95})
    assert n == 2
    assert f_single.epss == 0.3
    assert f_multi.epss == 0.95                                # the higher of the two named CVEs
    assert f_no.epss is None


def test_epss_high_score_boosts_priority() -> None:
    plain = Finding(check_id="x", severity="high", title="t", rule="CVE-1")
    low_epss = Finding(check_id="x", severity="high", title="t", rule="CVE-2", epss=0.02)
    high_epss = Finding(check_id="x", severity="high", title="t", rule="CVE-3", epss=0.5)
    assert priority_rank(low_epss) == priority_rank(plain)     # below the 10% threshold: no boost
    assert priority_rank(high_epss) < priority_rank(plain)     # above threshold: leads within severity


def test_kev_still_outranks_high_epss() -> None:
    # KEV (confirmed real-world exploitation) must stay a stronger signal than EPSS (predictive).
    kev_finding = Finding(check_id="x", severity="high", title="t", rule="CVE-1", kev=True)
    epss_finding = Finding(check_id="x", severity="high", title="t", rule="CVE-2", epss=0.99)
    assert priority_rank(kev_finding) < priority_rank(epss_finding)


def test_empty_scores_is_noop() -> None:
    f = Finding(check_id="x", severity="high", title="t", rule="CVE-2025-68664")
    assert epss.stamp_epss([f], {}) == 0 and f.epss is None


# ---------------------------------------------------------------------------
# Review H1/M2: _parse must be total against a malformed/hostile response
# (a captive portal, a TLS-terminating proxy, or a CDN error page in JSON
# clothing) rather than crashing the whole audit.
# ---------------------------------------------------------------------------

def test_parse_null_data_does_not_crash() -> None:
    assert epss._parse(b'{"status":"error","data":null}') == {}


def test_parse_data_not_a_list_does_not_crash() -> None:
    assert epss._parse(b'{"data": 5}') == {}
    assert epss._parse(b'{"data": "x"}') == {}


def test_parse_row_not_a_dict_does_not_crash() -> None:
    assert epss._parse(b'{"data": ["not-a-dict", 5, null]}') == {}


def test_parse_non_numeric_epss_score_skipped_not_crashed() -> None:
    assert epss._parse(b'{"data":[{"cve":"CVE-2024-3094","epss":{"x":1}}]}') == {}
    assert epss._parse(b'{"data":[{"cve":"CVE-2024-3094","epss":"not-a-number"}]}') == {}


def test_parse_out_of_range_score_rejected() -> None:
    # EPSS is a probability in [0, 1] by definition (review M2).
    assert epss._parse(b'{"data":[{"cve":"CVE-2024-3094","epss":"42.0"}]}') == {}
    assert epss._parse(b'{"data":[{"cve":"CVE-2024-3094","epss":"-1"}]}') == {}
    assert epss._parse(b'{"data":[{"cve":"CVE-2024-3094","epss":"nan"}]}') == {}
    assert epss._parse(b'{"data":[{"cve":"CVE-2024-3094","epss":"Infinity"}]}') == {}


def test_parse_valid_row_still_extracted_alongside_bad_ones() -> None:
    # The counterweight: a mix of good and bad rows must not lose the good one.
    raw = (
        b'{"data":[{"cve":"CVE-2024-3094","epss":"0.85974"},'
        b'{"cve":"CVE-2021-0001","epss":null},'
        b'"garbage"]}'
    )
    assert epss._parse(raw) == {"CVE-2024-3094": 0.85974}


def test_fetch_epss_degrades_on_malformed_response(tmp_path: Path) -> None:
    def fetch(*, cve_batch, tier, manifest=None):
        return b'{"data": null}'

    scores = epss.fetch_epss({"CVE-2024-3094"}, tier=1, now=NOW, cache_dir=tmp_path, fetch=fetch)
    assert scores == {}  # degrades, does not raise


def test_fetch_epss_degrades_on_deeply_nested_response(tmp_path: Path) -> None:
    # #624: json.loads raises RecursionError (not a ValueError) on deeply nested input.
    def fetch(*, cve_batch, tier, manifest=None):
        return b"[" * 100000

    scores = epss.fetch_epss({"CVE-2024-3094"}, tier=1, now=NOW, cache_dir=tmp_path, fetch=fetch)
    assert scores == {}


# ---------------------------------------------------------------------------
# Review H3: a corrupted/malformed on-disk cache file must not crash every
# subsequent --epss audit on that machine.
# ---------------------------------------------------------------------------

def test_read_cache_top_level_null_degrades(tmp_path: Path) -> None:
    epss.cache_path(tmp_path).parent.mkdir(parents=True, exist_ok=True)
    epss.cache_path(tmp_path).write_text("null", encoding="utf-8")
    assert epss._read_cache(epss.cache_path(tmp_path), NOW) == {}


def test_read_cache_top_level_list_degrades(tmp_path: Path) -> None:
    epss.cache_path(tmp_path).parent.mkdir(parents=True, exist_ok=True)
    epss.cache_path(tmp_path).write_text("[1, 2]", encoding="utf-8")
    assert epss._read_cache(epss.cache_path(tmp_path), NOW) == {}


def test_read_cache_top_level_scalar_degrades(tmp_path: Path) -> None:
    epss.cache_path(tmp_path).parent.mkdir(parents=True, exist_ok=True)
    epss.cache_path(tmp_path).write_text("5", encoding="utf-8")
    assert epss._read_cache(epss.cache_path(tmp_path), NOW) == {}


def test_fetch_epss_survives_corrupted_cache_file(tmp_path: Path) -> None:
    # End-to-end: a poisoned cache file must not prevent the audit from completing —
    # it should just be treated as an empty cache and re-fetch.
    epss.cache_path(tmp_path).parent.mkdir(parents=True, exist_ok=True)
    epss.cache_path(tmp_path).write_text("null", encoding="utf-8")

    def fetch(*, cve_batch, tier, manifest=None):
        return b'{"data":[{"cve":"CVE-2024-3094","epss":"0.5"}]}'

    scores = epss.fetch_epss({"CVE-2024-3094"}, tier=1, now=NOW, cache_dir=tmp_path, fetch=fetch)
    assert scores == {"CVE-2024-3094": 0.5}
