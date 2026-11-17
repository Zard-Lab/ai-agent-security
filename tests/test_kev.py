"""CISA KEV enrichment — fetch/cache + the stamp/boost (a re-ranking, never a drop)."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from agentsec import kev
from agentsec.findings import Finding
from agentsec.prioritize import priority_rank

NOW = datetime(2026, 6, 24, tzinfo=UTC)
_CATALOG = json.dumps({"vulnerabilities": [
    {"cveID": "CVE-2025-68664"}, {"cveID": "cve-2026-12345"},
]}).encode()


def _fetch_ok(*, tier, manifest=None):
    return _CATALOG


def test_fetch_parses_and_uppercases(tmp_path: Path) -> None:
    s = kev.fetch_kev(tier=1, now=NOW, cache_dir=tmp_path, fetch=_fetch_ok)
    assert s == {"CVE-2025-68664", "CVE-2026-12345"}


def test_fetch_uses_24h_cache(tmp_path: Path) -> None:
    calls = {"n": 0}

    def counting_fetch(*, tier, manifest=None):
        calls["n"] += 1
        return _CATALOG

    kev.fetch_kev(tier=1, now=NOW, cache_dir=tmp_path, fetch=counting_fetch)
    kev.fetch_kev(tier=1, now=NOW + timedelta(hours=23), cache_dir=tmp_path, fetch=counting_fetch)
    assert calls["n"] == 1                                  # 2nd call served from cache
    # past TTL → re-fetch
    kev.fetch_kev(tier=1, now=NOW + timedelta(hours=25), cache_dir=tmp_path, fetch=counting_fetch)
    assert calls["n"] == 2


def test_fetch_degrades_on_failure(tmp_path: Path) -> None:
    def boom(*, tier, manifest=None):
        raise OSError("offline")

    assert kev.fetch_kev(tier=1, now=NOW, cache_dir=tmp_path, fetch=boom) == set()  # never raises


def test_fetch_refused_below_tier_is_empty(tmp_path: Path) -> None:
    # the real default fetch at tier 0 → net.get refuses → degrade to empty (no audit break)
    assert kev.fetch_kev(tier=0, now=NOW, cache_dir=tmp_path) == set()


def test_stamp_marks_findings_with_known_exploited_cve() -> None:
    f_kev = Finding(check_id="pip-audit", severity="high", title="vuln", rule="CVE-2025-68664")
    f_msg = Finding(check_id="dep", severity="high", title="x", message="affected by CVE-2026-12345 ...")
    f_no = Finding(check_id="dep", severity="high", title="y", rule="CVE-2099-0001")
    n = kev.stamp_kev([f_kev, f_msg, f_no], {"CVE-2025-68664", "CVE-2026-12345"})
    assert n == 2 and f_kev.kev and f_msg.kev and not f_no.kev


def test_kev_boosts_priority() -> None:
    plain = Finding(check_id="x", severity="high", title="t", rule="CVE-1")
    exploited = Finding(check_id="x", severity="high", title="t", rule="CVE-2", kev=True)
    assert priority_rank(exploited) < priority_rank(plain)   # KEV leads within its severity


def test_empty_kev_set_is_noop() -> None:
    f = Finding(check_id="x", severity="high", title="t", rule="CVE-2025-68664")
    assert kev.stamp_kev([f], set()) == 0 and not f.kev


# ---------------------------------------------------------------------------
# #624 (the KEV twin of #609 H1): _parse must be total against a malformed/
# hostile response shape, so a present-but-null/scalar `vulnerabilities` value
# degrades to no enrichment instead of crashing the whole `--kev` audit.
# ---------------------------------------------------------------------------

def test_parse_null_vulnerabilities_does_not_crash() -> None:
    assert kev._parse(b'{"vulnerabilities": null}') == set()


def test_parse_vulnerabilities_not_a_list_does_not_crash() -> None:
    for body in (b"5", b"true", b"1.5", b'"abc"', b'{"a": 1}'):
        assert kev._parse(b'{"vulnerabilities": ' + body + b"}") == set(), body


def test_parse_row_not_a_dict_does_not_crash() -> None:
    assert kev._parse(b'{"vulnerabilities": [null, 5, "x"]}') == set()


def test_parse_non_string_cve_id_skipped() -> None:
    assert kev._parse(b'{"vulnerabilities": [{"cveID": 7}, {"cveID": {"k": 1}}, {"cveID": ""}]}') == set()


def test_parse_valid_rows_still_extracted_alongside_bad_ones() -> None:
    # The counterweight (Rule 1): hardening must not lose a good row sitting among bad ones.
    raw = (
        b'{"vulnerabilities": [null, 5, "x", {"cveID": null}, {"cveID": ""}, {"cveID": 7},'
        b'{"cveID": {"k": 1}}, {"cveID": "CVE-2024-3094"}, {"cveID": "cve-2026-12345"}]}'
    )
    assert kev._parse(raw) == {"CVE-2024-3094", "CVE-2026-12345"}


def test_fetch_kev_degrades_on_malformed_response(tmp_path: Path) -> None:
    def fetch(*, tier, manifest=None):
        return b'{"vulnerabilities": null}'

    assert kev.fetch_kev(tier=1, now=NOW, cache_dir=tmp_path, fetch=fetch) == set()  # never raises


def test_fetch_kev_degrades_on_deeply_nested_response(tmp_path: Path) -> None:
    # json.loads raises RecursionError (not a ValueError) here, before _parse's own logic runs.
    def fetch(*, tier, manifest=None):
        return b"[" * 100000

    assert kev.fetch_kev(tier=1, now=NOW, cache_dir=tmp_path, fetch=fetch) == set()
