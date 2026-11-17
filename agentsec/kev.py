"""CISA KEV (Known Exploited Vulnerabilities) enrichment — a **Tier 1** advisory fetch.

Downloads the public CISA KEV catalog (sends **nothing** about your code), caches it on disk
for 24h, and returns the set of known-exploited CVE ids. `audit()` stamps `Finding.kev` for any
finding whose CVE is in the set; `prioritize` boosts those (known-exploited = the top real-world
signal). It is a **re-ranking only** — never adds or drops a finding. Degrades gracefully: an
offline/refused/malformed fetch yields the empty set + a note, and the audit completes normally.

Routes through `agentsec/net.py` (the egress chokepoint); runtime is stdlib-only.
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path

from agentsec import net
from agentsec.findings import Finding

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_CACHE_TTL = timedelta(hours=24)
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# A test/offline override: (tier, manifest) -> raw catalog bytes.
KevFetch = Callable[..., bytes]


def cache_path(cache_dir: Path | None = None) -> Path:
    return (cache_dir or (Path.home() / ".agentsec")) / "kev-cache.json"


def fetch_kev(
    *, tier: int, now: datetime, manifest: net.Manifest | None = None,
    cache_dir: Path | None = None, fetch: KevFetch | None = None,
) -> set[str]:
    """The known-exploited CVE-id set (uppercased). Served from the 24h on-disk cache when fresh
    (deterministic within the TTL), else fetched via `net.get` at Tier 1. Returns `set()` on any
    failure — the audit never breaks on KEV."""
    path = cache_path(cache_dir)
    cached = _read_cache(path, now)
    if cached is not None:
        return cached
    try:
        raw = (fetch or _default_fetch)(tier=tier, manifest=manifest)
        cves = _parse(raw)
    # RecursionError: json.loads raises it on deeply nested input, and it is not a ValueError (#624).
    except (OSError, ValueError, RecursionError, net.EgressRefused):
        return set()
    _write_cache(path, cves, now)
    return cves


def stamp_kev(findings: list[Finding], kev: set[str]) -> int:
    """Mark each finding whose `rule`/`message` names a known-exploited CVE. Returns the count."""
    if not kev:
        return 0
    n = 0
    for f in findings:
        if {c.upper() for c in _CVE.findall(f"{f.rule} {f.message}")} & kev:
            f.kev = True
            n += 1
    return n


def _default_fetch(*, tier: int, manifest: net.Manifest | None) -> bytes:
    return net.get(
        KEV_URL, tier_required=1, feature="--kev", tier=tier, manifest=manifest,
        sends="nothing (downloads the public CISA KEV catalog)",
    )


def _parse(raw: bytes) -> set[str]:
    # Total against a malformed/hostile response shape (#624, the KEV twin of #609 H1): dict.get's
    # default covers only an ABSENT key, so a present-but-null/scalar `vulnerabilities` must be
    # rejected by type, not trusted to be iterable. Each row and its `cveID` is defended independently.
    data = json.loads(raw)
    vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
    out: set[str] = set()
    for v in vulns if isinstance(vulns, list) else []:
        cve = v.get("cveID") if isinstance(v, dict) else None
        if isinstance(cve, str) and cve:
            out.add(cve.upper())
    return out


def _read_cache(path: Path, now: datetime) -> set[str] | None:
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
        if now - datetime.fromisoformat(str(d["fetched_at"])) < _CACHE_TTL:
            return {str(c).upper() for c in d["cves"]}
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return None


def _write_cache(path: Path, cves: set[str], now: datetime) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({"fetched_at": now.isoformat(), "cves": sorted(cves)}) + "\n", encoding="utf-8"
        )
    except OSError:
        pass
