"""FIRST.org EPSS (Exploit Prediction Scoring System) enrichment — a **Tier 1** advisory fetch.

Queries the free, public FIRST.org EPSS API (`api.first.org/data/v1/epss`) for the CVEs already
present in the finding set, caches each CVE's score on disk for 24h (EPSS itself updates daily),
and returns a CVE -> score (0.0-1.0, modeled probability of exploitation in the next 30 days)
mapping. `audit()` stamps `Finding.epss` for any finding whose CVE is scored; `prioritize` boosts
findings above a documented high-probability threshold. It is a **re-ranking only** — never adds or
drops a finding.

Unlike KEV's fixed, bulk-downloaded catalog, this is queried PER-CVE: EPSS scores ~280k+ CVEs, the
overwhelming majority irrelevant to any one audit, so only the CVE ids already surfaced by this
audit's own findings are ever sent (`sends` records exactly that — CVE ids already found, nothing
about the target repo itself). Degrades gracefully: an offline/refused/malformed fetch yields the
already-cached subset (or {} if nothing was cached), and the audit completes normally.

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

EPSS_URL = "https://api.first.org/data/v1/epss"
_CACHE_TTL = timedelta(hours=24)
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_BATCH_SIZE = 100  # the API's own default page size; chunk larger CVE sets to stay within it

# A test/offline override: (cve_batch, tier, manifest) -> raw response bytes.
EpssFetch = Callable[..., bytes]


def cache_path(cache_dir: Path | None = None) -> Path:
    return (cache_dir or (Path.home() / ".agentsec")) / "epss-cache.json"


def cves_in_findings(findings: list[Finding]) -> set[str]:
    """Every CVE id named in any finding's rule/message, uppercased — the query set for `fetch_epss`."""
    out: set[str] = set()
    for f in findings:
        out |= {c.upper() for c in _CVE.findall(f"{f.rule} {f.message}")}
    return out


def fetch_epss(
    cve_ids: set[str], *, tier: int, now: datetime, manifest: net.Manifest | None = None,
    cache_dir: Path | None = None, fetch: EpssFetch | None = None,
) -> dict[str, float]:
    """CVE -> EPSS score (0.0-1.0) for `cve_ids`. Cache-first per CVE (24h TTL, matching EPSS's own
    daily update cadence) — only missing/stale CVEs are actually fetched, in batches of
    `_BATCH_SIZE`. Returns whatever was already cached (possibly {}) on any fetch failure — the
    audit never breaks on EPSS."""
    if not cve_ids:
        return {}
    path = cache_path(cache_dir)
    cached = _read_cache(path, now)
    fresh = {cve: score for cve, (score, _fetched_at) in cached.items() if cve in cve_ids}
    missing = sorted(cve_ids - fresh.keys())
    if not missing:
        return fresh
    try:
        fetched: dict[str, float] = {}
        for i in range(0, len(missing), _BATCH_SIZE):
            batch = missing[i:i + _BATCH_SIZE]
            raw = (fetch or _default_fetch)(cve_batch=batch, tier=tier, manifest=manifest)
            fetched.update(_parse(raw))
    # RecursionError: json.loads raises it on deeply nested input, and it is not a ValueError (#624).
    except (OSError, ValueError, TypeError, RecursionError, net.EgressRefused):
        return fresh
    cached.update({cve: (score, now) for cve, score in fetched.items()})
    _write_cache(path, cached)
    fresh.update(fetched)
    return fresh


def stamp_epss(findings: list[Finding], scores: dict[str, float]) -> int:
    """Set `finding.epss` to the highest scored CVE named in each finding's rule/message. Returns
    the count stamped."""
    if not scores:
        return 0
    n = 0
    for f in findings:
        hits = [scores[c.upper()] for c in _CVE.findall(f"{f.rule} {f.message}") if c.upper() in scores]
        if hits:
            f.epss = max(hits)
            n += 1
    return n


def _default_fetch(*, cve_batch: list[str], tier: int, manifest: net.Manifest | None) -> bytes:
    return net.get(
        f"{EPSS_URL}?cve={','.join(cve_batch)}", tier_required=1, feature="--epss", tier=tier,
        manifest=manifest, sends=f"{len(cve_batch)} CVE id(s) already found by this audit",
    )


def _parse(raw: bytes) -> dict[str, float]:
    # Total against a malformed/hostile response shape (review H1): a captive portal, a
    # TLS-terminating proxy, or a CDN error page in JSON clothing must degrade, not crash the
    # whole audit. `rows`/`row`/`row["epss"]` are all attacker- or intermediary-controlled shapes,
    # so each is defended independently rather than trusting the isinstance chain to hold together.
    data = json.loads(raw)
    rows = data.get("data") if isinstance(data, dict) else None
    out: dict[str, float] = {}
    for row in rows if isinstance(rows, list) else []:
        if not (isinstance(row, dict) and row.get("cve") and row.get("epss") is not None):
            continue
        try:
            score = float(row["epss"])
        except (TypeError, ValueError):
            continue
        if 0.0 <= score <= 1.0:  # EPSS is a probability — reject anything else (review M2)
            out[str(row["cve"]).upper()] = score
    return out


def _read_cache(path: Path, now: datetime) -> dict[str, tuple[float, datetime]]:
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
        out: dict[str, tuple[float, datetime]] = {}
        for cve, entry in d.items():
            fetched_at = datetime.fromisoformat(str(entry["fetched_at"]))
            if now - fetched_at < _CACHE_TTL:
                out[str(cve).upper()] = (float(entry["score"]), fetched_at)
        return out
    # AttributeError (review H3): the cache is a persistent user-level file, not transient
    # request input — a top-level JSON value that isn't an object (corrupted by an interrupted
    # write, a full disk, or version skew) must not crash every subsequent --epss audit on that
    # machine until someone works out they need to delete a file nothing told them about.
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return {}


def _write_cache(path: Path, cached: dict[str, tuple[float, datetime]]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            cve: {"score": score, "fetched_at": fetched_at.isoformat()}
            for cve, (score, fetched_at) in cached.items()
        }
        path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    except OSError:
        pass
