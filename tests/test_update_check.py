"""Registry update-awareness (RFC #253 Phase 2) — versions.json fetch/cache + the
comparison (version, guard delta, item delta, min_supported), plus Phase 1's 90-day
offline advisory line. All informational only — see agentsec/update_check.py."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from agentsec import net, update_check
from agentsec.checklist import load_checklist
from agentsec.cli import _EGRESS_CATALOG
from agentsec.registry import ALL_GUARDS

NOW = datetime(2026, 7, 3, tzinfo=UTC)
_LOCAL = load_checklist()
_LOCAL_GUARDS = len(ALL_GUARDS)


def _remote_bytes(
    latest: str, guard_count: int, item_count: int,
    min_supported: str = "0.15.0", changelog: str | None = "https://example.com/changelog",
) -> bytes:
    return json.dumps({
        "latest": latest, "released": "2026-07-01",
        "guard_count": guard_count, "item_count": item_count,
        "min_supported": min_supported, "changelog": changelog,
        "pack": {"url": None, "sha256": None},
    }).encode()


def test_up_to_date_when_versions_match(tmp_path: Path) -> None:
    def fetch(*, tier, manifest=None):
        return _remote_bytes(_LOCAL.version, _LOCAL_GUARDS, len(_LOCAL.items))

    r = update_check.check_updates(tier=1, now=NOW, cache_dir=tmp_path, fetch=fetch)
    assert r.remote_version == _LOCAL.version
    assert not r.behind
    assert r.guard_delta == 0
    assert r.item_delta == 0
    assert "up to date" in update_check.to_text(r)


def test_behind_reports_version_and_both_deltas(tmp_path: Path) -> None:
    def fetch(*, tier, manifest=None):
        return _remote_bytes("9.9.9", _LOCAL_GUARDS + 10, len(_LOCAL.items) + 12)

    r = update_check.check_updates(tier=1, now=NOW, cache_dir=tmp_path, fetch=fetch)
    assert r.behind
    assert r.remote_version == "9.9.9"
    assert r.guard_delta == 10
    assert r.item_delta == 12
    text = update_check.to_text(r)
    assert "9.9.9" in text and "+10 guards" in text and "+12 items" in text


def test_below_min_supported_gets_the_stronger_message(tmp_path: Path) -> None:
    def fetch(*, tier, manifest=None):
        return _remote_bytes("9.9.9", _LOCAL_GUARDS + 5, len(_LOCAL.items) + 5,
                              min_supported="99.0.0")

    r = update_check.check_updates(tier=1, now=NOW, cache_dir=tmp_path, fetch=fetch)
    assert r.unsupported
    text = update_check.to_text(r)
    assert "BELOW the minimum supported" in text
    assert "99.0.0" in text


def test_at_or_above_min_supported_is_not_unsupported(tmp_path: Path) -> None:
    def fetch(*, tier, manifest=None):
        return _remote_bytes(_LOCAL.version, _LOCAL_GUARDS, len(_LOCAL.items),
                              min_supported=_LOCAL.version)

    r = update_check.check_updates(tier=1, now=NOW, cache_dir=tmp_path, fetch=fetch)
    assert not r.unsupported


def test_no_min_supported_in_manifest_is_never_unsupported(tmp_path: Path) -> None:
    def fetch(*, tier, manifest=None):
        raw = json.loads(_remote_bytes(_LOCAL.version, _LOCAL_GUARDS, len(_LOCAL.items)))
        raw["min_supported"] = None
        return json.dumps(raw).encode()

    r = update_check.check_updates(tier=1, now=NOW, cache_dir=tmp_path, fetch=fetch)
    assert r.min_supported is None
    assert not r.unsupported


def test_fetch_uses_24h_cache(tmp_path: Path) -> None:
    calls = {"n": 0}

    def counting_fetch(*, tier, manifest=None):
        calls["n"] += 1
        return _remote_bytes("9.9.9", 1, 1)

    update_check.check_updates(tier=1, now=NOW, cache_dir=tmp_path, fetch=counting_fetch)
    update_check.check_updates(tier=1, now=NOW + timedelta(hours=23), cache_dir=tmp_path, fetch=counting_fetch)
    assert calls["n"] == 1                                  # 2nd call served from cache
    update_check.check_updates(tier=1, now=NOW + timedelta(hours=25), cache_dir=tmp_path, fetch=counting_fetch)
    assert calls["n"] == 2                                  # past TTL -> re-fetch


def test_degrades_on_fetch_failure(tmp_path: Path) -> None:
    def boom(*, tier, manifest=None):
        raise OSError("offline")

    r = update_check.check_updates(tier=1, now=NOW, cache_dir=tmp_path, fetch=boom)
    assert r.remote_version is None
    assert r.error is not None
    assert not r.behind                                     # unknown is never "behind"
    assert not r.unsupported                                # unknown is never "unsupported"
    assert "could not reach" in update_check.to_text(r)


def test_degrades_on_malformed_response(tmp_path: Path) -> None:
    def garbage(*, tier, manifest=None):
        return b"not json"

    r = update_check.check_updates(tier=1, now=NOW, cache_dir=tmp_path, fetch=garbage)
    assert r.remote_version is None
    assert r.error is not None


def test_degrades_on_missing_required_field(tmp_path: Path) -> None:
    def incomplete(*, tier, manifest=None):
        return json.dumps({"latest": "9.9.9"}).encode()  # no guard_count/item_count

    r = update_check.check_updates(tier=1, now=NOW, cache_dir=tmp_path, fetch=incomplete)
    assert r.remote_version is None
    assert r.error is not None


def test_refused_below_tier_degrades(tmp_path: Path) -> None:
    # the real default fetch at tier 0 -> net.get refuses -> degrade, never raise
    r = update_check.check_updates(tier=0, now=NOW, cache_dir=tmp_path)
    assert r.remote_version is None
    assert isinstance(r.error, str)


def test_local_counts_always_present_even_on_failure(tmp_path: Path) -> None:
    def boom(*, tier, manifest=None):
        raise OSError("offline")

    r = update_check.check_updates(tier=1, now=NOW, cache_dir=tmp_path, fetch=boom)
    assert r.local_version == _LOCAL.version
    assert r.local_guard_count == _LOCAL_GUARDS
    assert r.local_item_count == len(_LOCAL.items)


def test_fetch_records_manifest_disclosure(tmp_path: Path) -> None:
    # exercise the real default fetch path (tier 0, refused) to prove it discloses first.
    real_manifest = net.Manifest(tier=0)
    update_check.check_updates(tier=0, now=NOW, cache_dir=tmp_path, manifest=real_manifest)
    op = next(o for o in real_manifest.ops if o.feature == "--check-updates")
    # The runtime disclosure and the `agentsec network` preview row are two hand-written copies
    # of one claim: bind them so they cannot drift apart.
    row = next(e for e in _EGRESS_CATALOG if e[0] == "--check-updates")
    assert (op.dest, op.sends) == (row[1], row[2])
    # #645: versions.json sits in a private repo until the public launch, so "a public
    # versions.json GET" was false. The disclosure describes the request (unauthenticated, no
    # repo data), which is true in both states. Relax this pin after the launch only if someone
    # wants the word back.
    assert "public" not in op.sends.lower()


def test_changelog_included_when_present(tmp_path: Path) -> None:
    def fetch(*, tier, manifest=None):
        return _remote_bytes("9.9.9", _LOCAL_GUARDS, len(_LOCAL.items), changelog="https://x.example/y")

    r = update_check.check_updates(tier=1, now=NOW, cache_dir=tmp_path, fetch=fetch)
    assert "https://x.example/y" in update_check.to_text(r)


def test_changelog_omitted_when_absent(tmp_path: Path) -> None:
    def fetch(*, tier, manifest=None):
        return _remote_bytes("9.9.9", _LOCAL_GUARDS, len(_LOCAL.items), changelog=None)

    r = update_check.check_updates(tier=1, now=NOW, cache_dir=tmp_path, fetch=fetch)
    assert r.changelog is None
    text = update_check.to_text(r)
    assert "items). Upgrade:" in text  # no " — <url>" spliced in between


# --- stale_advisory_line (Phase 1's 90-day offline soft-line) --------------------------

def test_stale_advisory_none_below_threshold() -> None:
    assert update_check.stale_advisory_line(0) is None
    assert update_check.stale_advisory_line(89) is None


def test_stale_advisory_present_at_and_above_threshold() -> None:
    at = update_check.stale_advisory_line(90)
    above = update_check.stale_advisory_line(200)
    assert at is not None and "90 days old" in at
    assert above is not None and "200 days old" in above
    assert "doctor --check-updates" in at


def test_versions_json_matches_registry() -> None:
    """The committed versions.json is fetched raw off `main` by `--check-updates`, and its
    counts are meant to never drift from what shipped. Regen is manual (RFC #253) and nothing
    else gates it, so this drift test keeps it honest — mirrors `test_readme_facts` for the
    README badge. On failure: run `python scripts/regen-versions-json.py` and commit."""
    repo = Path(__file__).resolve().parents[1]
    vj = json.loads((repo / "versions.json").read_text(encoding="utf-8"))
    assert vj["latest"] == _LOCAL.version, "versions.json 'latest' drifted from the checklist version"
    assert vj["guard_count"] == _LOCAL_GUARDS, "versions.json 'guard_count' drifted from the registry"
    assert vj["item_count"] == len(_LOCAL.items), "versions.json 'item_count' drifted from the checklist"


def test_refresh_bypasses_cache(tmp_path: Path) -> None:
    calls = {"n": 0}

    def counting_fetch(*, tier, manifest=None):
        calls["n"] += 1
        return _remote_bytes("9.9.9", 1, 1)

    update_check.check_updates(tier=1, now=NOW, cache_dir=tmp_path, fetch=counting_fetch)
    # Within the 24h TTL a normal call would hit the cache; --refresh must re-fetch.
    update_check.check_updates(
        tier=1, now=NOW + timedelta(hours=1), cache_dir=tmp_path, fetch=counting_fetch, refresh=True,
    )
    assert calls["n"] == 2


def test_not_behind_when_local_ahead_of_manifest(tmp_path: Path) -> None:
    # A dev-HEAD install ahead of the published manifest is not "behind" — numeric compare,
    # not string `!=` (which used to point backwards for local > remote).
    def fetch(*, tier, manifest=None):
        return _remote_bytes("0.0.1", 1, 1)

    r = update_check.check_updates(tier=1, now=NOW, cache_dir=tmp_path, fetch=fetch)
    assert not r.behind
    assert "up to date" in update_check.to_text(r)


# --- the upgrade hint and the fetch URL (pypi-release plan, P2.5) ------------------------------


def test_dist_name_matches_pyproject() -> None:
    import tomllib
    project = tomllib.loads((Path(__file__).resolve().parent.parent / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["project"]["name"] == update_check.DIST_NAME


def test_upgrade_hint_names_pypi_not_the_git_url(tmp_path: Path) -> None:
    """Both directions: the PyPI hint is present, and the old private-repo git reinstall is gone (a PyPI
    user cannot clone the private repo). Covers the behind and the below-minimum branches."""
    def behind(*, tier, manifest=None):
        return _remote_bytes("9.9.9", _LOCAL_GUARDS, len(_LOCAL.items), changelog=None)

    def unsupported(*, tier, manifest=None):
        return _remote_bytes("9.9.9", _LOCAL_GUARDS, len(_LOCAL.items), changelog=None, min_supported="9.0.0")

    for fetch in (behind, unsupported):
        text = update_check.to_text(update_check.check_updates(tier=1, now=NOW, cache_dir=tmp_path / fetch.__name__,
                                                                fetch=fetch))
        assert "pipx upgrade ai-agent-security" in text, text
        assert "git+https://" not in text and "available on main" not in text, text


def test_versions_url_follows_the_repo_slug() -> None:
    from agentsec import AGENTSEC_REPO_SLUG
    assert f"https://raw.githubusercontent.com/{AGENTSEC_REPO_SLUG}/main/versions.json" == update_check.VERSIONS_URL
