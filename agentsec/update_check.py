"""Registry update-awareness — a **Tier 1** advisory fetch (RFC #253 Phase 2,
docs/knowledge/rfc-version-staleness-update-awareness.md).

Phase 1 (`Checklist.age_days`) answers "how old is my registry" from data already on
disk, offline. Phase 2 answers the question Phase 1 can't: "is there a newer one." Since
agentsec is offline by default, that check is opt-in (`doctor --check-updates`), mirrors
`--kev`'s tier-1 shape exactly, and fetches a small published manifest rather than your
current version — nothing about your repo, your stack, or which version you run leaves
your machine (the RFC's own privacy nuance: even `--kev`'s "sends nothing about your
code" GET still leaks IP + User-Agent; this fetch adds nothing on top of that floor).

**Design — implementing the RFC's own recommendations, not reopening them:**
  - **Manifest: a dedicated `versions.json`** (RFC open question 1's own recommendation:
    "richer delta, doubles as the pack index" — not the GitHub Releases API, which only
    gives version + date). Regenerated at release time by `scripts/regen-versions-json.py`
    from the checklist + registry (so `latest`/`guard_count`/`item_count` can never drift
    from what actually shipped); `changelog`/`min_supported`/`pack` are maintainer-set
    fields the script preserves once present. Lives at the repo root, fetched raw off
    `main` — "served from the repo now," per the RFC.
  - **Delta: both guard count and item count** (RFC's own report format: "+N guards, +M
    items"), current-vs-current, not a per-release changelog (a `pipx` install has no
    `.git` history to diff against, and the manifest doesn't publish one — cumulative
    totals in the manifest are the RFC's own "simplest" answer to open question 3).
  - **`min_supported`: a real floor, not deferred.** RFC open question 4, answered: an
    installed version strictly below `versions.json`'s `min_supported` gets a distinctly
    stronger "unsupported" line (still informational — advisory-only, never the exit
    code, per the RFC's own non-goals). Nothing enforces this floor anywhere else today
    (the checklist schema has been additive-only so far), so it costs nothing to carry
    now and is the hook for when a real breaking change eventually needs it.
  - **90-day offline soft-line:** RFC Phase 1's own design ("past a soft threshold (e.g.
    90 days) add one advisory line... run `doctor --check-updates`") — implemented here
    alongside Phase 2 since it's the same feature's zero-network half, and closes a gap
    Phase 1's actual merge (`feat/registry-staleness-stamp`) left out. Lives in
    `cli.py::_registry_stamp`, not this module (it's a pure function of `age_days`, no
    network) — see `stale_advisory_line()` below for the shared threshold/copy.

Routes through `agentsec/net.py` (the egress chokepoint); runtime is stdlib-only.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Protocol

from agentsec import AGENTSEC_REPO_SLUG, net

# Built from the one repo-identity switch point, so it follows the slug to the public repo, whose `main`
# moves only at release: exactly the "latest release" semantics versions.json wants. While the slug
# still names the private dev repo it 404s, since an anonymous raw GET cannot read it (#645). Not routed
# around with a token, which would send your GitHub credentials; the public launch is the fix. See the
# "Known current limitation" in docs/knowledge/registry-staleness-stamp-design.md.
VERSIONS_URL = f"https://raw.githubusercontent.com/{AGENTSEC_REPO_SLUG}/main/versions.json"
# The PyPI distribution name, which is NOT the command name: `agentsec` on PyPI is an unrelated
# project. tests/test_update_check.py pins this to pyproject.toml's [project].name.
DIST_NAME = "ai-agent-security"
_UPGRADE = f"Upgrade: pipx upgrade {DIST_NAME} (or pip install -U {DIST_NAME})"
_CACHE_TTL = timedelta(hours=24)

# The RFC's own "lean" answer to open question 2 (never a hard rule, just the default).
STALE_THRESHOLD_DAYS = 90

_VER_NUM = re.compile(r"\d+")

class UpdateFetch(Protocol):
    """A test/offline override for the network fetch: (tier, manifest) -> raw versions.json
    bytes. A `Protocol` (not `Callable[..., bytes]`) so the keyword-only signature is visible
    to mypy/pyright — a misspelled kwarg in a fake fails type-check, not just at runtime."""

    def __call__(self, *, tier: int, manifest: net.Manifest | None) -> bytes: ...


def _version_tuple(v: str) -> tuple[int, ...]:
    """Leading numeric components, e.g. '0.18.34' -> (0, 18, 34). Unparseable -> ()."""
    return tuple(int(x) for x in _VER_NUM.findall(v.strip().lstrip("vV")))


@dataclass(frozen=True)
class UpdateCheckResult:
    local_version: str
    local_guard_count: int
    local_item_count: int
    remote_version: str | None = None      # None = fetch failed/refused/malformed
    remote_guard_count: int | None = None
    remote_item_count: int | None = None
    min_supported: str | None = None
    changelog: str | None = None
    error: str | None = None

    @property
    def behind(self) -> bool:
        # A newer PUBLISHED version, by numeric comparison — a dev-HEAD install that is
        # *ahead* of the manifest is not "behind" (this was a plain `!=`, which mis-pointed
        # backwards whenever local > remote).
        if self.remote_version is None:
            return False
        return _version_tuple(self.remote_version) > _version_tuple(self.local_version)

    @property
    def guard_delta(self) -> int | None:
        return None if self.remote_guard_count is None else self.remote_guard_count - self.local_guard_count

    @property
    def item_delta(self) -> int | None:
        return None if self.remote_item_count is None else self.remote_item_count - self.local_item_count

    @property
    def unsupported(self) -> bool:
        """True when the installed version is strictly below the manifest's min_supported floor."""
        if not self.min_supported:
            return False
        local_t, floor_t = _version_tuple(self.local_version), _version_tuple(self.min_supported)
        return bool(local_t) and bool(floor_t) and local_t < floor_t


def cache_path(cache_dir: Path | None = None) -> Path:
    return (cache_dir or (Path.home() / ".agentsec")) / "update-check-cache.json"


@dataclass(frozen=True)
class _RemoteInfo:
    """The parsed/cached subset of `versions.json` — typed so `check_updates()` can
    construct `UpdateCheckResult` from named fields, never a loosely-typed `**dict`
    unpack (which erases per-key types under `mypy --strict`)."""

    remote_version: str
    remote_guard_count: int
    remote_item_count: int
    min_supported: str | None
    changelog: str | None


def check_updates(
    *, tier: int, now: datetime, manifest: net.Manifest | None = None,
    cache_dir: Path | None = None, fetch: UpdateFetch | None = None, refresh: bool = False,
) -> UpdateCheckResult:
    """Compare the installed registry against `versions.json` on `main`. Never raises; a
    failed/refused/malformed fetch yields a result with `remote_version=None` + `.error`
    set, and the caller (doctor) prints that as an informational note — never a failure,
    never a gate. `refresh=True` bypasses the 24h on-disk cache (RFC §2's `--refresh`)."""
    # Lazy so importing `stale_advisory_line` (used on every audit/doctor via _registry_stamp)
    # doesn't pull the full registry — only the network path below needs these.
    from agentsec.checklist import load_checklist
    from agentsec.registry import ALL_GUARDS

    local = load_checklist()
    local_guard_count = len(ALL_GUARDS)
    local_item_count = len(local.items)

    path = cache_path(cache_dir)
    cached = None if refresh else _read_cache(path, now)
    if cached is not None:
        return UpdateCheckResult(
            local_version=local.version, local_guard_count=local_guard_count,
            local_item_count=local_item_count, remote_version=cached.remote_version,
            remote_guard_count=cached.remote_guard_count, remote_item_count=cached.remote_item_count,
            min_supported=cached.min_supported, changelog=cached.changelog,
        )

    try:
        raw = (fetch or _default_fetch)(tier=tier, manifest=manifest)
        parsed = _parse(raw)
    except (OSError, ValueError, KeyError, TypeError, net.EgressRefused) as e:
        return UpdateCheckResult(
            local_version=local.version, local_guard_count=local_guard_count,
            local_item_count=local_item_count, error=str(e),
        )
    _write_cache(path, parsed, now)
    return UpdateCheckResult(
        local_version=local.version, local_guard_count=local_guard_count,
        local_item_count=local_item_count, remote_version=parsed.remote_version,
        remote_guard_count=parsed.remote_guard_count, remote_item_count=parsed.remote_item_count,
        min_supported=parsed.min_supported, changelog=parsed.changelog,
    )


def _default_fetch(*, tier: int, manifest: net.Manifest | None) -> bytes:
    return net.get(
        VERSIONS_URL, tier_required=1, feature="--check-updates", tier=tier, manifest=manifest,
        sends="nothing about your repo (an unauthenticated GET of agentsec's versions.json)",
    )


def _parse(raw: bytes) -> _RemoteInfo:
    data = json.loads(raw)
    return _RemoteInfo(
        remote_version=str(data["latest"]),
        remote_guard_count=int(data["guard_count"]),
        remote_item_count=int(data["item_count"]),
        min_supported=(str(data["min_supported"]) if data.get("min_supported") else None),
        changelog=(str(data["changelog"]) if data.get("changelog") else None),
    )


def _read_cache(path: Path, now: datetime) -> _RemoteInfo | None:
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
        if now - datetime.fromisoformat(str(d["fetched_at"])) < _CACHE_TTL:
            return _RemoteInfo(
                remote_version=str(d["remote_version"]),
                remote_guard_count=int(d["remote_guard_count"]),
                remote_item_count=int(d["remote_item_count"]),
                min_supported=(str(d["min_supported"]) if d.get("min_supported") else None),
                changelog=(str(d["changelog"]) if d.get("changelog") else None),
            )
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return None


def _write_cache(path: Path, parsed: _RemoteInfo, now: datetime) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({
                "fetched_at": now.isoformat(),
                "remote_version": parsed.remote_version,
                "remote_guard_count": parsed.remote_guard_count,
                "remote_item_count": parsed.remote_item_count,
                "min_supported": parsed.min_supported,
                "changelog": parsed.changelog,
            }) + "\n",
            encoding="utf-8",
        )
    except OSError:
        pass


def to_text(r: UpdateCheckResult) -> str:
    if r.remote_version is None:
        reason = f" ({r.error})" if r.error else ""
        return f"Update check: could not reach the registry{reason} — you're on v{r.local_version}."
    if r.unsupported:
        return (
            f"Update check: v{r.local_version} is BELOW the minimum supported version "
            f"(v{r.min_supported}) — please upgrade. Latest: v{r.remote_version} "
            f"({r.remote_guard_count} guards, {r.remote_item_count} items). {_UPGRADE}"
        )
    if not r.behind:
        return f"Update check: up to date (v{r.local_version}, {r.local_guard_count} guards, {r.local_item_count} items)."
    g, i = r.guard_delta or 0, r.item_delta or 0
    gs, is_ = ("+" if g >= 0 else ""), ("+" if i >= 0 else "")
    changelog = f" — {r.changelog}" if r.changelog else ""
    return (
        f"Update check: v{r.local_version} -> v{r.remote_version} available "
        f"({gs}{g} guards, {is_}{i} items){changelog}. {_UPGRADE}"
    )


def stale_advisory_line(age_days: int) -> str | None:
    """RFC Phase 1's soft advisory line — offline, zero network, a pure function of
    `age_days`. None below the threshold; the caller (`_registry_stamp`) appends the
    result as one extra line, never gating anything (RFC non-goals: never the exit code,
    never CI's default Tier 0 posture)."""
    if age_days < STALE_THRESHOLD_DAYS:
        return None
    return (
        f"your definitions are {age_days} days old: run `agentsec doctor --check-updates` "
        f"(opt-in, Tier 1) to see what is new."
    )
