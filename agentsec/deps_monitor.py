"""Deterministic dependency + tool CVE monitor (Phase 1 of the deps-CVE-monitor).

Walks agentsec's *own* pinned supply chain — the `pins.py` tool manifest, the
`pyproject.toml` `[dev]` floors, and the GitHub Actions SHA pins in
`.github/workflows/*.yml` — and for each:

  * asks **OSV.dev** (`POST /v1/querybatch`) whether the pinned version has a
    known advisory, and
  * asks the release feed (**PyPI** / **npm** / **GitHub Releases**) whether a
    newer version exists and **when it was published**,

then applies a **48h release-age cooldown** (`pins`-shared with the
python-supply-chain guard): a newer release younger than the window is *deferred*
(noted, not proposed) — **unless** the current pin has a CVE, which bypasses the
cooldown (Dependabot's security-update split). The result is a list of `Finding`s
plus three renderers the CLI/workflow consume: `build_plan` (markdown for humans /
offline), `build_input` (the actionable-set JSON an LLM agent turns into a PR
plan), and `actionable_count` (the gate that decides whether the agent runs).

**Deterministic + hermetic by construction:** `now` is injected (never
`datetime.now()`), and *all* network access is funnelled through a single injected
`fetch` callable, so the whole module runs offline under a stubbed `fetch` in
tests. Like the scanner runners, every network call degrades gracefully — a failed
or malformed response yields "unknown", never an exception that aborts the run.

Mirrors `intake.py` (clock-as-parameter, bounded-autonomy via `cap_proposals`) and
`runners/pip_audit.py` (advisory → `Finding`). Runtime is stdlib-only.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time as _time  # NOT `datetime.time`, which this module imports below
import tomllib
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time
from pathlib import Path
from typing import Protocol

from agentsec import net, pins
from agentsec.findings import Finding, sanitize_finding

# The cooldown window — the same 48h the python-supply-chain guard enforces on a
# target's deps, now turned inward onto agentsec's own pins.
from agentsec.guards.python_supply_chain import _REQUIRED_HOURS as REQUIRED_HOURS

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
_PYPI_URL = "https://pypi.org/pypi/{name}/json"
_NPM_URL = "https://registry.npmjs.org/{name}"
_GH_RELEASE_URL = "https://api.github.com/repos/{repo}/releases/latest"

# Effectively no per-run cap (used when emitting the reviewed plan — see --emit-plan).
_UNCAPPED = 10**6

# The backoff the CLI's apply path hands `RetryingFetch`. A module attribute rather than the
# constructor default, because that default is bound once at class-definition time and no test
# driving `main()` can reach it: one end-to-end test paid a real 2.02s of backoff on every run,
# including the `-m "not slow"` dev loop. Patch this, not `time.sleep`, to keep a retry test
# hermetic without mutating the stdlib for everything else in the process.
_retry_sleep: Callable[[float], None] = _time.sleep

# OSV ecosystem strings are case-sensitive ("PyPI", "npm", "GitHub Actions"). Native
# binaries have no OSV ecosystem keyed by their tool name → release-checked only.

# A `uses: owner/repo@<40-hex-sha>  # vX.Y.Z` pin in a workflow file.
_ACTION_PIN = re.compile(
    r"uses:\s*([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)@([0-9a-f]{40})\b[^\n]*?(?:#\s*(v?[0-9][\w.\-]*))?$"
)


class Fetch(Protocol):
    """The single network boundary. `body=None` → GET; bytes → POST JSON.

    Implementations MUST raise on transport/HTTP error (the caller catches and
    degrades); a non-raising stub makes tests fully offline + deterministic.
    """

    def __call__(self, url: str, body: bytes | None = ...) -> bytes: ...


def default_fetch(url: str, body: bytes | None = None) -> bytes:
    """The real network boundary — routed through `net.py` (the single egress chokepoint).
    `deps-monitor` is an explicitly-networked maintainer command (Tier 1): invoking it is the
    opt-in, so it uses the raw boundary directly rather than the tier-gated `net.get`."""
    return net._raw_request(url, body=body, timeout=20)


class RetryingFetch:
    """A `Fetch` that re-attempts once on a TRANSIENT failure, and records how many attempts
    the last failure took.

    Why this cannot hide flakiness — the real objection to any retry. When the second attempt
    succeeds the bump lands and there was nothing to hide. When it fails, the deferral says
    "after 2 attempts", which is STRONGER evidence than a single shot: it converts "something
    went wrong once" into "still broken after two tries", exactly the discrimination missing on
    2026-08-12, when one HTTP 503 dropped a CVE-forced bump out of a green run and only a
    manual re-run distinguished it from a permanent defect.

    Permanent failures (`ResolveDefect`, a 404, an unknown pin) are re-raised immediately —
    retrying a request that was wrong rather than unlucky just doubles the wait.

    `sleep` is injected so tests are instant and hermetic without patching a global, matching
    this module's clock-as-a-parameter discipline. Applied to the APPLY path only: the nightly
    scan already degrades a transient failure to "unknown" and re-runs tomorrow at no human
    cost, while an apply is human-triggered and expensive to repeat."""

    def __init__(self, inner: Fetch, *, attempts: int = 2, backoff: float = 2.0,
                 sleep: Callable[[float], None] = _time.sleep) -> None:
        self._inner = inner
        self._attempts = max(1, attempts)
        self._backoff = backoff
        self._sleep = sleep
        self.last_attempts = 1   # read by the deferral site, so the count reaches the report

    def __call__(self, url: str, body: bytes | None = None) -> bytes:
        from agentsec.deps_apply import classify

        for attempt in range(1, self._attempts + 1):
            self.last_attempts = attempt
            try:
                return self._inner(url, body)
            except Exception as exc:  # noqa: BLE001 — re-raised below; classification decides
                cause, _ = classify(exc)
                if cause != "transient" or attempt == self._attempts:
                    raise
                self._sleep(self._backoff)
        raise AssertionError("unreachable: the loop either returns or raises")  # pragma: no cover


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MonitoredDep:
    """One pinned dependency to track."""

    name: str
    kind: str                 # "native" | "python" | "node" | "action"
    current_version: str
    source: str               # where it's pinned (for the bump PR + the plan)
    osv_ecosystem: str = ""   # "" → release-check only (no OSV ecosystem)
    osv_name: str = ""        # the name OSV knows it by (defaults to `name`)
    repo: str = ""            # owner/repo for github-releases / actions
    pinned: bool = True       # exact pin (bump candidate) vs floor `>=` (advisory only)


@dataclass(frozen=True)
class Advisory:
    """One OSV advisory affecting a pinned version."""

    id: str                   # CVE-… or GHSA-…
    summary: str = ""
    fixed: str = ""           # first fixed version, if OSV states one
    url: str = ""


@dataclass(frozen=True)
class Waiver:
    """An expiring acceptance of one advisory against agentsec's own pins.

    `review_by` is mandatory: a missing/invalid/past date means the waiver has **lapsed**
    and no longer suppresses (the advisory re-surfaces) — no silent forever-ignores."""

    id: str                   # advisory id (CVE-… / GHSA-…)
    dep: str = ""             # optional pin name to scope the waiver to
    reason: str = ""
    review_by: str = ""       # YYYY-MM-DD

    def lapsed(self, today: date) -> bool:
        d = _parse_date(self.review_by)
        return d is None or today > d

    def covers(self, dep: MonitoredDep, adv: Advisory) -> bool:
        if self.id.strip().upper() != adv.id.strip().upper():
            return False
        return not self.dep or self.dep == dep.name


@dataclass(frozen=True)
class Release:
    """The latest available release of a dependency."""

    version: str
    published: datetime | None = None   # tz-aware UTC upload time, or None if unknown
    yanked: bool = False


@dataclass
class Candidate:
    """A dependency assessed against OSV + its release feed + the cooldown."""

    dep: MonitoredDep
    latest: Release | None = None
    advisories: list[Advisory] = field(default_factory=list)
    age_hours: float | None = None      # how old `latest` is, None if unknown
    notes: list[str] = field(default_factory=list)

    @property
    def has_cve(self) -> bool:
        return bool(self.advisories)

    @property
    def has_update(self) -> bool:
        return (
            self.latest is not None
            and not self.latest.yanked
            and _is_newer(self.latest.version, self.dep.current_version)
        )

    @property
    def past_cooldown(self) -> bool:
        """A newer release is adoptable only once it has aged past the window.
        Unknown age (no publish timestamp) → conservatively NOT past cooldown."""
        return self.age_hours is not None and self.age_hours >= REQUIRED_HOURS

    @property
    def proposable(self) -> bool:
        """Bump-able now: an exact pin with a newer, aged-out, non-yanked release —
        or any dep with a CVE (security bypasses the cooldown)."""
        if self.has_cve:
            return True
        return self.dep.pinned and self.has_update and self.past_cooldown

    @property
    def deferred(self) -> bool:
        """A newer release exists but is still inside the cooldown (and no CVE forces it)."""
        return not self.has_cve and self.dep.pinned and self.has_update and not self.past_cooldown


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------

def inventory(root: Path) -> list[MonitoredDep]:
    """Enumerate everything to monitor: pins.py tools + pyproject dev floors + Actions SHAs."""
    deps: list[MonitoredDep] = []
    deps.extend(_inventory_pins())
    deps.extend(_inventory_dev_deps(root))
    deps.extend(_inventory_actions(root))
    return deps


def _inventory_pins() -> list[MonitoredDep]:
    out: list[MonitoredDep] = []
    for p in pins.PINS:
        eco = {"PyPI": "PyPI", "npm": "npm"}.get(p.ecosystem, "")  # github-releases → no OSV by default
        # A Go-built native binary is CVE-checked in the OSV `Go` ecosystem under its own
        # module path (drift still tracks via `repo`); plus a synthetic `stdlib` dep below.
        osv_name = p.go_module or p.name
        if p.go_module:
            eco = "Go"
        out.append(MonitoredDep(
            name=p.name, kind=p.kind, current_version=p.version,
            source=f"pins.py:{p.name}", osv_ecosystem=eco, osv_name=osv_name,
            repo=p.repo, pinned=True,
        ))
        # The Go stdlib the binary was built with — its own OSV `Go` ecosystem entry, so a
        # stdlib CVE (the go-jose/stdlib class) surfaces even when the tool's release is current.
        if p.go_stdlib:
            out.append(MonitoredDep(
                name=f"{p.name} (go stdlib)", kind="native", current_version=p.go_stdlib,
                source=f"pins.py:{p.name} (built with go{p.go_stdlib})",
                osv_ecosystem="Go", osv_name="stdlib", repo="", pinned=True,
            ))
    return out


def _inventory_dev_deps(root: Path) -> list[MonitoredDep]:
    pyproject = root / "pyproject.toml"
    if not pyproject.is_file():
        return []
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError):
        return []
    extras = data.get("project", {}).get("optional-dependencies", {})
    out: list[MonitoredDep] = []
    for spec in extras.get("dev", []):
        name, floor = _split_requirement(str(spec))
        if not name:
            continue
        out.append(MonitoredDep(
            name=name, kind="python", current_version=floor,
            source="pyproject.toml:[dev]", osv_ecosystem="PyPI", osv_name=name,
            pinned=False,  # `>=` floor — advisory-only, not a bump candidate
        ))
    return out


def _inventory_actions(root: Path) -> list[MonitoredDep]:
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return []
    seen: dict[tuple[str, str], MonitoredDep] = {}
    for wf in sorted(wf_dir.glob("*.yml")) + sorted(wf_dir.glob("*.yaml")):
        try:
            text = wf.read_text(encoding="utf-8")
        except OSError:
            continue
        for line in text.splitlines():
            m = _ACTION_PIN.search(line.rstrip())
            if not m:
                continue
            repo, sha, ver = m.group(1), m.group(2), (m.group(3) or "")
            key = (repo, sha)
            if key in seen:
                continue
            seen[key] = MonitoredDep(
                name=repo, kind="action", current_version=ver or sha[:12],
                source=f"{wf.name}", osv_ecosystem="GitHub Actions", osv_name=repo,
                repo=repo, pinned=True,
            )
    return list(seen.values())


# ---------------------------------------------------------------------------
# Assessment (the single network boundary lives here)
# ---------------------------------------------------------------------------

def assess(deps: Sequence[MonitoredDep], *, now: datetime, fetch: Fetch) -> list[Candidate]:
    """Query OSV + the release feeds for every dep and apply the cooldown.

    `now` must be tz-aware. All network goes through `fetch`; any failure degrades
    to "unknown" (a note), never an exception."""
    now = _as_utc(now)
    advisories = _osv_querybatch(deps, fetch=fetch)
    out: list[Candidate] = []
    for dep in deps:
        cand = Candidate(dep=dep, advisories=advisories.get(_osv_key(dep), []))
        rel = _latest_release(dep, fetch=fetch)
        cand.latest = rel
        if rel is None:
            cand.notes.append("latest release unknown (release feed unavailable)")
        elif rel.published is not None:
            cand.age_hours = (now - rel.published).total_seconds() / 3600.0
        elif cand.has_update:
            cand.notes.append("release age unknown — deferring (no publish timestamp)")
        out.append(cand)
    return out


def _osv_key(dep: MonitoredDep) -> tuple[str, str, str]:
    return (dep.osv_ecosystem, dep.osv_name or dep.name, dep.current_version)


def _osv_querybatch(deps: Iterable[MonitoredDep], *, fetch: Fetch) -> dict[tuple[str, str, str], list[Advisory]]:
    """One batched OSV query for every dep that has an OSV ecosystem. Returns a map
    keyed by `_osv_key`. Degrades to `{}` on any failure."""
    queryable = [d for d in deps if d.osv_ecosystem and d.current_version]
    if not queryable:
        return {}
    queries = [
        {"package": {"ecosystem": d.osv_ecosystem, "name": d.osv_name or d.name},
         "version": d.current_version}
        for d in queryable
    ]
    try:
        raw = fetch(_OSV_BATCH_URL, json.dumps({"queries": queries}).encode("utf-8"))
        data = json.loads(raw)
        results = data.get("results", []) if isinstance(data, dict) else []
    except (OSError, ValueError):
        return {}
    out: dict[tuple[str, str, str], list[Advisory]] = {}
    for dep, result in zip(queryable, results, strict=False):
        if not isinstance(result, dict):
            continue
        advs: list[Advisory] = []
        for v in result.get("vulns", []) or []:
            if isinstance(v, dict) and v.get("id"):
                advs.append(_osv_detail(str(v["id"]), dep, fetch=fetch))
        if advs:
            out[_osv_key(dep)] = advs
    return out


def _osv_detail(vuln_id: str, dep: MonitoredDep, *, fetch: Fetch) -> Advisory:
    """Enrich one OSV id with its summary + first fixed version. Best-effort: on any
    failure, return a bare Advisory carrying just the id (still a usable finding)."""
    url = (f"https://nvd.nist.gov/vuln/detail/{vuln_id}" if vuln_id.startswith("CVE-")
           else f"https://github.com/advisories/{vuln_id}" if vuln_id.startswith("GHSA-") else "")
    try:
        raw = fetch(_OSV_VULN_URL + vuln_id, None)
        data = json.loads(raw)
    except (OSError, ValueError):
        return Advisory(id=vuln_id, url=url)  # keep the id even if enrichment fails
    summary = str(data.get("summary") or data.get("details") or "")[:160]
    fixed = _first_fixed(data, dep)
    return Advisory(id=vuln_id, summary=summary, fixed=fixed, url=url)


def _first_fixed(osv: dict[str, object], dep: MonitoredDep) -> str:
    """The first `fixed` version OSV lists for `dep`'s package, or ''."""
    affected = osv.get("affected")
    if not isinstance(affected, list):
        return ""
    for entry in affected:
        if not isinstance(entry, dict):
            continue
        pkg = entry.get("package")
        if isinstance(pkg, dict) and pkg.get("name") not in (dep.osv_name, dep.name):
            continue
        for rng in entry.get("ranges", []) or []:
            if not isinstance(rng, dict):
                continue
            for event in rng.get("events", []) or []:
                if isinstance(event, dict) and event.get("fixed"):
                    return str(event["fixed"])
    return ""


def _latest_release(dep: MonitoredDep, *, fetch: Fetch) -> Release | None:
    """Latest published version of `dep` from its release feed, or None if unknown."""
    try:
        if dep.kind == "python":
            return _latest_pypi(dep.osv_name or dep.name, fetch=fetch)
        if dep.kind == "node":
            return _latest_npm(dep.osv_name or dep.name, fetch=fetch)
        if dep.repo:  # native binaries + actions both track a GitHub repo
            return _latest_github(dep.repo, fetch=fetch)
    except (OSError, ValueError, AttributeError, TypeError):
        # AttributeError/TypeError: a valid-JSON-but-non-object feed response (proxy/error
        # page) makes the `_latest_*` helpers' `.get(...)` raise — degrade to "unknown".
        return None
    return None


def _latest_pypi(name: str, *, fetch: Fetch) -> Release | None:
    data = json.loads(fetch(_PYPI_URL.format(name=name), None))
    version = str(data.get("info", {}).get("version") or "")
    if not version:
        return None
    files = data.get("releases", {}).get(version, []) or []
    published = _earliest_upload(files)
    yanked = bool(files) and all(bool(f.get("yanked")) for f in files if isinstance(f, dict))
    return Release(version=version, published=published, yanked=yanked)


def _earliest_upload(files: list[object]) -> datetime | None:
    times: list[datetime] = []
    for f in files:
        if isinstance(f, dict):
            ts = _parse_iso(str(f.get("upload_time_iso_8601") or ""))
            if ts is not None:
                times.append(ts)
    return min(times) if times else None


def _latest_npm(name: str, *, fetch: Fetch) -> Release | None:
    data = json.loads(fetch(_NPM_URL.format(name=name), None))
    version = str(data.get("dist-tags", {}).get("latest") or "")
    if not version:
        return None
    published = _parse_iso(str(data.get("time", {}).get(version) or ""))
    return Release(version=version, published=published)


def _latest_github(repo: str, *, fetch: Fetch) -> Release | None:
    data = json.loads(fetch(_GH_RELEASE_URL.format(repo=repo), None))
    tag = str(data.get("tag_name") or "")
    if not tag:
        return None
    published = _parse_iso(str(data.get("published_at") or ""))
    return Release(version=tag, published=published)


# ---------------------------------------------------------------------------
# Findings + renderers
# ---------------------------------------------------------------------------

_WAIVERS_PATH = "docs/ledger/deps-monitor-exceptions.json"


def load_waivers(root: Path) -> list[Waiver]:
    """The dedicated, expiring deps-monitor waiver registry (advisory-id keyed). Total: a
    missing/malformed file yields no waivers. This is agentsec's own maintainer config —
    distinct from the per-target-repo `agentsec-exceptions.json` self-audit baseline."""
    try:
        data = json.loads((root / _WAIVERS_PATH).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    raw = data.get("waivers", []) if isinstance(data, dict) else []
    out: list[Waiver] = []
    for w in raw if isinstance(raw, list) else []:
        if isinstance(w, dict) and w.get("id"):
            out.append(Waiver(
                id=str(w["id"]), dep=str(w.get("dep", "")),
                reason=str(w.get("reason", "")), review_by=str(w.get("review_by", "")),
            ))
    return out


def apply_waivers(candidates: list[Candidate], waivers: list[Waiver], today: date) -> list[Candidate]:
    """Drop advisories covered by a **non-lapsed** waiver. A candidate whose only proposable
    reason was a now-waived CVE becomes non-proposable (and silent). Lapsed waivers do NOT
    suppress — the advisory re-surfaces. Applied at the candidate level so both the findings
    path (`evaluate`) and the apply-manifest path (`deps_apply.build_manifest`) honor it."""
    active = [w for w in waivers if not w.lapsed(today)]
    if not active:
        return candidates
    for c in candidates:
        if c.advisories:
            c.advisories = [a for a in c.advisories if not any(w.covers(c.dep, a) for w in active)]
    return candidates


def evaluate(
    root: Path, *, now: datetime, fetch: Fetch, waivers: list[Waiver] | None = None
) -> list[Finding]:
    """Inventory → assess → apply waivers → `Finding`s (security first, then aged-out updates,
    then deferred-in-cooldown as info). The fast path the CLI + workflow call."""
    candidates = assess(inventory(root), now=now, fetch=fetch)
    wv = waivers if waivers is not None else load_waivers(root)
    candidates = apply_waivers(candidates, wv, now.date())
    return to_findings(candidates)


def to_findings(candidates: Sequence[Candidate]) -> list[Finding]:
    out: list[Finding] = []
    for c in candidates:
        out.extend(_candidate_findings(c))
    return sorted(out, key=lambda f: f.sort_key())


def _candidate_findings(c: Candidate) -> list[Finding]:
    dep = c.dep
    out: list[Finding] = []
    for adv in c.advisories:
        fix = adv.fixed or (c.latest.version if c.latest and not c.latest.yanked else "")
        if dep.osv_name == "stdlib":
            # The fix isn't a version of `dep` — it's the Go toolchain the binary needs rebuilding with.
            tool = dep.name.replace(" (go stdlib)", "")
            remediation = (f"Bump {tool} to a release built with Go ≥ {fix}" if fix
                           else f"No fixed Go version published yet — track {adv.id}")
        else:
            remediation = (f"Upgrade {dep.name} to {fix}" if fix else
                           f"No fixed version published yet — track {adv.id}")
        out.append(Finding(
            check_id="deps-monitor",
            severity="high",
            title=f"Advisory for pinned {dep.name} {dep.current_version}",
            location=dep.source,
            message=f"{adv.id}: {adv.summary}".strip().rstrip(":"),
            remediation=remediation,
            url=adv.url,
            rule=adv.id,
            standards=["OWASP:A06", "OWASP-LLM:LLM03"],
        ))
    if not c.has_cve and c.proposable and c.latest is not None:
        age = f" (released {c.age_hours / 24:.0f}d ago)" if c.age_hours is not None else ""
        out.append(Finding(
            check_id="deps-monitor",
            severity="medium",
            title=f"Update available: {dep.name} {dep.current_version} → {c.latest.version}",
            location=dep.source,
            message=f"A newer {dep.name} ({c.latest.version}) is out and past the "
                    f"{REQUIRED_HOURS}h cooldown{age}.",
            remediation=f"Bump {dep.name} to {c.latest.version} in {dep.source}",
            rule="deps-monitor/update-available",
            standards=["OWASP:A06"],
        ))
    elif c.deferred and c.latest is not None:
        age = f"{c.age_hours:.0f}h old" if c.age_hours is not None else "age unknown"
        out.append(Finding(
            check_id="deps-monitor",
            severity="info",
            title=f"Deferred (in cooldown): {dep.name} → {c.latest.version}",
            location=dep.source,
            message=f"{dep.name} {c.latest.version} is {age}; holding until it passes "
                    f"the {REQUIRED_HOURS}h release-age cooldown.",
            remediation=f"Re-evaluate after the cooldown; no action yet ({dep.name}).",
            rule="deps-monitor/deferred",
            standards=["OWASP:A06"],
        ))
    return out


def _is_actionable(f: Finding) -> bool:
    """A finding that warrants opening a plan PR (CVE or an aged-out bump), as
    opposed to an informational 'deferred / in cooldown' note."""
    return f.rule != "deps-monitor/deferred" and f.severity != "info"


def actionable_count(findings: Iterable[Finding]) -> int:
    return sum(1 for f in findings if _is_actionable(f))


def build_input(findings: Sequence[Finding], *, today: str = "") -> dict[str, object]:
    """The structured actionable-set the LLM agent turns into a PR plan (mirrors the
    production fork's `remediation-input.json`). Security + update items only —
    deferred notes are excluded, since the agent should never propose them."""
    security = [_finding_dict(f) for f in findings if f.severity == "high" and f.rule != "deps-monitor/update-available"]
    updates = [_finding_dict(f) for f in findings if f.rule == "deps-monitor/update-available"]
    return {
        "generated_for": today,
        "actionable": len(security) + len(updates),
        "security_advisories": security,
        "available_updates": updates,
    }


def _finding_dict(f: Finding) -> dict[str, object]:
    # `sanitize_finding()` is the choke point for a Finding's LLM/tool-facing text - this is the
    # "structured actionable-set the LLM agent turns into a PR plan" per this module's own
    # docstring, exactly the channel PR #581's round-2 review flagged as unwired (High). `dep`
    # (the finding's `location`) is included since advisory/update-set text can originate from
    # upstream package-advisory descriptions, not only agentsec's own guard source.
    sf = sanitize_finding(f)
    return {
        "dep": sf.location, "rule": sf.rule, "severity": sf.severity,
        "title": sf.title, "detail": sf.message, "remediation": sf.remediation, "url": sf.url,
    }


def build_plan(findings: Sequence[Finding], *, today: str = "") -> str:
    """A human-readable markdown update plan (the CLI/offline renderer; the workflow's
    PR body is written by the agent from `build_input`)."""
    security = [f for f in findings if f.severity == "high" and f.rule != "deps-monitor/update-available"]
    updates = [f for f in findings if f.rule == "deps-monitor/update-available"]
    deferred = [f for f in findings if f.rule == "deps-monitor/deferred"]

    lines: list[str] = ["# Dependency update plan"]
    if today:
        lines.append(f"\n_Generated for {today}._")
    n = len(security) + len(updates)
    if n == 0:
        lines.append("\n✓ All pinned dependencies are current and advisory-free"
                     + (f" ({len(deferred)} update(s) waiting out the cooldown)." if deferred else "."))
        return "\n".join(lines) + "\n"

    if security:
        lines.append(f"\n## 🔴 Security advisories ({len(security)}) — bump regardless of cooldown\n")
        lines += [_plan_row(f) for f in security]
    if updates:
        lines.append(f"\n## 🟠 Available updates ({len(updates)}) — past the {REQUIRED_HOURS}h cooldown\n")
        lines += [_plan_row(f) for f in updates]
    if deferred:
        lines.append(f"\n## ⚪ Deferred ({len(deferred)}) — still in cooldown, no action\n")
        lines += [f"- {sanitize_finding(f).title}" for f in deferred]
    return "\n".join(lines) + "\n"


def _plan_row(f: Finding) -> str:
    f = sanitize_finding(f)
    url = f" ([advisory]({f.url}))" if f.url else ""
    return f"- **{f.location}** — {f.message}{url}\n  - → {f.remediation}"


# ---------------------------------------------------------------------------
# Small version / date helpers (no `packaging` dep — zero-runtime-dep contract)
# ---------------------------------------------------------------------------

_VER_NUM = re.compile(r"\d+")


def _version_tuple(v: str) -> tuple[int, ...]:
    """Leading numeric components of a version, e.g. 'v1.2.3-rc1' → (1, 2, 3, 1)."""
    return tuple(int(x) for x in _VER_NUM.findall(v.strip().lstrip("vV")))


def _is_newer(candidate: str, current: str) -> bool:
    """True if `candidate` is a strictly higher version than `current`. Tuple compare
    of numeric components; equal-or-lower (and unparseable) → not newer."""
    c, cur = _version_tuple(candidate), _version_tuple(current)
    if not c or not cur:
        return False
    return c > cur


def _split_requirement(spec: str) -> tuple[str, str]:
    """('pytest>=8') → ('pytest', '8'); ('types-PyYAML') → ('types-PyYAML', '')."""
    s = spec.split(";", 1)[0].strip()
    m = re.match(r"^([A-Za-z0-9._-]+)", s)
    if not m:
        return ("", "")
    name = m.group(1)
    floor = re.search(r"[><=!~]=?\s*([0-9][\w.\-]*)", s)
    return (name, floor.group(1) if floor else "")


def _parse_date(value: str) -> date | None:
    """Parse a `YYYY-MM-DD` string into a `date`, or None if missing/invalid."""
    try:
        return date.fromisoformat(value.strip())
    except (ValueError, AttributeError):
        return None


def _parse_iso(value: str) -> datetime | None:
    """Parse an ISO-8601 timestamp (handles a trailing 'Z') into tz-aware UTC, or None."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return _as_utc(dt)


def _as_utc(dt: datetime) -> datetime:
    """Coerce a datetime to tz-aware UTC (assume naive inputs are already UTC)."""
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


# ---------------------------------------------------------------------------
# Maintainer entry point — `python -m agentsec.deps_monitor`
#
# This is a tool for agentsec's OWN maintainers (it monitors agentsec's pins), NOT a
# user-facing `agentsec` subcommand — so it lives here behind `python -m`, out of the
# shipped CLI surface. The weekly workflow and a dev run it the same way.
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="python -m agentsec.deps_monitor",
        description="Maintainer tool: monitor (and, with --apply, bump) agentsec's own pinned "
                    "tools / dev-deps / Actions against OSV + the release feeds.",
    )
    p.add_argument("path", nargs="?", default=".", help="agentsec repo path (default: .)")
    p.add_argument("--date", help="Treat this YYYY-MM-DD as 'now' for the cooldown (default: today)")
    p.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p.add_argument("--out", help="Write the plan to this file instead of stdout")
    p.add_argument("--emit-input", metavar="FILE",
                   help="Write the actionable-set JSON to FILE + print the actionable count to stdout")
    p.add_argument("--emit-plan", metavar="FILE",
                   help="Write the frozen apply-contract manifest (resolved target versions) to FILE + "
                        "print the bump count to stdout — the committed plan `--apply --plan` consumes")
    p.add_argument("--offline", action="store_true", help="Inventory only — no network")
    p.add_argument("--apply", action="store_true",
                   help="v2: bump pins.py / pyproject floors + regenerate native sha256 (then run the "
                        "gauntlet + open a PR by hand — never auto-merged)")
    p.add_argument("--plan", metavar="FILE",
                   help="With --apply: apply EXACTLY this committed manifest (from --emit-plan), instead of "
                        "a live recompute — so apply matches the reviewed plan")
    p.add_argument("--scope", choices=["all", "security"], default="all",
                   help="With --apply --plan: which reviewed bumps to apply — all (default) or only the "
                        "CVE-forced (security) ones")
    p.add_argument("--only", metavar="NAMES",
                   help="With --apply --plan: apply ONLY these dep name(s) from the reviewed plan "
                        "(comma-separated) — overrides --scope")
    p.add_argument("--limit", type=int, default=None,
                   help="Max bumps in one live --apply run (default: the intake per-run cap). The committed "
                        "plan (--emit-plan) is uncapped — it's a reviewed proposal, gated by an explicit apply")
    p.add_argument("--render-apply-report", metavar="FILE",
                   help="Render an --apply-report JSON into the workflow's four artifacts "
                        "(pr-body.md, summary.md, reply.md, outputs.env) in --render-out")
    p.add_argument("--render-out", metavar="DIR", default=".",
                   help="With --render-apply-report: the directory to write the four artifacts into")
    p.add_argument("--render-bump-url", metavar="URL", default="",
                   help="With --render-apply-report: the bump PR's URL, for the plan-PR reply")
    p.add_argument("--render-gauntlet", metavar="OUTCOME", default="",
                   help="With --render-apply-report: the final gauntlet outcome, for the reply")
    p.add_argument("--assert-apply-report", metavar="FILE",
                   help="Read an --apply-report JSON and emit GitHub annotations; exit 1 if a "
                        "CVE-forced bump was deferred or an edit errored (nothing else reddens a run)")
    p.add_argument("--apply-report", metavar="FILE",
                   help="With --apply: write the structured outcome (what landed, what deferred and why, "
                        "whether a CVE-forced bump was dropped) as JSON. The workflow reads THIS instead of "
                        "grepping the log — stdout carries the status word")
    return _run(p.parse_args(argv))


def _run(args: argparse.Namespace) -> int:
    root = Path(args.path)
    today = date.fromisoformat(args.date) if args.date else date.today()
    now = datetime.combine(today, time.min, tzinfo=UTC)

    if args.offline and not args.apply:
        for d in inventory(root):
            print(f"{d.kind:8} {d.name:46} {d.current_version:14} osv={d.osv_ecosystem or '-':14} {d.source}")
        print("(--offline: inventory only — re-run without it for the CVE/update check)", file=sys.stderr)
        return 0

    if args.render_apply_report:
        from agentsec import deps_apply
        payload = json.loads(Path(args.render_apply_report).read_text(encoding="utf-8"))
        rendered = deps_apply.render_apply_report(
            payload, bump_url=args.render_bump_url, gauntlet=args.render_gauntlet)
        out_dir = Path(args.render_out)
        out_dir.mkdir(parents=True, exist_ok=True)
        for name, text in (("pr-body.md", rendered.pr_body), ("summary.md", rendered.summary),
                           ("reply.md", rendered.reply), ("outputs.env", rendered.outputs)):
            (out_dir / name).write_text(text, encoding="utf-8")
        print(f"Rendered apply report → {out_dir}", file=sys.stderr)
        return 0

    if args.assert_apply_report:
        from agentsec import deps_apply
        payload = json.loads(Path(args.assert_apply_report).read_text(encoding="utf-8"))
        code, annotations = deps_apply.assert_report(payload)
        for line in annotations:
            print(line, file=sys.stderr)
        return code

    if args.apply:
        only = {n.strip() for n in args.only.split(",") if n.strip()} if args.only else None
        return _run_apply(root, now=now, limit=args.limit, plan=args.plan, scope=args.scope,
                          only=only, report=args.apply_report, today=today.isoformat())

    if args.emit_plan:
        from agentsec import deps_apply
        # Uncapped: the committed plan is a complete reviewed proposal — the cap (bounded
        # autonomy) is enforced at the live-recompute apply, not on the human-gated plan.
        manifest = deps_apply.build_manifest(
            root, now=now, fetch=default_fetch, today=today.isoformat(), limit=_UNCAPPED)
        Path(args.emit_plan).write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"Wrote apply manifest → {args.emit_plan}", file=sys.stderr)
        print(manifest["actionable"])  # stdout = the bump count (gates the workflow)
        return 0

    findings = evaluate(root, now=now, fetch=default_fetch)  # honors deps-monitor-exceptions.json
    today_s = today.isoformat()

    if args.emit_input:
        payload = build_input(findings, today=today_s)
        Path(args.emit_input).write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"Wrote actionable-set → {args.emit_input}", file=sys.stderr)
        print(payload["actionable"])  # stdout = the count the workflow gates the agent on
        return 0

    out = (json.dumps(build_input(findings, today=today_s), indent=2, ensure_ascii=False) + "\n"
           if args.format == "json" else build_plan(findings, today=today_s))
    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")
        print(f"Wrote {args.format} plan → {args.out}", file=sys.stderr)
    else:
        print(out, end="")
    print(f"{actionable_count(findings)} actionable item(s).", file=sys.stderr)
    return 0


def _run_apply(
    root: Path, *, now: datetime, limit: int | None, plan: str | None = None,
    scope: str = "all", only: set[str] | None = None,
    report: str | None = None, today: str = "",
) -> int:
    """--apply: edit the files for each resolved bump. With `plan`, apply EXACTLY that frozen
    manifest (the reviewed plan) — filtered to `only` named deps, else by `scope` (all | security);
    otherwise recompute live. The maintainer then runs the gauntlet + opens the PR (never auto-merged)."""
    from agentsec import deps_apply

    # Retry a TRANSIENT failure once, on the apply path only. One HTTP 503 cost a whole
    # second /deps-apply run on 2026-08-12; the nightly scan needs no retry because it
    # re-runs tomorrow at no human cost.
    fetch = RetryingFetch(default_fetch, sleep=_retry_sleep)

    if plan is not None:
        plan_path = Path(plan)
        if not plan_path.is_file():
            print(f"error: --plan file not found: {plan}", file=sys.stderr)
            return 1
        try:
            manifest = json.loads(plan_path.read_text(encoding="utf-8"))
        except ValueError as exc:
            print(f"error: --plan file is not valid JSON ({exc})", file=sys.stderr)
            return 1
        bumps, deferred = deps_apply.bumps_from_manifest(manifest, fetch=fetch, scope=scope, only=only)
    else:
        candidates = assess(inventory(root), now=now, fetch=default_fetch)
        kwargs = {} if limit is None else {"limit": limit}
        bumps, deferred = deps_apply.resolve_bumps(candidates, fetch=fetch, **kwargs)
    result = deps_apply.apply_bumps(root, bumps)

    for b in result.bumped:
        print(f"bumped {b.name}: {b.old_version} → {b.new_version} ({b.reason})")
    for d in deferred + result.deferred:
        # A CVE-forced bump that failed to land by accident gets its own line shape, so it
        # cannot be read as one more routine hold in a wall of `deferred:` lines.
        if d.loud:
            advisory = f" ({d.reason})" if d.reason else ""
            print(f"SECURITY DEFERRED [{d.cause}] {d.dep}{advisory}: {d.detail}", file=sys.stderr)
        else:
            print(f"deferred [{d.cause}]: {d.line()}", file=sys.stderr)
    for warn in result.sync_warnings:
        # Applied, but a mirrored literal is now stale — the inverse of a deferral.
        print(f"warning: {warn}", file=sys.stderr)
    for err in result.errors:
        print(f"error: {err}", file=sys.stderr)
    if result.changed_files:
        print(f"\nEdited {', '.join(result.changed_files)}.", file=sys.stderr)
        print("Next: run ruff/mypy/pyright/pytest + `agentsec doctor --canary`, then open a PR "
              "(never auto-merge).", file=sys.stderr)
    else:
        print("No bumps applied — nothing proposable, or all deferred.", file=sys.stderr)

    if report is not None:
        # Same convention as --emit-plan: human line → stderr, machine scalar → stdout,
        # structured payload → the named file.
        payload = deps_apply.build_apply_report(deferred, result, today=today)
        Path(report).write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"Wrote apply report → {report}", file=sys.stderr)
        print(payload["status"])
    return 1 if result.errors else 0


if __name__ == "__main__":  # pragma: no cover
    # Re-enter through the canonical module name. Under `python -m agentsec.deps_monitor`
    # this file is loaded as `__main__`, so running the work here would build
    # `__main__.Candidate` instances while `deps_apply` imports
    # `agentsec.deps_monitor.Candidate` — divergent class identities that break
    # `isinstance()` in resolve_bumps (the classic -m double-import trap). Importing main
    # from the package name makes both refer to the same module/classes.
    from agentsec.deps_monitor import main as _main

    raise SystemExit(_main())
