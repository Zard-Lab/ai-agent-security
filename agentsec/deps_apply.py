"""v2 apply mode for the dependency monitor — turn proposable candidates into
concrete, verified edits to `pins.py` + `pyproject.toml`.

The monitor core (`deps_monitor.py`) *decides* what is actionable; this module
*executes* the mechanical bump:

  * for a **native** tool (gitleaks/trivy/hadolint) — bump the version AND
    regenerate every platform's sha256 from the **vendor's published checksums**
    (the authoritative source — never a self-computed hash of a single download),
  * for an **exact-pinned** python/node tool (schemathesis/react-doctor) — bump the
    version string,
  * for a **dev-dep floor** with a CVE — raise the `pyproject.toml` `[dev]` floor to
    the fixed version.

Bounded by `intake.cap_proposals` (G4): at most N bumps leave one run, most severe
first, the rest deferred as `capped` — logged, never silently dropped, and *loud* when
one of them was CVE-forced (a cap that quietly eats a security bump is the same failure
as a network blip that does, which is the one this module exists to abolish). GitHub Actions SHA pins
are **not** mechanically bumped here (resolving a tag→SHA + reading the changelog is
the agent's job) — they are reported as deferred so nothing is silently skipped.

Deterministic + hermetic: all network goes through the injected `fetch` (the same
boundary as `deps_monitor`); `apply_bumps` is pure text-editing with no network. The
caller (CLI / workflow) runs the full gauntlet after editing and opens the PR —
this module never commits, pushes, or auto-merges.
"""
from __future__ import annotations

import json
import re
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Literal, cast

from agentsec import pins
from agentsec.deps_monitor import Candidate, Fetch, _version_tuple
from agentsec.intake import MAX_PROPOSALS_PER_RUN, cap_proposals
from agentsec.textio import read_text_preserve, write_text_preserve

# The exact archive filename a native tool names per platform (mirrors tooling.py's URL
# construction) — the only name a regenerated sha256 is ever taken from.
_ARCHIVE_TEMPLATE = {
    "gitleaks": "gitleaks_{v}_{slug}.tar.gz",
    "trivy": "trivy_{v}_{slug}.tar.gz",
    "hadolint": "hadolint-{slug}",  # raw binary (no archive)
    "actionlint": "actionlint_{v}_{slug}.tar.gz",
}

# Tolerant platform aliases — only used to *diagnose* a vendor renaming its asset slugs
# across releases (e.g. hadolint 2.12 `Darwin-x86_64` → 2.14 `macos-x86_64`). A UNIQUE
# match names the renamed file in a `ResolveDefect`; it never supplies the sha (#591).
_OS_ALIASES = {"linux": ("linux",), "macos": ("macos", "darwin", "osx"), "windows": ("windows", "win")}
_ARCH_ALIASES = {"x86_64": ("x86_64", "amd64", "x64", "64bit"), "arm64": ("arm64", "aarch64")}

_GH_API_RELEASE = "https://api.github.com/repos/{repo}/releases/tags/v{version}"
_GH_DOWNLOAD = "https://github.com/{repo}/releases/download/v{version}"

# The platform the rendered CI workflows download on (backs the component.json sha256).
_CI_PLATFORM: tuple[str, str] = ("linux", "x86_64")

_SHA256 = re.compile(r"\b[0-9a-f]{64}\b")


class ResolveDefect(ValueError):
    """The vendor published something this resolver cannot read.

    Permanent by construction — retrying cannot help, because nothing about the request was
    wrong. Raised where we ourselves detect unusable vendor data (a checksum manifest that
    does not cover every pinned platform, a renamed asset slug, a "sha256" that is not 64 hex
    chars). The #591 class: hadolint moved from per-asset `.sha256` sidecars to a single
    `checksums.sha256` manifest, so every night it deferred with a message identical in shape
    to a passing network blip.

    Subclasses `ValueError` deliberately, so every existing `except (OSError, ValueError,
    KeyError)` keeps catching it and no call site changes behaviour."""


# What a caller should DO about a deferral. The taxonomy exists to answer exactly one
# question — re-run, or file an issue? — so two causes that answer it identically would be
# one cause.
#
# `capped` earns its place by that same rule: it answers "re-run", but NOT the same re-run
# `transient` means. A transient blip clears on the next attempt; an over-cap drop is a
# deterministic queue position (`cap_proposals` sorts by severity then id), so re-running now
# re-selects the identical top-N and defers it again. It clears only once the applied batch
# merges. It is emphatically NOT `policy`: a policy hold is a decision no re-run can change,
# while an over-cap bump is mechanically resolvable by this very code path and simply lost a
# size-limited queue. Collapsing the two made a CVE-forced bump dropped by the G4 cap silent
# and green — the 2026-08-12 incident shape, reached through a different door.
DeferCause = Literal["policy", "capped", "transient", "defect"]

# HTTP statuses worth a second attempt. Anything else (404/403/410/…) means the request was
# wrong, not unlucky, and recurs on every run.
_TRANSIENT_HTTP = frozenset({408, 425, 429, 500, 502, 503, 504})


@dataclass(frozen=True)
class Deferral:
    """One bump that did NOT get applied, and why — the unit that replaces a bare string.

    A flat `list[str]` had nowhere to record a cause, so a transient network blip and a
    permanent resolver defect produced byte-identical prefixes and an identically green run
    (the 2026-08-12 incident: a CVE-forced trivy bump dropped out of a `success`).

    `severity` is "high" iff the bump was CVE-forced — the same predicate `scope=security`
    uses. It is tracked separately from `cause` because they answer different questions:
    `cause` says whether to re-run or file, `severity` says how much it matters that this
    did not land."""

    dep: str                     # "" for a manifest-level problem that names no dep
    cause: DeferCause
    detail: str                  # the sentence, WITHOUT a "<dep>: " prefix
    severity: str = "medium"     # "high" iff CVE-forced
    reason: str = ""             # advisory id, when the manifest carried one
    attempts: int = 1            # network attempts made before giving up

    @property
    def loud(self) -> bool:
        """True when a human must look NOW: a CVE-forced bump that failed to land by accident.

        Excludes `policy`, and ONLY `policy`. A policy hold is a decision already made, not an
        accident — and the Go-stdlib holds are CVE-forced by definition and defer on EVERY
        run (three of them today: gitleaks, trivy, actionlint). Treating those as loud would
        paint every run red within a day, and a permanently-red signal is exactly as useless
        as the permanently-green one this exists to fix.

        `capped` is deliberately NOT excluded, though it reads like a policy decision. The cap
        is policy; *which* bump it drops is an accident of that night's CVE volume. A dropped
        CVE-forced bump is the exact thing this property exists to shout about, and it cannot
        go permanently red the way the Go-stdlib holds can: it needs more CVE-forced bumps in
        one run than the limit, and it clears itself as soon as the applied batch merges."""
        return self.severity == "high" and self.cause != "policy"

    def as_dict(self) -> dict[str, object]:
        return {
            "dep": self.dep, "cause": self.cause, "detail": self.detail,
            "severity": self.severity, "reason": self.reason, "attempts": self.attempts,
        }

    def line(self) -> str:
        """One rendered line — `<dep>: <detail>`, or just the detail when no dep is named."""
        return f"{self.dep}: {self.detail}" if self.dep else self.detail


def classify(exc: BaseException) -> tuple[DeferCause, str]:
    """`(cause, detail-suffix)` for an exception raised while resolving a bump.

    Order matters: `HTTPError` and `TimeoutError` both subclass `OSError`, so they must be
    tested before the bare-`OSError` rung or they can never be reached.

    `HTTPError` carries a structured `.code` that the old message-only formatting threw away —
    interpolating `{exc}` left "503" as a substring of prose and nothing could act on it.

    The honest residue: `JSONDecodeError` (a proxy error page where JSON was expected) cannot
    be split transient-vs-permanent by type or message. It is classified transient, and that
    ambiguity is *defused rather than solved* — in this design cause drives retry-and-wording
    and never visibility, so a misclassification costs one wasted retry or one spurious "file
    an issue" nag. It can never make a deferral disappear."""
    if isinstance(exc, ResolveDefect):
        return "defect", str(exc)
    if isinstance(exc, urllib.error.HTTPError):
        cause: DeferCause = "transient" if exc.code in _TRANSIENT_HTTP else "defect"
        return cause, f"HTTP {exc.code} {exc.reason}"
    if isinstance(exc, urllib.error.URLError):
        return "transient", f"network error ({exc.reason})"
    if isinstance(exc, TimeoutError):
        return "transient", f"timed out ({exc})"
    if isinstance(exc, json.JSONDecodeError):
        return "transient", f"vendor returned unparseable JSON ({exc})"
    if isinstance(exc, OSError):
        return "transient", str(exc)
    if isinstance(exc, KeyError):
        return "defect", f"unknown pin {exc}"
    return "defect", str(exc)


@dataclass
class Bump:
    """One resolved, ready-to-apply version bump."""

    name: str
    kind: str                              # native | python | node
    old_version: str
    new_version: str
    source: str                            # pins.py:<name> | pyproject.toml:[dev]
    reason: str                            # "CVE-…" or "update"
    severity: str = "medium"               # "high" iff CVE-forced (mirrors the manifest entry)
    sha_by_plat: dict[tuple[str, str], str] = field(default_factory=dict)  # native only


@dataclass
class ApplyResult:
    bumped: list[Bump] = field(default_factory=list)
    changed_files: list[str] = field(default_factory=list)
    deferred: list[Deferral] = field(default_factory=list)
    # A bump that WAS applied but left a mirrored literal stale (a component.json default, a
    # workflow env). The semantic inverse of a deferral, and it used to ride the same channel.
    # Not promoted to `errors`: that flips the exit code, and under the workflow's `set -e`
    # the job would die before the PR is opened, destroying the partially-applied work.
    sync_warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Resolve candidates → bumps (networked, via the injected fetch)
# ---------------------------------------------------------------------------

def _attempts_of(fetch: Fetch) -> int:
    """How many network attempts the fetch made before giving up (1 for a plain fetch).

    Read off the wrapper rather than threaded through every signature: only a retrying fetch
    knows, and only the deferral message cares. The count is what turns "something went wrong"
    into "still broken after two tries"."""
    return max(1, int(getattr(fetch, "last_attempts", 1)))


def _sev(c: Candidate) -> str:
    """"high" iff CVE-forced — the same predicate `_manifest_entry` and `scope=security` use."""
    return "high" if c.has_cve else "medium"


def _select_mechanizable(
    candidates: list[Candidate], limit: int
) -> tuple[list[Candidate], list[Deferral]]:
    """The proposable, mechanically-bumpable candidates (pins.py / pyproject only), capped
    by the G4 per-run limit. Actions + unknown sources are deferred. Returns
    ``(kept_candidates, deferrals)``. No network — pure selection."""
    deferred: list[Deferral] = []
    items: list[dict[str, object]] = []
    for c in candidates:
        if not c.proposable:
            continue
        if c.dep.kind == "action":
            deferred.append(Deferral(
                c.dep.name, "policy", "Actions SHA pin — bump left to the agent (tag→SHA + changelog)",
                severity=_sev(c), reason=_reason(c),
            ))
            continue
        if c.dep.osv_name == "stdlib":
            # A Go-stdlib CVE isn't fixed by bumping a pin — the tool must be rebuilt with a
            # newer Go. Surface it (the finding carries the advice) but never auto-bump it.
            # `policy`, so `Deferral.loud` stays False even though it is CVE-forced: three of
            # these defer on every single run, and a permanently-loud signal is no signal.
            deferred.append(Deferral(
                c.dep.name, "policy", "Go stdlib CVE — bump the tool to a release built with a patched Go",
                severity=_sev(c), reason=_reason(c),
            ))
            continue
        if not (c.dep.source.startswith("pins.py:") or c.dep.source.startswith("pyproject.toml")):
            deferred.append(Deferral(
                c.dep.name, "defect", f"unrecognized pin source {c.dep.source!r} — skipped",
                severity=_sev(c), reason=_reason(c),
            ))
            continue
        items.append({"id": c.dep.name, "severity": _sev(c), "_cand": c, "_reason": _reason(c)})
    kept, capped = cap_proposals(items, limit)
    # `capped`, NOT `policy`. The cap is a policy; the specific bump it drops is an accident of
    # this night's volume, and that bump would apply cleanly given a slot. Filing it under
    # `policy` made a CVE-forced drop invisible — no SECURITY bullet, no label, exit 0.
    deferred += [
        Deferral(
            str(it["id"]), "capped", f"deferred — over the per-run cap of {limit}",
            severity=str(it.get("severity", "medium")), reason=str(it.get("_reason", "")),
        )
        for it in capped
    ]
    # our own dict; cast, don't isinstance (the -m double-import note in deps_monitor)
    return [cast(Candidate, it["_cand"]) for it in kept], deferred


def resolve_bumps(
    candidates: list[Candidate], *, fetch: Fetch, limit: int = MAX_PROPOSALS_PER_RUN
) -> tuple[list[Bump], list[Deferral]]:
    """Live path: select mechanizable candidates, then resolve each to a `Bump` (fetching
    native sha256 from the vendor checksums). Returns ``(bumps, deferrals)``."""
    kept, deferred = _select_mechanizable(candidates, limit)
    bumps: list[Bump] = []
    for cand in kept:
        try:
            bumps.append(_resolve_one(cand, fetch=fetch))
        # `KeyError` included to match `bumps_from_manifest`'s filter exactly: both feed the same
        # `classify()`, which has an "unknown pin" rung, and `pins.pin()` raises `KeyError` for a
        # name it does not know. Unreachable today (every native `MonitoredDep` is built from
        # `pins.PINS`), but the failure mode if it ever fires is the worst available: the crash
        # lands BEFORE `--apply-report` is written, so `hashFiles()` is false, the render + assert
        # steps both skip, and none of this module's signalling engages.
        except (OSError, ValueError, KeyError) as exc:
            cause, detail = classify(exc)
            deferred.append(Deferral(
                cand.dep.name, cause, f"could not resolve bump ({detail})",
                severity=_sev(cand), reason=_reason(cand), attempts=_attempts_of(fetch),
            ))
    return bumps, deferred


def build_manifest(
    root: Path, *, now: datetime, fetch: Fetch, today: str = "", limit: int = MAX_PROPOSALS_PER_RUN
) -> dict[str, object]:
    """The frozen apply contract `deps-monitor` commits next to the prose plan. Carries the
    *resolved target version* per bump (no native sha — apply re-fetches it for that pinned
    version) plus the human fields the agent's prose needs. `--apply --plan` reads this back
    so the apply is exactly the reviewed set, not a live recompute."""
    from agentsec import deps_monitor as dm

    candidates = dm.assess(dm.inventory(root), now=now, fetch=fetch)
    # Honor the same expiring waivers the findings path does, so the workflow's `actionable`
    # gate count excludes accepted advisories (no PR / no LLM spend on a fully-waived night).
    candidates = dm.apply_waivers(candidates, dm.load_waivers(root), now.date())
    kept, deferred = _select_mechanizable(candidates, limit)
    bumps = [_manifest_entry(c) for c in kept]
    # `deferred` carries objects, not strings, since the cause is the point (the plan-writing
    # agent can now say "known defect, tracked as #591" instead of re-deriving it from prose).
    return {"generated_for": today, "actionable": len(bumps), "bumps": bumps,
            "deferred": [d.as_dict() for d in deferred]}


def _manifest_entry(c: Candidate) -> dict[str, object]:
    return {
        "name": c.dep.name,
        "kind": c.dep.kind,
        "source": c.dep.source,
        "current_version": c.dep.current_version,
        "target_version": _target_version(c),
        "reason": _reason(c),
        "severity": "high" if c.has_cve else "medium",
        "advisories": [{"id": a.id, "fixed": a.fixed, "url": a.url} for a in c.advisories],
        "latest": c.latest.version if c.latest is not None else "",
    }


def bumps_from_manifest(
    manifest: dict[str, object], *, fetch: Fetch, scope: str = "all", only: set[str] | None = None
) -> tuple[list[Bump], list[Deferral]]:
    """Rebuild bumps from a committed plan manifest (no live OSV/release re-query). Target
    versions come straight from the frozen contract; natives still fetch+verify the vendor
    sha256 for that pinned version.

    Selection (returns ``(bumps, deferred)``):
    - `only` (a set of dep names) — apply ONLY those named deps from the plan (overrides `scope`);
      a requested name absent from the plan is reported.
    - else `scope` — ``"all"`` (every bump) or ``"security"`` (only the CVE-forced, severity-high bumps)."""
    bumps: list[Bump] = []
    deferred: list[Deferral] = []
    if not isinstance(manifest, dict):
        return [], [Deferral("", "defect", "plan manifest is not a JSON object — nothing to apply")]
    entries = manifest.get("bumps", [])
    if not isinstance(entries, list):
        return [], [Deferral("", "defect", "manifest has no `bumps` list — nothing to apply")]
    if only is not None and not only:
        # An empty-but-not-None selection (`--only ","`) used to skip every entry through the
        # `e["name"] not in only` branch and record NOTHING: zero bumps, zero deferrals, exit 0,
        # "nothing to apply". A textbook failure that presents as success.
        return [], [Deferral("", "defect", "an empty --only selection matched no dependency")]
    if only:
        present = {str(e.get("name")) for e in entries if isinstance(e, dict)}
        for name in sorted(only - present):
            deferred.append(Deferral(name, "defect", "not in the reviewed plan — nothing to apply"))
    for e in entries:
        if not isinstance(e, dict) or not e.get("name") or not e.get("target_version"):
            deferred.append(Deferral("", "defect", f"skipped malformed manifest entry: {e!r}"[:160]))
            continue
        severity = str(e.get("severity", "medium"))
        reason = str(e.get("reason", "update"))
        if only is not None:
            if e["name"] not in only:
                continue  # a named-dep run silently skips the rest (it's the explicit selection)
        elif scope == "security" and severity != "high":
            deferred.append(Deferral(
                str(e["name"]), "policy", "held (scope=security — not a CVE-forced bump)",
                severity=severity, reason=reason,
            ))
            continue
        if e.get("kind") == "action":
            deferred.append(Deferral(
                str(e["name"]), "policy", "Actions SHA pin — not mechanically applied",
                severity=severity, reason=reason,
            ))
            continue
        bump = Bump(
            name=str(e["name"]), kind=str(e.get("kind", "")),
            old_version=str(e.get("current_version", "")), new_version=str(e["target_version"]),
            source=str(e.get("source", "")), reason=reason, severity=severity,
        )
        if bump.kind == "native":
            try:
                bump.sha_by_plat = _native_shas(bump.name, bump.new_version, fetch=fetch)
                if set(bump.sha_by_plat) != set(pins.pin(bump.name).assets):
                    missing = set(pins.pin(bump.name).assets) - set(bump.sha_by_plat)
                    raise ResolveDefect(f"vendor checksums missing {sorted(missing)}")
            except (OSError, ValueError, KeyError) as exc:
                cause, detail = classify(exc)
                deferred.append(Deferral(
                    bump.name, cause, f"could not resolve native sha256 ({detail})",
                    severity=severity, reason=reason, attempts=_attempts_of(fetch),
                ))
                continue
        bumps.append(bump)
    return bumps, deferred


def _resolve_one(c: Candidate, *, fetch: Fetch) -> Bump:
    dep = c.dep
    new_version = _target_version(c)
    bump = Bump(
        name=dep.name, kind=dep.kind, old_version=dep.current_version,
        new_version=new_version, source=dep.source, reason=_reason(c),
    )
    if dep.kind == "native":
        bump.sha_by_plat = _native_shas(dep.name, new_version, fetch=fetch)
        if set(bump.sha_by_plat) != set(pins.pin(dep.name).assets):
            missing = set(pins.pin(dep.name).assets) - set(bump.sha_by_plat)
            raise ResolveDefect(
                f"vendor checksums did not cover every pinned platform (missing {sorted(missing)})")
    return bump


def _reason(c: Candidate) -> str:
    """A short label for the bump: the advisory id (with a count when several), or 'update'."""
    if not c.has_cve:
        return "update"
    extra = f" (+{len(c.advisories) - 1} more)" if len(c.advisories) > 1 else ""
    return f"{c.advisories[0].id}{extra}"


def _target_version(c: Candidate) -> str:
    """The version to bump to. For a CVE, the **highest** fixed version across ALL of the
    dep's advisories (a single advisory's `fixed` may not clear the others — e.g. copier's
    six GHSAs need 9.14.1, not the first one's 9.9.1). Else the latest release. Any leading
    'v' is stripped to match how `pins.py` stores versions."""
    if c.has_cve:
        fixes = [a.fixed for a in c.advisories if a.fixed]
        if fixes:
            return max(fixes, key=_version_tuple).lstrip("vV")
    if c.latest is not None:
        return c.latest.version.lstrip("vV")
    raise ValueError("no target version (no fixed version and no latest release)")


def _native_shas(name: str, version: str, *, fetch: Fetch) -> dict[tuple[str, str], str]:
    """Regenerate every pinned platform's sha256 for `version` from the vendor's
    published checksums (authoritative — never a self-computed hash).

    Discovers the release's *actual* asset names from the GitHub releases API. A platform
    resolves only by its exact pinned archive name; a missing or ambiguous match is left out
    (the caller defers — it never guesses a checksum). On a miss, a UNIQUE tolerant platform
    match is still tried, but only to diagnose a vendor slug rename (hadolint 2.12
    `Darwin-x86_64` → 2.14 `macos-x86_64`). The renamed file's sha must not be pinned under
    the old slug, because `tooling.py` builds the download URL from the slug: that is how the
    2.14.0 bump shipped a macOS URL that 404s (#591). A rename raises `ResolveDefect` naming
    every slug to change by hand, in `pins.py` and in any workflow URL that mirrors it."""
    repo = pins.pin(name).repo
    assets = _release_assets(repo, version, fetch=fetch)
    sha_by_file = _build_sha_map(repo, version, assets, fetch=fetch)

    out: dict[tuple[str, str], str] = {}
    renamed: list[str] = []
    for plat, (slug, _old) in pins.pin(name).assets.items():
        expected = _ARCHIVE_TEMPLATE.get(name, "").format(v=version, slug=slug)
        found = _file_for_platform(expected, plat, sha_by_file)
        if found is None:
            continue
        if found.rsplit("/", 1)[-1] != expected:  # a path-prefixed line for the SAME file is fine
            renamed.append(f"{slug!r} → {found!r}")
            continue
        out[plat] = _checked_sha(sha_by_file[found], name, slug)
    if renamed:
        raise ResolveDefect(
            f"vendor renamed asset slug(s) on v{version} (pinned slug → published file: "
            f"{', '.join(renamed)}); fix the slug in pins.py and any workflow URL that mirrors it")
    return out


def _release_assets(repo: str, version: str, *, fetch: Fetch) -> list[str]:
    """The asset filenames published on the `v{version}` GitHub release."""
    data = json.loads(fetch(_GH_API_RELEASE.format(repo=repo, version=version), None))
    return [str(a.get("name", "")) for a in data.get("assets", []) if isinstance(a, dict)]


def _build_sha_map(repo: str, version: str, assets: list[str], *, fetch: Fetch) -> dict[str, str]:
    """Map each binary filename → its vendor sha256, reading whichever checksum scheme the
    release ships: one coreutils manifest, ``*_checksums.txt`` (gitleaks/trivy/actionlint) or
    ``checksums.sha256`` (hadolint >= 2.15), and/or per-asset ``<binary>.sha256`` sidecars
    (hadolint <= 2.14).

    A manifest is a ``checksum``-named file with a suffix on an ALLOWLIST. Accepting any
    suffix would also fetch trivy's ``*_checksums.txt.sigstore.json`` and a binary cosign
    ``*.sig``. The manifest test runs first because ``checksums.sha256`` also carries a
    sidecar's suffix: read as a sidecar, it became one bogus ``checksums`` entry holding the
    first line's sha, and no platform resolved (#591)."""
    base = _GH_DOWNLOAD.format(repo=repo, version=version)
    out: dict[str, str] = {}
    for asset in assets:
        low = asset.lower()
        if "checksum" in low and low.endswith((".txt", ".sha256")):
            for line in fetch(f"{base}/{asset}", None).decode().splitlines():
                parts = line.split()
                if len(parts) >= 2 and _SHA256.fullmatch(parts[0]):
                    out[parts[1].lstrip("*")] = parts[0]  # `<sha>  <filename>` (coreutils format)
        elif asset.endswith(".sha256"):
            sha = fetch(f"{base}/{asset}", None).decode().split()[0].strip()
            out[asset[: -len(".sha256")]] = sha
    return out


def _file_for_platform(
    expected: str, plat: tuple[str, str], sha_by_file: dict[str, str]
) -> str | None:
    """The checksum entry for one platform: the exact archive name if listed, else the
    UNIQUE same-extension entry naming this platform, else None (missing or ambiguous)."""
    if expected in sha_by_file:
        return expected                                    # precise (stable slug)
    ext = _ext(expected)
    cands = [k for k in sha_by_file if _ext(k) == ext and _plat_matches(k, plat)]
    return cands[0] if len(cands) == 1 else None


def _ext(filename: str) -> str:
    """The artifact's extension shape: '.tar.gz', '.exe', or '' (a raw binary)."""
    base = filename.rsplit("/", 1)[-1]
    if base.endswith(".tar.gz"):
        return ".tar.gz"
    return ("." + base.rsplit(".", 1)[1]) if "." in base else ""


def _plat_matches(filename: str, plat: tuple[str, str]) -> bool:
    os_key, arch_key = plat
    low = filename.lower()
    os_ok = any(a in low for a in _OS_ALIASES.get(os_key, (os_key,)))
    arch_ok = any(a in low for a in _ARCH_ALIASES.get(arch_key, (arch_key,)))
    return os_ok and arch_ok


def _checked_sha(sha: str, name: str, slug: str) -> str:
    if not _SHA256.fullmatch(sha):
        raise ResolveDefect(f"vendor checksum for {name} {slug} is not a 64-hex sha256: {sha!r}")
    return sha


# ---------------------------------------------------------------------------
# The apply report — the machine-readable outcome of one run
# ---------------------------------------------------------------------------

# Bumped when the payload shape changes in a way a consumer must notice. The plan manifest
# never versioned itself and that is a small ongoing tax; this one does from the start.
APPLY_REPORT_SCHEMA = 1


def build_apply_report(
    deferred: list[Deferral], result: ApplyResult, *, today: str = ""
) -> dict[str, object]:
    """The structured outcome of one apply run: what landed, what did not, and why.

    This exists so the workflow can act on DATA instead of grepping prose out of a log. Before
    it, the only record that a run had dropped a security bump was one line inside a fenced
    block in the PR body, under a heading that said "Applied bumps:".

    `status` is deliberately not derived from the exit code (rule 3 — assert the artifact):
      clean   — something landed and nothing went wrong beyond routine policy holds
      partial — something landed AND something non-policy did not (an over-cap `capped` drop
                counts: the run really did apply only part of what was actionable)
      empty   — nothing landed
      error   — a file edit failed"""
    all_deferred = deferred + result.deferred
    unexpected = [d for d in all_deferred if d.cause != "policy"]
    loud = [d for d in all_deferred if d.loud]

    if result.errors:
        status = "error"
    elif not result.bumped:
        status = "empty"
    elif unexpected or result.sync_warnings:
        status = "partial"
    else:
        status = "clean"

    counts = {
        "applied": len(result.bumped),
        "deferred": len(all_deferred),
        "policy": sum(1 for d in all_deferred if d.cause == "policy"),
        "capped": sum(1 for d in all_deferred if d.cause == "capped"),
        "transient": sum(1 for d in all_deferred if d.cause == "transient"),
        "defect": sum(1 for d in all_deferred if d.cause == "defect"),
        "security_deferred": len(loud),
        "sync_warnings": len(result.sync_warnings),
        "errors": len(result.errors),
    }
    return {
        "schema": APPLY_REPORT_SCHEMA,
        "generated_for": today,
        "status": status,
        "applied": [
            {"name": b.name, "kind": b.kind, "old_version": b.old_version,
             "new_version": b.new_version, "reason": b.reason, "severity": b.severity}
            for b in result.bumped
        ],
        "deferred": [d.as_dict() for d in all_deferred],
        "sync_warnings": list(result.sync_warnings),
        "errors": list(result.errors),
        "changed_files": list(result.changed_files),
        "counts": counts,
        "security_deferred": [d.dep for d in loud],
        "needs_attention": bool(loud or counts["defect"] or result.errors or result.sync_warnings),
        "headline": _headline(result.bumped, all_deferred, loud),
    }


def _headline(bumped: list[Bump], deferred: list[Deferral], loud: list[Deferral]) -> str:
    """One sentence the workflow can echo without composing prose of its own."""
    head = f"Applied {len(bumped)} bump(s)" if bumped else "Applied nothing"
    if not deferred:
        return head + "."
    tail = f"; {len(deferred)} deferred"
    if loud:
        who = ", ".join(f"{d.dep} ({d.reason})" if d.reason else d.dep for d in loud)
        tail += f" — {len(loud)} SECURITY ({who})"
    return head + tail + "."


# ---------------------------------------------------------------------------
# Rendering the report — every human-facing string, in Python where it is tested
# ---------------------------------------------------------------------------

# What a cause means for the reader, appended to its bullet so the line itself says what to do.
_CAUSE_ADVICE = {
    "transient": "re-run `/deps-apply all`",
    # Deliberately NOT transient's "re-run now". `cap_proposals` is deterministic (severity,
    # then id), so an immediate re-run re-selects the same top-N and defers this again — advice
    # that sends a maintainer round a loop that cannot close.
    "capped": "re-run once this bump PR merges — it moves up the queue then",
    "defect": "this recurs on every run until it is fixed — file an issue",
    "policy": "",
}


@dataclass(frozen=True)
class RenderedReport:
    """Every string the workflow prints, composed here rather than in ungated shell.

    `actionlint` runs with `-shellcheck=` off, so shell inside a `run:` block is checked by
    nothing; Python is checked by mypy --strict, pyright and pytest. So the YAML gets a `cat`
    and this module gets the logic."""

    pr_body: str      # the bump-PR body
    summary: str      # the $GITHUB_STEP_SUMMARY block
    reply: str        # the comment posted back on the plan PR
    outputs: str      # key=value lines for $GITHUB_OUTPUT


def _deferral_bullet(d: dict[str, object]) -> str:
    # Named `why`, not the obvious alternative: a local variable of that other name, assigned
    # from a str() call, is read by our own `error-info-leak/exception-str-in-detail` rule as an
    # HTTPException keyword argument, because the rule anchors on the name and never checks which
    # call it sits in (issue #590). Renaming is cheaper than a permanent self-reference baseline
    # entry, and this note is the evidence that it was a false positive rather than a suppression.
    # (Worded around the literal pattern on purpose — the rule does not strip comments either,
    # so spelling it out here re-fires the same finding on the explanation.)
    dep = str(d.get("dep", "")) or "(plan)"
    cause = str(d.get("cause", ""))
    why = str(d.get("detail", ""))
    attempts = int(cast(int, d.get("attempts", 1)) or 1)
    tried = f" after {attempts} attempts" if attempts > 1 else ""
    advice = _CAUSE_ADVICE.get(cause, "")
    tail = f" — {advice}." if advice else ""
    if str(d.get("severity", "")) == "high" and cause != "policy":
        adv = f" ({d['reason']})" if d.get("reason") else ""
        return f"- **`{dep}` — SECURITY{adv}** · *{cause}* · {why}{tried}{tail}"
    return f"- `{dep}` · *{cause}* · {why}{tried}{tail}"


def render_apply_report(
    report: dict[str, object], *, bump_url: str = "", gauntlet: str = ""
) -> RenderedReport:
    """Turn an apply report into the four strings the workflow needs. Pure — no I/O, no clock.

    Two rules the old body broke, both encoded here rather than in prose:

    * **Headings are a function of the data.** The 2026-08-12 body said "Applied bumps:" above a
      block whose content was mostly `deferred:` lines. When nothing applied there is now no
      "Applied" heading at all.
    * **Bullets, not a fenced log dump.** A fence reads as opaque spew and hides its own contents;
      it is also why the same text could not be reused as a step summary. Bullets render in both.
    """
    counts = cast(dict[str, int], report.get("counts", {}))
    applied = cast(list[dict[str, object]], report.get("applied", []))
    deferred = cast(list[dict[str, object]], report.get("deferred", []))
    warnings = cast(list[str], report.get("sync_warnings", []))
    errors = cast(list[str], report.get("errors", []))
    loud_names = cast(list[str], report.get("security_deferred", []))
    headline = str(report.get("headline", ""))
    status = str(report.get("status", ""))

    policy = [d for d in deferred if d.get("cause") == "policy"]
    unexpected = [d for d in deferred if d.get("cause") != "policy"]

    lines: list[str] = []
    if loud_names:
        lines += [f"> ⚠️ **A CVE-forced bump did not land: {', '.join(loud_names)}.** "
                  "The advisory is still open on this repo until it does.", ""]
    if applied:
        lines.append(f"### Applied ({len(applied)})")
        lines += [f"- `{a['name']}` {a['old_version']} → {a['new_version']} — {a['reason']}"
                  for a in applied]
    else:
        lines.append("### Nothing applied")
    if unexpected:
        n_sec = len(loud_names)
        label = f"{n_sec} SECURITY, {len(unexpected) - n_sec} other" if n_sec else f"{len(unexpected)}"
        lines += ["", f"### ⚠️ Deferred — {label}"]
        lines += [_deferral_bullet(d) for d in unexpected]
    if policy:
        lines += ["", f"### Held by policy ({len(policy)})",
                  "<details><summary>expected, no action</summary>", ""]
        lines += [_deferral_bullet(d) for d in policy]
        lines += ["", "</details>"]
    if warnings:
        lines += ["", "### ⚠️ Applied, but a mirrored literal is now stale"]
        lines += [f"- {w}" for w in warnings]
    if errors:
        lines += ["", "### ❌ Errors"] + [f"- {e}" for e in errors]

    body = "\n".join(lines) + "\n"
    summary = f"## deps-apply — {headline}\n\n{body}"
    reply_head = f"✅ Applied this plan → bump PR: {bump_url}" if bump_url else "ℹ️ Nothing to apply."
    if loud_names:
        reply_head = (f"⚠️ **Applied with a SECURITY bump deferred ({', '.join(loud_names)})** → "
                      f"bump PR: {bump_url}" if bump_url
                      else f"⚠️ **Nothing applied, and a SECURITY bump deferred: {', '.join(loud_names)}.**")
    reply = (f"{reply_head}\n\n{headline}\n\n{body}\n"
             f"Gauntlet: `{gauntlet or 'unknown'}` (ruff · mypy · pyright · pytest · "
             "`doctor --canary`). Review + merge the bump PR — **never auto-merged.**\n")

    outputs = "".join(f"{k}={v}\n" for k, v in {
        "status": status,
        "applied_count": counts.get("applied", 0),
        "deferred_count": counts.get("deferred", 0),
        "defect_count": counts.get("defect", 0),
        "security_deferred": "true" if loud_names else "false",
        "needs_attention": "true" if report.get("needs_attention") else "false",
        "headline": headline,
    }.items())
    return RenderedReport(pr_body=body, summary=summary, reply=reply, outputs=outputs)


def assert_report(report: dict[str, object]) -> tuple[int, list[str]]:
    """`(exit_code, annotation lines)` — the gate that decides whether the run goes red.

    Red **only** for a CVE-forced bump that failed to land by accident, or a hard error. A
    defect on a routine update is a `::warning::` and a transient one a `::notice::`: failing
    on those trains people to ignore red, which is the same disease as a green run that hides a
    drop, just inverted."""
    loud = cast(list[str], report.get("security_deferred", []))
    counts = cast(dict[str, int], report.get("counts", {}))
    errors = cast(list[str], report.get("errors", []))
    # The advice has to follow the cause, not the severity. Telling someone to re-run now when
    # the cap dropped their bump sends them round a loop that cannot close: `cap_proposals` is
    # deterministic, so the same top-N wins again until this batch merges.
    cause_by_dep = {str(d.get("dep", "")): str(d.get("cause", ""))
                    for d in cast(list[dict[str, object]], report.get("deferred", []))}
    out: list[str] = []
    for name in loud:
        advice = ("merge this bump PR, then re-run — re-running first re-selects the same top-N"
                  if cause_by_dep.get(name) == "capped"
                  else "re-run `/deps-apply all`, or fix the resolver if it defers again")
        out.append(f"::error::A CVE-forced bump did not land: {name}. "
                   f"The advisory stays open until it does — {advice}.")
    for err in errors:
        out.append(f"::error::{err}")
    if counts.get("defect"):
        out.append(f"::warning::{counts['defect']} dependency bump(s) deferred on a DEFECT — "
                   "these recur on every run until fixed, so re-running will not help.")
    if counts.get("transient"):
        out.append(f"::notice::{counts['transient']} dependency bump(s) deferred on a transient "
                   "failure — re-run `/deps-apply all`.")
    if counts.get("capped"):
        out.append(f"::notice::{counts['capped']} dependency bump(s) deferred by the per-run cap — "
                   "they move up the queue once this bump PR merges. (A CVE-forced one among them "
                   "is reported as an error above, not here.)")
    for warn in cast(list[str], report.get("sync_warnings", [])):
        out.append(f"::warning::{warn}")
    return (1 if (loud or errors) else 0), out


# ---------------------------------------------------------------------------
# Apply bumps → file edits (pure; no network)
# ---------------------------------------------------------------------------

def apply_bumps(root: Path, bumps: list[Bump]) -> ApplyResult:
    """Edit `pins.py` + `pyproject.toml` in place for each bump. Pure text editing —
    each edit is anchored + verified (the file must still compile / the new version
    must be present), so a failed edit aborts that one bump, never corrupts the file."""
    result = ApplyResult()
    if not bumps:
        return result
    pins_path = root / "agentsec" / "pins.py"
    pyproject_path = root / "pyproject.toml"

    # Read each file only if a bump targets it (so a pins-only run never needs pyproject).
    pins_text = _read(pins_path) if any(b.source.startswith("pins.py:") for b in bumps) else ""
    pyproject_text = _read(pyproject_path) if any(b.source.startswith("pyproject.toml") for b in bumps) else ""
    pins_dirty = pyproject_dirty = False

    for bump in bumps:
        try:
            if bump.source.startswith("pins.py:"):
                pins_text = _edit_pins_block(pins_text, bump)
                pins_dirty = True
            elif bump.source.startswith("pyproject.toml"):
                pyproject_text = _edit_pyproject_floor(pyproject_text, bump)
                pyproject_dirty = True
            else:
                result.deferred.append(Deferral(
                    bump.name, "defect", f"no editor for source {bump.source!r}",
                    severity=bump.severity, reason=bump.reason,
                ))
                continue
            result.bumped.append(bump)
        except ValueError as exc:
            result.errors.append(f"{bump.name}: {exc}")

    if pins_dirty:
        # pins_text is internally generated, never attacker input, syntax-checked not executed.
        compile(pins_text, str(pins_path), "exec")  # security: allow-eval-exec
        _write(pins_path, pins_text)
        result.changed_files.append("agentsec/pins.py")
        # A pins.py version/sha256 is mirrored as a literal default in some component.json
        # files (the rendered-CI copies the drift test guards). Sync them so the bump
        # doesn't leave them stale (which would fail test_pins.py::…_defaults_match_pins).
        for bump in result.bumped:
            if bump.source.startswith("pins.py:"):
                changed, warns = _sync_component_jsons(root, bump)
                result.changed_files.extend(changed)
                result.sync_warnings.extend(warns)
                # Some tools (actionlint) are downloaded by a workflow directly, before
                # checkout can `import pins` — their version/sha256 lives as a literal
                # env default in that workflow file instead of a component.json. Sync
                # those too (test_pins.py::…_ci_yml_actionlint_matches_pins is the guard).
                changed, warns = _sync_workflow_env(root, bump)
                result.changed_files.extend(changed)
                result.sync_warnings.extend(warns)
    if pyproject_dirty:
        _write(pyproject_path, pyproject_text)
        result.changed_files.append("pyproject.toml")
    return result


def _sync_component_jsons(root: Path, bump: Bump) -> tuple[list[str], list[str]]:
    """Update the literal `<TOOL>_VERSION` / `<TOOL>_SHA256` param defaults in every
    `ci/components/*/component.json` that consumes this pin (from `Pin.used_by`). Returns
    ``(changed_files, warnings)``."""
    changed: list[str] = []
    warns: list[str] = []
    prefix = bump.name.upper().replace("-", "_")
    ci_sha = bump.sha_by_plat.get(_CI_PLATFORM, "")
    for used in pins.pin(bump.name).used_by:
        if not used.startswith("ci/components/"):
            continue
        cj = root / "agentsec" / used / "component.json"
        if not cj.is_file():
            warns.append(f"{bump.name}: {used}/component.json not found — sync skipped")
            continue
        text = cj.read_text(encoding="utf-8")
        text, n = _edit_component_default(text, f"{prefix}_VERSION", bump.new_version)
        if n != 1:
            warns.append(f"{bump.name}: {prefix}_VERSION not found in {used}/component.json")
            continue
        if ci_sha:  # native tools also carry a sha256 default (the linux/x86_64 one)
            text, _ = _edit_component_default(text, f"{prefix}_SHA256", ci_sha)
        _write(cj, text)
        changed.append(f"agentsec/{used}/component.json")
    return changed, warns


def _edit_component_default(text: str, param: str, new_value: str) -> tuple[str, int]:
    """Replace `"<param>": {"default": "<old>"}` → new_value (anchored, count of edits)."""
    pat = re.compile(rf'("{re.escape(param)}":\s*\{{\s*"default":\s*")[^"]*(")')
    return pat.subn(rf"\g<1>{new_value}\g<2>", text, count=1)


def _sync_workflow_env(root: Path, bump: Bump) -> tuple[list[str], list[str]]:
    """Update the literal `<TOOL>_VERSION` / `<TOOL>_SHA256` env-var defaults in a
    `.github/workflows/*.yml` that downloads this pin directly (from `Pin.used_by`, e.g.
    `"ci.yml"`) — the raw-workflow counterpart to `_sync_component_jsons`, for a tool a
    workflow fetches before checkout can `import pins` (so a component.json indirection
    isn't available). Returns ``(changed_files, warnings)``."""
    changed: list[str] = []
    warns: list[str] = []
    prefix = bump.name.upper().replace("-", "_")
    ci_sha = bump.sha_by_plat.get(_CI_PLATFORM, "")
    for used in pins.pin(bump.name).used_by:
        if not used.endswith(".yml"):
            continue
        wf = root / ".github" / "workflows" / used
        if not wf.is_file():
            warns.append(f"{bump.name}: .github/workflows/{used} not found — sync skipped")
            continue
        text = wf.read_text(encoding="utf-8")
        text, n = _edit_workflow_env(text, f"{prefix}_VERSION", bump.new_version)
        if n != 1:
            warns.append(f"{bump.name}: {prefix}_VERSION not found in .github/workflows/{used}")
            continue
        if ci_sha:  # native tools also carry a sha256 default (the linux/x86_64 one)
            text, _ = _edit_workflow_env(text, f"{prefix}_SHA256", ci_sha)
        _write(wf, text)
        changed.append(f".github/workflows/{used}")
    return changed, warns


def _edit_workflow_env(text: str, key: str, new_value: str) -> tuple[str, int]:
    """Replace `<KEY>: "<old>"` → new_value (anchored to that literal env key, count of edits)."""
    pat = re.compile(rf'({re.escape(key)}:\s*")[^"]*(")')
    return pat.subn(rf"\g<1>{new_value}\g<2>", text, count=1)


def _edit_pins_block(text: str, bump: Bump) -> str:
    """Replace the version (and, for natives, every platform sha256) inside the one
    `Pin(name="<bump.name>", …)` literal. Anchored to that block so a same-valued
    string elsewhere is never touched."""
    anchor = text.find(f'name="{bump.name}"')
    if anchor == -1:
        raise ValueError(f"no Pin block for {bump.name!r} in pins.py")
    nxt = text.find("\n    Pin(", anchor)
    end = nxt if nxt != -1 else text.find("\n)", anchor)
    if end == -1:
        end = len(text)
    block = text[anchor:end]

    new_block, n = re.subn(
        rf'version="{re.escape(bump.old_version)}"', f'version="{bump.new_version}"', block, count=1
    )
    if n != 1:
        raise ValueError(f"version=\"{bump.old_version}\" not found in {bump.name}'s block")

    for (_os, _arch), new_sha in bump.sha_by_plat.items():
        slug = pins.pin(bump.name).assets[(_os, _arch)][0]
        new_block, hits = re.subn(
            rf'"{re.escape(slug)}",\s*"[0-9a-f]{{64}}"', f'"{slug}", "{new_sha}"', new_block, count=1
        )
        if hits != 1:
            raise ValueError(f"sha256 slot for {bump.name} {slug} not found")
    return text[:anchor] + new_block + text[end:]


def _edit_pyproject_floor(text: str, bump: Bump) -> str:
    """Raise the `[dev]` floor for `bump.name` to the new version (CVE-driven)."""
    pat = re.compile(rf'("{re.escape(bump.name)}>=)[0-9][\w.\-]*"')
    new_text, n = pat.subn(rf'\g<1>{bump.new_version}"', text, count=1)
    if n != 1:
        raise ValueError(f"no `{bump.name}>=…` floor found in pyproject.toml")
    return new_text


def _read(path: Path) -> str:
    if not path.is_file():
        raise ValueError(f"{path} not found")
    return read_text_preserve(path)


def _write(path: Path, text: str) -> None:
    # newline-preserving so an existing CRLF/LF file isn't re-translated on Windows.
    write_text_preserve(path, text)
