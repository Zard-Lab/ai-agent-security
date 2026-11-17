"""The normalized findings model + emitters (the reporting spine).

Generalized from the donor repo's `scripts/security/format_findings_for_slack.py`
(a single `Finding` shape + severity ordering + per-tool parsers + renderers),
with **SARIF 2.1.0** added as the canonical interchange format alongside markdown.

Every check in agentsec — deterministic-scanner runner OR portable static guard —
produces `Finding`s, so there is exactly one report model regardless of source.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Literal, cast

from agentsec.checkmeta import AREA_ORDER, FALLBACK_AREA
from agentsec.text_sanitize import neutralize_delivery_markers

Severity = Literal["critical", "high", "medium", "low", "info"]

# A trailing `:line` or `:line:col` suffix on a `location` (kept across normalization).
_LOCATION_LINE_SUFFIX = re.compile(r":\d+(?::\d+)?$")

# Lower rank = more severe (sort ascending). Mirrors the donor's SEVERITY_ORDER;
# scanner-native severities are normalized into these five by the runners.
SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

# SARIF only defines error/warning/note/none — map our severities onto it.
_SARIF_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "warning",
    "info": "note",
}

_SEVERITY_EMOJI: dict[str, str] = {
    "critical": "🔴",
    "high": "🔴",
    "medium": "🟠",
    "low": "🟡",
    "info": "⚪",
}

# DRAINED (BB4). A check now declares its own surfacing status — `surfacing = True` for a whole
# check (`bola`, `lethal-trifecta`, `system-prompt-leak`, `input-delimiters`) or
# `surfacing_rule_prefixes` when only some of its rules are review signals (`trivy`, whose
# `trivy-image/` CVEs are surfacing while its bare fs-scan CVE ids are proven). Kept rather than
# deleted because `_is_review_finding()` still reads it for UNREGISTERED (ingested / synthetic)
# ids, which have no class to declare on — so a prefix re-added here would silently work for
# those and silently NOT work for every registered check, the exact split BB4 removes.
# `test_review_prefixes_legacy_stays_drained` pins it empty.
_REVIEW_RULE_PREFIXES: tuple[str, ...] = ()


def _is_review_finding(f: Finding) -> bool:
    """True when a finding points at an architecture to review rather than a proven bug.

    Resolved from what the check itself declares (`surfacing` for a whole check,
    `surfacing_rule_prefixes` when only some of its rules are review signals — `trivy` emits
    both). An unregistered id (ingested / synthetic) has no class to ask, so it falls back to
    the drained legacy prefix tuple.
    """
    from agentsec.registry import check_meta  # lazy: avoids an import cycle

    meta = check_meta(f.check_id)
    if meta is None:
        return any(f.rule.startswith(p) for p in _REVIEW_RULE_PREFIXES)
    return meta.surfacing or any(f.rule.startswith(p) for p in meta.surfacing_rule_prefixes)


def normalize_severity(raw: str | None) -> Severity:
    """Map a scanner-native severity string onto our five-level scale.

    Total by contract: callers pass the raw `dict.get(...)` value (effectively `Any`), so a
    non-string (a numeric/list/bool severity in malformed or version-drifted scanner JSON)
    must return ``info`` rather than raise — a raise inside a `parse()` loop collapses a whole
    scanner's output into one "could not parse" finding, silently dropping every real result.
    """
    if not isinstance(raw, str) or not raw.strip():
        return "info"
    s = raw.strip().lower()
    if s in SEVERITY_RANK:
        return cast(Severity, s)  # validated above: s is a SEVERITY_RANK key
    if s in ("error", "err", "blocker"):
        return "high"
    if s in ("warning", "warn", "moderate", "major"):
        return "medium"
    if s in ("note", "minor", "informational", "information"):
        return "low"
    return "info"


def _finding_fingerprint(identity: str, location: str, message: str) -> str:
    """The single canonical basis+hash shared by `Finding.fingerprint()` (line-sensitive)
    and `Finding.stable_fingerprint()` (line-insensitive). Keeping the basis in one place is
    the fix for issue #325: the two identities may differ ONLY in the `location` passed in
    (full vs line-stripped) — never in separator, identity field, or message window."""
    basis = "|".join([identity, location, message[:120]])
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def split_line_suffix(location: str) -> tuple[str, str]:
    """Split a finding `location` into (path, trailing ``:line[:col]`` suffix).

    A URL yields ``(location, "")``. `scheme://host:9200` ends in the same `:<digits>`
    a `path:line` does, so reading that port as a line number collapsed two findings
    differing only by PORT into one identity, and one port's waiver then suppressed the
    other (#567). The `://` test is `normalize_location`'s own, so every caller agrees
    on what a URL is.

    Every IDENTITY and SUPPRESSION-path caller routes through this (or through
    `strip_line_suffix`) rather than re-deriving the strip, because the same guard going
    missing at one of several copies is what produced #567 and its two siblings on #474
    (`f90852e2`, `871f9cd1`): `normalize_location`, `Finding.stable_fingerprint` and
    `triage_cli._location_file`. `audit.py` still keeps its own unguarded copy for the
    `--exclude` / `--changed-files-only` path FILTERS, which compare patterns rather than
    hash an identity and so cannot collapse two findings into one waiver (#703)."""
    m = _LOCATION_LINE_SUFFIX.search(location)
    if not m:
        return location, ""
    path = location[: len(location) - len(m.group(0))]
    if not path:
        return "", ""              # degenerate ":42": nothing left of the suffix to BE a path
    if "://" in path:
        return location, ""        # a URL: the trailing `:<digits>` is a port, not a line
    return path, m.group(0)


def strip_line_suffix(location: str) -> str:
    """The path/URL part of `location`. A URL is returned WHOLE (see `split_line_suffix`), and a
    degenerate `":42"` (no path component) is returned as-is rather than as an empty string."""
    return split_line_suffix(location)[0] or location


def normalize_location(root: Path | str, location: str) -> str:
    """Make a finding `location` repo-relative + posix so baselines and SARIF URIs
    are **portable across machines** (the same finding fingerprints identically no
    matter what absolute path the repo lives at).

    A `path:line[:col]` suffix is preserved. The path is resolved (an absolute path,
    or a runner's CWD-relative path like ``../repo/x.py``, both land under `root`) and
    re-expressed relative to `root`. Anything not under `root` — a package name, a ZAP
    URL, a guard's already-correct repo-relative path, or a genuinely external file —
    passes through, but with separators posix-normalized (``\\`` → ``/``) so a path is
    **portable across operating systems too**: a guard's relative location and its
    fingerprint match identically whether the repo was scanned on Linux or Windows
    (also keeps SARIF URIs forward-slashed)."""
    if not location:
        return location
    path, suffix = split_line_suffix(location)
    if not path or "://" in path:   # URLs (e.g. ZAP alerts) are not filesystem paths
        return location
    try:
        rel = Path(path).resolve().relative_to(Path(root).resolve())
    except (ValueError, OSError):
        return location.replace("\\", "/")  # not under root → keep, but posix-normalize separators
    return rel.as_posix() + suffix


def location_matches(selector: str, location: str) -> bool:
    """True iff `location` IS `selector` or lies strictly beneath it in the path hierarchy.

    The one matching rule shared by every SUPPRESSION-path location selector: the
    `location` field of an exception/baseline entry (`exceptions.py::Exception_.matches`)
    and `agentsec triage --location`. Both decide whether a real security finding gets
    waived, so both must answer the same question the same way.

    Selection is ANCHORED and BOUNDARY-SAFE, never substring containment:

    * exact       `app/main.py`   selects `app/main.py`
    * line/col    `app/main.py`   selects `app/main.py:4` and `app/main.py:4:11` (the `:` boundary)
    * directory   `rag` / `rag/`  selects `rag/tools.py:4` (the `/` boundary)
    * NOT a sibling with a shared prefix: `app` never selects `application/svc.py`
    * NOT a suffix or a mid-string hit: `main.py` never selects `app/main.py`
    * NOT `.` selecting the world: `.` selects only the finding whose location IS `.`
    * NOT a URL scheme: `https` / `file` never select `https://host/admin` / `file:///etc/passwd`

    That last one is why the `:` boundary is not taken blindly. The boundary exists so a
    bare-file selector covers its own per-line findings (`app/main.py` → `app/main.py:42`),
    but `scheme://host/path` wears the same first separator, and an ingested location keeps
    its URL verbatim (`normalize_location` passes anything `://`-bearing through untouched).
    Left unqualified, an exception whose location was exactly `file` or `https` suppressed an
    unrelated finding at a different URL — a different message and a different severity. The
    `://` test here is `normalize_location`'s own, so both functions call the same strings URLs.
    A URL selector still selects beneath itself through the `/` boundary, exactly as a
    directory does (`https://host/admin` selects `https://host/admin/users`).

    Fails CLOSED on a degenerate selector: one that is empty, is nothing but separators
    (`/`, `//`), or names no real path segment (`.`, `..`, `./`) selects nothing beyond an
    exact hit. Those are the shapes an unset shell variable and `dirname` produce
    (`--location "$UNSET"`, `--location "$UNSET/"`, `--location "$(dirname repo-root-file)"`),
    and on a suppression path the accident must waive nothing rather than everything. `.` is
    NOT a contrived value: the python-supply-chain guard emits a real finding whose location
    IS `.`, so narrowly triaging that one finding is a legitimate request that must not widen
    into "waive the whole result set". It stays exact-only in every spelling, so an ingested
    `./`-prefixed location cannot re-open the hole either (#474 re-review).

    Matching is literal: no globbing, no case folding, no `\\` to `/` normalization. A
    regex metacharacter in `selector` has no special meaning, and a Windows-style
    `app\\main.py` selects nothing because finding locations are posix-normalized
    (see `normalize_location`). `audit.py::_matches_excludes` deliberately does NOT share
    this rule: `--exclude` is a display filter with intentionally loose glob/segment
    semantics, and loosening a filter only ever shows fewer findings, never waives one.
    """
    if not selector or not location:
        return False
    if location == selector:
        return True
    base = selector.rstrip("/")
    if not base or base in (".", ".."):   # names no path segment → nothing is "beneath" it
        return False
    if location == base or location.startswith(base + "/"):
        return True
    # The `:` boundary covers `path:line[:col]`, never a `scheme://` separator (see above).
    return location.startswith(base + ":") and not location.startswith(base + "://")


@dataclass
class Finding:
    """A single normalized security finding.

    `check_id` is the agentsec rule/guard id (e.g. ``frontend-xss``); `rule` is
    the finer-grained rule that fired. `location` is ``path`` or ``path:line``.
    `standards` carries the mapped framework refs (``OWASP-LLM:LLM01`` etc.) so
    the report can group by standard.
    """

    check_id: str
    severity: Severity
    title: str
    location: str = ""
    message: str = ""
    remediation: str = ""
    url: str = ""
    rule: str = ""
    standards: list[str] = field(default_factory=list)
    # Set by the SQL schema-state pass (audit) when this finding's statement is in a `.sql` file
    # the authoritative schema dump governs (in the dump's subtree, not the dump itself), so it
    # is history. `prioritize` DEMOTES it (never drops); excluded from `fingerprint()` so
    # baselines stay stable. `superseded_by` is that dump's repo-relative path, which the report
    # names instead of claiming a later migration replaced the statement (#1037); None on a
    # finding stamped without one (a synthetic or hand-built finding). Also outside `fingerprint()`.
    superseded: bool = False
    superseded_by: str | None = None
    # Set by the static↔Splinter cross-confirmation pass (live audits): "confirmed-live"
    # (a static finding the live DB also reported — boosted), "static-only" (mapped but not
    # seen live — TAG only, never demoted), or "splinter-only" (live, not in the SQL).
    # Excluded from `fingerprint()`.
    provenance: str = ""
    # Set by `audit()` when this finding's directory matches the repo's opt-in
    # `.agentsec/config.json` `nonproduct_paths` (per-repo DEMOTE tier — e.g. `evals/`,
    # `scripts/`). `prioritize` DEMOTES it (never drops); excluded from `fingerprint()` so
    # baselines stay stable. Distinct from `archive_paths`, which DROPS in `audit()`.
    nonproduct: bool = False
    # Set by `audit()`'s KEV pass (when `--kev` + network tier ≥ 1) for a finding whose CVE is
    # in the CISA Known-Exploited-Vulnerabilities catalog. `prioritize` BOOSTS it (known-exploited
    # = the top real-world signal — it leads its severity); excluded from `fingerprint()`.
    kev: bool = False
    # Set by `audit()`'s EPSS pass (when `--epss` + network tier ≥ 1) to the FIRST.org EPSS score
    # (0.0-1.0, modeled probability of exploitation in the next 30 days) for a finding's CVE, when
    # scored. A predictive signal, weaker than KEV's real-world confirmation — `prioritize` boosts
    # it only above a documented high-probability threshold, and never above KEV. Excluded from
    # `fingerprint()`.
    epss: float | None = None

    def sort_key(self) -> tuple[int, str, str]:
        return (SEVERITY_RANK.get(self.severity, 99), self.check_id, self.location)

    def fingerprint(self) -> str:
        """A stable, **machine-independent** identity for this finding — a short hash
        of (portable rule) + (normalized location) + (message head). Used by the
        exception/baseline registry so a baseline written on one checkout suppresses
        the same finding on another. Mirrors ai-agent-mastery's `cache_key`.

        Assumes `location` is already normalized (see `normalize_location`), which
        `audit()` guarantees before findings leave the pipeline.

        Line-SENSITIVE by design (the trailing `:line[:col]` is part of the basis) so a
        baseline waiver is exact. For the line-INSENSITIVE identity the triage layer keys
        on, see `stable_fingerprint()`."""
        return _finding_fingerprint(self.rule or self.check_id, self.location, self.message)

    def stable_fingerprint(self) -> str:
        """A **line-insensitive** sibling of `fingerprint()` — the same basis with the
        trailing `:line[:col]` stripped from the location, so the identity survives a
        refactor that shifts line numbers.

        This is the single canonical identity the triage layer keys on (see
        `triage.fingerprint`), so a triage verdict and an exception can be joined on one
        key (issue #325). The ONLY difference from `fingerprint()` is line-sensitivity —
        the separator, identity field (`rule or check_id`), and message window are
        deliberately identical (that shared basis lives in `_finding_fingerprint`)."""
        loc = strip_line_suffix(self.location)   # a URL port is not a line number (#567)
        return _finding_fingerprint(self.rule or self.check_id, loc, self.message)


def sanitize_finding(f: Finding) -> Finding:
    """The single choke point for neutralizing an OUTPUT-BOUND `Finding`'s LLM/tool-facing text
    fields (`title`/`message`/`remediation`/`location`/`superseded_by`).

    Every renderer that turns a `Finding` into output an LLM or tool might read — SARIF, the
    drift/coverage JSON snapshots, the markdown/human-summary reports, `deps_monitor.py`'s
    LLM-facing plan input, the corpus-scan report, ... — MUST call this once per finding and use
    the RETURNED copy, rather than hand-calling `neutralize_delivery_markers()` per field at each
    call site. A per-call-site approach silently misses the next emitter and the next field: PR
    #581's round-2 review found two emitters fixed and a third (`report.py`) missed entirely, and
    found `location` never neutralized anywhere at all, including at the two call sites already
    "fixed" — a filename is attacker-controlled on a hostile-repo scan, and a synthetic turn
    boundary built from one reached a real rendered report end to end.

    Returns a NEW `Finding` (never mutates `f`) — `fingerprint()`/`stable_fingerprint()` must stay
    keyed on the ORIGINAL, unsanitized text so the baseline/exception registry's identity is a
    property of the real finding, not of a rendering-only concern; only the returned copy is for
    output. `check_id`/`severity`/`rule`/`standards`/`url` are left untouched — they're fixed,
    guard-authored enum-like values or reference links, never derived from scanned repo content.
    """
    return replace(
        f,
        title=neutralize_delivery_markers(f.title),
        location=neutralize_delivery_markers(f.location),
        message=neutralize_delivery_markers(f.message) if f.message else f.message,
        remediation=neutralize_delivery_markers(f.remediation) if f.remediation else f.remediation,
        superseded_by=neutralize_delivery_markers(f.superseded_by) if f.superseded_by else f.superseded_by,
    )


def is_historical(f: Finding) -> bool:
    """True when a finding is superseded history, not live schema: stamped `superseded` by the
    SQL schema-state pass (its file sits in the authoritative dump's subtree and is not a dump)
    and NOT confirmed live by Splinter. The one predicate every consumer of the stamp shares — the
    triage split, the CI gate sites, the report tallies and SARIF — so they cannot disagree about
    what "superseded" means. It is a verdict, not a reachability guess: the dump carries anything still live at full
    priority, so the migration copy is by construction a duplicate or history. Before #800 the stamp
    was a rank-only hint, and 138 superseded HIGHs failed the flagship gate the dump had answered."""
    return bool(f.superseded) and f.provenance != "confirmed-live"


def _dump_name(f: Finding) -> str:
    return f"schema dump `{f.superseded_by}`" if f.superseded_by else "a schema dump"


def history_note(f: Finding) -> str:
    """How a report describes a superseded finding: the dump that governs its file, which is all
    the schema-state pass knows. Pass the `sanitize_finding` copy. The old wording, "superseded by a
    later migration", claimed more: nothing checks that a later migration exists, and on a repo
    whose only "dump" was a hand-written `schema.sql` there was none (#1037)."""
    return f"history: {_dump_name(f)} is authoritative here"


def governing_dumps(findings: list[Finding]) -> list[str]:
    """The schema dumps the historical findings name, sanitized for output and sorted."""
    return sorted({
        neutralize_delivery_markers(f.superseded_by)
        for f in findings
        if is_historical(f) and f.superseded_by
    })


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: f.sort_key())


# ---------------------------------------------------------------------------
# Emitters
# ---------------------------------------------------------------------------

# External-scanner check ids whose low/info findings form the "noise floor" — high
# volume, low confidence (bandit asserts, semgrep OSS notes). They are still reported
# in full, but collapsed into their own section so curated guard findings and real
# high-severity scanner hits lead the report (noise discipline, not suppression).
_NOISE_FLOOR_TOOLS: frozenset[str] = frozenset({
    "bandit", "semgrep", "pip-audit", "node-audit", "eslint",
    "react-doctor", "gitleaks", "trivy", "hadolint",
})


def _is_noise_floor(f: Finding) -> bool:
    return f.check_id in _NOISE_FLOOR_TOOLS and f.severity in ("low", "info")


def _tally(findings: list[Finding]) -> str:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return ", ".join(
        f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low", "info") if counts.get(s)
    )


def _render_finding(f: Finding) -> list[str]:
    f = sanitize_finding(f)
    emoji = _SEVERITY_EMOJI.get(f.severity, "⚪")
    loc = f" `{f.location}`" if f.location else ""
    std = f"  _[{', '.join(f.standards)}]_" if f.standards else ""
    if f.provenance == "confirmed-live":
        # the live DB confirms it — it is NOT historical, so the superseded tag is suppressed.
        tag = "  _(✓ confirmed live by Splinter)_"
    elif f.superseded and f.provenance == "static-only":
        # superseded (historical SQL) + not seen live is one signal: historical, not live.
        tag = f"  _({history_note(f)}; not in the live DB)_"
    else:
        sup = f"  _({history_note(f)}; non-gating)_" if f.superseded else ""
        prov = {
            "static-only": "  _(static — not confirmed live)_",
            "splinter-only": "  _(live only — not in checked-in SQL)_",
        }.get(f.provenance, "")
        tag = f"{sup}{prov}"
    kev = "  🔥 **[KEV: known-exploited]**" if getattr(f, "kev", False) else ""
    epss_score = getattr(f, "epss", None)
    if epss_score is None:
        epss = ""
    else:
        # Review M3: most real EPSS scores sit well below 1% — `:.0%` rendered "EPSS: 0%" for the
        # typical case, which a reader reasonably reads as "zero exploitation probability", a
        # stronger claim than the data makes. Floor the display instead of rounding it away.
        epss_pct = "<1%" if epss_score < 0.01 else f"{epss_score:.0%}"
        epss = f"  📈 **[EPSS: {epss_pct}]**"
    out = [f"- {emoji} **{f.severity.upper()}** [{f.check_id}]{loc} — {f.title}{std}{kev}{epss}{tag}"]
    if f.message:
        out.append(f"  - {f.message}")
    if f.remediation:
        out.append(f"  - _Fix:_ {f.remediation}")
    if f.url:
        out.append(f"  - {f.url}")
    return out


def _group_key(f: Finding) -> tuple[str, str]:
    return (f.check_id, f.rule or "")


def _summary_by_check(ordered: list[Finding]) -> list[str]:
    """A severity-ordered roll-up table: one row per (check, rule) with a count. This
    is the always-complete tally — `--top N` may shorten the detail list, but this
    table never hides anything (honest coverage)."""
    groups: dict[tuple[str, str], list[Finding]] = {}
    for f in ordered:
        groups.setdefault(_group_key(f), []).append(f)
    rows = sorted(
        groups.items(),
        key=lambda kv: (SEVERITY_RANK.get(kv[1][0].severity, 99), -len(kv[1]), kv[0]),
    )
    lines = ["### Summary by check", "", "| Severity | Check | Rule | Count |", "|---|---|---|---|"]
    for (check_id, rule), fs in rows:
        worst = min(fs, key=lambda f: SEVERITY_RANK.get(f.severity, 99)).severity
        emoji = _SEVERITY_EMOJI.get(worst, "⚪")
        lines.append(f"| {emoji} {worst} | {check_id} | {rule or '—'} | {len(fs)} |")
    return lines


def _noise_floor_section(noise: list[Finding]) -> list[str]:
    """The collapsed noise-floor: grouped by (check, rule) with a count and a few
    example locations. Reported, never dropped — just out of the lead."""
    groups: dict[tuple[str, str], list[Finding]] = {}
    for f in noise:
        groups.setdefault(_group_key(f), []).append(f)
    lines = [
        "",
        f"### Noise floor ({len(noise)} low-confidence scanner finding(s), collapsed)",
        "",
    ]
    for (check_id, rule), fs in sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        sanitized = [sanitize_finding(f) for f in fs]
        locs = [f.location for f in sanitized if f.location]
        examples = ", ".join(locs[:3])
        more = f" (+{len(locs) - 3} more)" if len(locs) > 3 else ""
        eg = f" — e.g. {examples}{more}" if examples else ""
        label = rule or sanitized[0].title
        lines.append(f"- {len(fs)}× [{check_id}] {label}{eg}")
    return lines


def to_markdown(findings: list[Finding], *, top: int | None = None) -> str:
    """Render findings as a prioritized markdown report (severity-ordered, superseded history last).

    Structure: a header tally, a complete **Summary by check** table, the curated
    **Findings** (guards + high/critical scanner hits, optionally capped by `top`
    with an explicit 'showing N of M'), then a collapsed **Noise floor** for
    low-confidence scanner output. Nothing is silently dropped — the summary table
    and noise-floor counts always reflect every finding."""
    if not findings:
        return "## Security findings\n\n✅ No findings.\n"
    ordered = sort_findings(findings)
    # Superseded (historical) SQL findings sink below every live one and leave the headline
    # tally. They stay rendered (tagged) and in the Summary-by-check table — never dropped —
    # but a migration copy of a policy the dump carries live is not an issue to count (#800).
    live = [f for f in ordered if not is_historical(f)]
    historical = [f for f in ordered if is_historical(f)]
    ordered = live + historical
    head = f"{len(live)}: {_tally(live)}" if live else "0 live"
    if historical:
        head += f"; {len(historical)} governed by the schema dump (non-gating)"
    lines = [f"## Security findings ({head})", ""]
    lines.extend(_summary_by_check(ordered))

    signal = [f for f in ordered if not _is_noise_floor(f)]
    noise = [f for f in ordered if _is_noise_floor(f)]

    lines.append("")
    lines.append("### Findings")
    if not signal:
        lines.append("")
        lines.append("_Nothing above the noise floor — see the collapsed section below._")
    else:
        shown = signal if top is None else signal[:top]
        for f in shown:
            lines.extend(_render_finding(f))
        if top is not None and len(signal) > len(shown):
            lines.append("")
            lines.append(
                f"_…showing {len(shown)} of {len(signal)} findings (live first, most severe within) — "
                "the full tally is in 'Summary by check' above._"
            )

    if noise:
        lines.extend(_noise_floor_section(noise))

    lines.extend(_markdown_footer(ordered))
    return "\n".join(lines)


# DRAINED (BB4). Every registered check declares its own `area` on the class, directly under
# `id`/`title`, drawn from `checkmeta.AREA_ORDER`. Kept rather than deleted because `_area()`
# still consults it, so an id re-added here TAKES EFFECT and `test_area_legacy_stays_drained`
# is the one thing that catches it — drop the lookup and a stray entry here becomes a silent
# no-op instead. This map is why the migration happened: at 37 of 293 entries with no coverage
# gate, `to_human_summary()` filed 256 checks under "Other checks" and still rendered, passed
# CI and looked correct (CLAUDE.md Rule 3). Adding a guard must not mean editing this file.
_AREA_LEGACY: dict[str, str] = {}

# Areas for the check ids produced OUTSIDE the registry — ingested reports and synthetic
# findings have no check class to declare on, so this map is legitimately non-empty and is NOT
# pinned the way `_AREA_LEGACY` is. `test_known_nonregistry_check_ids_have_an_area` keeps it complete.
# Deliberately excluded: the two DYNAMIC id prefixes, `sarif:<tool>` (`ingest.py`) and
# `ingest:<kind>`, whose tails are open-ended — they fall through to `FALLBACK_AREA` by design.
_NONREGISTRY_AREA: dict[str, str] = {
    "zap": "Web setup",              # DAST sweep of the running app
    "splinter": "Database",          # Supabase/Postgres lint (RLS, definer, search_path)
    "schemathesis": "Reliability",   # OpenAPI fuzzing — unhandled input, 500s, contract breaks
    "jwt-tool": "Login & access",    # JWT forgery / alg-confusion attacks
    "garak": "AI agent",             # LLM red-team probes
    "promptfoo": "AI agent",         # prompt-injection / jailbreak evals
    "deps-monitor": "Dependencies",  # agentsec's own pinned-supply-chain drift report
    "harden-host": "Server hardening",  # the opt-in live-host audit (sshd/ufw/systemctl)
    # A disclosure about THIS SCAN's resource caps, not about the app: the catch-all is the
    # honest bucket, and stating it here records that as a decision rather than a fallthrough.
    "gitignore-cap": FALLBACK_AREA,
}


def _area(check_id: str) -> str:
    """The app-area bucket for a check id, for the human summary's grouping.

    Resolution order, most authoritative first: what the check declares about itself, then the
    drained legacy map, then the explicit non-registry map, then the catch-all. A registered
    check always wins over `_NONREGISTRY_AREA` so the two can never disagree silently.
    """
    from agentsec.registry import check_meta  # lazy: avoids an import cycle

    meta = check_meta(check_id)
    if meta is not None and meta.area:
        return meta.area
    return _AREA_LEGACY.get(check_id) or _NONREGISTRY_AREA.get(check_id, FALLBACK_AREA)


def to_human_summary(findings: list[Finding]) -> str:
    """Render a plain-English summary for a non-technical reader (the vibe view).

    No file paths, rule ids, or code — just what is wrong, why it matters, and how
    to fix it, grouped by app area, with a ship-readiness verdict and a top-3.
    A pure function over the same `Finding` list `to_markdown` uses (no second scan).
    """
    if not findings:
        return "# Security check — all clear ✅\n\nNothing needs fixing right now.\n"
    ordered = sort_findings(findings)
    # The verdict, tally and top-3 are computed over LIVE findings only: a superseded (historical)
    # SQL finding is the migration copy of something the dump already carries at full priority,
    # so letting it drive "Needs work before shipping" is exactly the #800 false alarm.
    live = [f for f in ordered if not is_historical(f)]
    n_hist = len(ordered) - len(live)
    counts: dict[str, int] = {}
    for f in live:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    crit, high = counts.get("critical", 0), counts.get("high", 0)
    if crit:
        verdict = "Not ready to ship. There are critical problems an attacker could use right now."
    elif high:
        verdict = "Needs work before shipping. There are serious problems to fix first."
    elif counts.get("medium"):
        verdict = "Mostly okay. A few medium issues are worth fixing."
    elif live:
        verdict = "Looking good. Only minor, low-risk items remain."
    else:
        verdict = "Looking good. Everything found is history: your schema dump is the source of truth there."
    tally = ", ".join(
        f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low", "info") if counts.get(s)
    ) or "0 live"
    if n_hist:
        tally += f"; {n_hist} governed by the schema dump, not counted"
    lines = [f"# Security check — {len(live)} issue(s) found", "", verdict, "", f"_({tally})_", ""]

    # Fix these first: the top 3 by exploitability (severity x confidence x reachability),
    # not just severity — so a proven bug in product code beats a surfacing or test-only one.
    from agentsec.prioritize import _triage_internal, prioritized  # lazy: avoids an import cycle

    _, deprioritized = _triage_internal(ordered)
    top = [g for g in prioritized(ordered) if not is_historical(g)][:3]
    # Nothing live → no "first". Rendering the heading anyway produced an empty section followed by
    # "fix the above first" with nothing above it, on exactly the all-superseded repo this PR makes
    # common (#829 review round 2, issue 8). The tally line already discloses the history count.
    if top:
        lines.append("## Fix these first")
        for f in top:
            f = sanitize_finding(f)
            message = f.message if f.message else "see below"
            lines.append(f"- **{f.title}** — {message}")
        if deprioritized:
            lines.append(
                f"\n_{len(deprioritized)} lower-priority finding(s) sit in tests / migrations / "
                "scripts (less likely to be live) — fix the above first._"
            )
        lines.append("")

    # Grouped by app area.
    by_area: dict[str, list[Finding]] = {}
    for f in ordered:
        by_area.setdefault(_area(f.check_id), []).append(f)
    lines.append("## What we found, by area")
    for area in AREA_ORDER:
        items = by_area.get(area)
        if not items:
            continue
        lines.append(f"\n### {area} ({len(items)})")
        for f in items:
            hist = is_historical(f)
            f = sanitize_finding(f)
            emoji = _SEVERITY_EMOJI.get(f.severity, "⚪")
            # This listing builds its own lines rather than going through `_render_finding`, so the
            # superseded marker has to be repeated here — without it the vibe view showed a bare red
            # HIGH under "0 issue(s) found · Looking good" (#829 review round 2, issue 9). Plain
            # English, not `_render_finding`'s technical wording: this is the non-technical view.
            tag = f"  _(history: {_dump_name(f)} is the source of truth here — not counted)_" if hist else ""
            lines.append(f"- {emoji} **{f.title}**{tag}")
            if f.message:
                lines.append(f"  - Why it matters: {f.message}")
            if f.remediation:
                lines.append(f"  - How to fix: {f.remediation}")
    lines.append("")
    return "\n".join(lines)


def _markdown_footer(ordered: list[Finding]) -> list[str]:
    """The 'next steps' footer: a fix pointer plus, when present, a reminder that
    surfacing findings are review signals to confirm by hand."""
    review = sum(1 for f in ordered if _is_review_finding(f))
    out = ["", "---", ""]
    out.append(
        "**Next steps.** Run `agentsec fix --write` to apply the mechanical fixes "
        "(allow-listed, reversible changes only); re-run the audit to confirm."
    )
    if review:
        noun = "finding is a review signal" if review == 1 else "findings are review signals"
        out.append(
            f"\n⚠ {review} {noun} (authorization/prompt-injection architecture, or a CVE inside a "
            "third-party base image with no direct code fix): the guard points you where to look, "
            "it does not prove a bug — confirm each by hand before acting."
        )
    out.append("")
    return out


# The reportingDescriptor for guards KILLED over the per-guard time budget (#677). Its own
# descriptor, at level `error`, because this is harder than a coverage disclosure: the guard's
# checks did not complete, the exit gate fails unconditionally (see cli._gate), and a consumer
# filtering by id must be able to tell "ran degraded" from "was interrupted".
GUARD_BUDGET_NOTIFICATION_ID = "agentsec/guard-budget-exceeded"
_GUARD_BUDGET_NOTIFICATION_DESCRIPTOR: dict[str, Any] = {
    "id": GUARD_BUDGET_NOTIFICATION_ID,
    "name": "GuardBudgetExceeded",
    "shortDescription": {"text": "A guard was killed over its per-guard time budget"},
    "fullDescription": {
        "text": (
            "The named guard exceeded its wall-clock budget and was killed; none of its checks "
            "completed for this scan. The result is PARTIAL for that guard — absence of its "
            "findings is not a pass."
        )
    },
}

# The reportingDescriptor backing every coverage notice we emit as a SARIF notification.
# One descriptor (rather than none) so consumers can group/filter the disclosure by a stable id.
COVERAGE_NOTIFICATION_ID = "agentsec/coverage-disclosure"
_COVERAGE_NOTIFICATION_DESCRIPTOR: dict[str, Any] = {
    "id": COVERAGE_NOTIFICATION_ID,
    "name": "CoverageDisclosure",
    "shortDescription": {"text": "This scan did not run at full coverage"},
    "fullDescription": {
        "text": (
            "A scanner was missing, skipped below its network tier, ran with a reduced rule "
            "set, or errored. Absence of a finding is not proof of safety for the affected "
            "checks."
        )
    },
}


def to_sarif(
    findings: list[Finding],
    tool_name: str = "agentsec",
    tool_version: str = "0.1.0",
    *,
    notifications: list[str] | None = None,
    budget_exceeded: list[str] | None = None,
    uri_prefix: str = "",
) -> dict[str, Any]:
    """Render findings as a SARIF 2.1.0 log (GitHub code-scanning ingestible).

    `uri_prefix` makes every artifact URI repo-relative when the scan root is a subdirectory
    of the checkout (`agentsec audit services/api` run from the repo root): finding locations
    are scan-root-relative, but code scanning and workflow annotations resolve a URI against
    the repository root, so without it every result of a monorepo scan points at the wrong
    file. A location of `.` (a finding about the scan root itself) maps to the prefix, and
    URLs and absolute paths are left alone (`_prefixed_uri`). The default `""` leaves the
    output byte-identical to the unprefixed form, and `partialFingerprints` never sees the
    prefix: it is computed from the original finding, so baselines and code-scanning alert
    identities survive turning the prefix on.

    `notifications` carries the honest-coverage disclosure (`AuditResult.coverage_notices()`)
    into the machine-readable path as `runs[].invocations[].toolExecutionNotifications` — the
    SARIF-native home for run-level tool messages, and what GitHub's code-scanning tool-status
    page reads. Before #434 this channel did not exist in SARIF at all, so a `--format sarif`
    CI run — the documented CI path — could not tell a reduced/degraded scan from a full one.
    Level is `note`, never `error`: a disclosure must not fail the analysis. Omitted entirely
    when there is nothing to disclose, so the key's presence is itself the signal.

    `budget_exceeded` (#677) carries the ids of guards KILLED over the per-guard time budget
    as `error`-level notifications under their own descriptor — the one run-level state that
    is harder than a disclosure (those checks did not complete at all; the CLI gate fails on
    it unconditionally). The aggregate line also arrives via `notifications` (it is part of
    `coverage_notices()`), deliberately: a consumer reading either channel still learns of it.

    Every field, including `locations[].physicalLocation.artifactLocation.uri`, is rendered from a
    `sanitize_finding()` copy — this is the machine-readable, pipe-out-to-a-downstream-tool path
    (the documented substitute for the deferred, decision-gated `--llm-triage`; see
    `text_sanitize.py`), so guard/runner-authored text is sanitized here at the point of use. The
    `Finding` objects passed in are never mutated; `fingerprint()` is still computed from the
    original, unsanitized finding so partial-fingerprint identity is unaffected."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for f in sort_findings(findings):
        # `fingerprint()` stays keyed on the ORIGINAL `f` — identity must not depend on a
        # rendering-only concern (see `sanitize_finding`'s docstring) — everything else below
        # renders from the sanitized copy `sf`.
        fingerprint = f.fingerprint()
        sf = sanitize_finding(f)
        rule_id = sf.rule or sf.check_id
        if rule_id not in rules:
            rule: dict[str, Any] = {
                "id": rule_id,
                "name": sf.check_id,
                "shortDescription": {"text": sf.title},
                "properties": {"security-severity": _security_severity(sf.severity), "tags": sf.standards},
            }
            if sf.url:
                rule["helpUri"] = sf.url
            rules[rule_id] = rule
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(sf.severity, "note"),
            "message": {"text": sf.message or sf.title},
            # A stable per-finding id so GitHub code-scanning can track/dismiss an individual alert
            # even when the location is synthetic or absent (e.g. a promptfoo probe) — otherwise
            # same-ruleId, location-less alerts collapse to one and can't be dismissed singly (#365).
            "partialFingerprints": {"agentsecFingerprint/v1": fingerprint},
        }
        if is_historical(f):
            # Superseded history (a migration copy of what the authoritative dump carries live).
            # The CLI gate skips it; tag it so a code-scanning consumer can filter the same way,
            # and name the dump that governs it, as every other renderer does (#1037).
            props: dict[str, object] = {"agentsec/superseded": True}
            if sf.superseded_by:
                props["agentsec/supersededBy"] = sf.superseded_by
            result["properties"] = props
        if sf.location:
            # location is "path", "path:line", or "path:line:col" (POSIX repo-relative, no
            # drive-letter ":" to worry about). Take the first numeric component as the line
            # so a column-qualified location doesn't lose its startLine in code-scanning.
            uri, _, tail = sf.location.partition(":")
            if uri_prefix:
                uri = _prefixed_uri(sf.location, uri, uri_prefix)
            first = tail.partition(":")[0]
            region = {"startLine": int(first)} if first.isdigit() else {}
            result["locations"] = [
                {"physicalLocation": {"artifactLocation": {"uri": uri}, **({"region": region} if region else {})}}
            ]
        results.append(result)
    driver: dict[str, Any] = {
        "name": tool_name,
        "version": tool_version,
        "rules": list(rules.values()),
    }
    run: dict[str, Any] = {"tool": {"driver": driver}, "results": results}
    if notifications or budget_exceeded:
        descriptors: list[dict[str, Any]] = []
        tool_notes: list[dict[str, Any]] = []
        if notifications:
            descriptors.append(_COVERAGE_NOTIFICATION_DESCRIPTOR)
            tool_notes.extend(
                {
                    "descriptor": {"id": COVERAGE_NOTIFICATION_ID},
                    "level": "note",
                    "message": {"text": text},
                }
                for text in notifications
            )
        if budget_exceeded:
            # One `error`-level notification PER killed guard (#677), so a consumer can see
            # exactly which checks never completed without parsing an aggregate string.
            descriptors.append(_GUARD_BUDGET_NOTIFICATION_DESCRIPTOR)
            tool_notes.extend(
                {
                    "descriptor": {"id": GUARD_BUDGET_NOTIFICATION_ID},
                    "level": "error",
                    "message": {
                        "text": (
                            f"Guard '{gid}' was killed over its per-guard time budget; "
                            "none of its checks completed for this scan."
                        )
                    },
                }
                for gid in budget_exceeded
            )
        run["invocations"] = [
            {
                # True: the tool completed. A coverage gap is a disclosure, not a failed run —
                # marking it False would make GitHub reject/flag the whole analysis. That holds
                # even for a budget kill (#677): flipping this to False would drop the findings
                # the scan DID produce from code-scanning, hiding real results to report a
                # partial one — the gate failure is carried by the exit code and the
                # error-level notifications above instead.
                "executionSuccessful": True,
                "toolExecutionNotifications": tool_notes,
            }
        ]
        driver["notifications"] = descriptors
    return {
        "version": "2.1.0",
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.json",
        "runs": [run],
    }


def to_sarif_json(findings: list[Finding], *, notifications: list[str] | None = None,
                  budget_exceeded: list[str] | None = None, uri_prefix: str = "") -> str:
    return json.dumps(
        to_sarif(findings, notifications=notifications, budget_exceeded=budget_exceeded,
                 uri_prefix=uri_prefix),
        indent=2,
    )


def _prefixed_uri(location: str, uri: str, uri_prefix: str) -> str:
    """`uri` (the path part of `location`) re-expressed under `uri_prefix`, the scan root's
    POSIX path relative to the checkout. `.` and an empty path ARE the scan root, so they map
    to the prefix itself. A URL location (an ingested ZAP alert) and an absolute path (a file
    outside the scan root, which `normalize_location` passes through) are not under the scan
    root at all, so they keep their own spelling. Never raises."""
    prefix = uri_prefix.strip("/")
    if not prefix or "://" in location or uri.startswith("/"):
        return uri
    if uri in ("", "."):
        return prefix
    return f"{prefix}/{uri.removeprefix('./')}"


# Workflow-command level per severity: GitHub renders `error` red, `warning` amber, and
# `notice` grey, which is the same three-tier reading the report gives its findings.
_ANNOTATION_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "notice",
    "info": "notice",
}


def _escape_command_data(text: str) -> str:
    """The message half of a workflow command (`@actions/core` `escapeData`): `%`, CR and LF.
    Escaping the line breaks is what stops a finding message from starting a second command
    on a line of its own."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_command_property(text: str) -> str:
    """A `key=value` property of a workflow command (`@actions/core` `escapeProperty`): the data
    escapes plus `:` and `,`, the two characters that end a property or the property list."""
    return _escape_command_data(text).replace(":", "%3A").replace(",", "%2C")


def to_github_annotations(findings: list[Finding], *, top: int, uri_prefix: str = "") -> list[str]:
    """GitHub Actions workflow-command lines (`::error file=…,line=…,title=…::message`) for
    the `top` most severe of `findings`, one per finding, for printing to a step's stdout.

    Pass the GATE set (`cli._gating`): a finding a `--baseline-snapshot` accepted is visible in
    the report but must not be annotated onto a PR as if it were new. Superseded history is
    dropped here as well, so a caller that passes the full list cannot annotate it either.
    `top` <= 0 yields nothing; GitHub caps how many annotations a step can show, so the
    caller keeps `top` small and the report and SARIF carry the rest.

    `file`/`line` are omitted when the location is empty, `.`, a URL or an absolute path: the
    annotation still shows in the run, just not inline on a file. Rendered from
    `sanitize_finding` copies and escaped per the workflow-command rules. Never raises."""
    if top <= 0:
        return []
    live = sort_findings([f for f in findings if not is_historical(f)])
    lines: list[str] = []
    for f in live[:top]:
        sf = sanitize_finding(f)
        props: list[str] = []
        path, _, tail = sf.location.partition(":")
        if path and path != "." and "://" not in sf.location and not path.startswith("/"):
            props.append(f"file={_escape_command_property(_prefixed_uri(sf.location, path, uri_prefix))}")
            first = tail.partition(":")[0]
            if first.isdigit():
                props.append(f"line={int(first)}")
        rule = sf.rule or sf.check_id
        props.append(f"title={_escape_command_property(f'agentsec {sf.severity}: {sf.title} [{rule}]')}")
        level = _ANNOTATION_LEVEL.get(sf.severity, "notice")
        lines.append(f"::{level} {','.join(props)}::{_escape_command_data(sf.message or sf.title)}")
    return lines


def _security_severity(sev: Severity) -> str:
    # GitHub's numeric security-severity bands.
    return {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}[sev]
