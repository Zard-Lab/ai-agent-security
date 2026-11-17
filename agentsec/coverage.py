"""Checklist coverage — joins the registry against a repo's detected stack.

`coverage(root)` computes, per checklist item, one of four states:

- ``covered`` / ``partial`` / ``manual`` — the tool's claim from `checklist.json`
  (see `agentsec.checklist` for the rules each status must satisfy);
- ``na`` — computed here, never stored: `applies_when` is non-empty and no listed
  feature is in the detected `profile.features`.

The markdown emitter is the **security score card**: per-section rollups plus the
applicable `manual` items — the user's to-do list. A clean audit is not "secure";
the score card is what makes that distinction visible (the dead-lint lesson:
docs/knowledge/exposed-schema-rls-blind-spot.md).

Coverage states describe the TOOL's capability, not one run's tool availability —
a `covered` item whose scanner binary is missing still shows `covered` here; the
audit report's skip list is where availability shows.

Deterministic by construction: no timestamps, stable ordering, `sort_keys` JSON.
Reports stamp the registry version + sha so a run is reproducible against a
pinned checklist (the two-clock model, methodology-and-roadmap.md Part 2).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from agentsec.checklist import Checklist, ChecklistItem, checklist_sha, load_checklist
from agentsec.detect import StackProfile, detect
from agentsec.findings import SEVERITY_RANK
from agentsec.text_sanitize import neutralize_delivery_markers

# Live-scanner check ids (agentsec live / ingest.py parsers) that checklist
# items may reference alongside guard/runner ids.
LIVE_CHECK_IDS = frozenset({"zap", "splinter", "schemathesis", "jwt-tool", "harden-host", "scan-live-url"})

# The feature vocabulary detect.py can emit (languages + normalized flags).
# checklist.json `applies_when` values must come from this set (drift-tested).
KNOWN_FEATURES = frozenset({
    "python", "typescript", "javascript", "sql", "go", "php", "ruby", "java", "rust",  # languages
    "fastapi", "express",                                 # backend framework
    "nextjs",                                              # Next.js (frontend + API routes) present
    "react-native",                                         # React Native / Expo mobile app present
    "pydantic-ai", "langchain", "llm",                    # LLM frameworks + flag
    "supabase", "postgres",                               # db
    "frontend", "docker", "terraform", "rls", "payments",  # normalized flags
    "mcp",                                                 # MCP server config present
    "electron",                                            # Electron desktop-app packaging present
    "ansible",                                             # Ansible playbook/role tree present
    "k8s",                                                 # K8s workload manifest present
    "cloudformation",                                      # AWS CloudFormation template present
    "arm",                                                  # Azure Resource Manager template present
    "bicep",                                                # Azure Bicep (.bicep) file present
    "redis",                                               # Redis client dependency/import present
    "graphql",                                             # Python GraphQL server library present
})

_STATES = ("covered", "partial", "manual", "na")


def detection_tier(item: ChecklistItem) -> int | None:
    """The trust tier at which `item` is detected (the tool-adoption-security-doctrine
    layered-trust model): 1 = our own guard, 2 = a vendored rule in our pack, 3 = an
    external advisory tool. None = not yet detected.

    For `covered`/`partial` items it is **derived** from `check_ids` — an own-guard makes
    it Tier 1; otherwise an external runner / live scanner makes it Tier 3 (advisory). We
    have no distinct check id for the vendored Semgrep pack today, so Tier 2 is reached
    only via an explicitly declared `item.tier` (the roadmap intent on `manual` items).
    For `manual` items it returns the declared `item.tier` (or None)."""
    if item.status not in ("covered", "partial"):
        return item.tier  # manual: the declared roadmap intent (or None)
    from agentsec.registry import ALL_GUARDS, ALL_RUNNERS  # late import (registry pulls all guards)

    ids = set(item.check_ids)
    if ids & {g.id for g in ALL_GUARDS}:
        return 1
    if ids & ({r.id for r in ALL_RUNNERS} | set(LIVE_CHECK_IDS)):
        return 3
    return item.tier


@dataclass(frozen=True)
class CoverageItem:
    item: ChecklistItem
    state: str  # covered | partial | manual | na


@dataclass(frozen=True)
class SectionRollup:
    section: str
    section_title: str
    covered: int
    partial: int
    manual: int
    na: int


@dataclass(frozen=True)
class CoverageResult:
    version: str
    sha: str
    released: str
    age_days: int
    features: tuple[str, ...]
    items: tuple[CoverageItem, ...]
    sections: tuple[SectionRollup, ...]


def _section_key(section: str) -> tuple[int, str]:
    """Natural sort: '2a' < '10' (plain string sort would not)."""
    m = re.match(r"(\d+)(.*)", section)
    return (int(m.group(1)), m.group(2)) if m else (99, section)


def coverage(root: Path, profile: StackProfile | None = None) -> CoverageResult:
    """Compute the coverage states for `root` (detects the stack if no profile given)."""
    prof = profile or detect(root)
    checklist: Checklist = load_checklist()

    cov_items = tuple(
        CoverageItem(item=it, state=it.status if it.applicable(prof.features) else "na")
        for it in checklist.items
    )

    rollups: dict[str, dict[str, int]] = {}
    titles: dict[str, str] = {}
    for ci in cov_items:
        sec = ci.item.section
        titles[sec] = ci.item.section_title
        rollups.setdefault(sec, dict.fromkeys(_STATES, 0))[ci.state] += 1
    sections = tuple(
        SectionRollup(
            section=sec, section_title=titles[sec],
            covered=counts["covered"], partial=counts["partial"],
            manual=counts["manual"], na=counts["na"],
        )
        for sec, counts in sorted(rollups.items(), key=lambda kv: _section_key(kv[0]))
    )
    return CoverageResult(
        version=checklist.version,
        sha=checklist_sha(),
        released=checklist.released,
        age_days=checklist.age_days(date.today()),
        features=tuple(sorted(prof.features)),
        items=cov_items,
        sections=sections,
    )


def _sev_key(item: ChecklistItem) -> tuple[int, str]:
    return (SEVERITY_RANK.get(item.severity, 99), item.id)


def _stamp_line(result: CoverageResult) -> str:
    """Shared registry version/sha/staleness line (RFC #253 Phase 1) for both markdown
    formats — mirrors `cli._registry_stamp()`, duplicated (not imported) to avoid a
    cli->coverage->cli import cycle. Includes the same 90-day soft advisory line
    (`update_check.stale_advisory_line`, zero network) so the two stay in sync — see
    `test_registry_stamp_matches_coverage_stamp_line`."""
    from agentsec.update_check import stale_advisory_line

    plural = "day" if result.age_days == 1 else "days"
    line = (
        f"_Checklist registry:_ v{result.version} (sha256 {result.sha[:12]}), "
        f"released {result.released}, {result.age_days} {plural} old"
    )
    advisory = stale_advisory_line(result.age_days)
    return line if advisory is None else f"{line}\n{advisory}"


def to_markdown(result: CoverageResult) -> str:
    """The security score card."""
    lines: list[str] = []
    lines.append("# agentsec coverage score card")
    lines.append("")
    lines.append(_stamp_line(result))
    lines.append(f"_Detected stack features:_ {', '.join(result.features) or '(none)'}")
    lines.append("")

    total_applicable = sum(s.covered + s.partial + s.manual for s in result.sections)
    total_covered = sum(s.covered for s in result.sections)
    lines.append(
        f"**{total_covered} of {total_applicable} applicable checklist items are verified by a check** "
        f"({sum(s.partial for s in result.sections)} partially checked, "
        f"{sum(s.manual for s in result.sections)} manual, "
        f"{sum(s.na for s in result.sections)} not applicable to this stack)."
    )
    lines.append("")
    lines.append("| § | Section | Covered | Partial | Manual | N/A |")
    lines.append("|---|---|---|---|---|---|")
    for s in result.sections:
        lines.append(
            f"| {s.section} | {s.section_title} | {s.covered} | {s.partial} | {s.manual} | {s.na} |"
        )

    manual = sorted(
        (ci.item for ci in result.items if ci.state == "manual"), key=_sev_key
    )
    if manual:
        lines.append("")
        lines.append("## Your manual checklist (no automated check — verify these yourself)")
        lines.append("")
        for it in manual:
            lines.append(f"- **{it.severity}** [§{it.section}] {it.title}")

    partial = sorted(
        (ci.item for ci in result.items if ci.state == "partial"), key=_sev_key
    )
    if partial:
        lines.append("")
        lines.append("## Partially checked (a check helps, but does not prove the item)")
        lines.append("")
        for it in partial:
            lines.append(f"- **{it.severity}** [§{it.section}] {it.title} — via `{'`, `'.join(it.check_ids)}`")

    lines.append("")
    lines.append(
        "> Coverage states describe the tool's capability, not this run's scanner availability — "
        "see the audit report's skip list for what actually ran. `covered` items are backed by a "
        "planted-violation test in the agentsec suite.\n"
        ">\n"
        "> They are also **network-tier-blind**: an item covered by an external runner can still "
        "run with a reduced rule set at the offline default (Tier 0). `agentsec audit` discloses "
        "that per run on its `Reduced coverage` line — read the two together."
    )
    return "\n".join(lines) + "\n"


def _bar(fraction: float, width: int = 20) -> str:
    """A deterministic unicode progress bar (no color, no clock)."""
    filled = round(max(0.0, min(1.0, fraction)) * width)
    return "█" * filled + "░" * (width - filled)


def to_dashboard(result: CoverageResult) -> str:
    """A self-regenerating per-section coverage **dashboard** — progress bars over the
    same score-card data, so the snapshot can never drift from the registry (it is
    regenerated, not hand-maintained). Deterministic: identical bytes for identical
    inputs."""
    total_covered = sum(s.covered for s in result.sections)
    total_partial = sum(s.partial for s in result.sections)
    total_manual = sum(s.manual for s in result.sections)
    total_na = sum(s.na for s in result.sections)
    total_app = total_covered + total_partial + total_manual
    frac = total_covered / total_app if total_app else 0.0

    lines = [
        "# agentsec coverage dashboard",
        "",
        _stamp_line(result),
        f"_Detected stack features:_ {', '.join(result.features) or '(none)'}",
        "",
        f"**Overall: {total_covered}/{total_app} covered** {_bar(frac)} {round(frac * 100)}%",
        f"_partial {total_partial} · manual {total_manual} · n/a {total_na}_",
        "",
        "| § | Section | Covered | Applicable | Progress |",
        "|---|---|---|---|---|",
    ]
    for s in result.sections:
        applicable = s.covered + s.partial + s.manual
        f = s.covered / applicable if applicable else 0.0
        lines.append(
            f"| {s.section} | {s.section_title} | {s.covered} | {applicable} "
            f"| {_bar(f, 12)} {round(f * 100)}% |"
        )
    lines += [
        "",
        "> Regenerate with `agentsec coverage --format dashboard`. `covered` = backed by a "
        "planted-violation test; `partial`/`manual` still need your eyes (a green bar is not "
        "proof of security — see the score card for the manual to-do list).",
        "",
    ]
    return "\n".join(lines) + "\n"


def to_json(result: CoverageResult) -> str:
    """Deterministic JSON (stable ordering; byte-identical across runs).

    Deliberately omits `age_days`: it is derived from `date.today()`, so baking it into
    this payload would break the byte-identical guarantee for two runs on different
    days against the same registry. `released` is included — it is a static property
    of the registry version, not a function of when you happened to run this.

    `title`/`section_title` text is passed through `neutralize_delivery_markers()` at this
    serialization point — this JSON payload is the machine-readable, pipe-out-to-a-downstream-tool
    surface (the documented substitute for the deferred, decision-gated `--llm-triage`; see
    `text_sanitize.py`), so `checklist.json`'s title text is sanitized here at the point of use.
    `checklist.json` itself and the human-readable dashboard/markdown score card are unaffected."""
    payload = {
        "version": result.version,
        "sha256": result.sha,
        "released": result.released,
        "features": list(result.features),
        "sections": [
            {
                "section": s.section, "title": neutralize_delivery_markers(s.section_title),
                "covered": s.covered, "partial": s.partial, "manual": s.manual, "na": s.na,
            }
            for s in result.sections
        ],
        "items": [
            {
                "id": ci.item.id, "section": ci.item.section,
                "title": neutralize_delivery_markers(ci.item.title),
                "severity": ci.item.severity, "state": ci.state,
                "check_ids": list(ci.item.check_ids), "verified_by": ci.item.verified_by,
                "tier": detection_tier(ci.item), "cwe": ci.item.cwe,
            }
            for ci in result.items
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


TRACKER_BEGIN = "<!-- BEGIN GENERATED: coverage table (agentsec coverage --write-tracker) -->"
TRACKER_END = "<!-- END GENERATED -->"


def render_tracker_block() -> str:
    """The generated 'Guards that exist' table for docs/knowledge/checklist-gaps.md.

    Derived purely from ALL_GUARDS x checklist.json — never hand-edit; edit
    checklist.json and re-run `agentsec coverage . --write-tracker`."""
    from agentsec.registry import ALL_GUARDS  # late import: registry pulls every guard module

    checklist = load_checklist()
    lines = [
        TRACKER_BEGIN,
        "",
        "| Guard | Checklist items it checks | Coverage |",
        "|---|---|---|",
    ]
    for guard in ALL_GUARDS:
        hits = [it for it in checklist.items if guard.id in it.check_ids]
        refs = ", ".join(f"§{it.section} {it.id}" for it in hits) or "(unmapped)"
        n_cov = sum(1 for it in hits if it.status == "covered")
        n_part = sum(1 for it in hits if it.status == "partial")
        lines.append(f"| `{guard.id}` | {refs} | {n_cov} covered, {n_part} partial |")
    lines += [
        "",
        f"_Generated from `checklist.json` v{checklist.version} — edit that file, then run_",
        "_`agentsec coverage . --write-tracker` (drift-tested in `tests/test_coverage.py`)._",
        "",
        TRACKER_END,
    ]
    return "\n".join(lines)


def write_tracker(tracker_path: Path) -> bool:
    """Splice the generated block between the markers in `tracker_path`.

    Returns False (untouched) when the file or markers are missing."""
    if not tracker_path.is_file():
        return False
    text = tracker_path.read_text(encoding="utf-8")
    begin, end = text.find(TRACKER_BEGIN), text.find(TRACKER_END)
    if begin == -1 or end == -1 or end < begin:
        return False
    new = text[:begin] + render_tracker_block() + text[end + len(TRACKER_END):]
    tracker_path.write_text(new, encoding="utf-8")
    return True
