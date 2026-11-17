"""The machine-readable checklist registry — the tool's coverage claims, as data.

`checklist.json` is the sole source of truth: one entry per checklist item
(§1–§13), each with a stable id, severity, standards mapping, applicability
features, and the tool's coverage `status`. It was seeded from the original kit
checklist (now archived at `docs/archive/reference-kit/SECURITY_CHECKLIST.md`)
and has since grown well beyond it via the threat-intake loop.

Each entry carries:

- ``covered`` — a check verifies the item; REQUIRES `check_ids` (the guard /
  runner / live-scanner ids) AND `verified_by` (a `tests/file.py::test_fn`
  planted-violation test proving the check is alive — the dead-lint lesson,
  see docs/knowledge/exposed-schema-rls-blind-spot.md).
- ``partial`` — a check helps but does not prove the item; REQUIRES `check_ids`.
- ``manual`` — no automated check; the score card surfaces it as the user's to-do.

**What a `standards` tag claims.** An `OWASP:`/`CWE-`/`OWASP-LLM:` entry is a category link: the
item's risk falls under that category. A compliance-framework entry (`SOC2:CC<n>.<n>`, and any future
`HIPAA:`/`ISO:`) claims less than that — it says this item's check is EVIDENCE toward that criterion,
not that the criterion itself is met. A real SOC 2 criterion is normally satisfied by a mix of policy,
process, and technical controls; a single automated check is one input to an auditor's judgment, never
the whole of it. So a `covered` item tagged `SOC2:CC6.1` means "agentsec's check for this item is
evidence toward CC6.1," not "agentsec covers CC6.1" — the tag borrows the item's own `status` semantics
against the mapped criterion, scoped to what this one check can attest.

**N/A is computed, never stored**: an item is not-applicable for a repo when
`applies_when` is non-empty and no listed feature is in the detected
`profile.features` (ANY-of semantics, mirroring guard ``applies()``). The
registry describes the *tool's* capability; applicability is the *repo's*
property.

Ids are stable across versions (the two-clock join key); renames require a
deprecation note. The loader is intentionally strict — this file ships in the
wheel, so malformed content is a packaging bug: fail loudly, naming the item.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import cast

from agentsec.findings import SEVERITY_RANK

CHECKLIST_PATH = Path(__file__).parent / "checklist.json"

_STATUSES = ("covered", "partial", "manual")


@dataclass(frozen=True)
class ChecklistItem:
    """One checklist item and the tool's coverage claim for it."""

    id: str
    section: str
    section_title: str
    title: str
    severity: str
    standards: tuple[str, ...]
    # ANY-of profile features; empty = always applies. Contract: a token belongs only if a
    # mapped guard actually RUNS on that feature (coverage, not mere relevance) — an item must
    # not display as in-scope on a stack where nothing checks it. (Doctrine call: #292.)
    applies_when: tuple[str, ...]
    status: str  # covered | partial | manual
    check_ids: tuple[str, ...]
    verified_by: str | None  # "tests/<file>.py::<test_fn>" — required when covered
    # Trust tier at which this control is (or, for `manual` items, is planned to be)
    # detected — the [[tool-adoption-security-doctrine]] layered-trust model: 1 = our
    # own dep-free sandboxed guard, 2 = a vendored+pinned rule in our pack, 3 = a pinned
    # advisory external tool. For covered/partial items it is DERIVED from `check_ids`
    # (see coverage.detection_tier) and need not be stored; a stored value on a
    # covered/partial item is drift-checked against the derivation. On `manual` items it
    # is the optional roadmap intent (declared, maintainer judgment). None = unset.
    tier: int | None = None
    # The primary CWE this item maps to, as `CWE-<n>` (e.g. `CWE-434`). Optional —
    # lets the coverage scorecard join against the CWE Top-25 / a CWE-keyed corpus.
    # A single representative weakness per item; not an exhaustive CWE set.
    cwe: str | None = None
    # MITRE ATLAS technique IDs that threaten this control (AML.T prefix; verified vs ATLAS data 2026.09).
    # Empty = no ATLAS mapping. Used by corpus-scan gap candidates and report generation.
    atlas_techniques: tuple[str, ...] = ()
    # For `manual` items only: how the control is verified — `code` (reviewable from
    # repository files: app source, frontend, docker/compose, workflow yaml, migrations,
    # tests, the lockfile) vs `ops` (needs the live/production environment, external infra,
    # runtime behaviour, a recurring process, or human governance). The report's manual
    # checklist uses it to tag each item, and `/security-audit` can only act on `code` ones.
    # REQUIRED on manual items (drift-gated); MUST be None on covered/partial (moot there).
    # Section is too coarse to carry this — several sections mix both kinds — so it is a
    # per-item maintainer judgment, not derived. None = unset.
    surface: str | None = None

    def applicable(self, features: set[str]) -> bool:
        return not self.applies_when or any(f in features for f in self.applies_when)


@dataclass(frozen=True)
class Checklist:
    version: str
    # ISO date the current `version` was released — the offline staleness-stamp source
    # (RFC #253 Phase 1). Updated alongside `version` on any build that bumps it.
    released: str
    items: tuple[ChecklistItem, ...]
    # The OWASP Top 10 edition every bare `OWASP:Axx` tag is written against (#295: pinned
    # to 2021 rather than migrated — 2025 renumbered/renamed several categories non-1:1,
    # see wiki/research/owasp-top10-2025.md for the full cross-walk). Defaults to "2021"
    # for any Checklist built without the field (older snapshots, direct-construction tests).
    owasp_edition: str = "2021"

    def age_days(self, today: date) -> int:
        """Days between `released` and `today` — the ONE time input, passed explicitly
        by the caller (mirrors `exceptions.Exception.lapsed(today)`); never computed
        internally, so this stays a pure function like every other registry accessor."""
        return (today - date.fromisoformat(self.released)).days


def checklist_sha() -> str:
    """sha256 hex of the packaged checklist.json bytes (for report stamping)."""
    return hashlib.sha256(CHECKLIST_PATH.read_bytes()).hexdigest()


def _validate(item: ChecklistItem) -> None:
    if item.status not in _STATUSES:
        raise ValueError(f"checklist item {item.id!r}: bad status {item.status!r}")
    if item.severity not in SEVERITY_RANK:
        raise ValueError(f"checklist item {item.id!r}: bad severity {item.severity!r}")
    if item.status in ("covered", "partial") and not item.check_ids:
        raise ValueError(f"checklist item {item.id!r}: status {item.status!r} requires check_ids")
    if item.status == "covered" and not item.verified_by:
        raise ValueError(f"checklist item {item.id!r}: covered requires verified_by")
    if item.status == "manual" and (item.check_ids or item.verified_by):
        raise ValueError(f"checklist item {item.id!r}: manual must not carry check_ids/verified_by")
    if item.status == "manual":
        if item.surface not in ("code", "ops"):
            raise ValueError(
                f"checklist item {item.id!r}: manual requires surface 'code' or 'ops', got {item.surface!r}"
            )
    elif item.surface is not None:
        raise ValueError(
            f"checklist item {item.id!r}: surface is only for manual items (status {item.status!r})"
        )
    if item.tier is not None and item.tier not in (1, 2, 3):
        raise ValueError(f"checklist item {item.id!r}: bad tier {item.tier!r} (expected 1, 2, 3, or null)")
    if item.cwe is not None and not re.fullmatch(r"CWE-\d+", item.cwe):
        raise ValueError(f"checklist item {item.id!r}: bad cwe {item.cwe!r} (expected 'CWE-<n>' or null)")
    for code in item.atlas_techniques:
        if not code.startswith("AML.T"):
            raise ValueError(
                f"checklist item {item.id!r}: invalid atlas_techniques entry {code!r} (must start with 'AML.T')"
            )


def _item_from_entry(entry: dict[str, object]) -> ChecklistItem:
    """One raw JSON entry -> a `ChecklistItem`. The SINGLE construction site: `load_checklist`
    uses it, and so does `scripts/validate-checklist.py`, which needs to build+`_validate` each
    entry independently so it can report EVERY schema violation in one pass (the loader
    deliberately aborts on the first). Raises KeyError on a missing required field."""
    return ChecklistItem(
        id=cast(str, entry["id"]),
        section=cast(str, entry["section"]),
        section_title=cast(str, entry["section_title"]),
        title=cast(str, entry["title"]),
        severity=cast(str, entry["severity"]),
        standards=tuple(cast("list[str]", entry.get("standards", []))),
        applies_when=tuple(cast("list[str]", entry.get("applies_when", []))),
        status=cast(str, entry["status"]),
        check_ids=tuple(cast("list[str]", entry.get("check_ids", []))),
        verified_by=cast("str | None", entry.get("verified_by")),
        tier=(int(cast(int, entry["tier"])) if entry.get("tier") is not None else None),
        cwe=cast("str | None", entry.get("cwe")),
        atlas_techniques=tuple(cast("list[str]", entry.get("atlas_techniques", []))),
        surface=cast("str | None", entry.get("surface")),
    )


def load_checklist() -> Checklist:
    """Load + structurally validate the packaged registry. Raises ValueError on any bad item."""
    raw = json.loads(CHECKLIST_PATH.read_text(encoding="utf-8"))
    released = raw.get("released")
    if not isinstance(released, str) or not released:
        raise ValueError("checklist.json: missing or empty top-level 'released' date")
    try:
        date.fromisoformat(released)
    except ValueError as e:
        raise ValueError(f"checklist.json: 'released' {released!r} is not a valid ISO date") from e
    items: list[ChecklistItem] = []
    seen: set[str] = set()
    for entry in raw["items"]:
        item = _item_from_entry(entry)
        if item.id in seen:
            raise ValueError(f"checklist item {item.id!r}: duplicate id")
        seen.add(item.id)
        _validate(item)
        items.append(item)
    return Checklist(
        version=str(raw["version"]),
        released=released,
        items=tuple(items),
        owasp_edition=str(raw.get("owasp_edition", "2021")),
    )
