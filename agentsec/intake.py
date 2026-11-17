"""Slow-clock threat intake — the deterministic helper behind `/threat-intake`.

The two-clock model: the **slow clock** (the `threat-intake` skill) researches new
threats from canonical feeds and *proposes* versioned checklist changes; the
**fast clock** (`audit`/`coverage`/`fix`) runs deterministically against a pinned
checklist version. This module is the deterministic core the slow clock leans on
so its one output — a **docs-only** diff (seen-ledger + proposed-additions doc) —
is structurally sound:

  * a **seen-ledger** (`docs/ledger/intake-ledger.json`) for idempotent runs —
    a `source` (CVE/GHSA/OWASP id) already recorded is skipped, and `excluded`
    records preserve *why* a candidate was dropped;
  * `validate_proposal()` — gates a proposed checklist item against the same
    invariants `load_checklist()` enforces, plus `KNOWN_FEATURES`, and restricts
    intake to `manual`/`partial` items (never `covered` — that is the
    guard-factory's job, so an intake PR can never make a false coverage claim);
  * `cap_proposals()` — enforces the bounded-autonomy cap (G4): at most
    `MAX_PROPOSALS_PER_RUN` proposals leave a run (most severe first), the rest
    deferred (logged, never silently dropped). The bound lives in this
    deterministic core, not only in the skill prose, so a flood is structurally
    impossible — not merely instructed.

Intake is **docs-only**: per proposal it stages a ledger entry (`disposition:
"proposed"`), the machine-readable item in `proposed-items.json`, and a human
rationale in `checklist-proposed-additions.md` — touching neither `checklist.json`
nor the welded version. A maintainer *promotes* accepted proposals with
`scripts/promote-proposal.py <id>` (which inserts the staged item into the
checklist and cuts the PATCH via `scripts/cut-release.py`), at accept time — so
the version stays an honest fingerprint of the *accepted* checklist and an
unreviewed intake PR never goes stale. (Adding a detection is non-breaking, hence
a PATCH, not a MINOR — RFC #253.)

Pure + deterministic: it takes `date` as a parameter (never calls
`date.today()`), does no network, and the research/triage/PR orchestration lives
in the skill, not here.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from agentsec.checklist import Checklist
from agentsec.coverage import KNOWN_FEATURES
from agentsec.findings import SEVERITY_RANK

_DISPOSITIONS = frozenset({"baseline", "proposed", "excluded"})
_INTAKE_STATUSES = frozenset({"manual", "partial"})

# Bounded autonomy (G4): at most this many proposals leave a single intake run.
# Matches the maintainers' threat-intake skill and its design notes.
MAX_PROPOSALS_PER_RUN = 5

# The live `agentsec/` package (the registry, checklist, and guards live here).
# Intake's deterministic core must never write inside it (G4: outputs are the
# seen-ledger + proposal files on a PR branch, never the live registry).
_PKG_DIR = Path(__file__).resolve().parent

_REQUIRED_KEYS = ("id", "section", "section_title", "title", "severity", "standards",
                  "applies_when", "status")


@dataclass(frozen=True)
class LedgerEntry:
    """One recorded intake decision, keyed on a canonical `source` id."""

    source: str           # CVE / GHSA / OWASP doc id — the dedup key
    disposition: str      # baseline | proposed | excluded
    date: str             # YYYY-MM-DD (passed in by the caller — never computed here)
    note: str = ""


def load_ledger(path: Path) -> list[LedgerEntry]:
    """Parse the seen-ledger. Returns [] if the file is missing or empty (never raises on absence)."""
    if not path.is_file():
        return []
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    raw = json.loads(text)
    return [
        LedgerEntry(
            source=str(e["source"]),
            disposition=str(e["disposition"]),
            date=str(e["date"]),
            note=str(e.get("note", "")),
        )
        for e in raw.get("seen", [])
    ]


def _refuse_in_package(path: Path) -> None:
    """G4 (bounded autonomy): **refuse** to write anywhere inside the live `agentsec/`
    package. The registry/checklist/guards live there; intake's only outputs are the
    seen-ledger + proposal staging (both under `docs/ledger/`), on a PR branch — never
    the live registry. This makes "writes only to a proposals PR branch, never the live
    registry" a structural property of the core, not just skill prose. Raises `ValueError`
    on an in-package target (never silently clobbers the registry)."""
    target = path.resolve()
    if target == _PKG_DIR or _PKG_DIR in target.parents:
        raise ValueError(
            f"refusing to write inside the live agentsec package ({path}) — intake writes "
            "the ledger/proposals under docs/ledger/, never the live registry (G4)"
        )


def save_ledger(path: Path, entries: list[LedgerEntry]) -> None:
    """Write the ledger as stable, diff-friendly JSON (2-space, unicode preserved).
    Refuses an in-package target (`_refuse_in_package`, G4)."""
    _refuse_in_package(path)
    payload = {
        "version": 1,
        "seen": [
            {"source": e.source, "disposition": e.disposition, "date": e.date, "note": e.note}
            for e in entries
        ],
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def is_seen(entries: list[LedgerEntry], source: str) -> bool:
    return any(e.source == source for e in entries)


def record(
    entries: list[LedgerEntry], source: str, disposition: str, date: str, note: str = ""
) -> list[LedgerEntry]:
    """Return a new ledger with `source` recorded. Raises on an unknown disposition."""
    if disposition not in _DISPOSITIONS:
        raise ValueError(f"unknown disposition {disposition!r} (expected one of {sorted(_DISPOSITIONS)})")
    return [*entries, LedgerEntry(source=source, disposition=disposition, date=date, note=note)]


# --- proposed-items staging (machine-readable; the promote-side handoff) ------
#
# Docs-only intake stages the *full, validated* checklist item here so a maintainer
# can promote it with `scripts/promote-proposal.py <id>` — no re-authoring from the
# human `checklist-proposed-additions.md` prose. Lives in `docs/ledger/`, so it is
# still outside the live registry (never `checklist.json`, never a version bump).


def load_proposed_items(path: Path) -> list[dict[str, object]]:
    """Parse the machine-readable proposed-items staging file. Returns [] if the file is
    missing or empty (never raises on absence)."""
    if not path.is_file():
        return []
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    raw = json.loads(text)
    return [dict(it) for it in raw.get("items", [])]


def save_proposed_items(path: Path, items: list[dict[str, object]]) -> None:
    """Write the staging file as stable, diff-friendly JSON (2-space, unicode preserved).
    Refuses an in-package target (`_refuse_in_package`, G4)."""
    _refuse_in_package(path)
    payload = {"version": 1, "items": items}
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def stage_proposal(
    items: list[dict[str, object]], item: dict[str, object]
) -> list[dict[str, object]]:
    """Return a new staging list with `item` appended. Raises if an item with the same
    `id` is already staged — idempotent staging, mirroring the ledger's dedup."""
    item_id = str(item.get("id", ""))
    if any(str(it.get("id", "")) == item_id for it in items):
        raise ValueError(f"item id {item_id!r} is already staged")
    return [*items, item]


def validate_proposal(item: dict[str, object], checklist: Checklist) -> list[str]:
    """Return a list of problems with a proposed checklist item ([] == valid).

    Mirrors the loader's invariants (`agentsec.checklist._validate`) plus the
    `applies_when` feature gate, and restricts intake to manual/partial items.
    Pure — no I/O."""
    problems: list[str] = []
    missing = [k for k in _REQUIRED_KEYS if k not in item]
    if missing:
        return [f"missing required key(s): {', '.join(missing)}"]

    item_id = str(item["id"])
    if item_id in {it.id for it in checklist.items}:
        problems.append(f"id {item_id!r} already exists in the checklist")

    status = str(item["status"])
    if status not in _INTAKE_STATUSES:
        problems.append(
            f"status {status!r} not allowed for intake (use one of {sorted(_INTAKE_STATUSES)}; "
            "'covered' is the guard-factory's job)"
        )

    if str(item["severity"]) not in SEVERITY_RANK:
        problems.append(f"bad severity {item['severity']!r} (expected one of {sorted(SEVERITY_RANK)})")

    standards = item["standards"]
    if not isinstance(standards, list) or not standards:
        problems.append("standards must be a non-empty list")

    applies_when = item["applies_when"]
    if not isinstance(applies_when, list):
        problems.append("applies_when must be a list")
    else:
        unknown = [f for f in applies_when if f not in KNOWN_FEATURES]
        if unknown:
            problems.append(f"applies_when has unknown feature(s): {', '.join(map(str, unknown))}")

    # manual items must not carry coverage claims (the loader rejects this too)
    if status == "manual" and (item.get("check_ids") or item.get("verified_by")):
        problems.append("manual item must not carry check_ids/verified_by")

    # manual items must declare how they're verified (the loader requires this too):
    # surface 'code' (reviewable from repo files) or 'ops' (live/deploy/process check).
    if status == "manual":
        if item.get("surface") not in ("code", "ops"):
            problems.append("manual item must declare surface 'code' or 'ops'")
    elif item.get("surface") is not None:
        problems.append(f"surface is only for manual items (status {status!r})")

    return problems


def cap_proposals(
    proposals: list[dict[str, object]], limit: int = MAX_PROPOSALS_PER_RUN
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Enforce the G4 per-run proposal cap. Returns ``(kept, deferred)``.

    Keeps the ``limit`` most severe proposals (by severity rank, then ``id`` — both
    deterministic tiebreaks) and defers the rest, so overflow is **logged, never
    silently dropped** (the caller records the deferred ids). Pure + deterministic:
    the same candidate set always splits the same way. ``limit=0`` defers everything;
    a negative limit is a programming error."""
    if limit < 0:
        raise ValueError(f"limit must be >= 0, got {limit}")
    ordered = sorted(
        proposals,
        key=lambda it: (SEVERITY_RANK.get(str(it.get("severity")), 99), str(it.get("id", ""))),
    )
    return ordered[:limit], ordered[limit:]
