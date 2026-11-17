"""Pins the finding-severity vs item-severity doctrine.

The doctrine (`docs/knowledge/severity-axes-doctrine.md`): a guard's emitted `Finding.severity`
and the `severity` on the checklist item it maps to are INDEPENDENT axes. A finding's severity is
the risk of that instance; an item's is the risk of the control being absent across the stack.

This file exists because the question has been asked three times and answered informally each time.
It pins the relationship *even though that relationship is "none"* — the point is that a future
reader gets an answer from the suite rather than opening a fourth investigation.

Note what is deliberately NOT here: any assertion that the two agree. Adding one would be the
mistake the doctrine exists to prevent.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.checklist import load_checklist
from agentsec.findings import SEVERITY_RANK

_REPO = Path(__file__).resolve().parent.parent
_GUARDS_DIR = _REPO / "agentsec" / "guards"


def _item_severities_by_check_id() -> dict[str, set[str]]:
    """check-id -> every severity declared by an item mapping to it."""
    out: dict[str, set[str]] = {}
    for item in load_checklist().items:
        for cid in item.check_ids:
            out.setdefault(cid, set()).add(item.severity)
    return out


def _source_severities_by_guard_id() -> dict[str, set[str]]:
    """guard-id -> every literal `severity="..."` in that guard's module.

    The STATIC read (method B in the doctrine doc). It cannot see a computed severity, and it
    treats a multi-severity guard as agreeing if ANY branch matches — which is exactly why it
    counts fewer disagreements than the runtime method. Both are documented; neither is canonical.
    """
    out: dict[str, set[str]] = {}
    for path in sorted(_GUARDS_DIR.glob("*.py")):
        if path.name.startswith("_") or path.name == "base.py":
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        m = re.search(r'^\s*id\s*[:=]\s*["\']([^"\']+)["\']', text, re.M)
        if not m:
            continue
        sevs = {s for s in re.findall(r'severity\s*=\s*["\']([a-z]+)["\']', text) if s in SEVERITY_RANK}
        if sevs:
            out[m.group(1)] = sevs
    return out


# `test_severity_axes_doctrine_is_documented` lives in the maintainers' private test module: it reads a file this repository does
# not publish.


def test_guard_and_item_severity_are_allowed_to_disagree() -> None:
    """The absence of a gate is itself the invariant, so pin it.

    If someone 'aligns' every guard to its item, this fails and points at the doctrine. That is
    the intended failure: a repo-wide alignment pass destroys real information in both directions
    (per-finding severities inflate into noise at the default `--fail-on high` gate, or item
    severities deflate until the coverage score card stops reflecting control risk).
    """
    items = _item_severities_by_check_id()
    source = _source_severities_by_guard_id()
    disagreeing = [
        gid for gid, emitted in source.items()
        if gid in items and not (emitted & items[gid])
    ]
    assert disagreeing, (
        "no guard disagrees with its checklist item on severity. If that is the result of a "
        "deliberate alignment pass, it contradicts docs/knowledge/severity-axes-doctrine.md — "
        "the two are independent axes and disagreement is expected, not drift."
    )


def test_bola_is_the_canonical_intentional_disagreement() -> None:
    """`bola` is the worked example in the doctrine, so it is the one pinned by name.

    It emits `medium` per finding (one unscoped route is usually one object class) against a
    `critical` item (an app with NO object-level authorization anywhere is a different
    proposition). Both are correct. If either moves, the doc's worked example must move with it.
    """
    items = _item_severities_by_check_id()
    source = _source_severities_by_guard_id()
    assert "bola" in source, "bola guard not found — update the doctrine doc's worked example"
    assert "bola" in items, "bola is not mapped to any checklist item"
    assert "medium" in source["bola"], (
        f"bola now emits {sorted(source['bola'])}, not medium. The doctrine doc uses it as the "
        "worked example for per-instance vs per-control severity — update the doc to match."
    )
    assert items["bola"] == {"critical"}, (
        f"bola's item now declares {sorted(items['bola'])}, not critical. Same as above: the "
        "doctrine doc's worked example needs updating."
    )
    assert not (source["bola"] & items["bola"]), (
        "bola's guard and item severities now agree. If that was deliberate, the doctrine doc "
        "needs a new worked example; if not, it is an unintended alignment."
    )
