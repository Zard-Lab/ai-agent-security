"""README anti-drift guard — the README went stale (239 tests / ~160 items / 7 guards) because
the headline numbers were hand-maintained prose. Pin the two most drift-prone facts to the live
values so a guard/checklist change that forgets the README fails here.

Matches labeled patterns (the badges), not brittle full lines, so prose edits don't break it.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.checklist import load_checklist
from agentsec.registry import ALL_GUARDS, ALL_RUNNERS

_README = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")


def test_readme_guard_count_matches_registry() -> None:
    live = len(ALL_GUARDS)
    m = re.search(r"guards-(\d+)-", _README)  # the shields badge: guards-<N>-brightgreen
    assert m, "README is missing the guards-<N> badge"
    assert int(m.group(1)) == live, f"README guard badge says {m.group(1)}, registry has {live}"
    # also pin the prose count so the body can't drift from the badge
    assert f"{live} guards" in _README or f"{live} dependency-free" in _README, (
        f"README prose should state '{live} guards'"
    )


def test_readme_runner_count_matches_registry() -> None:
    # No other gate owns this: cut-release.py::patch_readme only rewrites the guards badge and
    # the checklist badge/version, this file's own guard-count test only pins guards, and
    # doc_counts.py excludes README by design — so a stale "N optional scanners" count in the
    # product front door could drift silently (review finding M3: README said 10, registry had 11
    # once go-osv-hygiene landed). Pin both prose occurrences to the live runner count.
    live = len(ALL_RUNNERS)
    occurrences = len(re.findall(rf"\*\*{live} optional scanners\*\*", _README))
    assert occurrences >= 2, (
        f"README should state '**{live} optional scanners**' in both the intro and the "
        f"'What it checks' section (registry has {live} runners: {[r.id for r in ALL_RUNNERS]})"
    )


def test_readme_checklist_version_and_count_match() -> None:
    c = load_checklist()
    # Pin the version AND the item count *inside the badge* (not merely present somewhere in the file), so a
    # stale count can't hide behind a coincidental match elsewhere — this is the exact shape cut-release.py
    # (patch_readme) rewrites.
    assert re.search(rf"checklist-v{re.escape(c.version)}%20\({len(c.items)}%20items\)", _README), (
        f"README checklist badge should state v{c.version} ({len(c.items)} items)"
    )
