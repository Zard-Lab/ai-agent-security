#!/usr/bin/env python3
"""Regenerate versions.json — the published manifest `doctor --check-updates` fetches
(RFC #253 Phase 2, docs/knowledge/rfc-version-staleness-update-awareness.md).

    python scripts/regen-versions-json.py [--changelog URL]

Derives `latest`/`released`/`guard_count`/`item_count` straight from the current
checklist.json + guard registry — the numbers that grow every release — so they can
never drift from what actually shipped. `changelog`, `min_supported`, and `pack` are
maintainer-set fields this script does NOT overwrite once present (they need human
judgment: which tag to link, when to bump the compatibility floor, whether a signed
pack exists yet) — only fill them with a sane placeholder on first creation.

Run this as part of cutting a release, right after bumping checklist.json's version.
Commit the result — `versions.json` lives at the repo root, fetched raw off `main` by
`doctor --check-updates`, the same way `checklist.json` itself is fetched today.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agentsec import AGENTSEC_REPO_SLUG  # noqa: E402
from agentsec.checklist import load_checklist  # noqa: E402

# stdout/stderr as UTF-8 — these scripts print the same non-ASCII the CLI does, and on
# Windows the default cp1252 cannot encode it. Shared with the CLI (#453 review).
from agentsec.console import force_utf8_stdio  # noqa: E402
from agentsec.registry import ALL_GUARDS  # noqa: E402

force_utf8_stdio()

REPO_ROOT = Path(__file__).resolve().parent.parent
VERSIONS_JSON = REPO_ROOT / "versions.json"
REPO_SLUG = AGENTSEC_REPO_SLUG


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--changelog", help="Override the changelog URL for this release")
    args = ap.parse_args()

    cl = load_checklist()
    existing: dict[str, object] = {}
    if VERSIONS_JSON.exists():
        existing = json.loads(VERSIONS_JSON.read_text(encoding="utf-8"))

    data = {
        "latest": cl.version,
        "released": cl.released,
        "guard_count": len(ALL_GUARDS),
        "item_count": len(cl.items),
        "changelog": args.changelog or existing.get(
            "changelog", f"https://github.com/{REPO_SLUG}/releases/tag/v{cl.version}"
        ),
        # Maintainer-set floor (RFC open question #4): below this, doctor --check-updates
        # surfaces a stronger "unsupported" message, not just "behind". Not enforced
        # anywhere else — schema has been additive-only so far, so nothing actually
        # breaks yet on an old registry; this is the hook for when something does.
        "min_supported": existing.get("min_supported", "0.15.0"),
        # Forward-compat bridge to the Definitions-distribution pack-pull model (RFC §6):
        # once a signed pack exists, this is the same index a pack client reads.
        "pack": existing.get("pack", {"url": None, "sha256": None}),
    }

    VERSIONS_JSON.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {VERSIONS_JSON.name}: v{data['latest']} — "
          f"{data['guard_count']} guards, {data['item_count']} items")


if __name__ == "__main__":
    main()
