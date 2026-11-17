#!/usr/bin/env python3
"""Regenerate tests/canary_golden.json — the per-file golden manifest of the assembled canary.

    python scripts/repin-canary-golden.py [--check]

`agentsec/canary.py` no longer holds the whole canary: it assembles the generated repo by
unioning its shrinking base (`_BASE_FILES`/`_LEGACY_EXPECTED`) with every guard's declared
`canary_plant`. This manifest pins the assembled result per plant file, so moving a plant from
the base onto its guard can be PROVEN byte-identical (`test_assembled_canary_matches_golden`).

Why a per-file manifest and not one sha256 of the whole repo: a single pinned hash taxes the
wrong PRs. Adding any new guard legitimately changes the assembled canary, so every unrelated
guard PR would have to re-pin one constant — and two concurrent guard branches then produce a
conflicting one-line hash that cannot be take-both merged. That is the exact append-conflict
hotspot the per-guard-plant work exists to remove, reintroduced inside the gate meant to protect
it. A per-file manifest degrades the per-guard cost to an append, and it carries strictly more
information: it distinguishes *added* (a new guard — re-pin) from *changed* (a migration that was
NOT behavior-preserving — fix the plant, never re-pin).

Run this when you ADD a guard (additions only). Do NOT run it to make a red
`test_assembled_canary_matches_golden` go green after moving a plant — a CHANGED entry means the
move was lossy, and re-pinning would launder exactly the regression the gate exists to catch.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# stdout/stderr as UTF-8 — these scripts print the same non-ASCII the CLI does, and on
# Windows the default cp1252 cannot encode it. Shared with the CLI (#453 review).
from agentsec.canary import _FILES, EXPECTED_RULES  # noqa: E402
from agentsec.console import force_utf8_stdio  # noqa: E402

force_utf8_stdio()

REPO_ROOT = Path(__file__).resolve().parent.parent
GOLDEN_JSON = REPO_ROOT / "tests" / "canary_golden.json"


def build_manifest() -> dict[str, dict[str, object]]:
    """The assembled canary as {files: {path: sha256}, expects: {guard id: [rule, ...]}}.

    Hashes the plant CONTENT rather than storing it: the manifest stays small and readable
    while still being byte-exact, and a diff names the path that moved rather than dumping
    the whole plant. Encoded UTF-8 explicitly — plants carry non-ASCII and the platform
    default (cp1252 on Windows) would hash different bytes on a contributor's machine.
    """
    return {
        "files": {
            path: hashlib.sha256(content.encode("utf-8")).hexdigest()
            for path, content in sorted(_FILES.items())
        },
        "expects": {gid: sorted(rules) for gid, rules in sorted(EXPECTED_RULES.items())},
    }


def render(manifest: dict[str, dict[str, object]]) -> str:
    return json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument(
        "--check",
        action="store_true",
        help="exit 1 if the golden is stale instead of rewriting it (what CI would ask)",
    )
    args = ap.parse_args()

    text = render(build_manifest())
    current = GOLDEN_JSON.read_text(encoding="utf-8") if GOLDEN_JSON.exists() else ""

    if args.check:
        if text != current:
            print(f"STALE: {GOLDEN_JSON.relative_to(REPO_ROOT)} does not match the assembled canary.")
            print("Run `python scripts/repin-canary-golden.py` — but read the diff first: a CHANGED")
            print("entry means a plant migration was not behavior-preserving. Fix the plant, don't re-pin.")
            return 1
        print(f"OK: {GOLDEN_JSON.relative_to(REPO_ROOT)} matches the assembled canary.")
        return 0

    if text == current:
        print(f"unchanged: {GOLDEN_JSON.relative_to(REPO_ROOT)}")
        return 0

    GOLDEN_JSON.parent.mkdir(parents=True, exist_ok=True)
    GOLDEN_JSON.write_text(text, encoding="utf-8")
    manifest_files = build_manifest()["files"]
    print(f"wrote {GOLDEN_JSON.relative_to(REPO_ROOT)} — {len(manifest_files)} plant files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
