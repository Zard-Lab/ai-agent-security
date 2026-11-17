#!/usr/bin/env python3
"""Guard the welded-version invariant at release time: a `vX.Y.Z` tag's commit must actually declare
version X.Y.Z.

    python scripts/check-release-tag.py v0.20.3        # checks the working tree against the tag name

Run by `.github/workflows/release-tag-guard.yml` on every `v*` tag push (against the tag's checked-out
tree), and usable locally before tagging. The version is welded to `agentsec/checklist/checklist.json`
(and mirrored into `versions.json`), so this asserts:

    tag name  ==  v{checklist.json version}  ==  v{versions.json latest}

Exit 0 if all three agree, exit 1 with an actionable message otherwise. This is the one invariant a plain
pytest can't cover — git tags aren't in the working tree — so it lives in CI on the tag event instead.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# This script NEWLY imports `agentsec` (the shared UTF-8 stdio helper below); it imported nothing
# from the package before. So the insert ENABLES that import rather than fixing a pre-existing
# fall-through, and it is here to make the new import bind THIS checkout rather than whatever
# editable install happens to be on `sys.path` — run from a git worktree it would otherwise bind a
# different tree. The wording matters: `doc_counts.py` carries the other version of this comment
# because it already imported `agentsec` and really was reporting another tree's numbers at exit 0
# (#453 review).
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# stdout/stderr as UTF-8 — these scripts print the same non-ASCII the CLI does, and on
# Windows the default cp1252 cannot encode it. Shared with the CLI (#453 review).
from agentsec.console import force_utf8_stdio  # noqa: E402

force_utf8_stdio()

REPO_ROOT = Path(__file__).resolve().parent.parent
CHECKLIST = REPO_ROOT / "agentsec" / "checklist" / "checklist.json"
VERSIONS_JSON = REPO_ROOT / "versions.json"


def normalize_tag(tag: str) -> str:
    """Strip a leading `refs/tags/` and a leading `v` → the bare `X.Y.Z`."""
    tag = tag.strip()
    tag = re.sub(r"^refs/tags/", "", tag)
    return tag[1:] if tag.startswith("v") else tag


def check(tag: str, checklist_version: str, versions_latest: str) -> tuple[bool, str]:
    """Pure comparison: the tag must equal both the checklist version and versions.json's latest."""
    want = normalize_tag(tag)
    if not re.fullmatch(r"\d+\.\d+\.\d+", want):
        return False, f"tag {tag!r} is not a vMAJOR.MINOR.PATCH release tag"
    mismatches = []
    if checklist_version != want:
        mismatches.append(f"checklist.json version is {checklist_version!r}, tag says {want!r}")
    if versions_latest != want:
        mismatches.append(f"versions.json latest is {versions_latest!r}, tag says {want!r}")
    if mismatches:
        return False, (
            "release-tag drift: " + "; ".join(mismatches) + f".\n"
            f"The version is welded to checklist.json — tag the commit whose checklist version equals the "
            f"tag name (run `scripts/cut-release.py {want}` on the release commit, or fix the tag)."
        )
    return True, f"ok: tag v{want} matches checklist.json and versions.json"


def _read_version(path: Path, key: str) -> str:
    """Read a top-level string key, surfacing a clean actionable message (not a raw traceback) if the
    file is missing/malformed or lacks the key."""
    try:
        return str(json.loads(path.read_text(encoding="utf-8"))[key])
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        print(f"cannot read {key!r} from {path.name}: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: check-release-tag.py <tag>  (e.g. v0.20.3)", file=sys.stderr)
        return 2
    ok, message = check(args[0], _read_version(CHECKLIST, "version"), _read_version(VERSIONS_JSON, "latest"))
    print(message, file=sys.stderr if not ok else sys.stdout)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
