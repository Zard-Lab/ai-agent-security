#!/usr/bin/env python3
"""Cut a release: bump the (checklist-welded) version and regenerate every derived artifact in one shot.

    python scripts/cut-release.py 0.20.2                 # a PATCH
    python scripts/cut-release.py 0.21.0                 # a MINOR (needs a BREAKING_CHANGES.md entry first)
    python scripts/cut-release.py 0.20.2 --dry-run       # show the plan, write nothing

This removes the manual bump-and-regen dance that made releasing feel like toil
(docs/knowledge/rfc-versioning-and-release-policy.md, issue #331). It mutates the working tree only:
it does NOT commit, tag, or push, so it composes with the normal Loop-B / land-pr flow. It prints the
exact commit + tag + release commands to run next.

What it does, in order:
  1. Validate the version is a forward bump from the current checklist version.
  2. For a MINOR (v0.MINOR.0 = the breaking-change signal): require a matching `## v0.MINOR.0` entry in
     BREAKING_CHANGES.md (the same rule tests/test_versioning_policy.py enforces), and scaffold a full
     `## v0.MINOR.0` CHANGELOG.md entry to fill in. For a PATCH: append a one-line entry to CHANGELOG.md's
     `## Patch Releases` section (use --summary for the text + GitHub Release title, else a placeholder).
  3. Bump agentsec/checklist/checklist.json's `version` + `released`.
  4. Regenerate versions.json (via scripts/regen-versions-json.py), the README badges + prose counts,
     and the coverage tracker (via `agentsec coverage . --write-tracker`).
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import date
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
from agentsec import AGENTSEC_REPO_SLUG  # noqa: E402
from agentsec.console import force_utf8_stdio  # noqa: E402

force_utf8_stdio()

REPO_ROOT = Path(__file__).resolve().parent.parent
CHECKLIST = REPO_ROOT / "agentsec" / "checklist" / "checklist.json"
VERSIONS_JSON = REPO_ROOT / "versions.json"
README = REPO_ROOT / "README.md"
CHANGELOG = REPO_ROOT / "CHANGELOG.md"
BREAKING_CHANGES = REPO_ROOT / "BREAKING_CHANGES.md"
REGEN_SCRIPT = REPO_ROOT / "scripts" / "regen-versions-json.py"
REPO_SLUG = AGENTSEC_REPO_SLUG

Version = tuple[int, int, int]

# A version heading in BREAKING_CHANGES.md, e.g. "## v0.20.0" (kept in sync with test_versioning_policy.py).
_BREAKING_HEADING = re.compile(r"^##\s+v(\d+)\.(\d+)\.(\d+)\s*$", re.MULTILINE)


def parse_version(s: str) -> Version:
    """Parse ``[v]MAJOR.MINOR.PATCH`` into a tuple, rejecting anything else."""
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", s.strip())
    if not m:
        raise ValueError(f"not a MAJOR.MINOR.PATCH version: {s!r}")
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def fmt_version(v: Version) -> str:
    return f"{v[0]}.{v[1]}.{v[2]}"


def release_kind(v: Version) -> str:
    """MINOR when the PATCH component is 0 (the v0.MINOR.0 breaking-change signal), else PATCH."""
    return "MINOR" if v[2] == 0 else "PATCH"


def current_version(checklist_text: str) -> Version:
    return parse_version(json.loads(checklist_text)["version"])


def bump_checklist_text(text: str, new_version: str, released: str) -> str:
    """Rewrite the top-level ``version`` + ``released`` fields.

    ``count=1`` targets only the FIRST match. This relies on the checklist's top-level ``version`` /
    ``released`` being the first such keys in the file (they are the first two keys today), so an item that
    later gains its own ``version``/``released`` key is not touched. A full JSON round-trip would remove that
    ordering assumption but reformats the whole file into a noisy diff, which is not worth it here.
    """
    text = re.sub(r'("version":\s*")[^"]+(")', rf"\g<1>{new_version}\g<2>", text, count=1)
    text = re.sub(r'("released":\s*")[^"]+(")', rf"\g<1>{released}\g<2>", text, count=1)
    return text


def patch_readme(text: str, guard_count: int, version: str, item_count: int) -> str:
    """Update the guards badge + prose and the checklist badge (version + item count) to live values."""
    text = re.sub(r"guards-\d+-brightgreen", f"guards-{guard_count}-brightgreen", text)
    text = re.sub(r"(\*\*)\d+( guards\*\*)", rf"\g<1>{guard_count}\g<2>", text)
    text = re.sub(
        r"checklist-v[0-9.]+%20\(\d+%20items\)",
        f"checklist-v{version}%20({item_count}%20items)",
        text,
    )
    return text


def latest_breaking_minor(text: str) -> int | None:
    """Highest MINOR across all BREAKING_CHANGES.md entries, or None if there are none."""
    minors = [int(m.group(2)) for m in _BREAKING_HEADING.finditer(text)]
    return max(minors) if minors else None


def changelog_has_entry(text: str, version: str) -> bool:
    return re.search(rf"^##\s+v{re.escape(version)}\b", text, re.MULTILINE) is not None


def scaffold_changelog(text: str, version: str, released: str) -> str:
    """Insert a skeleton MINOR entry directly under the ``## Major Releases`` header for the human to fill."""
    skeleton = (
        f"## v{version} - <TITLE>\n\n"
        f"**Date**: {released}\n"
        f"**Focus**: <one-line theme>\n"
        f"**Stability**: Stable\n\n"
        f"### Overview\n<fill in: what changed and why it matters>\n\n"
        f"### Key Changes\n#### ✨ Features\n- \n#### 🔒 Security / Correctness\n- \n\n"
        f"### Impact\n**User-Facing**:\n- \n**Developer-Facing**:\n- \n\n"
        f"### GitHub Issues Closed\n- \n\n---\n\n"
    )
    anchor = "## Major Releases\n\n"
    idx = text.find(anchor)
    if idx == -1:
        raise ValueError("CHANGELOG.md is missing the '## Major Releases' header")
    cut = idx + len(anchor)
    return text[:cut] + skeleton + text[cut:]


def patch_has_entry(text: str, version: str) -> bool:
    """True if the ``## Patch Releases`` list already has a ``- **vX.Y.Z**`` line (idempotency guard)."""
    return re.search(rf"^- \*\*v{re.escape(version)}\*\*", text, re.MULTILINE) is not None


def scaffold_patch(text: str, version: str, released: str, summary: str) -> str:
    """Prepend a one-line patch entry as the newest item under ``## Patch Releases``.

    ``summary`` is a short one-liner (the same string used for the GitHub Release title). Pass a
    ``<SUMMARY>`` placeholder when the maintainer will fill it in, mirroring the MINOR ``<TITLE>``.
    """
    line = f"- **v{version}** ({released}): {summary}\n"
    header = "## Patch Releases\n"
    hidx = text.find(header)
    if hidx == -1:
        raise ValueError("CHANGELOG.md is missing the '## Patch Releases' section")
    # Insert before the newest existing entry (keeps the list newest-first).
    m = re.search(r"^- \*\*v", text[hidx:], re.MULTILINE)
    if m:
        cut = hidx + m.start()
        return text[:cut] + line + text[cut:]
    # Empty list: land after the intro, before the next section boundary (heading / horizontal rule),
    # adding a trailing blank line so the entry keeps the file's blank-before-`---` spacing convention.
    boundary = re.search(r"\n(?:## |---)", text[hidx + len(header):])
    if boundary:
        cut = hidx + len(header) + boundary.start() + 1
        return text[:cut] + line + "\n" + text[cut:]
    return text + line  # no boundary (EOF): append (line already ends with a newline)


def _run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True, cwd=REPO_ROOT)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("version", help="the release version, e.g. 0.20.2 or v0.21.0")
    ap.add_argument("--date", default=date.today().isoformat(), help="release date (default: today)")
    ap.add_argument("--changelog-url", help="override the versions.json changelog URL")
    ap.add_argument("--summary", help="one-line summary for a PATCH's CHANGELOG entry + GitHub Release title")
    ap.add_argument("--dry-run", action="store_true", help="print the plan, write nothing")
    args = ap.parse_args(argv)

    new = parse_version(args.version)
    new_str = fmt_version(new)
    kind = release_kind(new)

    checklist_text = CHECKLIST.read_text(encoding="utf-8")
    cur = current_version(checklist_text)
    if new <= cur:
        print(f"error: v{new_str} is not ahead of the current v{fmt_version(cur)}", file=sys.stderr)
        return 2

    breaking_text = BREAKING_CHANGES.read_text(encoding="utf-8")
    changelog_text = CHANGELOG.read_text(encoding="utf-8")
    scaffolding = kind == "MINOR" and not changelog_has_entry(changelog_text, new_str)
    patch_summary = args.summary or "<SUMMARY>"
    patch_scaffolding = kind == "PATCH" and not patch_has_entry(changelog_text, new_str)

    if kind == "MINOR":
        latest = latest_breaking_minor(breaking_text)
        if latest is None or latest < new[1]:
            print(
                f"error: v{new_str} is a MINOR (breaking) release but BREAKING_CHANGES.md has no matching "
                f"'## v{new_str}' entry. Add it first (policy + tests/test_versioning_policy.py), then re-run.",
                file=sys.stderr,
            )
            return 2

    changelog_url = args.changelog_url or f"https://github.com/{REPO_SLUG}/releases/tag/v{new_str}"

    print(f"Cutting v{new_str} ({kind}) — from v{fmt_version(cur)}, released {args.date}")
    if args.dry_run:
        print("  [dry-run] would bump checklist.json, regenerate versions.json + README + coverage tracker"
              + (", and scaffold a CHANGELOG.md entry" if scaffolding else "")
              + (f", and append a CHANGELOG.md patch line (summary: {patch_summary})" if patch_scaffolding else ""))
        return 0

    CHECKLIST.write_text(bump_checklist_text(checklist_text, new_str, args.date), encoding="utf-8")
    _run([sys.executable, str(REGEN_SCRIPT), "--changelog", changelog_url])

    versions = json.loads(VERSIONS_JSON.read_text(encoding="utf-8"))
    guard_count = int(versions["guard_count"])
    item_count = int(versions["item_count"])
    README.write_text(patch_readme(README.read_text(encoding="utf-8"), guard_count, new_str, item_count),
                      encoding="utf-8")
    _run([sys.executable, "-m", "agentsec", "coverage", ".", "--write-tracker"])

    if scaffolding:
        CHANGELOG.write_text(scaffold_changelog(changelog_text, new_str, args.date), encoding="utf-8")
    elif patch_scaffolding:
        CHANGELOG.write_text(scaffold_patch(changelog_text, new_str, args.date, patch_summary), encoding="utf-8")

    print(f"  bumped to v{new_str} — {guard_count} guards, {item_count} items")
    print("\nNext:")
    print("  git add -A")
    print(f'  git commit -m "chore(release): bump {fmt_version(cur)} -> {new_str} ({kind})"')
    if kind == "MINOR":
        if scaffolding:
            print("  # ^ first fill in the scaffolded CHANGELOG.md v" + new_str + " entry (title + prose)")
        print("  # land via PR, then on main:")
        print(f"  python scripts/check-release-tag.py v{new_str}   # verify sync BEFORE tagging (preventive)")
        print(f'  git tag -s v{new_str} -m "v{new_str} - <title>" && git push origin v{new_str}')
        print("  # ^ -s signs with the release key (issue #620); it prompts for the passphrase, so "
              "tagging is an interactive step and cannot be driven by an agent session")
        print(f"  gh release create v{new_str} --title \"v{new_str} - <title>\" "
              f"--notes-file <(sed -n '/## v{new_str}/,/^---$/p' CHANGELOG.md) --latest")
        print("  # (the <(...) is POSIX-shell only; on Windows, sed the section to a temp file "
              "and pass that to --notes-file)")
    else:
        if patch_scaffolding and not args.summary:
            print(f"  # ^ fill in the <SUMMARY> in CHANGELOG.md's Patch Releases entry for v{new_str} "
                  "(or re-run with --summary)")
        # `<title>` here fills the tag/Release title; the CHANGELOG line uses `<SUMMARY>` (line ~177) —
        # deliberately different placeholders so a grep can tell which artifact still needs the text.
        title = args.summary or "<title>"
        print("  # land via PR, then on main:")
        print(f"  python scripts/check-release-tag.py v{new_str}   # verify sync BEFORE tagging (preventive)")
        print(f'  git tag -s v{new_str} -m "v{new_str} - {title}" && git push origin v{new_str}')
        print("  # ^ -s signs with the release key (issue #620); it prompts for the passphrase, so "
              "tagging is an interactive step and cannot be driven by an agent session")
        print(f'  gh release create v{new_str} --title "v{new_str} - {title}" --generate-notes --latest')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
