"""Enforce the versioning + release policy (docs/knowledge/rfc-versioning-and-release-policy.md).

The load-bearing check: the checklist MINOR cannot advance past the most recent ``BREAKING_CHANGES.md``
entry's MINOR. In other words, a ``v0.MINOR.0`` bump (the breaking-change signal) cannot ship without a
matching ``BREAKING_CHANGES.md`` entry. The convention is machine-checked here rather than left to a doc,
because checklist bumps happen often enough that a doc-only rule would erode (issue #331, Marconi's addition).

The topmost entry is allowed to *lead* the current version (a break may be written up against its target
``v0.MINOR.0`` before that release is cut). Only the erosion case fails: a MINOR that moved with no entry.

A parallel check enforces the patch record: a PATCH release (``v0.MINOR.Z``, Z>0) must have its one-line
entry under ``CHANGELOG.md``'s ``## Patch Releases`` section, so the CHANGELOG cannot silently fall behind
the shipped patch (mirrors the major-only enforcement above).
"""

from __future__ import annotations

import re
from pathlib import Path

from agentsec import __version__

_ROOT = Path(__file__).resolve().parents[1]
_BREAKING_CHANGES = _ROOT / "BREAKING_CHANGES.md"
_CHANGELOG = _ROOT / "CHANGELOG.md"

# A version heading in BREAKING_CHANGES.md: a line like "## v0.20.0".
_ENTRY_HEADING = re.compile(r"^##\s+v(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)\s*$", re.MULTILINE)

# A patch line in CHANGELOG.md's "## Patch Releases" list: "- **v0.20.3** (date): summary".
_PATCH_ENTRY = re.compile(r"^- \*\*v(?P<v>\d+\.\d+\.\d+)\*\*", re.MULTILINE)


def _minor(version: str) -> int:
    """Return the MINOR component of a ``MAJOR.MINOR.PATCH`` string.

    NOTE: the whole enforcement scheme keys on MINOR and ignores MAJOR, which is correct only for the
    pre-1.0 SemVer clause this RFC adopts (MAJOR is always 0). This test must be revisited at ``v1.0.0``.
    """
    parts = version.split(".")
    assert len(parts) == 3, f"version {version!r} is not MAJOR.MINOR.PATCH"
    return int(parts[1])


def _latest_breaking_minor() -> int | None:
    """Highest MINOR across all BREAKING_CHANGES.md entries, or None if there are none yet.

    Entries are reverse-chronological, so the topmost is normally the highest; taking ``max`` over every
    entry rather than just the first match means an accidentally-misordered ledger still yields the true
    ceiling instead of a confusing failure that points at the wrong entry.
    """
    text = _BREAKING_CHANGES.read_text(encoding="utf-8")
    minors = [int(m.group("minor")) for m in _ENTRY_HEADING.finditer(text)]
    if not minors:
        return None
    return max(minors)


def test_policy_artifacts_exist() -> None:
    """Both release ledgers must be present (drift guard). The policy doc they cite is private; its
    check lives in the maintainers' private test module."""
    assert _CHANGELOG.is_file(), f"missing CHANGELOG.md: {_CHANGELOG}"
    assert _BREAKING_CHANGES.is_file(), f"missing BREAKING_CHANGES.md: {_BREAKING_CHANGES}"


def test_minor_bump_requires_breaking_changes_entry() -> None:
    """Checklist MINOR must not advance past the latest BREAKING_CHANGES.md entry (issue #331)."""
    current_minor = _minor(__version__)
    latest_entry_minor = _latest_breaking_minor()

    if latest_entry_minor is None:
        # No breaking entries yet: only valid while nothing breaking has shipped. Guard the window
        # explicitly so an empty ledger cannot silently mask a real MINOR advance.
        assert current_minor == 0, (
            "checklist MINOR has advanced but BREAKING_CHANGES.md has no entries; "
            "add an entry for the MINOR bump (see the versioning policy)."
        )
        return

    assert current_minor <= latest_entry_minor, (
        f"checklist MINOR is v0.{current_minor}.x but the latest BREAKING_CHANGES.md entry is "
        f"v0.{latest_entry_minor}.0. A v0.MINOR.0 bump is the breaking-change signal and must be "
        f"documented: add a `## v0.{current_minor}.0` entry to BREAKING_CHANGES.md, or, if this "
        f"release does not break anything, it should be a PATCH (v0.{latest_entry_minor}.Z) not a MINOR."
    )


def test_patch_bump_has_changelog_entry() -> None:
    """A PATCH release (v0.MINOR.Z, Z>0) must have its one-line CHANGELOG `## Patch Releases` entry.

    Vacuous when the current version is a `v0.MINOR.0` (tracked as a structured Major entry instead).
    Mirrors the major-only enforcement: the release record cannot silently fall behind the shipped version.
    """
    if int(__version__.split(".")[2]) == 0:
        return
    entries = {m.group("v") for m in _PATCH_ENTRY.finditer(_CHANGELOG.read_text(encoding="utf-8"))}
    assert __version__ in entries, (
        f"checklist version is v{__version__} (a PATCH) but CHANGELOG.md's `## Patch Releases` section has "
        f"no `- **v{__version__}**` line. Add it, or re-run "
        f'`scripts/cut-release.py {__version__} --summary "..."`, or reconsider whether this is a PATCH.'
    )
