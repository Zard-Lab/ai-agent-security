"""Unit tests for scripts/cut-release.py's pure helpers (the release bump/regen automation, #331)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "cut-release.py"
_spec = importlib.util.spec_from_file_location("cut_release", _SCRIPT)
assert _spec is not None and _spec.loader is not None
cr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cr)


def test_parse_version_accepts_with_and_without_v() -> None:
    assert cr.parse_version("0.20.1") == (0, 20, 1)
    assert cr.parse_version("v0.21.0") == (0, 21, 0)
    assert cr.parse_version("  1.2.3 ") == (1, 2, 3)


@pytest.mark.parametrize("bad", ["0.20", "0.20.1.2", "x", "v1.2", ""])
def test_parse_version_rejects_junk(bad: str) -> None:
    with pytest.raises(ValueError):
        cr.parse_version(bad)


def test_release_kind() -> None:
    assert cr.release_kind((0, 20, 0)) == "MINOR"
    assert cr.release_kind((0, 20, 1)) == "PATCH"
    assert cr.release_kind((1, 0, 0)) == "MINOR"


def test_bump_checklist_text_only_touches_the_header() -> None:
    text = '{\n  "version": "0.20.0",\n  "released": "2026-07-01",\n  "items": [{"version": "keep"}]\n}\n'
    out = cr.bump_checklist_text(text, "0.20.1", "2026-07-05")
    assert '"version": "0.20.1"' in out
    assert '"released": "2026-07-05"' in out
    assert '"version": "keep"' in out  # item-level key untouched (count=1)


def test_patch_readme_updates_badges_and_prose() -> None:
    text = (
        "[![guards](https://img.shields.io/badge/guards-150-brightgreen.svg)](#x)\n"
        "[![checklist](https://img.shields.io/badge/checklist-v0.20.0%20(287%20items)-brightgreen.svg)](y)\n"
        "**150 guards** across the stack\n"
    )
    out = cr.patch_readme(text, 151, "0.20.1", 288)
    assert "guards-151-brightgreen" in out
    assert "checklist-v0.20.1%20(288%20items)" in out
    assert "**151 guards**" in out
    assert "150" not in out


def test_latest_breaking_minor() -> None:
    text = "# Breaking\n\n## v0.20.0\nstuff\n\n## v0.19.0\nolder\n"
    assert cr.latest_breaking_minor(text) == 20
    assert cr.latest_breaking_minor("no entries here") is None
    # a subheading must not be mistaken for an entry
    assert cr.latest_breaking_minor("### v0.99.0\n") is None


def test_changelog_has_entry() -> None:
    text = "## Major Releases\n\n## v0.20.0 - Title\nbody\n"
    assert cr.changelog_has_entry(text, "0.20.0")
    assert not cr.changelog_has_entry(text, "0.21.0")


def test_scaffold_changelog_inserts_under_header() -> None:
    text = "# History\n\n## Major Releases\n\n## v0.20.0 - Old\nbody\n"
    out = cr.scaffold_changelog(text, "0.21.0", "2026-07-05")
    assert "## v0.21.0 - <TITLE>" in out
    # inserted above the previous entry, below the header
    assert out.index("## v0.21.0") < out.index("## v0.20.0 - Old")
    assert out.index("## Major Releases") < out.index("## v0.21.0")


# --- main() orchestration (drives the whole flow against a tmp fixture repo, _run stubbed) ---


def _noop_run(cmd: list[str]) -> None:
    """Stand-in for cut-release's _run so main() never shells out (regen/coverage) during a unit test."""
    _ = cmd


def _fixture_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, breaking: str = "0.20.0") -> dict[str, Path]:
    """Point cut-release's file constants at a minimal tmp repo; stub the subprocess calls to no-ops."""
    checklist = tmp_path / "checklist.json"
    checklist.write_text(json.dumps({"version": "0.20.0", "released": "2026-07-01", "items": [1, 2, 3]}),
                         encoding="utf-8")
    versions = tmp_path / "versions.json"
    versions.write_text(json.dumps({"latest": "0.20.0", "guard_count": 151, "item_count": 288}), encoding="utf-8")
    readme = tmp_path / "README.md"
    readme.write_text(
        "[![guards](https://img.shields.io/badge/guards-150-brightgreen.svg)](#x)\n"
        "[![checklist](https://img.shields.io/badge/checklist-v0.20.0%20(287%20items)-brightgreen.svg)](y)\n"
        "**150 guards**\n",
        encoding="utf-8",
    )
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(
        "# H\n\n## Major Releases\n\n## v0.20.0 - Old\nbody\n\n---\n\n"
        "## Patch Releases\n\nOne line per patch.\n\n- **v0.19.9** (2026-06-01): earlier patch\n",
        encoding="utf-8",
    )
    breaking_md = tmp_path / "BREAKING_CHANGES.md"
    breaking_md.write_text(f"# Breaking\n\n## v{breaking}\nstuff\n", encoding="utf-8")
    for name, path in [("CHECKLIST", checklist), ("VERSIONS_JSON", versions), ("README", readme),
                       ("CHANGELOG", changelog), ("BREAKING_CHANGES", breaking_md)]:
        monkeypatch.setattr(cr, name, path)
    monkeypatch.setattr(cr, "_run", _noop_run)  # don't shell out to regen/coverage in a unit test
    return {"checklist": checklist, "readme": readme, "changelog": changelog}


def _version_of(checklist: Path) -> str:
    return json.loads(checklist.read_text(encoding="utf-8"))["version"]


def test_main_rejects_non_forward_version(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _fixture_repo(tmp_path, monkeypatch)
    assert cr.main(["0.20.0"]) == 2  # equal, not ahead
    assert cr.main(["0.19.9"]) == 2  # behind
    assert _version_of(repo["checklist"]) == "0.20.0"  # unchanged


def test_main_dry_run_writes_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _fixture_repo(tmp_path, monkeypatch)
    assert cr.main(["0.20.1", "--dry-run"]) == 0
    assert _version_of(repo["checklist"]) == "0.20.0"  # not bumped


def test_main_minor_gate_blocks_undocumented_even_under_dry_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _fixture_repo(tmp_path, monkeypatch, breaking="0.20.0")  # no v0.21.0 entry
    assert cr.main(["0.21.0", "--dry-run"]) == 2  # MINOR gate fires before the dry-run return
    assert _version_of(repo["checklist"]) == "0.20.0"  # nothing written


def test_main_patch_bumps_and_patches_readme(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _fixture_repo(tmp_path, monkeypatch)
    assert cr.main(["0.20.1", "--summary", "a fix"]) == 0
    assert _version_of(repo["checklist"]) == "0.20.1"
    readme = repo["readme"].read_text(encoding="utf-8")
    assert "guards-151-brightgreen" in readme
    assert "checklist-v0.20.1%20(288%20items)" in readme  # version + count from versions.json
    assert "**151 guards**" in readme
    changelog = repo["changelog"].read_text(encoding="utf-8")
    assert "## v0.20.1" not in changelog  # PATCH -> no structured entry
    assert "- **v0.20.1** (" in changelog and ": a fix" in changelog  # one-line Patch Releases entry
    # newest-first: the new patch lands above the pre-existing one
    assert changelog.index("**v0.20.1**") < changelog.index("**v0.19.9**")


@pytest.mark.parametrize(("version", "kind"), [("0.20.1", "PATCH"), ("0.21.0", "MINOR")])
def test_main_prints_a_signed_tag_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    version: str, kind: str,
) -> None:
    """The printed next-steps must tag with `-s`, on both release paths (issue #620).

    Release tags are signed with a dedicated SSH key, and this printed line is the only thing that
    tells a maintainer so. It is prose emitted by a script, so nothing else in the suite would notice
    it reverting to `-a`: the tag would still be created, the release would still ship, and the
    signature would simply be absent. Asserting the emitted artifact rather than the exit code.
    """
    _fixture_repo(tmp_path, monkeypatch, breaking=version if kind == "MINOR" else "0.20.0")
    assert cr.main([version, "--summary", "a fix"]) == 0
    out = capsys.readouterr().out
    assert f"git tag -s v{version}" in out
    assert "git tag -a" not in out
    assert "passphrase" in out  # the interactive-step warning travels with it


def test_main_patch_without_summary_uses_placeholder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _fixture_repo(tmp_path, monkeypatch)
    assert cr.main(["0.20.1"]) == 0  # no --summary
    assert "- **v0.20.1** (2026-" in repo["changelog"].read_text(encoding="utf-8")  # placeholder line still written
    assert "<SUMMARY>" in repo["changelog"].read_text(encoding="utf-8")


def test_main_patch_is_idempotent_on_changelog(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Re-cutting the same PATCH must not duplicate its Patch Releases line."""
    repo = _fixture_repo(tmp_path, monkeypatch)
    assert cr.main(["0.20.1", "--summary", "a fix"]) == 0
    text = repo["changelog"].read_text(encoding="utf-8")
    assert text.count("**v0.20.1**") == 1

    # main()'s forward-version check makes a literal second cr.main() at the same version impossible to
    # drive here, so exercise the exact `patch_scaffolding` guard main() uses against the post-run
    # CHANGELOG. This WOULD duplicate the line if `not patch_has_entry(...)` were dropped/inverted.
    if not cr.patch_has_entry(text, "0.20.1"):
        text = cr.scaffold_patch(text, "0.20.1", "2026-07-05", "a fix")
    assert text.count("**v0.20.1**") == 1


def test_scaffold_patch_prepends_newest_first_and_needs_section() -> None:
    text = "# H\n\n## Patch Releases\n\nintro.\n\n- **v0.20.0** (2026-07-01): old\n"
    out = cr.scaffold_patch(text, "0.20.1", "2026-07-05", "new thing")
    assert "- **v0.20.1** (2026-07-05): new thing" in out
    assert out.index("**v0.20.1**") < out.index("**v0.20.0**")  # newest first
    with pytest.raises(ValueError):
        cr.scaffold_patch("# no section here\n", "0.20.1", "2026-07-05", "x")


def test_scaffold_patch_empty_list_keeps_blank_before_boundary() -> None:
    """First entry into an empty Patch Releases list keeps the blank line before the next `---`."""
    text = "# H\n\n## Patch Releases\n\nintro.\n\n---\n\n## Pre-history\n"
    out = cr.scaffold_patch(text, "0.20.1", "2026-07-05", "first")
    assert "- **v0.20.1** (2026-07-05): first\n\n---" in out  # blank line preserved before the rule
    # lands after the intro, above the boundary
    assert out.index("intro.") < out.index("**v0.20.1**") < out.index("---")


def test_patch_has_entry() -> None:
    text = "## Patch Releases\n\n- **v0.20.3** (d): s\n"
    assert cr.patch_has_entry(text, "0.20.3")
    assert not cr.patch_has_entry(text, "0.20.4")


def test_main_minor_scaffolds_changelog(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _fixture_repo(tmp_path, monkeypatch, breaking="0.21.0")  # documented MINOR
    assert cr.main(["0.21.0"]) == 0
    assert _version_of(repo["checklist"]) == "0.21.0"
    assert "## v0.21.0 - <TITLE>" in repo["changelog"].read_text(encoding="utf-8")  # scaffolded
