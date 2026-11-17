"""Unit tests for scripts/check-release-tag.py — the release-tag / checklist-version sync guard."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check-release-tag.py"
_spec = importlib.util.spec_from_file_location("check_release_tag", _SCRIPT)
assert _spec is not None and _spec.loader is not None
crt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(crt)


def test_normalize_tag_strips_ref_and_v() -> None:
    assert crt.normalize_tag("v0.20.3") == "0.20.3"
    assert crt.normalize_tag("refs/tags/v0.20.3") == "0.20.3"
    assert crt.normalize_tag("0.20.3") == "0.20.3"
    assert crt.normalize_tag("  refs/tags/v1.2.3 ") == "1.2.3"


def test_check_passes_when_all_three_agree() -> None:
    ok, msg = crt.check("v0.20.3", "0.20.3", "0.20.3")
    assert ok
    assert "ok" in msg


def test_check_fails_on_checklist_mismatch() -> None:
    ok, msg = crt.check("v0.20.3", "0.20.2", "0.20.3")
    assert not ok
    assert "checklist.json version is '0.20.2'" in msg
    assert "cut-release.py 0.20.3" in msg  # actionable remedy


def test_check_fails_on_versions_json_mismatch() -> None:
    ok, msg = crt.check("v0.20.3", "0.20.3", "0.20.2")
    assert not ok
    assert "versions.json latest is '0.20.2'" in msg


def test_check_reports_both_mismatches() -> None:
    ok, msg = crt.check("v0.20.3", "0.20.1", "0.20.2")
    assert not ok
    assert "checklist.json" in msg and "versions.json" in msg


def test_check_rejects_non_release_tag() -> None:
    ok, msg = crt.check("v0.20", "0.20.0", "0.20.0")
    assert not ok
    assert "not a vMAJOR.MINOR.PATCH" in msg


def test_check_matches_the_current_repo_state() -> None:
    # The live invariant: the current working tree's checklist/versions must agree with each other, and
    # a tag named for that version would pass. (Proves the guard would green-light a correct release.)
    import json

    root = Path(__file__).resolve().parents[1]
    cv = str(json.loads((root / "agentsec" / "checklist" / "checklist.json").read_text(encoding="utf-8"))["version"])
    vl = str(json.loads((root / "versions.json").read_text(encoding="utf-8"))["latest"])
    ok, msg = crt.check(f"v{cv}", cv, vl)
    assert ok, msg  # checklist.json and versions.json are in sync on the current tree


# --- main() (reads the real repo files; the tagged commit's tree at CI time) ---


def test_main_usage_error_on_wrong_argc() -> None:
    assert crt.main([]) == 2
    assert crt.main(["v1", "v2"]) == 2


def test_main_passes_for_the_current_repo_version() -> None:
    import json

    root = Path(__file__).resolve().parents[1]
    cv = str(json.loads((root / "agentsec" / "checklist" / "checklist.json").read_text(encoding="utf-8"))["version"])
    assert crt.main([f"v{cv}"]) == 0


def test_main_fails_on_a_wrong_tag() -> None:
    assert crt.main(["v99.99.99"]) == 1
