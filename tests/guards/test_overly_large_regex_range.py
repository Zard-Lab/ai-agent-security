from __future__ import annotations

from agentsec.guards.overly_large_regex_range import OverlyLargeRegexRangeGuard
from tests.guards._common import *  # noqa: F401,F403


def test_overly_large_regex_range_fires_on_a_to_z(tmp_path: Path) -> None:
    (tmp_path / "validate.js").write_text(
        "function isAlpha(value) {\n"
        "  return /^[A-z]+$/.test(value);\n"
        "}\n",
        encoding="utf-8",
    )
    findings = OverlyLargeRegexRangeGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1
    assert findings[0].rule == "overly-large-regex-range/unintended-character-span"
    assert findings[0].severity == "medium"


def test_overly_large_regex_range_fires_on_zero_to_z(tmp_path: Path) -> None:
    (tmp_path / "validate.js").write_text(
        "const RE = /^[0-z]+$/;\n",
        encoding="utf-8",
    )
    findings = OverlyLargeRegexRangeGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1


def test_overly_large_regex_range_fires_on_zero_to_upper_z(tmp_path: Path) -> None:
    (tmp_path / "validate.js").write_text(
        "const RE = /^[0-Z]+$/;\n",
        encoding="utf-8",
    )
    findings = OverlyLargeRegexRangeGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1


def test_overly_large_regex_range_silent_on_correct_range(tmp_path: Path) -> None:
    (tmp_path / "validate.js").write_text(
        "function isAlpha(value) {\n"
        "  return /^[A-Za-z]+$/.test(value);\n"
        "}\n",
        encoding="utf-8",
    )
    assert OverlyLargeRegexRangeGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_overly_large_regex_range_silent_on_alphanumeric_range(tmp_path: Path) -> None:
    # FP-bait: 0-9A-Za-z is the correct, intentionally joined set of ranges.
    (tmp_path / "validate.js").write_text(
        "const RE = /^[0-9A-Za-z]+$/;\n",
        encoding="utf-8",
    )
    assert OverlyLargeRegexRangeGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_overly_large_regex_range_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "validate.js").write_text(
        "const RE = /^[A-z]+$/;  // security: allow-overly-large-regex-range\n",
        encoding="utf-8",
    )
    assert OverlyLargeRegexRangeGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_overly_large_regex_range_does_not_apply_without_js(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"python", "fastapi"})
    assert OverlyLargeRegexRangeGuard().applies(profile) is False
    assert OverlyLargeRegexRangeGuard().run(tmp_path, profile) == []


def test_overly_large_regex_range_applies_with_typescript_only(tmp_path: Path) -> None:
    # Regression (#548 gate review, systemic High): a TS-only repo (a Vite/React frontend with
    # no .js at all and no Express) must not be silently skipped.
    profile = mkprofile(tmp_path, features={"typescript"})
    assert OverlyLargeRegexRangeGuard().applies(profile) is True


def test_overly_large_regex_range_silent_on_range_outside_character_class(tmp_path: Path) -> None:
    # Regression (#548 gate review, Critical 2): "A-z" as ordinary literal text, not inside a
    # `[...]` character class, must not fire — there is no character-class range to widen.
    (tmp_path / "validate.js").write_text(
        "const label = /^Grade A-z$/;\n",
        encoding="utf-8",
    )
    assert OverlyLargeRegexRangeGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_overly_large_regex_range_silent_on_date_range(tmp_path: Path) -> None:
    (tmp_path / "validate.js").write_text(
        "const label = /^date is 2024-2025$/;\n",
        encoding="utf-8",
    )
    assert OverlyLargeRegexRangeGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []
