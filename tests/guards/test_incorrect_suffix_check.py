from __future__ import annotations

from agentsec.guards.incorrect_suffix_check import IncorrectSuffixCheckGuard
from tests.guards._common import *  # noqa: F401,F403


def test_incorrect_suffix_check_fires_on_indexof_length_comparison(tmp_path: Path) -> None:
    (tmp_path / "path.js").write_text(
        "function hasExtension(path, ext) {\n"
        "  return path.indexOf(ext) === path.length - ext.length;\n"
        "}\n",
        encoding="utf-8",
    )
    findings = IncorrectSuffixCheckGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1
    assert findings[0].rule == "incorrect-suffix-check/indexof-endswith-emulation"
    assert findings[0].severity == "medium"


def test_incorrect_suffix_check_fires_on_last_index_of(tmp_path: Path) -> None:
    (tmp_path / "path.js").write_text(
        "function hasExtension(path, ext) {\n"
        "  return path.lastIndexOf(ext) === path.length - ext.length;\n"
        "}\n",
        encoding="utf-8",
    )
    findings = IncorrectSuffixCheckGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1


def test_incorrect_suffix_check_fires_on_string_literal_arg(tmp_path: Path) -> None:
    (tmp_path / "path.js").write_text(
        "function isJson(path) {\n"
        "  return path.indexOf('.json') === path.length - '.json'.length;\n"
        "}\n",
        encoding="utf-8",
    )
    findings = IncorrectSuffixCheckGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1


def test_incorrect_suffix_check_silent_on_endswith(tmp_path: Path) -> None:
    (tmp_path / "path.js").write_text(
        "function hasExtension(path, ext) {\n"
        "  return path.endsWith(ext);\n"
        "}\n",
        encoding="utf-8",
    )
    assert IncorrectSuffixCheckGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_incorrect_suffix_check_silent_on_different_receiver(tmp_path: Path) -> None:
    # FP-bait: the indexOf receiver and the length-comparison receiver are different
    # variables — not the homemade-endsWith shape at all.
    (tmp_path / "app.js").write_text(
        "function check(path, other, ext) {\n"
        "  return path.indexOf(ext) === other.length - ext.length;\n"
        "}\n",
        encoding="utf-8",
    )
    assert IncorrectSuffixCheckGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_incorrect_suffix_check_silent_on_plain_indexof_check(tmp_path: Path) -> None:
    # FP-bait: an ordinary indexOf() != -1 "contains" check has nothing to do with
    # emulating endsWith().
    (tmp_path / "app.js").write_text(
        "function contains(haystack, needle) {\n"
        "  return haystack.indexOf(needle) !== -1;\n"
        "}\n",
        encoding="utf-8",
    )
    assert IncorrectSuffixCheckGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_incorrect_suffix_check_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "path.js").write_text(
        "function hasExtension(path, ext) {\n"
        "  return path.indexOf(ext) === path.length - ext.length;  "
        "// security: allow-incorrect-suffix-check\n"
        "}\n",
        encoding="utf-8",
    )
    assert IncorrectSuffixCheckGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_incorrect_suffix_check_does_not_apply_without_js(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"python", "fastapi"})
    assert IncorrectSuffixCheckGuard().applies(profile) is False
    assert IncorrectSuffixCheckGuard().run(tmp_path, profile) == []


def test_incorrect_suffix_check_applies_with_typescript_only(tmp_path: Path) -> None:
    # Regression (#548 gate review, systemic High): a TS-only repo (no .js, no Express) must
    # not be silently skipped.
    profile = mkprofile(tmp_path, features={"typescript"})
    assert IncorrectSuffixCheckGuard().applies(profile) is True
