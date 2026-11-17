from __future__ import annotations

from agentsec.guards.incomplete_url_scheme_check import IncompleteUrlSchemeCheckGuard
from tests.guards._common import *  # noqa: F401,F403


def test_incomplete_url_scheme_check_fires_when_only_javascript_checked(tmp_path: Path) -> None:
    (tmp_path / "sanitize.js").write_text(
        "function isSafeUrl(url) {\n"
        "  return !url.startsWith('javascript:');\n"
        "}\n",
        encoding="utf-8",
    )
    findings = IncompleteUrlSchemeCheckGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1
    assert findings[0].rule == "incomplete-url-scheme-check/missing-dangerous-scheme"
    assert findings[0].severity == "medium"
    assert "vbscript:" in findings[0].message
    assert "data:" in findings[0].message


def test_incomplete_url_scheme_check_silent_when_all_three_checked(tmp_path: Path) -> None:
    (tmp_path / "sanitize.js").write_text(
        "function isSafeUrl(url) {\n"
        "  const bad = ['javascript:', 'vbscript:', 'data:'];\n"
        "  return !bad.some((s) => url.startsWith(s));\n"
        "}\n",
        encoding="utf-8",
    )
    assert IncompleteUrlSchemeCheckGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_incomplete_url_scheme_check_silent_no_scheme_check_at_all(tmp_path: Path) -> None:
    # FP-bait: a file that never does scheme checking at all has nothing to flag.
    (tmp_path / "app.js").write_text(
        "function greet(name) {\n"
        "  return `Hello, ${name}`;\n"
        "}\n",
        encoding="utf-8",
    )
    assert IncompleteUrlSchemeCheckGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_incomplete_url_scheme_check_silent_on_bare_literal_no_check_verb(tmp_path: Path) -> None:
    # FP-bait: the string "javascript:" appears but not inside a check-shaped context
    # (e.g. it's just being logged or displayed).
    (tmp_path / "app.js").write_text(
        "console.log('Blocked scheme: javascript:');\n",
        encoding="utf-8",
    )
    assert IncompleteUrlSchemeCheckGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_incomplete_url_scheme_check_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "sanitize.js").write_text(
        "// security: allow-incomplete-url-scheme-check\n"
        "function isSafeUrl(url) {\n"
        "  return !url.startsWith('javascript:');\n"
        "}\n",
        encoding="utf-8",
    )
    assert IncompleteUrlSchemeCheckGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_incomplete_url_scheme_check_does_not_apply_without_js(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"python", "fastapi"})
    assert IncompleteUrlSchemeCheckGuard().applies(profile) is False
    assert IncompleteUrlSchemeCheckGuard().run(tmp_path, profile) == []


def test_incomplete_url_scheme_check_applies_with_typescript_only(tmp_path: Path) -> None:
    # Regression (#548 gate review, systemic High): a TS-only repo (no .js, no Express) must
    # not be silently skipped.
    profile = mkprofile(tmp_path, features={"typescript"})
    assert IncompleteUrlSchemeCheckGuard().applies(profile) is True
