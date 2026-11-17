"""Tests for the hardcoded-password-default-arg guard.

Covers:
  - hardcoded-password-default-arg/non-empty-literal (HIGH)
"""
from __future__ import annotations

from agentsec.guards.hardcoded_password_default_arg import HardcodedPasswordDefaultArgGuard
from tests.guards._common import *  # noqa: F401,F403


def test_fires_on_typed_default(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        'def connect(host: str, password: str = "admin123") -> None:\n'
        "    pass\n", encoding="utf-8"
    )
    findings = HardcodedPasswordDefaultArgGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "hardcoded-password-default-arg/non-empty-literal"
    assert findings[0].severity == "high"


def test_fires_on_untyped_default(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        'def connect(host, password="admin123"):\n'
        "    pass\n", encoding="utf-8"
    )
    findings = HardcodedPasswordDefaultArgGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1


def test_fires_on_passwd_variant(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        'def login(user, passwd="letmein"):\n'
        "    pass\n", encoding="utf-8"
    )
    findings = HardcodedPasswordDefaultArgGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1


def test_passes_empty_string_default(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        'def connect(host: str, password: str = "") -> None:\n'
        "    pass\n", encoding="utf-8"
    )
    assert HardcodedPasswordDefaultArgGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_passes_no_default(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "def connect(host: str, password: str) -> None:\n"
        "    pass\n", encoding="utf-8"
    )
    assert HardcodedPasswordDefaultArgGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_passes_dict_literal_not_def(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text('config = {"password": "admin123"}\n', encoding="utf-8")
    assert HardcodedPasswordDefaultArgGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_passes_comparison_not_default(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "def check(pw):\n"
        '    if pw == "admin123":\n'
        "        return True\n", encoding="utf-8"
    )
    assert HardcodedPasswordDefaultArgGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        'def connect(password: str = "test-only"):  # security: allow-hardcoded-password-default\n'
        "    pass\n", encoding="utf-8"
    )
    assert HardcodedPasswordDefaultArgGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_passes_docstring_example(tmp_path: Path) -> None:
    # a hardcoded-password default inside a docstring must not self-fire (strip_python_strings). (PR #267 review)
    (tmp_path / "t.py").write_text(
        '"""Bad:\n    def connect(password: str = "admin123") -> None: ...\n"""\nx = 1\n', encoding="utf-8"
    )
    assert HardcodedPasswordDefaultArgGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_hardcoded_password_default_arg_pragma_quoted_in_a_string_on_the_line_still_fires(
    tmp_path: Path,
) -> None:
    # #1040: the pragma phrase as another parameter's string default is not a comment, so it must not suppress.
    for note in ("# security: allow-hardcoded-password-default", "# neutral note"):
        (tmp_path / "t.py").write_text(
            f'def connect(password: str = "admin123", note: str = "{note}") -> None:\n'
            "    pass\n", encoding="utf-8"
        )
        findings = HardcodedPasswordDefaultArgGuard().run(tmp_path, _pyprof(tmp_path))
        assert [f.rule for f in findings] == ["hardcoded-password-default-arg/non-empty-literal"], note
        assert findings[0].location.endswith("t.py:1")
