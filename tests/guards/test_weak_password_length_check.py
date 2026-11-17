"""Tests for the weak-password-length-check guard.

Covers:
  - weak-password-length-check/short-minimum (LOW)
"""
from __future__ import annotations

from agentsec.guards.weak_password_length_check import WeakPasswordLengthCheckGuard
from tests.guards._common import *  # noqa: F401,F403


def test_fires_on_lt_operator(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "def validate(password):\n"
        "    if len(password) < 8:\n"
        '        raise ValueError("too short")\n',
        encoding="utf-8",
    )
    findings = WeakPasswordLengthCheckGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "weak-password-length-check/short-minimum"
    assert findings[0].severity == "low"


def test_fires_on_le_operator_pwd_variant(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "def validate(pwd):\n"
        "    if len(pwd) <= 6:\n"
        "        return False\n",
        encoding="utf-8",
    )
    findings = WeakPasswordLengthCheckGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1


def test_fires_on_passwd_variant(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "def validate(passwd):\n"
        "    if len(passwd) < 5:\n"
        "        return False\n",
        encoding="utf-8",
    )
    findings = WeakPasswordLengthCheckGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1


def test_passes_strong_length_requirement(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "def validate(password):\n"
        "    if len(password) < 12:\n"
        "        return False\n",
        encoding="utf-8",
    )
    assert WeakPasswordLengthCheckGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_passes_max_length_check(tmp_path: Path) -> None:
    # a `>` comparison is a max-length guard, not a weak minimum-length policy
    (tmp_path / "t.py").write_text(
        "def validate(password):\n"
        "    if len(password) > 100:\n"
        "        return False\n",
        encoding="utf-8",
    )
    assert WeakPasswordLengthCheckGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_passes_unrelated_variable(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "def validate(username):\n"
        "    if len(username) < 3:\n"
        "        return False\n",
        encoding="utf-8",
    )
    assert WeakPasswordLengthCheckGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_passes_commented_out_length_check(tmp_path: Path) -> None:
    # Regression (H2): a fully commented-out length check must not fire — the `#` line comment
    # is stripped before matching (mirrors the sibling weak_secret_key_literal guard).
    (tmp_path / "t.py").write_text(
        "def validate(password):\n"
        "    # legacy: if len(password) < 8: reject  (removed, now uses zxcvbn)\n"
        "    return check(password)\n",
        encoding="utf-8",
    )
    assert WeakPasswordLengthCheckGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "def validate(password):\n"
        "    if len(password) < 8:  # security: allow-weak-password-length\n"
        "        return False\n",
        encoding="utf-8",
    )
    assert WeakPasswordLengthCheckGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_passes_docstring_example(tmp_path: Path) -> None:
    # a weak-length-check EXAMPLE inside a docstring must not self-fire (strip_python_strings)
    (tmp_path / "t.py").write_text(
        '"""Bad:\n    if len(password) < 8:\n        ...\n"""\nx = 1\n',
        encoding="utf-8",
    )
    assert WeakPasswordLengthCheckGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_applies_gate_requires_python_feature(tmp_path: Path) -> None:
    assert WeakPasswordLengthCheckGuard().applies(_pyprof(tmp_path)) is True
    assert WeakPasswordLengthCheckGuard().applies(mkprofile(tmp_path, features={"frontend"})) is False


def test_pragma_quoted_in_a_string_on_the_line_still_fires(tmp_path: Path) -> None:
    # #1040: the pragma quoted in a string on the flagged line is not a comment; neutral run = control.
    for note in ("# reviewed", "# security: allow-weak-password-length"):
        (tmp_path / "t.py").write_text(
            "def validate(password):\n"
            f'    if len(password) < 8 or password == "{note}":\n'
            "        return False\n",
            encoding="utf-8",
        )
        assert len(WeakPasswordLengthCheckGuard().run(tmp_path, _pyprof(tmp_path))) == 1, note
