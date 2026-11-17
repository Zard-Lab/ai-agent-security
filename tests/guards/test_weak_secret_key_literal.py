"""Tests for the weak-secret-key-literal guard.

Covers:
  - weak-secret-key-literal/known-weak-literal (HIGH)
"""
from __future__ import annotations

from agentsec.guards.weak_secret_key_literal import WeakSecretKeyLiteralGuard
from tests.guards._common import *  # noqa: F401,F403


def test_fires_on_changeme_literal(tmp_path: Path) -> None:
    (tmp_path / "settings.py").write_text('SECRET_KEY = "changeme"\n', encoding="utf-8")
    findings = WeakSecretKeyLiteralGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "weak-secret-key-literal/known-weak-literal"
    assert findings[0].severity == "high"


def test_fires_on_django_insecure_default(tmp_path: Path) -> None:
    (tmp_path / "settings.py").write_text(
        'SECRET_KEY = "django-insecure-abc123xyz"\n',
        encoding="utf-8",
    )
    findings = WeakSecretKeyLiteralGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1


def test_fires_on_app_secret_key_variant(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text('APP_SECRET_KEY = "test-only-value"\n', encoding="utf-8")
    findings = WeakSecretKeyLiteralGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1


def test_fires_on_jwt_secret_key_variant(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text('JWT_SECRET_KEY = "default-signing-key"\n', encoding="utf-8")
    findings = WeakSecretKeyLiteralGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1


def test_passes_strong_random_literal(tmp_path: Path) -> None:
    # FP-bait: a strong random-looking value must never fire (source material's
    # deny-list is a tight prefix match, not entropy scoring).
    (tmp_path / "settings.py").write_text(
        'SECRET_KEY = "kJ8x!mQ2mZpL9vRt3wXbY7cFhN2sD4eG"\n',
        encoding="utf-8",
    )
    assert WeakSecretKeyLiteralGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_passes_comment_mentioning_weak_value(tmp_path: Path) -> None:
    # FP-bait: a comment that merely mentions the word must not fire — only a real
    # assignment statement is matched.
    (tmp_path / "settings.py").write_text(
        '# SECRET_KEY should not be "changeme"\n',
        encoding="utf-8",
    )
    assert WeakSecretKeyLiteralGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_passes_unrelated_variable_name(tmp_path: Path) -> None:
    # A longer identifier that merely contains SECRET_KEY as a substring is not in
    # the tight variable-name deny-list.
    (tmp_path / "settings.py").write_text('MY_SECRET_KEY = "changeme"\n', encoding="utf-8")
    assert WeakSecretKeyLiteralGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_passes_env_var_indirection(tmp_path: Path) -> None:
    (tmp_path / "settings.py").write_text(
        'SECRET_KEY = os.environ.get("SECRET_KEY")\n',
        encoding="utf-8",
    )
    assert WeakSecretKeyLiteralGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "settings.py").write_text(
        'SECRET_KEY = "changeme"  # security: allow-weak-secret-key\n',
        encoding="utf-8",
    )
    assert WeakSecretKeyLiteralGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_passes_docstring_example(tmp_path: Path) -> None:
    # a weak-literal example inside a docstring must not self-fire (strip_python_strings).
    (tmp_path / "settings.py").write_text(
        '"""Bad:\n    SECRET_KEY = "changeme"\n"""\nx = 1\n',
        encoding="utf-8",
    )
    assert WeakSecretKeyLiteralGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_fires_in_a_deployment_tree(tmp_path: Path) -> None:
    # The WIRING test for `credential_scan=True` (#483 re-gate). `alembic` is in the shared
    # non-product list, so without the flag this guard silently stopped seeing the one file that
    # most often holds a real committed credential. The helper's own unit tests cannot catch a
    # regression here: a guard that stops passing the flag, passes the wrong path, or filters the
    # file out earlier in its own discovery loop still leaves them green.
    alembic = tmp_path / "alembic"
    alembic.mkdir()
    (alembic / "env.py").write_text('SECRET_KEY = "changeme"\n', encoding="utf-8")
    findings = WeakSecretKeyLiteralGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["weak-secret-key-literal/known-weak-literal"]
    assert findings[0].location.replace("\\", "/").startswith("alembic/env.py")


def test_stays_silent_in_a_fake_secret_tree(tmp_path: Path) -> None:
    # The FP-bait half: `credential_scan` must NOT reopen the deliberately-fake secrets in
    # `tests/`/`fixtures/`, including a deployment tree nested inside one.
    for rel_dir in ("tests/fixtures", "examples", "tests/alembic"):
        d = tmp_path / rel_dir
        d.mkdir(parents=True, exist_ok=True)
        (d / "settings.py").write_text('SECRET_KEY = "changeme"\n', encoding="utf-8")
    assert WeakSecretKeyLiteralGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_applies_unconditionally() -> None:
    # Generic Python-config pattern, not framework-gated — applies() is always True,
    # even against a profile with no recognized features (same convention as iam_wildcard).
    assert WeakSecretKeyLiteralGuard().applies(_ANY) is True


def test_pragma_quoted_in_a_string_on_the_line_still_fires(tmp_path: Path) -> None:
    # #1040: the pragma quoted in a string on the flagged line is not a comment; neutral run = control.
    for note in ("# reviewed", "# security: allow-weak-secret-key"):
        (tmp_path / "settings.py").write_text(f'SECRET_KEY = "changeme"; _note = "{note}"\n', encoding="utf-8")
        assert len(WeakSecretKeyLiteralGuard().run(tmp_path, _pyprof(tmp_path))) == 1, note


# A form feed is a line break to `str.splitlines()` but not to Python; inside a docstring the
# stripper blanks it, so a pragma set numbered on the raw text lands one line low (#1132 review, H1).
_FF_DOCSTRING = f'"""doc{chr(12)}x\nmore"""\n'


def test_pragma_comment_after_a_form_feed_docstring_stays_on_its_own_line(tmp_path: Path) -> None:
    def run(body: str) -> int:
        (tmp_path / "settings.py").write_text(_FF_DOCSTRING + body, encoding="utf-8")
        return len(WeakSecretKeyLiteralGuard().run(tmp_path, _pyprof(tmp_path)))

    assert run('SECRET_KEY = "changeme"\n') == 1  # control: still detected past the docstring
    assert run('SECRET_KEY = "changeme"  # security: allow-weak-secret-key\n') == 0
    # The other direction: the line ABOVE carries the pragma, so the finding must not be silenced.
    assert run('OTHER = 1  # security: allow-weak-secret-key\nSECRET_KEY = "changeme"\n') == 1
