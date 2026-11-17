"""Tests for AuthDisabledByDefaultGuard — planted-violation + FP-bait."""
from __future__ import annotations

from agentsec.guards.auth_disabled_by_default import AuthDisabledByDefaultGuard
from tests.guards._common import *  # noqa: F401,F403


def test_auth_enabled_false_fires(tmp_path: Path) -> None:
    """HIGH: AUTH_ENABLED = False is the CVE-2026-44338 PraisonAI pattern."""
    (tmp_path / "config.py").write_text("AUTH_ENABLED = False\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = AuthDisabledByDefaultGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "auth-disabled-by-default/auth-toggle-literal-false"
    assert findings[0].severity == "high"


def test_auth_token_none_fires(tmp_path: Path) -> None:
    """HIGH: AUTH_REQUIRED = None is a disabling literal too."""
    (tmp_path / "config.py").write_text("AUTH_REQUIRED = None\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = AuthDisabledByDefaultGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_auth_gate_zero_fires(tmp_path: Path) -> None:
    """HIGH: AUTH_GATE = 0 (falsy int literal) fires too."""
    (tmp_path / "config.py").write_text("AUTH_GATE = 0\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = AuthDisabledByDefaultGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_all_toggle_names_fire(tmp_path: Path) -> None:
    """Every curated toggle name in the deny-list fires when set to a disabling literal."""
    names = [
        "AUTH_ENABLED", "AUTHENTICATION_ENABLED", "REQUIRE_AUTH",
        "ENABLE_AUTH", "AUTH_REQUIRED", "AUTH_GATE",
    ]
    for name in names:
        (tmp_path / f"{name.lower()}.py").write_text(f"{name} = False\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = AuthDisabledByDefaultGuard().run(tmp_path, profile)
    assert len(findings) == len(names)


def test_auth_enabled_true_is_safe(tmp_path: Path) -> None:
    """FP-bait: AUTH_ENABLED = True is the safe default -- must not fire."""
    (tmp_path / "config.py").write_text("AUTH_ENABLED = True\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert AuthDisabledByDefaultGuard().run(tmp_path, profile) == []


def test_auth_enabled_from_env_with_safe_default_is_safe(tmp_path: Path) -> None:
    """FP-bait: a dynamic env-derived toggle is not a bare literal -- must not fire."""
    (tmp_path / "config.py").write_text(
        'AUTH_ENABLED = os.getenv("AUTH_ENABLED", "true") == "true"\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert AuthDisabledByDefaultGuard().run(tmp_path, profile) == []


def test_prefixed_identifier_is_safe(tmp_path: Path) -> None:
    """FP-bait: a longer/prefixed identifier must not collide (REQUIRE_AUTH_HEADER, MY_AUTH_GATE)."""
    (tmp_path / "config.py").write_text(
        "REQUIRE_AUTH_HEADER = False\nMY_AUTH_GATE = False\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert AuthDisabledByDefaultGuard().run(tmp_path, profile) == []


def test_function_parameter_default_is_safe(tmp_path: Path) -> None:
    """FP-bait: `def f(AUTH_ENABLED=False):` is a function-parameter default, not the documented
    module-level-constant shape — must not fire (#530 review: this was firing, undocumented and
    untested, before the scope was narrowed to a genuine top-level assignment)."""
    (tmp_path / "config.py").write_text(
        "def create_app(AUTH_ENABLED=False):\n    pass\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert AuthDisabledByDefaultGuard().run(tmp_path, profile) == []


def test_call_site_kwarg_is_safe(tmp_path: Path) -> None:
    """FP-bait: `configure(AUTH_ENABLED=False)` is an explicit call-site keyword argument, not
    the documented module-level-constant shape — must not fire (#530 review)."""
    (tmp_path / "config.py").write_text(
        "configure_server(AUTH_ENABLED=False, port=8080)\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert AuthDisabledByDefaultGuard().run(tmp_path, profile) == []


def test_module_level_constant_after_narrowing_still_fires(tmp_path: Path) -> None:
    """The direction traded against narrowing to column-0 matches: a genuine unindented
    module-level constant, the documented and CVE-2026-44338-matching shape, must still fire."""
    (tmp_path / "config.py").write_text("AUTH_ENABLED = False\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = AuthDisabledByDefaultGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_pragma_suppresses(tmp_path: Path) -> None:
    """The inline pragma silences the finding on that line."""
    (tmp_path / "config.py").write_text(
        "AUTH_ENABLED = False  # security: allow-auth-disabled-by-default\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert AuthDisabledByDefaultGuard().run(tmp_path, profile) == []


def test_comment_only_mention_is_safe(tmp_path: Path) -> None:
    """FP-bait: a comment describing the pattern (not a real assignment) must not fire."""
    (tmp_path / "config.py").write_text(
        "# Do not set AUTH_ENABLED = False in production!\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert AuthDisabledByDefaultGuard().run(tmp_path, profile) == []


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    """A fixture/test file mentioning the pattern is skipped."""
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_config.py").write_text("AUTH_ENABLED = False\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert AuthDisabledByDefaultGuard().run(tmp_path, profile) == []


def test_applies_universally() -> None:
    """Universal guard: this is generic Python config, not framework-gated."""
    assert AuthDisabledByDefaultGuard().applies(mkprofile(Path("/tmp"), features={"java"})) is True
    assert AuthDisabledByDefaultGuard().applies(mkprofile(Path("/tmp"), features=set())) is True


def test_auth_disabled_by_default_pragma_quoted_in_a_string_on_the_line_still_fires(tmp_path: Path) -> None:
    """#1040: the pragma quoted in a string on the flagged line is not a comment; neutral run = control."""
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    for note in ("# reviewed", "# security: allow-auth-disabled-by-default"):
        (tmp_path / "config.py").write_text(f'AUTH_ENABLED = False; _note = "{note}"\n', encoding="utf-8")
        assert len(AuthDisabledByDefaultGuard().run(tmp_path, profile)) == 1, note
