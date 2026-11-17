from __future__ import annotations

from agentsec.guards.debug_default_off import DebugDefaultOffGuard
from tests.guards._common import *  # noqa: F401,F403


def test_debug_default_off_flags_debug_true(tmp_path: Path) -> None:
    (tmp_path / "settings.py").write_text("DEBUG = True\n", encoding="utf-8")
    findings = DebugDefaultOffGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "debug-default-off/debug-enabled"
    assert findings[0].severity == "high"

def test_debug_default_off_flags_fastapi_debug(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("from fastapi import FastAPI\napp = FastAPI(debug=True)\n", encoding="utf-8")
    assert len(DebugDefaultOffGuard().run(tmp_path, _pyprof(tmp_path))) == 1

def test_debug_default_off_flags_typed_default(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text("class S:\n    DEBUG: bool = True\n", encoding="utf-8")
    assert len(DebugDefaultOffGuard().run(tmp_path, _pyprof(tmp_path))) == 1

def test_debug_default_off_passes_false_and_env(tmp_path: Path) -> None:
    (tmp_path / "settings.py").write_text(
        "import os\n"
        "DEBUG = False\n"
        'DEBUG = os.getenv("DEBUG", "") == "1"\n', encoding="utf-8"
    )
    assert DebugDefaultOffGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_debug_default_off_pragma_and_comment(tmp_path: Path) -> None:
    (tmp_path / "settings.py").write_text(
        "DEBUG = True  # security: allow-debug-true\n"
        "# DEBUG = True\n", encoding="utf-8"
    )
    assert DebugDefaultOffGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_debug_default_off_na_without_python() -> None:
    prof = mkprofile(Path("/tmp"), features={"frontend"})
    assert DebugDefaultOffGuard().applies(prof) is False

def test_debug_default_off_docstring_example_silent(tmp_path: Path) -> None:
    # Precision fix: a docstring that MENTIONS debug=True as an anti-pattern should not fire.
    (tmp_path / "guide.py").write_text(
        '"""Configuration guide.\n'
        "\n"
        "Anti-pattern — do not use debug=True in production:\n"
        "    app = FastAPI(debug=True)  # BAD\n"
        '"""\n'
        "app = FastAPI(debug=False)\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert DebugDefaultOffGuard().run(tmp_path, prof) == []



def test_debug_default_off_pragma_quoted_in_a_string_on_the_line_still_fires(tmp_path: Path) -> None:
    # #1040: the pragma phrase inside a string on the flagged line is not a comment, so it must not suppress.
    for note in ("# security: allow-debug-true", "# neutral note"):
        (tmp_path / "settings.py").write_text(f'DEBUG = True; _note = "{note}"\n', encoding="utf-8")
        findings = DebugDefaultOffGuard().run(tmp_path, _pyprof(tmp_path))
        assert [f.rule for f in findings] == ["debug-default-off/debug-enabled"], note
        assert findings[0].location.endswith("settings.py:1")
