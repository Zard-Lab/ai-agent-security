"""Tests for the dynamic-import-non-literal guard.

Covers:
  - dynamic-import-non-literal/attacker-influenced-name (HIGH)
"""
from __future__ import annotations

from agentsec.guards.dynamic_import_non_literal import DynamicImportNonLiteralGuard
from tests.guards._common import *  # noqa: F401,F403


def test_fires_on_bare_variable_import_module(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import importlib\n"
        "def load(plugin_name):\n"
        "    return importlib.import_module(plugin_name)\n", encoding="utf-8"
    )
    findings = DynamicImportNonLiteralGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "dynamic-import-non-literal/attacker-influenced-name"
    assert findings[0].severity == "high"


def test_fires_on_fstring_import_module(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import importlib\n"
        "def load(name):\n"
        "    return importlib.import_module(f'plugins.{name}')\n", encoding="utf-8"
    )
    findings = DynamicImportNonLiteralGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1


def test_fires_on_dunder_import(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "def load(mod):\n"
        "    return __import__(mod)\n", encoding="utf-8"
    )
    findings = DynamicImportNonLiteralGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1


def test_passes_static_literal(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import importlib\n"
        "def load():\n"
        "    return importlib.import_module('myapp.plugins.pdf_export')\n", encoding="utf-8"
    )
    assert DynamicImportNonLiteralGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_passes_static_literal_with_extra_arg(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import importlib\n"
        "def load():\n"
        "    return importlib.import_module('myapp.plugins.pdf_export', package=None)\n", encoding="utf-8"
    )
    assert DynamicImportNonLiteralGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import importlib\n"
        "def load(name):\n"
        "    return importlib.import_module(name)  # security: allow-dynamic-import\n", encoding="utf-8"
    )
    assert DynamicImportNonLiteralGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_passes_docstring_example(tmp_path: Path) -> None:
    # the anti-pattern inside a docstring must not self-fire (strip_python_strings). (PR #267 review)
    (tmp_path / "t.py").write_text(
        '"""Bad:\n    return importlib.import_module(plugin_name)\n"""\nx = 1\n', encoding="utf-8"
    )
    assert DynamicImportNonLiteralGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_dynamic_import_non_literal_pragma_quoted_in_a_string_on_the_line_still_fires(tmp_path: Path) -> None:
    # #1040: the pragma phrase inside a string on the flagged line is not a comment, so it must not suppress.
    for note in ("# security: allow-dynamic-import", "# neutral note"):
        (tmp_path / "t.py").write_text(
            "import importlib\n"
            "def load(name):\n"
            f'    mod = importlib.import_module(name); _note = "{note}"\n'
            "    return mod\n", encoding="utf-8"
        )
        findings = DynamicImportNonLiteralGuard().run(tmp_path, _pyprof(tmp_path))
        assert [f.rule for f in findings] == ["dynamic-import-non-literal/attacker-influenced-name"], note
        assert findings[0].location.endswith("t.py:3")
