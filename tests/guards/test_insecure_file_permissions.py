"""Tests for the insecure-file-permissions guard.

Covers:
  - insecure-file-permissions/group-or-other-write (HIGH)
"""
from __future__ import annotations

from agentsec.guards.insecure_file_permissions import InsecureFilePermissionsGuard
from tests.guards._common import *  # noqa: F401,F403


def test_fires_on_0o777(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import os\n"
        "os.chmod('/etc/app/secrets.env', 0o777)\n", encoding="utf-8"
    )
    findings = InsecureFilePermissionsGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "insecure-file-permissions/group-or-other-write"
    assert findings[0].severity == "high"


def test_fires_on_0o666(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text("import os\nos.chmod(path, 0o666)\n", encoding="utf-8")
    findings = InsecureFilePermissionsGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1


def test_fires_on_stat_constant(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text("import os, stat\nos.chmod(path, stat.S_IRWXO)\n", encoding="utf-8")
    findings = InsecureFilePermissionsGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1


def test_passes_0o640(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text("import os\nos.chmod(path, 0o640)\n", encoding="utf-8")
    assert InsecureFilePermissionsGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_passes_0o600(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text("import os\nos.chmod(path, 0o600)\n", encoding="utf-8")
    assert InsecureFilePermissionsGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_passes_0o644(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text("import os\nos.chmod(path, 0o644)\n", encoding="utf-8")
    assert InsecureFilePermissionsGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_passes_setuid_owner_only(tmp_path: Path) -> None:
    # 4-digit literal: setuid bit + owner rw only, group/other = 00.
    (tmp_path / "t.py").write_text("import os\nos.chmod(path, 0o4600)\n", encoding="utf-8")
    assert InsecureFilePermissionsGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import os\nos.chmod(path, 0o777)  # security: allow-insecure-permissions\n", encoding="utf-8"
    )
    assert InsecureFilePermissionsGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_passes_0o755(tmp_path: Path) -> None:
    # group/other read+execute, NO write — the ubiquitous mode for executables/dirs, not a finding.
    # (PR #267 review, Major — 0o755 was wrongly flagged)
    (tmp_path / "t.py").write_text("import os\nos.chmod('/usr/local/bin/app', 0o755)\n", encoding="utf-8")
    assert InsecureFilePermissionsGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_passes_0o750(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text("import os\nos.chmod(script_dir, 0o750)\n", encoding="utf-8")
    assert InsecureFilePermissionsGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_fires_on_0o707_other_write(tmp_path: Path) -> None:
    # group none (0), other rwx (7): other still has the WRITE bit, so it must fire
    # (locks the false-negative the review flagged). (PR #267 review)
    (tmp_path / "t.py").write_text("import os\nos.chmod(path, 0o707)\n", encoding="utf-8")
    assert len(InsecureFilePermissionsGuard().run(tmp_path, _pyprof(tmp_path))) == 1


def test_passes_docstring_example(tmp_path: Path) -> None:
    # a 0o777 chmod inside a docstring must not self-fire (strip_python_strings). (PR #267 review)
    (tmp_path / "t.py").write_text('"""Bad:\n    os.chmod(path, 0o777)\n"""\nx = 1\n', encoding="utf-8")
    assert InsecureFilePermissionsGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_insecure_file_permissions_pragma_quoted_in_a_string_on_the_line_still_fires(tmp_path: Path) -> None:
    # The pragma phrase in a string on the flagged line is not a comment, so it must not suppress (#1040).
    def run(note: str) -> list:
        (tmp_path / "t.py").write_text(f'import os\nos.chmod(path, 0o777); _note = "{note}"\n', encoding="utf-8")
        return InsecureFilePermissionsGuard().run(tmp_path, _pyprof(tmp_path))

    assert len(run("neutral")) == 1
    findings = run("# security: allow-insecure-permissions")
    assert len(findings) == 1
    assert findings[0].location.endswith("t.py:2")
