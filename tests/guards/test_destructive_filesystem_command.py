"""Tests for the destructive-filesystem-command guard."""
from __future__ import annotations

import pytest

from agentsec.guards.destructive_filesystem_command import DestructiveFilesystemCommandGuard
from tests.guards._common import *  # noqa: F401,F403


def test_fires_on_rm_rf_root(tmp_path: Path) -> None:
    (tmp_path / "wipe.sh").write_text("#!/bin/sh\nrm -rf /\n", encoding="utf-8")
    findings = DestructiveFilesystemCommandGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "destructive-filesystem-command/rm-root" for f in findings)


def test_fires_on_rm_rf_home(tmp_path: Path) -> None:
    (tmp_path / "wipe.sh").write_text("#!/bin/sh\nrm -rf /home\n", encoding="utf-8")
    findings = DestructiveFilesystemCommandGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "destructive-filesystem-command/rm-home-root" for f in findings)


def test_fires_on_rmtree_root(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import shutil\ndef wipe():\n    shutil.rmtree('/')\n", encoding="utf-8"
    )
    findings = DestructiveFilesystemCommandGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "destructive-filesystem-command/rmtree-root" for f in findings)


def test_fires_on_rmtree_expanduser(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import shutil, os\ndef wipe():\n    shutil.rmtree(os.path.expanduser('~'))\n",
        encoding="utf-8",
    )
    findings = DestructiveFilesystemCommandGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "destructive-filesystem-command/rmtree-home" for f in findings)


def test_fires_on_dd_wipe(tmp_path: Path) -> None:
    (tmp_path / "wipe.sh").write_text(
        "#!/bin/sh\ndd if=/dev/zero of=/dev/sda bs=1M\n", encoding="utf-8"
    )
    findings = DestructiveFilesystemCommandGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "destructive-filesystem-command/dd-wipe" for f in findings)


def test_passes_ordinary_subdirectory_cleanup(tmp_path: Path) -> None:
    (tmp_path / "clean.sh").write_text("#!/bin/sh\nrm -rf ./build\nrm -rf /tmp/myapp-cache\n", encoding="utf-8")
    assert DestructiveFilesystemCommandGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_passes_ordinary_rmtree_tempdir(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import shutil, tempfile\n"
        "def cleanup(d):\n"
        "    shutil.rmtree(d)\n",
        encoding="utf-8",
    )
    assert DestructiveFilesystemCommandGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_pragma_suppresses_whole_file(tmp_path: Path) -> None:
    (tmp_path / "wipe.sh").write_text(
        "#!/bin/sh\n# security: allow-destructive-filesystem-command\nrm -rf /\n", encoding="utf-8"
    )
    assert DestructiveFilesystemCommandGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_does_not_apply_with_no_relevant_stack(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features=set())
    assert DestructiveFilesystemCommandGuard().applies(prof) is False


@pytest.mark.parametrize("arg", ["'~'", '"~/"', "'~/'"])
def test_fires_on_rmtree_expanduser_of_the_home_dir_itself(tmp_path: Path, arg: str) -> None:
    (tmp_path / "t.py").write_text(
        f"import shutil, os\ndef wipe():\n    shutil.rmtree(os.path.expanduser({arg}))\n",
        encoding="utf-8",
    )
    findings = DestructiveFilesystemCommandGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["destructive-filesystem-command/rmtree-home"]
    assert findings[0].location.endswith("t.py:3")


@pytest.mark.parametrize("arg", ["'~/.cache/myapp'", '"~/projects/build"', "path", "f'~/{name}'"])
def test_passes_rmtree_expanduser_of_a_subpath_or_variable(tmp_path: Path, arg: str) -> None:
    # Cache/state-dir cleanup is the ordinary use of rmtree + expanduser; only the home
    # directory itself is the sabotage target.
    (tmp_path / "clean_cache.py").write_text(
        f"import shutil, os\ndef clean(path, name):\n    shutil.rmtree(os.path.expanduser({arg}))\n",
        encoding="utf-8",
    )
    assert DestructiveFilesystemCommandGuard().run(tmp_path, _pyprof(tmp_path)) == []
