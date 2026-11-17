from __future__ import annotations

from agentsec.guards.insecure_tempfile_mktemp import InsecureTempfileMktempGuard
from tests.guards._common import *  # noqa: F401,F403


def test_insecure_tempfile_mktemp_fires(tmp_path: Path) -> None:
    (tmp_path / "exporter.py").write_text(
        "import tempfile\n\n"
        "path = tempfile.mktemp(suffix='.csv')\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = InsecureTempfileMktempGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "insecure-tempfile-mktemp/mktemp-race-condition"
    assert findings[0].severity == "high"


def test_insecure_tempfile_mktemp_fires_no_args(tmp_path: Path) -> None:
    (tmp_path / "exporter.py").write_text(
        "import tempfile\n\n"
        "path = tempfile.mktemp()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = InsecureTempfileMktempGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_insecure_tempfile_mktemp_silent_on_mkstemp(tmp_path: Path) -> None:
    # FP-bait: the safe atomic alternative must not fire.
    (tmp_path / "exporter.py").write_text(
        "import tempfile\n\n"
        "fd, path = tempfile.mkstemp(suffix='.csv')\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    assert InsecureTempfileMktempGuard().run(tmp_path, profile) == []


def test_insecure_tempfile_mktemp_silent_on_named_temporary_file(tmp_path: Path) -> None:
    # FP-bait: another safe alternative must not fire.
    (tmp_path / "exporter.py").write_text(
        "import tempfile\n\n"
        "f = tempfile.NamedTemporaryFile(suffix='.csv')\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    assert InsecureTempfileMktempGuard().run(tmp_path, profile) == []


def test_insecure_tempfile_mktemp_silent_on_unrelated_method(tmp_path: Path) -> None:
    # FP-bait: an unrelated object's .mktemp() (not the tempfile module) must not fire.
    (tmp_path / "custom.py").write_text(
        "path = my_factory.mktemp()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    assert InsecureTempfileMktempGuard().run(tmp_path, profile) == []


def test_insecure_tempfile_mktemp_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "exporter.py").write_text(
        "# security: allow-insecure-tempfile-mktemp\n"
        "import tempfile\n\n"
        "path = tempfile.mktemp()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    assert InsecureTempfileMktempGuard().run(tmp_path, profile) == []


def test_insecure_tempfile_mktemp_not_applies_without_python(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"frontend"})
    assert InsecureTempfileMktempGuard().applies(profile) is False
