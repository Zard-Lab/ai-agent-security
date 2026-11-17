"""Tests for the compose-tmpfs-insecure-options guard (§6c)."""
from __future__ import annotations

from agentsec.guards.compose_tmpfs_insecure_options import ComposeTmpfsInsecureOptionsGuard
from tests.guards._common import *  # noqa: F401,F403

_RULE = "compose-tmpfs-insecure-options/secure-default-removed"


def _prof(tmp_path: Path):
    return mkprofile(tmp_path, features={"docker"})


def _run(tmp_path: Path):
    return ComposeTmpfsInsecureOptionsGuard().run(tmp_path, _prof(tmp_path))


def _compose(tmp_path: Path, body: str) -> None:
    (tmp_path / "docker-compose.yml").write_text(body, encoding="utf-8")


def test_list_form_exec_fires(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    tmpfs:\n      - /tmp:exec\n")
    findings = _run(tmp_path)
    assert any(f.rule == _RULE for f in findings)
    match = next(f for f in findings if f.rule == _RULE)
    assert match.severity == "low"


def test_scalar_form_suid_fires(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    tmpfs: /tmp:suid\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_dev_option_fires(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    tmpfs:\n      - /tmp:size=100m,dev\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_secure_default_options_silent(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    tmpfs:\n      - /tmp:size=100m\n")
    assert _run(tmp_path) == []


def test_bare_tmpfs_path_silent(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    tmpfs:\n      - /tmp\n")
    assert _run(tmp_path) == []


def test_pragma_silences(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "# security: allow-compose-tmpfs-insecure-options\n"
        "services:\n  app:\n    image: alpine\n    tmpfs:\n      - /tmp:exec\n",
    )
    assert _run(tmp_path) == []


def test_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert ComposeTmpfsInsecureOptionsGuard().applies(profile) is False


def test_applies_with_docker() -> None:
    profile = mkprofile(Path("/tmp"), features={"docker"})
    assert ComposeTmpfsInsecureOptionsGuard().applies(profile) is True
