"""Tests for the compose-sensitive-host-mount guard (§6c)."""
from __future__ import annotations

from agentsec.guards.compose_sensitive_host_mount import ComposeSensitiveHostMountGuard
from tests.guards._common import *  # noqa: F401,F403

_RULE = "compose-sensitive-host-mount/sensitive-path"


def _prof(tmp_path: Path):
    return mkprofile(tmp_path, features={"docker"})


def _run(tmp_path: Path):
    return ComposeSensitiveHostMountGuard().run(tmp_path, _prof(tmp_path))


def _compose(tmp_path: Path, body: str) -> None:
    (tmp_path / "docker-compose.yml").write_text(body, encoding="utf-8")


def test_home_root_fires(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    volumes:\n      - /home:/host-home\n")
    findings = _run(tmp_path)
    assert any(f.rule == _RULE for f in findings)
    match = next(f for f in findings if f.rule == _RULE)
    assert match.severity == "high"


def test_ssh_credential_dir_fires(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    volumes:\n      - /home/alice/.ssh:/host-ssh\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_dev_bind_fires(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    volumes:\n      - /dev:/host-dev\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_readonly_root_equivalent_fires(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    volumes:\n      - /etc:/host-etc:ro\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_inert_dev_null_does_not_fire(tmp_path: Path) -> None:
    """FP-bait: /dev/null is a bit bucket, discloses nothing."""
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    volumes:\n      - /dev/null:/dev/null\n")
    assert _run(tmp_path) == []


def test_app_project_dir_under_home_does_not_fire(tmp_path: Path) -> None:
    """FP-bait: a nested application dir under a home tree is not a disclosure."""
    _compose(
        tmp_path,
        "services:\n  app:\n    image: alpine\n    volumes:\n      - /home/alice/projects/app/data:/app/data\n",
    )
    assert _run(tmp_path) == []


def test_pragma_silences(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "# security: allow-sensitive-host-mount\n"
        "services:\n  app:\n    image: alpine\n    volumes:\n      - /home:/host-home\n",
    )
    assert _run(tmp_path) == []


def test_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert ComposeSensitiveHostMountGuard().applies(profile) is False


def test_applies_with_docker() -> None:
    profile = mkprofile(Path("/tmp"), features={"docker"})
    assert ComposeSensitiveHostMountGuard().applies(profile) is True
