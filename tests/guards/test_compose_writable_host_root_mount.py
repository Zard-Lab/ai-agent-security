"""Tests for the compose-writable-host-root-mount guard (§6c)."""
from __future__ import annotations

from agentsec.guards.compose_writable_host_root_mount import ComposeWritableHostRootMountGuard
from tests.guards._common import *  # noqa: F401,F403

_RULE = "compose-writable-host-root-mount/host-root-equivalent"


def _prof(tmp_path: Path):
    return mkprofile(tmp_path, features={"docker"})


def _run(tmp_path: Path):
    return ComposeWritableHostRootMountGuard().run(tmp_path, _prof(tmp_path))


def _compose(tmp_path: Path, body: str) -> None:
    (tmp_path / "docker-compose.yml").write_text(body, encoding="utf-8")


def test_writable_etc_mount_fires(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    volumes:\n      - /etc:/host-etc\n")
    findings = _run(tmp_path)
    assert any(f.rule == _RULE for f in findings)
    match = next(f for f in findings if f.rule == _RULE)
    assert match.severity == "critical"


def test_writable_var_lib_exact_fires(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    volumes:\n      - /var/lib:/x\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_var_lib_mysql_does_not_fire(tmp_path: Path) -> None:
    """FP-bait: /var/lib/mysql is an app data dir, not the container store."""
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    volumes:\n      - /var/lib/mysql:/x\n")
    assert not any(f.rule == _RULE for f in _run(tmp_path))


def test_readonly_root_equivalent_does_not_fire(tmp_path: Path) -> None:
    """FP-bait: :ro is a disclosure, not a writable takeover — this guard's not it."""
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    volumes:\n      - /etc:/host-etc:ro\n")
    assert not any(f.rule == _RULE for f in _run(tmp_path))


def test_relative_bind_does_not_fire(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    volumes:\n      - ./data:/app/data\n")
    assert _run(tmp_path) == []


def test_named_volume_does_not_fire(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    volumes:\n      - pgdata:/var/lib/postgresql/data\n")
    assert _run(tmp_path) == []


def test_whole_root_mount_out_of_scope(tmp_path: Path) -> None:
    """A whole-root mount is docker-socket-access's territory, not this guard's."""
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    volumes:\n      - /:/host\n")
    assert _run(tmp_path) == []


def test_pragma_silences(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "# security: allow-writable-host-root-mount\n"
        "services:\n  app:\n    image: alpine\n    volumes:\n      - /etc:/host-etc\n",
    )
    assert _run(tmp_path) == []


def test_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert ComposeWritableHostRootMountGuard().applies(profile) is False


def test_applies_with_docker() -> None:
    profile = mkprofile(Path("/tmp"), features={"docker"})
    assert ComposeWritableHostRootMountGuard().applies(profile) is True
