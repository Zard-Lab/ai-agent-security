"""Tests for the compose-shared-mount-propagation guard (§6c)."""
from __future__ import annotations

from agentsec.guards.compose_shared_mount_propagation import (
    ComposeSharedMountPropagationGuard,
)
from tests.guards._common import *  # noqa: F401,F403

_RULE = "compose-shared-mount-propagation/shared-propagation"


def _prof(tmp_path: Path):
    return mkprofile(tmp_path, features={"docker"})


def _run(tmp_path: Path):
    return ComposeSharedMountPropagationGuard().run(tmp_path, _prof(tmp_path))


def _compose(tmp_path: Path, body: str) -> None:
    (tmp_path / "docker-compose.yml").write_text(body, encoding="utf-8")


def test_short_syntax_shared_fires(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    volumes:\n      - /host/path:/container/path:shared\n")
    findings = _run(tmp_path)
    assert any(f.rule == _RULE for f in findings)
    match = next(f for f in findings if f.rule == _RULE)
    assert match.severity == "low"


def test_short_syntax_rshared_fires(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    volumes:\n      - /host/path:/container/path:rshared\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_long_syntax_bind_propagation_shared_fires(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "services:\n  app:\n    image: alpine\n    volumes:\n"
        "      - type: bind\n"
        "        source: /host/path\n"
        "        target: /container/path\n"
        "        bind:\n"
        "          propagation: shared\n",
    )
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_slave_propagation_not_flagged(tmp_path: Path) -> None:
    """FP-bait: slave propagates host->container only, not the risk direction this rule covers."""
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    volumes:\n      - /host/path:/container/path:slave\n")
    assert _run(tmp_path) == []


def test_plain_bind_mount_silent(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    volumes:\n      - /host/path:/container/path\n")
    assert _run(tmp_path) == []


def test_pragma_silences(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "# security: allow-compose-shared-mount-propagation\n"
        "services:\n  app:\n    image: alpine\n    volumes:\n      - /host/path:/container/path:shared\n",
    )
    assert _run(tmp_path) == []


def test_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert ComposeSharedMountPropagationGuard().applies(profile) is False


def test_applies_with_docker() -> None:
    profile = mkprofile(Path("/tmp"), features={"docker"})
    assert ComposeSharedMountPropagationGuard().applies(profile) is True
