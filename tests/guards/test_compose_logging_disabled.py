"""Tests for the compose-logging-disabled guard (§6c)."""
from __future__ import annotations

from agentsec.guards.compose_logging_disabled import ComposeLoggingDisabledGuard
from tests.guards._common import *  # noqa: F401,F403

_RULE = "compose-logging-disabled/driver-none"


def _prof(tmp_path: Path):
    return mkprofile(tmp_path, features={"docker"})


def _run(tmp_path: Path):
    return ComposeLoggingDisabledGuard().run(tmp_path, _prof(tmp_path))


def _compose(tmp_path: Path, body: str) -> None:
    (tmp_path / "docker-compose.yml").write_text(body, encoding="utf-8")


def test_driver_none_fires(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    logging:\n      driver: none\n")
    findings = _run(tmp_path)
    assert any(f.rule == _RULE for f in findings)
    match = next(f for f in findings if f.rule == _RULE)
    assert match.severity == "low"


def test_quoted_driver_none_fires(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    logging:\n      driver: 'none'\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_json_file_driver_silent(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "services:\n  app:\n    image: alpine\n    logging:\n      driver: json-file\n"
        "      options:\n        max-size: 10m\n",
    )
    assert _run(tmp_path) == []


def test_no_logging_block_silent(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n")
    assert _run(tmp_path) == []


def test_pragma_silences(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "# security: allow-compose-logging-disabled\n"
        "services:\n  app:\n    image: alpine\n    logging:\n      driver: none\n",
    )
    assert _run(tmp_path) == []


def test_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert ComposeLoggingDisabledGuard().applies(profile) is False


def test_applies_with_docker() -> None:
    profile = mkprofile(Path("/tmp"), features={"docker"})
    assert ComposeLoggingDisabledGuard().applies(profile) is True
