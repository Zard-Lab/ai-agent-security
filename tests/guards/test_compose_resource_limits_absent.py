"""Tests for the compose-resource-limits-absent guard (§6c)."""
from __future__ import annotations

from agentsec.guards.compose_resource_limits_absent import ComposeResourceLimitsAbsentGuard
from tests.guards._common import *  # noqa: F401,F403

_RULE = "compose-resource-limits-absent/no-limits"


def _prof(tmp_path: Path):
    return mkprofile(tmp_path, features={"docker"})


def _run(tmp_path: Path):
    return ComposeResourceLimitsAbsentGuard().run(tmp_path, _prof(tmp_path))


def _compose(tmp_path: Path, body: str) -> None:
    (tmp_path / "docker-compose.yml").write_text(body, encoding="utf-8")


def test_no_limits_at_all_fires(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    command: ['sleep', 'infinity']\n")
    findings = _run(tmp_path)
    assert any(f.rule == _RULE for f in findings)
    match = next(f for f in findings if f.rule == _RULE)
    assert match.severity == "low"


def test_memory_only_fires(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    mem_limit: 512m\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_deploy_resources_limits_both_set_silent(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "services:\n  app:\n    image: alpine\n    deploy:\n      resources:\n        limits:\n"
        "          memory: 512M\n          cpus: '0.50'\n",
    )
    assert _run(tmp_path) == []


def test_mem_limit_and_cpus_both_set_silent(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    mem_limit: 512m\n    cpus: '0.5'\n")
    assert _run(tmp_path) == []


def test_cpu_quota_counts_as_cpu_bound(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    mem_limit: 512m\n    cpu_quota: 50000\n")
    assert _run(tmp_path) == []


def test_pragma_silences(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "# security: allow-compose-resource-limits\n"
        "services:\n  app:\n    image: alpine\n    command: ['sleep', 'infinity']\n",
    )
    assert _run(tmp_path) == []


def test_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert ComposeResourceLimitsAbsentGuard().applies(profile) is False


def test_applies_with_docker() -> None:
    profile = mkprofile(Path("/tmp"), features={"docker"})
    assert ComposeResourceLimitsAbsentGuard().applies(profile) is True
