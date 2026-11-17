from __future__ import annotations

from agentsec.guards.arm_redis_ssl_disabled import ArmRedisSslDisabledGuard
from tests.guards._common import *  # noqa: F401,F403


def _armprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"arm"})


def test_arm_redis_ssl_flags_enable_non_ssl_port_true(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"resources": [{"type": "Microsoft.Cache/redis", "name": "r", '
        '"properties": {"enableNonSslPort": true}}]}',
        encoding="utf-8",
    )
    findings = ArmRedisSslDisabledGuard().run(tmp_path, _armprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "arm-redis-ssl-disabled/non-ssl-port-enabled"
    assert findings[0].severity == "medium"


def test_arm_redis_ssl_silent_when_property_absent(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"resources": [{"type": "Microsoft.Cache/redis", "name": "r", "properties": {}}]}',
        encoding="utf-8",
    )
    assert ArmRedisSslDisabledGuard().run(tmp_path, _armprof(tmp_path)) == []


def test_arm_redis_ssl_silent_when_explicitly_false(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"resources": [{"type": "Microsoft.Cache/redis", "name": "r", '
        '"properties": {"enableNonSslPort": false}}]}',
        encoding="utf-8",
    )
    assert ArmRedisSslDisabledGuard().run(tmp_path, _armprof(tmp_path)) == []


def test_arm_redis_ssl_silent_on_non_redis_resource(tmp_path: Path) -> None:
    # FP-bait: a different resource type entirely (not even one with a similarly-named property).
    (tmp_path / "template.json").write_text(
        '{"resources": [{"type": "Microsoft.Storage/storageAccounts", "name": "s", '
        '"properties": {"enableNonSslPort": true}}]}',
        encoding="utf-8",
    )
    assert ArmRedisSslDisabledGuard().run(tmp_path, _armprof(tmp_path)) == []


def test_arm_redis_ssl_multiple_resources_only_redis_flagged(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"resources": ['
        '{"type": "Microsoft.Cache/redis", "name": "safe", "properties": {"enableNonSslPort": false}}, '
        '{"type": "Microsoft.Cache/redis", "name": "unsafe", "properties": {"enableNonSslPort": true}}'
        ']}',
        encoding="utf-8",
    )
    findings = ArmRedisSslDisabledGuard().run(tmp_path, _armprof(tmp_path))
    assert len(findings) == 1
    assert "unsafe" in findings[0].message


def test_arm_redis_ssl_not_applicable_without_arm() -> None:
    prof = mkprofile(Path("/tmp"), features={"terraform"})
    assert ArmRedisSslDisabledGuard().applies(prof) is False
