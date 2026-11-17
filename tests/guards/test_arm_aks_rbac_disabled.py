from __future__ import annotations

from agentsec.guards.arm_aks_rbac_disabled import ArmAksRbacDisabledGuard
from tests.guards._common import *  # noqa: F401,F403


def _armprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"arm"})


def test_arm_aks_rbac_flags_explicit_false(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"resources": [{"type": "Microsoft.ContainerService/managedClusters", "name": "c", '
        '"properties": {"enableRBAC": false}}]}',
        encoding="utf-8",
    )
    findings = ArmAksRbacDisabledGuard().run(tmp_path, _armprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "arm-aks-rbac-disabled/rbac-disabled"
    assert findings[0].severity == "critical"


def test_arm_aks_rbac_flags_absent_property(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"resources": [{"type": "Microsoft.ContainerService/managedClusters", "name": "c", '
        '"properties": {}}]}',
        encoding="utf-8",
    )
    findings = ArmAksRbacDisabledGuard().run(tmp_path, _armprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "arm-aks-rbac-disabled/rbac-disabled"


def test_arm_aks_rbac_silent_when_explicitly_true(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"resources": [{"type": "Microsoft.ContainerService/managedClusters", "name": "c", '
        '"properties": {"enableRBAC": true}}]}',
        encoding="utf-8",
    )
    assert ArmAksRbacDisabledGuard().run(tmp_path, _armprof(tmp_path)) == []


def test_arm_aks_rbac_silent_on_non_aks_resource(tmp_path: Path) -> None:
    # FP-bait: a different resource type entirely (not even one with a similarly-named property).
    (tmp_path / "template.json").write_text(
        '{"resources": [{"type": "Microsoft.Cache/redis", "name": "r", '
        '"properties": {"enableRBAC": false}}]}',
        encoding="utf-8",
    )
    assert ArmAksRbacDisabledGuard().run(tmp_path, _armprof(tmp_path)) == []


def test_arm_aks_rbac_multiple_resources_only_disabled_flagged(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"resources": ['
        '{"type": "Microsoft.ContainerService/managedClusters", "name": "safe", '
        '"properties": {"enableRBAC": true}}, '
        '{"type": "Microsoft.ContainerService/managedClusters", "name": "unsafe", '
        '"properties": {"enableRBAC": false}}'
        ']}',
        encoding="utf-8",
    )
    findings = ArmAksRbacDisabledGuard().run(tmp_path, _armprof(tmp_path))
    assert len(findings) == 1
    assert "unsafe" in findings[0].message


def test_arm_aks_rbac_not_applicable_without_arm() -> None:
    prof = mkprofile(Path("/tmp"), features={"terraform"})
    assert ArmAksRbacDisabledGuard().applies(prof) is False
