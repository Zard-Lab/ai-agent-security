from __future__ import annotations

from agentsec.guards.bicep_admin_username_literal import BicepAdminUsernameLiteralGuard
from tests.guards._common import *  # noqa: F401,F403


def _bicepprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"bicep"})


def test_bicep_admin_username_flags_literal(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "resource vm 'Microsoft.Compute/virtualMachines@2023-03-01' = {\n"
        "  name: 'vm'\n"
        "  properties: {\n"
        "    osProfile: {\n"
        "      adminUsername: 'admin'\n"
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    findings = BicepAdminUsernameLiteralGuard().run(tmp_path, _bicepprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "bicep-admin-username-literal/hardcoded-literal"
    assert findings[0].severity == "medium"


def test_bicep_admin_username_silent_on_parameter_reference(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "param adminUsernameParam string\n"
        "resource vm 'Microsoft.Compute/virtualMachines@2023-03-01' = {\n"
        "  name: 'vm'\n"
        "  properties: {\n"
        "    osProfile: {\n"
        "      adminUsername: adminUsernameParam\n"
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    assert BicepAdminUsernameLiteralGuard().run(tmp_path, _bicepprof(tmp_path)) == []


def test_bicep_admin_username_silent_on_property_access_reference(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "resource vm 'Microsoft.Compute/virtualMachines@2023-03-01' = {\n"
        "  name: 'vm'\n"
        "  properties: {\n"
        "    osProfile: {\n"
        "      adminUsername: vmConfig.adminUsername\n"
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    assert BicepAdminUsernameLiteralGuard().run(tmp_path, _bicepprof(tmp_path)) == []


def test_bicep_admin_username_silent_on_unrelated_resource(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "resource sa 'Microsoft.Storage/storageAccounts@2021-09-01' = {\n"
        "  name: 'sa'\n"
        "}\n",
        encoding="utf-8",
    )
    assert BicepAdminUsernameLiteralGuard().run(tmp_path, _bicepprof(tmp_path)) == []


def test_bicep_admin_username_multiple_resources_only_literal_flagged(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "resource safe 'Microsoft.Compute/virtualMachines@2023-03-01' = {\n"
        "  name: 'safe'\n"
        "  properties: { osProfile: { adminUsername: adminParam } }\n"
        "}\n"
        "resource unsafe 'Microsoft.Compute/virtualMachines@2023-03-01' = {\n"
        "  name: 'unsafe'\n"
        "  properties: { osProfile: { adminUsername: 'admin' } }\n"
        "}\n",
        encoding="utf-8",
    )
    findings = BicepAdminUsernameLiteralGuard().run(tmp_path, _bicepprof(tmp_path))
    assert len(findings) == 1
    assert "unsafe" in findings[0].message


def test_bicep_admin_username_not_applicable_without_bicep() -> None:
    prof = mkprofile(Path("/tmp"), features={"arm"})
    assert BicepAdminUsernameLiteralGuard().applies(prof) is False
