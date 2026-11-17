from __future__ import annotations

from agentsec.guards.bicep_commandtoexecute_plaintext_settings import (
    BicepCommandtoexecutePlaintextSettingsGuard,
)
from tests.guards._common import *  # noqa: F401,F403


def _bicepprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"bicep"})


def test_bicep_commandtoexecute_flags_secret_in_settings(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "resource vmExt 'Microsoft.Compute/virtualMachines/extensions@2023-03-01' = {\n"
        "  parent: vm\n"
        "  name: 'CustomScript'\n"
        "  properties: {\n"
        "    publisher: 'Microsoft.Azure.Extensions'\n"
        "    type: 'CustomScript'\n"
        "    settings: {\n"
        "      commandToExecute: 'echo ${dbPassword} > /tmp/config'\n"
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    findings = BicepCommandtoexecutePlaintextSettingsGuard().run(tmp_path, _bicepprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "bicep-commandtoexecute-plaintext-settings/secret-in-plaintext-settings"
    assert findings[0].severity == "high"


def test_bicep_commandtoexecute_flags_literal_secret_word_in_settings(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "resource vmExt 'Microsoft.Compute/virtualMachines/extensions@2023-03-01' = {\n"
        "  properties: {\n"
        "    settings: {\n"
        "      commandToExecute: 'configure.sh --secret abc123'\n"
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    findings = BicepCommandtoexecutePlaintextSettingsGuard().run(tmp_path, _bicepprof(tmp_path))
    assert len(findings) == 1


def test_bicep_commandtoexecute_silent_when_under_protected_settings(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "resource vmExt 'Microsoft.Compute/virtualMachines/extensions@2023-03-01' = {\n"
        "  properties: {\n"
        "    publisher: 'Microsoft.Azure.Extensions'\n"
        "    type: 'CustomScript'\n"
        "    settings: {}\n"
        "    protectedSettings: {\n"
        "      commandToExecute: 'echo ${dbPassword} > /tmp/config'\n"
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    assert BicepCommandtoexecutePlaintextSettingsGuard().run(tmp_path, _bicepprof(tmp_path)) == []


def test_bicep_commandtoexecute_silent_when_no_secret_signal(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "resource vmExt 'Microsoft.Compute/virtualMachines/extensions@2023-03-01' = {\n"
        "  properties: {\n"
        "    publisher: 'Microsoft.Azure.Extensions'\n"
        "    type: 'CustomScript'\n"
        "    settings: {\n"
        "      commandToExecute: 'echo hello'\n"
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    assert BicepCommandtoexecutePlaintextSettingsGuard().run(tmp_path, _bicepprof(tmp_path)) == []


def test_bicep_commandtoexecute_silent_on_unrelated_resource_type(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "resource sa 'Microsoft.Storage/storageAccounts@2021-09-01' = {\n"
        "  name: 'sa'\n"
        "  properties: {\n"
        "    settings: {\n"
        "      commandToExecute: 'echo ${dbPassword}'\n"
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    assert BicepCommandtoexecutePlaintextSettingsGuard().run(tmp_path, _bicepprof(tmp_path)) == []


def test_bicep_commandtoexecute_not_applicable_without_bicep() -> None:
    prof = mkprofile(Path("/tmp"), features={"arm"})
    assert BicepCommandtoexecutePlaintextSettingsGuard().applies(prof) is False
