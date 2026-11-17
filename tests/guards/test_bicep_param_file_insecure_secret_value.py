from __future__ import annotations

from agentsec.guards.bicep_param_file_insecure_secret_value import (
    BicepParamFileInsecureSecretValueGuard,
)
from tests.guards._common import *  # noqa: F401,F403


def _bicepprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"bicep"})


def test_bicep_param_file_flags_secret_name_with_literal_value(tmp_path: Path) -> None:
    (tmp_path / "main.bicepparam").write_text(
        "using 'main.bicep'\n\nparam dbPassword = 'hardcoded-value-in-the-params-file'\n",
        encoding="utf-8",
    )
    findings = BicepParamFileInsecureSecretValueGuard().run(tmp_path, _bicepprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "bicep-param-file-insecure-secret-value/local-literal"
    assert findings[0].severity == "medium"


def test_bicep_param_file_silent_on_environment_variable_source(tmp_path: Path) -> None:
    (tmp_path / "main.bicepparam").write_text(
        "using 'main.bicep'\n\nparam dbPassword = readEnvironmentVariable('DB_PASSWORD')\n",
        encoding="utf-8",
    )
    assert BicepParamFileInsecureSecretValueGuard().run(tmp_path, _bicepprof(tmp_path)) == []


def test_bicep_param_file_silent_on_keyvault_secret_source(tmp_path: Path) -> None:
    (tmp_path / "main.bicepparam").write_text(
        "using 'main.bicep'\n\n"
        "param apiKey = az.getSecret('mySubscription', 'myRG', 'myVault', 'apiKeySecretName')\n",
        encoding="utf-8",
    )
    assert BicepParamFileInsecureSecretValueGuard().run(tmp_path, _bicepprof(tmp_path)) == []


def test_bicep_param_file_silent_on_non_secret_shaped_name(tmp_path: Path) -> None:
    (tmp_path / "main.bicepparam").write_text(
        "using 'main.bicep'\n\nparam environmentName = 'production'\n",
        encoding="utf-8",
    )
    assert BicepParamFileInsecureSecretValueGuard().run(tmp_path, _bicepprof(tmp_path)) == []


def test_bicep_param_file_not_applicable_without_bicep() -> None:
    prof = mkprofile(Path("/tmp"), features={"arm"})
    assert BicepParamFileInsecureSecretValueGuard().applies(prof) is False
