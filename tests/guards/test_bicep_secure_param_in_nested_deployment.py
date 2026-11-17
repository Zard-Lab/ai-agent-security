from __future__ import annotations

from agentsec.guards.bicep_secure_param_in_nested_deployment import (
    BicepSecureParamInNestedDeploymentGuard,
)
from tests.guards._common import *  # noqa: F401,F403


def _bicepprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"bicep"})


def test_bicep_nested_deployment_flags_list_function_reference(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "resource nestedDeploy 'Microsoft.Resources/deployments@2022-09-01' = {\n"
        "  name: 'nested'\n"
        "  properties: {\n"
        "    mode: 'Incremental'\n"
        "    template: {\n"
        "      resources: [\n"
        "        {\n"
        "          type: 'Microsoft.Sql/servers'\n"
        "          properties: {\n"
        "            administratorLoginPassword: listKeys(storageAccount.id, '2021-09-01').keys[0].value\n"
        "          }\n"
        "        }\n"
        "      ]\n"
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    findings = BicepSecureParamInNestedDeploymentGuard().run(tmp_path, _bicepprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "bicep-secure-param-in-nested-deployment/outer-scope-secure-leak"
    assert findings[0].severity == "high"


def test_bicep_nested_deployment_flags_secure_param_reference(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "@secure()\n"
        "param dbPassword string\n"
        "\n"
        "resource nestedDeploy 'Microsoft.Resources/deployments@2022-09-01' = {\n"
        "  name: 'nested'\n"
        "  properties: {\n"
        "    mode: 'Incremental'\n"
        "    template: {\n"
        "      resources: [\n"
        "        {\n"
        "          type: 'Microsoft.Sql/servers'\n"
        "          properties: {\n"
        "            administratorLoginPassword: dbPassword\n"
        "          }\n"
        "        }\n"
        "      ]\n"
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    findings = BicepSecureParamInNestedDeploymentGuard().run(tmp_path, _bicepprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "bicep-secure-param-in-nested-deployment/outer-scope-secure-leak"
    assert "dbPassword" in findings[0].message


def test_bicep_nested_deployment_silent_on_non_secure_param_reference(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "param dbUsername string\n"
        "\n"
        "resource nestedDeploy 'Microsoft.Resources/deployments@2022-09-01' = {\n"
        "  name: 'nested'\n"
        "  properties: {\n"
        "    mode: 'Incremental'\n"
        "    template: {\n"
        "      resources: [\n"
        "        {\n"
        "          type: 'Microsoft.Sql/servers'\n"
        "          properties: {\n"
        "            administratorLogin: dbUsername\n"
        "          }\n"
        "        }\n"
        "      ]\n"
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    assert BicepSecureParamInNestedDeploymentGuard().run(tmp_path, _bicepprof(tmp_path)) == []


def test_bicep_nested_deployment_silent_when_inner_scoped(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "@secure()\n"
        "param dbPassword string\n"
        "\n"
        "resource nestedDeploy 'Microsoft.Resources/deployments@2022-09-01' = {\n"
        "  name: 'nested'\n"
        "  properties: {\n"
        "    mode: 'Incremental'\n"
        "    expressionEvaluationOptions: {\n"
        "      scope: 'inner'\n"
        "    }\n"
        "    template: {\n"
        "      resources: [\n"
        "        {\n"
        "          type: 'Microsoft.Sql/servers'\n"
        "          properties: {\n"
        "            administratorLoginPassword: dbPassword\n"
        "          }\n"
        "        }\n"
        "      ]\n"
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    assert BicepSecureParamInNestedDeploymentGuard().run(tmp_path, _bicepprof(tmp_path)) == []


def test_bicep_nested_deployment_silent_on_unrelated_resource_with_list_substring(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.bicep").write_text(
        "resource sa 'Microsoft.Storage/storageAccounts@2021-09-01' = {\n"
        "  name: 'sa'\n"
        "  properties: {\n"
        "    accessTier: 'listings-hot-tier'\n"
        "    comment: 'list(a, b, c)'\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    assert BicepSecureParamInNestedDeploymentGuard().run(tmp_path, _bicepprof(tmp_path)) == []


def test_bicep_nested_deployment_not_applicable_without_bicep() -> None:
    prof = mkprofile(Path("/tmp"), features={"arm"})
    assert BicepSecureParamInNestedDeploymentGuard().applies(prof) is False


# --- user-defined list*-named functions (PR #843 review, Low) ---------------------------------
# The Azure list* family is matched by PREFIX on purpose (it is open-ended -- any provider
# operation starting with "list"), so an allowlist is not the fix: it would decay into false
# negatives. A call the file itself declares as a user function is the one safe exclusion. Both
# directions are pinned: the user function must go silent, every real/novel list action must fire.

def _nested(expr: str, prelude: str = "") -> str:
    return (
        prelude
        + "resource nestedDeploy 'Microsoft.Resources/deployments@2022-09-01' = {\n"
        "  name: 'nested'\n"
        "  properties: {\n"
        "    mode: 'Incremental'\n"
        "    template: {\n"
        "      resources: [\n"
        "        {\n"
        "          type: 'Microsoft.Sql/servers'\n"
        "          properties: {\n"
        f"            administratorLoginPassword: {expr}\n"
        "          }\n"
        "        }\n"
        "      ]\n"
        "    }\n"
        "  }\n"
        "}\n"
    )


def test_bicep_nested_deployment_silent_on_user_defined_list_named_function(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.bicep").write_text(
        _nested(
            "listActiveRegions('prod')[0]",
            prelude="func listActiveRegions(env string) array => ['eastus']\n\n",
        ),
        encoding="utf-8",
    )
    assert BicepSecureParamInNestedDeploymentGuard().run(tmp_path, _bicepprof(tmp_path)) == []


def test_bicep_nested_deployment_silent_on_exported_user_defined_list_named_function(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.bicep").write_text(
        _nested(
            "listActiveRegions('prod')[0]",
            prelude="@export()\nfunc listActiveRegions(env string) array => ['eastus']\n\n",
        ),
        encoding="utf-8",
    )
    assert BicepSecureParamInNestedDeploymentGuard().run(tmp_path, _bicepprof(tmp_path)) == []


def test_bicep_nested_deployment_flags_a_novel_list_action_not_on_any_allowlist(
    tmp_path: Path,
) -> None:
    # The traded direction: prefix matching must survive, so a provider list action nobody has
    # heard of is still caught.
    (tmp_path / "main.bicep").write_text(
        _nested("listClusterAdminCredential(cluster.id, '2023-01-01').value"),
        encoding="utf-8",
    )
    findings = BicepSecureParamInNestedDeploymentGuard().run(tmp_path, _bicepprof(tmp_path))
    assert len(findings) == 1
    assert "listClusterAdminCredential" in findings[0].message


def test_bicep_nested_deployment_flags_real_list_call_alongside_a_user_function(
    tmp_path: Path,
) -> None:
    # A declared user function must not mask a genuine list* call elsewhere in the same block.
    (tmp_path / "main.bicep").write_text(
        _nested(
            "'${listActiveRegions('prod')[0]}-${listKeys(sa.id, '2021-09-01').keys[0].value}'",
            prelude="func listActiveRegions(env string) array => ['eastus']\n\n",
        ),
        encoding="utf-8",
    )
    findings = BicepSecureParamInNestedDeploymentGuard().run(tmp_path, _bicepprof(tmp_path))
    assert len(findings) == 1
    assert "listKeys" in findings[0].message


def test_bicep_nested_deployment_names_the_matched_list_function_in_the_message(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.bicep").write_text(
        _nested("listSecrets(vault.id, '2023-07-01').value"),
        encoding="utf-8",
    )
    findings = BicepSecureParamInNestedDeploymentGuard().run(tmp_path, _bicepprof(tmp_path))
    assert len(findings) == 1
    assert "`listSecrets(...)` credential-retrieval function" in findings[0].message


# --- decorator across a comment line (#844): the FN half -- must STILL fire (narrowing) ---------
def test_bicep_nested_deployment_flags_secure_param_split_from_decorator_by_a_comment(
    tmp_path: Path,
) -> None:
    # A `//` comment between `@secure()` and the param must not drop it from secure_param_names.
    (tmp_path / "main.bicep").write_text(
        "@secure()\n"
        "// the production DB password\n"
        "param dbPassword string\n"
        "\n"
        "resource nestedDeploy 'Microsoft.Resources/deployments@2022-09-01' = {\n"
        "  name: 'nested'\n"
        "  properties: {\n"
        "    mode: 'Incremental'\n"
        "    template: {\n"
        "      resources: [\n"
        "        {\n"
        "          type: 'Microsoft.Sql/servers'\n"
        "          properties: {\n"
        "            administratorLoginPassword: dbPassword\n"
        "          }\n"
        "        }\n"
        "      ]\n"
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    findings = BicepSecureParamInNestedDeploymentGuard().run(tmp_path, _bicepprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "bicep-secure-param-in-nested-deployment/outer-scope-secure-leak"
    assert "dbPassword" in findings[0].message


# --- decorator with a TRAILING comment (#846): the FN half -- must STILL fire (narrowing) --------
def test_bicep_nested_deployment_flags_secure_param_with_a_trailing_comment(
    tmp_path: Path,
) -> None:
    # A `//` comment trailing on the `@secure()` line itself must not drop it from secure_param_names.
    (tmp_path / "main.bicep").write_text(
        "@secure() // the production DB password\n"
        "param dbPassword string\n"
        "\n"
        "resource nestedDeploy 'Microsoft.Resources/deployments@2022-09-01' = {\n"
        "  name: 'nested'\n"
        "  properties: {\n"
        "    mode: 'Incremental'\n"
        "    template: {\n"
        "      resources: [\n"
        "        {\n"
        "          type: 'Microsoft.Sql/servers'\n"
        "          properties: {\n"
        "            administratorLoginPassword: dbPassword\n"
        "          }\n"
        "        }\n"
        "      ]\n"
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    findings = BicepSecureParamInNestedDeploymentGuard().run(tmp_path, _bicepprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "bicep-secure-param-in-nested-deployment/outer-scope-secure-leak"
    assert "dbPassword" in findings[0].message
