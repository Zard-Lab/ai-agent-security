from __future__ import annotations

from agentsec.guards.bicep_output_secret_not_secure import BicepOutputSecretNotSecureGuard
from tests.guards._common import *  # noqa: F401,F403


def _bicepprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"bicep"})


def test_bicep_output_secret_flags_unsecured_password_output(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "output adminPassword string = 'not-a-real-password'\n",
        encoding="utf-8",
    )
    findings = BicepOutputSecretNotSecureGuard().run(tmp_path, _bicepprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "bicep-output-secret-not-secure/unsecured-secret-output"
    assert findings[0].severity == "high"


def test_bicep_output_secret_flags_connection_string_camel_case(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "output dbConnectionString string = 'Server=tcp:example;Password=x;'\n",
        encoding="utf-8",
    )
    findings = BicepOutputSecretNotSecureGuard().run(tmp_path, _bicepprof(tmp_path))
    assert len(findings) == 1
    assert "dbConnectionString" in findings[0].message


def test_bicep_output_secret_flags_storage_account_key_camel_case(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "output storageAccountKey string = listKeys(storageAccount.id, '2021-09-01').keys[0].value\n",
        encoding="utf-8",
    )
    findings = BicepOutputSecretNotSecureGuard().run(tmp_path, _bicepprof(tmp_path))
    assert len(findings) == 1
    assert "storageAccountKey" in findings[0].message


def test_bicep_output_secret_flags_api_token_camel_case(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "output apiToken string = tokenParam\n",
        encoding="utf-8",
    )
    findings = BicepOutputSecretNotSecureGuard().run(tmp_path, _bicepprof(tmp_path))
    assert len(findings) == 1
    assert "apiToken" in findings[0].message


def test_bicep_output_secret_fires_regardless_of_literal_value_shape(tmp_path: Path) -> None:
    """Value-shape independence: a plain literal secret-shaped output still fires."""
    (tmp_path / "main.bicep").write_text(
        "output accountKey string = 'literal-value-not-a-function-call'\n",
        encoding="utf-8",
    )
    findings = BicepOutputSecretNotSecureGuard().run(tmp_path, _bicepprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "bicep-output-secret-not-secure/unsecured-secret-output"


def test_bicep_output_secret_fires_regardless_of_function_call_value_shape(tmp_path: Path) -> None:
    """Value-shape independence: a listKeys()-style function-call value still fires -- the
    canonical real-world pattern for surfacing a storage account key via output."""
    (tmp_path / "main.bicep").write_text(
        "output accountKey string = listKeys(storageAccount.id, '2021-09-01').keys[0].value\n",
        encoding="utf-8",
    )
    findings = BicepOutputSecretNotSecureGuard().run(tmp_path, _bicepprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "bicep-output-secret-not-secure/unsecured-secret-output"


def test_bicep_output_secret_silent_when_secure_decorator_present(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "@secure()\n"
        "output adminPassword string = 'not-a-real-password'\n",
        encoding="utf-8",
    )
    assert BicepOutputSecretNotSecureGuard().run(tmp_path, _bicepprof(tmp_path)) == []


def test_bicep_output_secret_silent_on_unrelated_output_name(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "output storageAccountName string = storageAccount.name\n",
        encoding="utf-8",
    )
    assert BicepOutputSecretNotSecureGuard().run(tmp_path, _bicepprof(tmp_path)) == []


def test_bicep_output_secret_not_applicable_without_bicep() -> None:
    prof = mkprofile(Path("/tmp"), features={"arm"})
    assert BicepOutputSecretNotSecureGuard().applies(prof) is False


# --- decorator across a comment line (#844): the FP half -- must STAY silent (widening) ---------
def test_bicep_output_secret_silent_when_secure_split_from_output_by_a_comment(
    tmp_path: Path,
) -> None:
    # FP-bait: the output IS `@secure()`; a `//` doc comment between the two must not resurrect the
    # secret-name finding.
    (tmp_path / "main.bicep").write_text(
        "@secure()\n"
        "// exported connection secret\n"
        "output dbConnectionString string = connStr\n",
        encoding="utf-8",
    )
    assert BicepOutputSecretNotSecureGuard().run(tmp_path, _bicepprof(tmp_path)) == []


# --- decorator with a TRAILING comment (#846): the FP half -- must STAY silent (widening) ---------
def test_bicep_output_secret_silent_when_secure_has_a_trailing_comment(
    tmp_path: Path,
) -> None:
    # FP-bait: the output IS `@secure()`; a `//` comment trailing on that same line must not
    # resurrect the secret-name finding.
    (tmp_path / "main.bicep").write_text(
        "@secure() // exported connection secret\n"
        "output dbConnectionString string = connStr\n",
        encoding="utf-8",
    )
    assert BicepOutputSecretNotSecureGuard().run(tmp_path, _bicepprof(tmp_path)) == []
