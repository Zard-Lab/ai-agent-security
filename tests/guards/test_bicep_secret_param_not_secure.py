from __future__ import annotations

from agentsec.guards.bicep_secret_param_not_secure import BicepSecretParamNotSecureGuard
from tests.guards._common import *  # noqa: F401,F403


def _bicepprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"bicep"})


def test_bicep_secret_param_flags_unsecured_password_param(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "param password string\n",
        encoding="utf-8",
    )
    findings = BicepSecretParamNotSecureGuard().run(tmp_path, _bicepprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "bicep-secret-param-not-secure/unmarked-secret-param"
    assert findings[0].severity == "high"


def test_bicep_secret_param_flags_camel_case_names(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "param dbPassword string\n"
        "param apiSecret string\n"
        "param storageAccountKey string\n",
        encoding="utf-8",
    )
    findings = BicepSecretParamNotSecureGuard().run(tmp_path, _bicepprof(tmp_path))
    assert len(findings) == 3
    names = {f.location for f in findings}
    assert len(names) == 3


def test_bicep_secret_param_silent_when_secure_decorator_present(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "@secure()\n"
        "param dbPassword string\n",
        encoding="utf-8",
    )
    assert BicepSecretParamNotSecureGuard().run(tmp_path, _bicepprof(tmp_path)) == []


def test_bicep_secret_param_silent_when_securestring_type(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "param dbPassword securestring\n",
        encoding="utf-8",
    )
    assert BicepSecretParamNotSecureGuard().run(tmp_path, _bicepprof(tmp_path)) == []


def test_bicep_secret_param_silent_when_secureobject_type(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "param secretConfig secureobject\n",
        encoding="utf-8",
    )
    assert BicepSecretParamNotSecureGuard().run(tmp_path, _bicepprof(tmp_path)) == []


def test_bicep_secret_param_silent_on_unrelated_param_name(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "param location string\n"
        "param environmentName string\n",
        encoding="utf-8",
    )
    assert BicepSecretParamNotSecureGuard().run(tmp_path, _bicepprof(tmp_path)) == []


def test_bicep_secret_param_not_applicable_without_bicep() -> None:
    prof = mkprofile(Path("/tmp"), features={"arm"})
    assert BicepSecretParamNotSecureGuard().applies(prof) is False


# --- decorator across a comment line (#844): the FP half -- must STAY silent (widening) ---------
def test_bicep_secret_param_silent_when_secure_split_from_param_by_a_comment(
    tmp_path: Path,
) -> None:
    # FP-bait: the param IS `@secure()`; a `//` doc comment between the two must not make the guard
    # tell the user to add a decorator that is already there.
    (tmp_path / "main.bicep").write_text(
        "@secure()\n"
        "// the production DB password\n"
        "param dbPassword string\n",
        encoding="utf-8",
    )
    assert BicepSecretParamNotSecureGuard().run(tmp_path, _bicepprof(tmp_path)) == []


# --- decorator with a TRAILING comment (#846): the FP half -- must STAY silent (widening) ---------
def test_bicep_secret_param_silent_when_secure_has_a_trailing_comment(
    tmp_path: Path,
) -> None:
    # FP-bait: the param IS `@secure()`; a `//` comment trailing on that same line must not make the
    # guard tell the user to add a decorator that is already there.
    (tmp_path / "main.bicep").write_text(
        "@secure() // the production DB password\n"
        "param dbPassword string\n",
        encoding="utf-8",
    )
    assert BicepSecretParamNotSecureGuard().run(tmp_path, _bicepprof(tmp_path)) == []
