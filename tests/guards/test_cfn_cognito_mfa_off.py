from __future__ import annotations

from agentsec.guards.cfn_cognito_mfa_off import CfnCognitoMfaOffGuard
from tests.guards._common import *  # noqa: F401,F403


def _cfnprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"cloudformation"})


def test_cfn_cognito_mfa_off_flags_explicit_off(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyPool:\n    Type: AWS::Cognito::UserPool\n    Properties:\n"
        "      MfaConfiguration: OFF\n",
        encoding="utf-8",
    )
    findings = CfnCognitoMfaOffGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-cognito-mfa-off/mfa-disabled"
    assert findings[0].severity == "high"


def test_cfn_cognito_mfa_off_flags_explicit_off_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Resources": {"MyPool": {"Type": "AWS::Cognito::UserPool", '
        '"Properties": {"MfaConfiguration": "OFF"}}}}',
        encoding="utf-8",
    )
    findings = CfnCognitoMfaOffGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-cognito-mfa-off/mfa-disabled"


def test_cfn_cognito_mfa_off_flags_missing_property(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyPool:\n    Type: AWS::Cognito::UserPool\n    Properties:\n"
        "      UserPoolName: mypool\n",
        encoding="utf-8",
    )
    findings = CfnCognitoMfaOffGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-cognito-mfa-off/mfa-disabled"


def test_cfn_cognito_mfa_off_flags_missing_property_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Resources": {"MyPool": {"Type": "AWS::Cognito::UserPool", "Properties": {}}}}',
        encoding="utf-8",
    )
    findings = CfnCognitoMfaOffGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1


def test_cfn_cognito_mfa_off_silent_when_on(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyPool:\n    Type: AWS::Cognito::UserPool\n    Properties:\n"
        "      MfaConfiguration: ON\n",
        encoding="utf-8",
    )
    assert CfnCognitoMfaOffGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_cognito_mfa_off_silent_when_optional(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyPool:\n    Type: AWS::Cognito::UserPool\n    Properties:\n"
        "      MfaConfiguration: OPTIONAL\n",
        encoding="utf-8",
    )
    assert CfnCognitoMfaOffGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_cognito_mfa_off_silent_when_on_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Resources": {"MyPool": {"Type": "AWS::Cognito::UserPool", '
        '"Properties": {"MfaConfiguration": "ON"}}}}',
        encoding="utf-8",
    )
    assert CfnCognitoMfaOffGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_cognito_mfa_off_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyPool:\n    Type: AWS::Cognito::UserPool\n    Properties:\n"
        "      UserPoolName: x # security: allow-cfn-cognito-mfa-off\n",
        encoding="utf-8",
    )
    assert CfnCognitoMfaOffGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_cognito_mfa_off_silent_on_non_cognito_resource(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n    Properties: {}\n",
        encoding="utf-8",
    )
    assert CfnCognitoMfaOffGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_cognito_mfa_off_not_applicable_without_cloudformation() -> None:
    prof = mkprofile(Path("/tmp"), features={"terraform"})
    assert CfnCognitoMfaOffGuard().applies(prof) is False
