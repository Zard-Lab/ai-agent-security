from __future__ import annotations

from agentsec.guards.cfn_cognito_unauth_identities import CfnCognitoUnauthIdentitiesGuard
from tests.guards._common import *  # noqa: F401,F403


def _cfnprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"cloudformation"})


def test_cfn_cognito_unauth_identities_flags_true(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyPool:\n    Type: AWS::Cognito::IdentityPool\n"
        "    Properties:\n      IdentityPoolName: mypool\n"
        "      AllowUnauthenticatedIdentities: true\n",
        encoding="utf-8",
    )
    findings = CfnCognitoUnauthIdentitiesGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-cognito-unauth-identities/allow-unauthenticated"
    assert findings[0].severity == "high"


def test_cfn_cognito_unauth_identities_flags_true_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Resources": {"MyPool": {"Type": "AWS::Cognito::IdentityPool", '
        '"Properties": {"AllowUnauthenticatedIdentities": true}}}}',
        encoding="utf-8",
    )
    findings = CfnCognitoUnauthIdentitiesGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-cognito-unauth-identities/allow-unauthenticated"


def test_cfn_cognito_unauth_identities_silent_when_false(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyPool:\n    Type: AWS::Cognito::IdentityPool\n"
        "    Properties:\n      AllowUnauthenticatedIdentities: false\n",
        encoding="utf-8",
    )
    assert CfnCognitoUnauthIdentitiesGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_cognito_unauth_identities_silent_when_false_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Resources": {"MyPool": {"Type": "AWS::Cognito::IdentityPool", '
        '"Properties": {"AllowUnauthenticatedIdentities": false}}}}',
        encoding="utf-8",
    )
    assert CfnCognitoUnauthIdentitiesGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_cognito_unauth_identities_silent_when_property_missing(tmp_path: Path) -> None:
    # AWS's own default is false — unauthenticated access is opt-in, not opt-out — so a template
    # that never mentions the property at all is not flagged.
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyPool:\n    Type: AWS::Cognito::IdentityPool\n"
        "    Properties:\n      IdentityPoolName: mypool\n",
        encoding="utf-8",
    )
    assert CfnCognitoUnauthIdentitiesGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_cognito_unauth_identities_silent_on_unrelated_resource(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n    Properties: {}\n",
        encoding="utf-8",
    )
    assert CfnCognitoUnauthIdentitiesGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_cognito_unauth_identities_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyPool:\n    Type: AWS::Cognito::IdentityPool\n"
        "    Properties:\n"
        "      AllowUnauthenticatedIdentities: true # security: allow-cognito-unauth-identities\n",
        encoding="utf-8",
    )
    assert CfnCognitoUnauthIdentitiesGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_cognito_unauth_identities_not_applicable_without_cloudformation() -> None:
    prof = mkprofile(Path("/tmp"), features={"terraform"})
    assert CfnCognitoUnauthIdentitiesGuard().applies(prof) is False
