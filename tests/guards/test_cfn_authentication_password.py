from __future__ import annotations

from agentsec.guards.cfn_authentication_password import CfnAuthenticationPasswordGuard
from tests.guards._common import *  # noqa: F401,F403


def _cfnprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"cloudformation"})


def test_cfn_authentication_password_flags_literal_password(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "AWSTemplateFormatVersion: '2010-09-09'\n"
        "Resources:\n"
        "  MyAuth:\n"
        "    Type: AWS::CloudFormation::Authentication\n"
        "    Properties:\n"
        "      testBasicAuth:\n"
        "        type: basic\n"
        "        username: admin\n"
        "        password: SuperSecret123\n"
        "        uris: [http://example.com/private]\n",
        encoding="utf-8",
    )
    findings = CfnAuthenticationPasswordGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-authentication-password/literal-password"
    assert findings[0].severity == "high"


def test_cfn_authentication_password_flags_literal_password_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Resources": {"MyAuth": {"Type": "AWS::CloudFormation::Authentication", '
        '"Properties": {"testBasicAuth": {"type": "basic", "username": "admin", '
        '"password": "SuperSecret123"}}}}}',
        encoding="utf-8",
    )
    findings = CfnAuthenticationPasswordGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-authentication-password/literal-password"


def test_cfn_authentication_password_silent_on_ref(tmp_path: Path) -> None:
    # FP-bait: a NoEcho parameter reference carries no plaintext credential.
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyAuth:\n"
        "    Type: AWS::CloudFormation::Authentication\n"
        "    Properties:\n"
        "      testBasicAuth:\n"
        "        type: basic\n"
        "        password: !Ref DBPassword\n",
        encoding="utf-8",
    )
    assert CfnAuthenticationPasswordGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_authentication_password_silent_on_fn_sub_flow_mapping(tmp_path: Path) -> None:
    # FP-bait: an Fn::Sub flow-mapping value is a reference, not a literal.
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyAuth:\n"
        "    Type: AWS::CloudFormation::Authentication\n"
        "    Properties:\n"
        "      testBasicAuth:\n"
        '        password: {"Fn::Sub": "${SomeParam}"}\n',
        encoding="utf-8",
    )
    assert CfnAuthenticationPasswordGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_authentication_password_silent_on_ref_object_json(tmp_path: Path) -> None:
    # FP-bait: JSON {"Ref": "..."} object value.
    (tmp_path / "template.json").write_text(
        '{"Resources": {"MyAuth": {"Type": "AWS::CloudFormation::Authentication", '
        '"Properties": {"testBasicAuth": {"password": {"Ref": "DBPassword"}}}}}}',
        encoding="utf-8",
    )
    assert CfnAuthenticationPasswordGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_authentication_password_silent_on_dynamic_reference(tmp_path: Path) -> None:
    # FP-bait: a Secrets Manager dynamic reference resolves at deploy time, not a literal.
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyAuth:\n"
        "    Type: AWS::CloudFormation::Authentication\n"
        "    Properties:\n"
        "      testBasicAuth:\n"
        "        password: '{{resolve:secretsmanager:MySecret:SecretString:password}}'\n",
        encoding="utf-8",
    )
    assert CfnAuthenticationPasswordGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_authentication_password_silent_on_unrelated_resource_type(tmp_path: Path) -> None:
    # FP-bait: an unrelated resource type with a "password"-shaped key is not our target.
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyBucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties:\n"
        "      password: SuperSecret123\n",
        encoding="utf-8",
    )
    assert CfnAuthenticationPasswordGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_authentication_password_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyAuth:\n"
        "    Type: AWS::CloudFormation::Authentication\n"
        "    Properties:\n"
        "      testBasicAuth:\n"
        "        password: SuperSecret123 # security: allow-cfn-authentication-password\n",
        encoding="utf-8",
    )
    assert CfnAuthenticationPasswordGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_authentication_password_not_applicable_without_cloudformation() -> None:
    prof = mkprofile(Path("/tmp"), features={"terraform"})
    assert CfnAuthenticationPasswordGuard().applies(prof) is False
