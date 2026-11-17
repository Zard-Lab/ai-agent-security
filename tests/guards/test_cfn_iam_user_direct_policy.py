from __future__ import annotations

from agentsec.guards.cfn_iam_user_direct_policy import CfnIamUserDirectPolicyGuard
from tests.guards._common import *  # noqa: F401,F403


def _cfnprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"cloudformation"})


def test_cfn_iam_user_direct_policy_flags_inline_policy(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyUser:\n"
        "    Type: AWS::IAM::User\n"
        "    Properties:\n"
        "      Policies:\n"
        "        - PolicyName: p\n"
        "          PolicyDocument: {}\n",
        encoding="utf-8",
    )
    findings = CfnIamUserDirectPolicyGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-iam-user-direct-policy/inline-policy-on-user"
    assert findings[0].severity == "medium"


def test_cfn_iam_user_direct_policy_flags_inline_policy_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Resources": {"MyUser": {"Type": "AWS::IAM::User", '
        '"Properties": {"Policies": [{"PolicyName": "p", "PolicyDocument": {}}]}}}}',
        encoding="utf-8",
    )
    findings = CfnIamUserDirectPolicyGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-iam-user-direct-policy/inline-policy-on-user"


def test_cfn_iam_user_direct_policy_flags_managed_policy_users(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyPolicy:\n"
        "    Type: AWS::IAM::ManagedPolicy\n"
        "    Properties:\n"
        "      Users:\n"
        "        - myuser\n",
        encoding="utf-8",
    )
    findings = CfnIamUserDirectPolicyGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-iam-user-direct-policy/managed-policy-on-user"
    assert findings[0].severity == "medium"


def test_cfn_iam_user_direct_policy_flags_managed_policy_users_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Resources": {"MyPolicy": {"Type": "AWS::IAM::ManagedPolicy", '
        '"Properties": {"Users": ["myuser"]}}}}',
        encoding="utf-8",
    )
    findings = CfnIamUserDirectPolicyGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-iam-user-direct-policy/managed-policy-on-user"


def test_cfn_iam_user_direct_policy_flags_legacy_iam_policy_type_with_users(tmp_path: Path) -> None:
    # AWS::IAM::Policy is the older/legacy resource type but shares the same Users property shape.
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyPolicy:\n"
        "    Type: AWS::IAM::Policy\n"
        "    Properties:\n"
        "      PolicyName: p\n"
        "      Users:\n"
        "        - myuser\n",
        encoding="utf-8",
    )
    findings = CfnIamUserDirectPolicyGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-iam-user-direct-policy/managed-policy-on-user"


def test_cfn_iam_user_direct_policy_pragma_silences_inline(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyUser:\n"
        "    Type: AWS::IAM::User\n"
        "    Properties:\n"
        "      Policies:  # security: allow-iam-user-direct-policy\n"
        "        - PolicyName: p\n"
        "          PolicyDocument: {}\n",
        encoding="utf-8",
    )
    assert CfnIamUserDirectPolicyGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_iam_user_direct_policy_pragma_silences_managed(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyPolicy:\n"
        "    Type: AWS::IAM::ManagedPolicy\n"
        "    Properties:\n"
        "      Users:  # security: allow-iam-user-direct-policy\n"
        "        - myuser\n",
        encoding="utf-8",
    )
    assert CfnIamUserDirectPolicyGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_iam_user_direct_policy_silent_on_group_with_policies(tmp_path: Path) -> None:
    # FP-bait: an AWS::IAM::Group with a Policies property is the correct pattern, not a hit.
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyGroup:\n"
        "    Type: AWS::IAM::Group\n"
        "    Properties:\n"
        "      Policies:\n"
        "        - PolicyName: p\n"
        "          PolicyDocument: {}\n",
        encoding="utf-8",
    )
    assert CfnIamUserDirectPolicyGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_iam_user_direct_policy_silent_on_managed_policy_with_groups(tmp_path: Path) -> None:
    # FP-bait: a ManagedPolicy attached via Groups (the correct pattern) is not a hit.
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyPolicy:\n"
        "    Type: AWS::IAM::ManagedPolicy\n"
        "    Properties:\n"
        "      Groups:\n"
        "        - mygroup\n",
        encoding="utf-8",
    )
    assert CfnIamUserDirectPolicyGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_iam_user_direct_policy_silent_on_user_without_policies(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyUser:\n"
        "    Type: AWS::IAM::User\n"
        "    Properties:\n"
        "      UserName: bob\n",
        encoding="utf-8",
    )
    assert CfnIamUserDirectPolicyGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_iam_user_direct_policy_silent_on_unrelated_resource(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyBucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties: {}\n",
        encoding="utf-8",
    )
    assert CfnIamUserDirectPolicyGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_iam_user_direct_policy_not_applicable_without_cloudformation() -> None:
    prof = mkprofile(Path("/tmp"), features={"terraform"})
    assert CfnIamUserDirectPolicyGuard().applies(prof) is False
