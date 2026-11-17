from __future__ import annotations

from agentsec.guards.cfn_iam_escalation_action_no_condition import (
    CfnIamEscalationActionNoConditionGuard,
)
from tests.guards._common import *  # noqa: F401,F403


def _cfnprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"cloudformation"})


def test_cfn_iam_escalation_flags_passrole_yaml(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyRole:\n"
        "    Type: AWS::IAM::Role\n"
        "    Properties:\n"
        "      Policies:\n"
        "        - PolicyName: escalate\n"
        "          PolicyDocument:\n"
        "            Statement:\n"
        "              - Effect: Allow\n"
        "                Action: iam:PassRole\n"
        "                Resource: '*'\n",
        encoding="utf-8",
    )
    findings = CfnIamEscalationActionNoConditionGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-iam-escalation-action-no-condition/allow-no-condition"
    assert findings[0].severity == "high"
    assert "iam:PassRole" in findings[0].message


def test_cfn_iam_escalation_flags_attachrolepolicy_list_yaml(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyPolicy:\n"
        "    Type: AWS::IAM::Policy\n"
        "    Properties:\n"
        "      PolicyName: bad\n"
        "      PolicyDocument:\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        "            Action:\n"
        "              - iam:AttachRolePolicy\n"
        "              - iam:PutRolePolicy\n"
        "            Resource: '*'\n",
        encoding="utf-8",
    )
    findings = CfnIamEscalationActionNoConditionGuard().run(tmp_path, _cfnprof(tmp_path))
    rules_actions = {f.message for f in findings}
    assert len(findings) == 2
    assert any("iam:AttachRolePolicy" in m for m in rules_actions)
    assert any("iam:PutRolePolicy" in m for m in rules_actions)


def test_cfn_iam_escalation_flags_createaccesskey_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Resources": {"MyPolicy": {"Type": "AWS::IAM::ManagedPolicy", "Properties": '
        '{"PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "iam:CreateAccessKey", '
        '"Resource": "*"}]}}}}}',
        encoding="utf-8",
    )
    findings = CfnIamEscalationActionNoConditionGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-iam-escalation-action-no-condition/allow-no-condition"


def test_cfn_iam_escalation_flags_setdefaultpolicyversion_list_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Resources": {"MyRole": {"Type": "AWS::IAM::Role", "Properties": {"Policies": [{'
        '"PolicyName": "bad", "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": '
        '["iam:SetDefaultPolicyVersion", "iam:UpdateAssumeRolePolicy"], "Resource": "*"}]}}]}}}}',
        encoding="utf-8",
    )
    findings = CfnIamEscalationActionNoConditionGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 2


def test_cfn_iam_escalation_silent_with_condition(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyRole:\n"
        "    Type: AWS::IAM::Role\n"
        "    Properties:\n"
        "      Policies:\n"
        "        - PolicyName: scoped\n"
        "          PolicyDocument:\n"
        "            Statement:\n"
        "              - Effect: Allow\n"
        "                Action: iam:PassRole\n"
        "                Resource: '*'\n"
        "                Condition:\n"
        "                  StringEquals:\n"
        "                    'iam:PassedToService': 'ec2.amazonaws.com'\n",
        encoding="utf-8",
    )
    assert CfnIamEscalationActionNoConditionGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_iam_escalation_silent_on_benign_action(tmp_path: Path) -> None:
    # FP-bait: an action not on the curated escalation list.
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyRole:\n"
        "    Type: AWS::IAM::Role\n"
        "    Properties:\n"
        "      Policies:\n"
        "        - PolicyName: benign\n"
        "          PolicyDocument:\n"
        "            Statement:\n"
        "              - Effect: Allow\n"
        "                Action: s3:GetObject\n"
        "                Resource: '*'\n",
        encoding="utf-8",
    )
    assert CfnIamEscalationActionNoConditionGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_iam_escalation_silent_on_unrelated_resource_type(tmp_path: Path) -> None:
    # FP-bait: an unrelated resource type, even one whose text incidentally contains an
    # action-shaped substring.
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyBucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties:\n"
        "      BucketName: not-a-policy-iam:PassRole-lookalike\n",
        encoding="utf-8",
    )
    assert CfnIamEscalationActionNoConditionGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_iam_escalation_silent_on_notaction(tmp_path: Path) -> None:
    # FP-bait: the dangerous action appears only as a NotAction value, not an Action value.
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyRole:\n"
        "    Type: AWS::IAM::Role\n"
        "    Properties:\n"
        "      Policies:\n"
        "        - PolicyName: notaction\n"
        "          PolicyDocument:\n"
        "            Statement:\n"
        "              - Effect: Allow\n"
        "                NotAction: iam:PassRole\n"
        "                Resource: '*'\n",
        encoding="utf-8",
    )
    assert CfnIamEscalationActionNoConditionGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_iam_escalation_silent_on_effect_deny(tmp_path: Path) -> None:
    # FP-bait: Effect Deny is the opposite of a grant.
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyRole:\n"
        "    Type: AWS::IAM::Role\n"
        "    Properties:\n"
        "      Policies:\n"
        "        - PolicyName: deny\n"
        "          PolicyDocument:\n"
        "            Statement:\n"
        "              - Effect: Deny\n"
        "                Action: iam:PassRole\n"
        "                Resource: '*'\n",
        encoding="utf-8",
    )
    assert CfnIamEscalationActionNoConditionGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_iam_escalation_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyRole:\n"
        "    Type: AWS::IAM::Role\n"
        "    Properties:\n"
        "      Policies:\n"
        "        - PolicyName: audited\n"
        "          PolicyDocument:\n"
        "            Statement:\n"
        "              - Effect: Allow\n"
        "                Action: iam:PassRole  # security: allow-iam-escalation-no-condition\n"
        "                Resource: '*'\n",
        encoding="utf-8",
    )
    assert CfnIamEscalationActionNoConditionGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_iam_escalation_silent_on_ordinary_trust_policy(tmp_path: Path) -> None:
    """FP-bait (Dean's review repro): an ordinary IAM role trust policy
    (AssumeRolePolicyDocument, Effect Allow, Action sts:AssumeRole, no Condition) is the
    commonest role shape in AWS — it states who may assume this role, not a permissions grant
    this role/identity holds. Must NOT fire even with no Policies at all."""
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyRole:\n"
        "    Type: AWS::IAM::Role\n"
        "    Properties:\n"
        "      AssumeRolePolicyDocument:\n"
        "        Version: '2012-10-17'\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        "            Principal:\n"
        "              Service: ec2.amazonaws.com\n"
        "            Action: sts:AssumeRole\n",
        encoding="utf-8",
    )
    assert CfnIamEscalationActionNoConditionGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_iam_escalation_still_flags_permissions_policy_alongside_trust_policy(
    tmp_path: Path,
) -> None:
    """Still-fires (CLAUDE.md Rule 1): a role with BOTH an ordinary trust policy (silent, see
    above) AND a real escalation-shaped permissions grant must still flag the permissions side —
    the trust-policy carve-out must not blind the guard to a genuine finding elsewhere in the
    same resource."""
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyRole:\n"
        "    Type: AWS::IAM::Role\n"
        "    Properties:\n"
        "      AssumeRolePolicyDocument:\n"
        "        Version: '2012-10-17'\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        "            Principal:\n"
        "              Service: ec2.amazonaws.com\n"
        "            Action: sts:AssumeRole\n"
        "      Policies:\n"
        "        - PolicyName: escalate\n"
        "          PolicyDocument:\n"
        "            Statement:\n"
        "              - Effect: Allow\n"
        "                Action: iam:PassRole\n"
        "                Resource: '*'\n",
        encoding="utf-8",
    )
    findings = CfnIamEscalationActionNoConditionGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert "iam:PassRole" in findings[0].message
    assert "sts:AssumeRole" not in findings[0].message


def test_cfn_iam_escalation_not_applicable_without_cloudformation() -> None:
    prof = mkprofile(Path("/tmp"), features={"terraform"})
    assert CfnIamEscalationActionNoConditionGuard().applies(prof) is False
