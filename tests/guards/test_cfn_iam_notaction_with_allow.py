from __future__ import annotations

import json

from agentsec.guards.cfn_iam_notaction_with_allow import CfnIamNotactionWithAllowGuard
from tests.guards._common import *  # noqa: F401,F403


def _cfnprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"cloudformation"})


def test_cfn_iam_notaction_with_allow_flags_iam_policy_yaml(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  BadPolicy:\n"
        "    Type: AWS::IAM::Policy\n"
        "    Properties:\n"
        "      PolicyDocument:\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        "            NotAction:\n"
        "              - iam:*\n"
        "            Resource: '*'\n",
        encoding="utf-8",
    )
    findings = CfnIamNotactionWithAllowGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-iam-notaction-with-allow/allow-notaction"
    assert findings[0].severity == "high"


def test_cfn_iam_notaction_with_allow_flags_managed_policy_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        "{"
        '"Resources": {'
        '"BadManagedPolicy": {'
        '"Type": "AWS::IAM::ManagedPolicy",'
        '"Properties": {'
        '"PolicyDocument": {'
        '"Statement": [{'
        '"Effect": "Allow",'
        '"NotAction": ["iam:*", "organizations:*"],'
        '"Resource": "*"'
        "}]"
        "}"
        "}"
        "}"
        "}"
        "}",
        encoding="utf-8",
    )
    findings = CfnIamNotactionWithAllowGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-iam-notaction-with-allow/allow-notaction"


def test_cfn_iam_notaction_with_allow_flags_iam_role(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  BadRole:\n"
        "    Type: AWS::IAM::Role\n"
        "    Properties:\n"
        "      AssumeRolePolicyDocument:\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        "            Principal:\n"
        "              Service: ec2.amazonaws.com\n"
        "            Action: sts:AssumeRole\n"
        "      Policies:\n"
        "        - PolicyName: inline\n"
        "          PolicyDocument:\n"
        "            Statement:\n"
        "              - Effect: Allow\n"
        "                NotAction:\n"
        "                  - iam:*\n"
        "                Resource: '*'\n",
        encoding="utf-8",
    )
    findings = CfnIamNotactionWithAllowGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1


def test_cfn_iam_notaction_with_allow_silent_on_plain_action(tmp_path: Path) -> None:
    # FP-bait: a normal Action allow-list, not NotAction.
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  GoodPolicy:\n"
        "    Type: AWS::IAM::Policy\n"
        "    Properties:\n"
        "      PolicyDocument:\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        "            Action:\n"
        "              - s3:GetObject\n"
        "            Resource: '*'\n",
        encoding="utf-8",
    )
    assert CfnIamNotactionWithAllowGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_iam_notaction_with_allow_silent_on_deny_notaction(tmp_path: Path) -> None:
    # FP-bait: Effect: Deny + NotAction is a legitimate "deny everything except these" guardrail,
    # the defining precision risk of this pattern -- must not fire.
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  GuardrailPolicy:\n"
        "    Type: AWS::IAM::Policy\n"
        "    Properties:\n"
        "      PolicyDocument:\n"
        "        Statement:\n"
        "          - Effect: Deny\n"
        "            NotAction:\n"
        "              - safe:AllowedAction\n"
        "            Resource: '*'\n",
        encoding="utf-8",
    )
    assert CfnIamNotactionWithAllowGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_iam_notaction_with_allow_silent_on_deny_notaction_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        "{"
        '"Resources": {'
        '"GuardrailPolicy": {'
        '"Type": "AWS::IAM::Policy",'
        '"Properties": {'
        '"PolicyDocument": {'
        '"Statement": [{'
        '"Effect": "Deny",'
        '"NotAction": ["safe:AllowedAction"],'
        '"Resource": "*"'
        "}]"
        "}"
        "}"
        "}"
        "}"
        "}",
        encoding="utf-8",
    )
    assert CfnIamNotactionWithAllowGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_iam_notaction_with_allow_silent_on_unrelated_resource(tmp_path: Path) -> None:
    # FP-bait: an unrelated resource type, even if it happens to contain Allow/NotAction-ish text.
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyBucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties:\n"
        "      BucketName: allow-notaction-in-the-name-only\n",
        encoding="utf-8",
    )
    assert CfnIamNotactionWithAllowGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_iam_notaction_with_allow_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  SuppressedPolicy:\n"
        "    Type: AWS::IAM::Policy\n"
        "    Properties:\n"
        "      PolicyName: suppressed  # security: allow-cfn-iam-notaction-with-allow\n"
        "      PolicyDocument:\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        "            NotAction:\n"
        "              - iam:*\n"
        "            Resource: '*'\n",
        encoding="utf-8",
    )
    assert CfnIamNotactionWithAllowGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_iam_notaction_with_allow_silent_when_allow_and_notaction_are_different_statements(
    tmp_path: Path,
) -> None:
    """FP-bait (Dean's review repro): a legitimate Deny+NotAction guardrail statement
    sitting alongside an UNRELATED Allow statement (no NotAction of its own) in the same policy
    must NOT fire -- the two conditions have to belong to the SAME statement, not just the same
    resource block."""
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MixedPolicy:\n"
        "    Type: AWS::IAM::Policy\n"
        "    Properties:\n"
        "      PolicyDocument:\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        "            Action:\n"
        "              - s3:GetObject\n"
        "            Resource: '*'\n"
        "          - Effect: Deny\n"
        "            NotAction:\n"
        "              - safe:AllowedAction\n"
        "            Resource: '*'\n",
        encoding="utf-8",
    )
    assert CfnIamNotactionWithAllowGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_iam_notaction_with_allow_silent_when_split_across_separate_policies(
    tmp_path: Path,
) -> None:
    """FP-bait -- the cross-Policies-entry variant: an Allow statement in one inline
    policy and a Deny+NotAction guardrail in a SEPARATE inline policy on the same role must not
    be read as one dangerous statement either."""
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MixedRole:\n"
        "    Type: AWS::IAM::Role\n"
        "    Properties:\n"
        "      AssumeRolePolicyDocument:\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        "            Principal:\n"
        "              Service: ec2.amazonaws.com\n"
        "            Action: sts:AssumeRole\n"
        "      Policies:\n"
        "        - PolicyName: allow-only\n"
        "          PolicyDocument:\n"
        "            Statement:\n"
        "              - Effect: Allow\n"
        "                Action:\n"
        "                  - s3:GetObject\n"
        "                Resource: '*'\n"
        "        - PolicyName: guardrail\n"
        "          PolicyDocument:\n"
        "            Statement:\n"
        "              - Effect: Deny\n"
        "                NotAction:\n"
        "                  - safe:AllowedAction\n"
        "                Resource: '*'\n",
        encoding="utf-8",
    )
    assert CfnIamNotactionWithAllowGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_iam_notaction_with_allow_silent_when_dash_alone_bullets_separate_statements(
    tmp_path: Path,
) -> None:
    """FP-bait round 2 (Dean's review repro): the same different-statements case as
    test_cfn_iam_notaction_with_allow_silent_when_allow_and_notaction_are_different_statements,
    but authored with a dash alone on its own line instead of `- key: value` -- valid, common YAML
    that `_YAML_BULLET` didn't recognize as an item boundary before this fix, merging both
    statements into one blob and false-firing on this legitimate guardrail."""
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MixedPolicy:\n"
        "    Type: AWS::IAM::Policy\n"
        "    Properties:\n"
        "      PolicyDocument:\n"
        "        Statement:\n"
        "          -\n"
        "            Effect: Allow\n"
        "            Action:\n"
        "              - s3:GetObject\n"
        "            Resource: '*'\n"
        "          -\n"
        "            Effect: Deny\n"
        "            NotAction:\n"
        "              - safe:AllowedAction\n"
        "            Resource: '*'\n",
        encoding="utf-8",
    )
    assert CfnIamNotactionWithAllowGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_iam_notaction_with_allow_flags_json_single_object_statement(tmp_path: Path) -> None:
    """Still-fires (Dean's review repro): `Statement` as a single JSON object (not
    wrapped in an array) is valid IAM and a real Allow+NotAction combination on it must still be
    caught -- before this fix, `_STATEMENT_KEY` only recognized an opening `[`, so this silently
    produced zero findings (a regression introduced by the very fix meant to close the earlier FP)."""
    (tmp_path / "template.json").write_text(
        json.dumps(
            {
                "Resources": {
                    "SingleObjectPolicy": {
                        "Type": "AWS::IAM::Policy",
                        "Properties": {
                            "PolicyDocument": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "NotAction": "iam:*",
                                    "Resource": "*",
                                }
                            }
                        },
                    }
                }
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    findings = CfnIamNotactionWithAllowGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1


def test_cfn_iam_notaction_with_allow_not_applicable_without_cloudformation() -> None:
    prof = mkprofile(Path("/tmp"), features={"terraform"})
    assert CfnIamNotactionWithAllowGuard().applies(prof) is False
