from __future__ import annotations

from agentsec.guards.cfn_wildcard_principal import CfnWildcardPrincipalGuard
from tests.guards._common import *  # noqa: F401,F403


def _cfnprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"cloudformation"})


def test_cfn_wildcard_principal_flags_s3_bucket_policy_yaml(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyBucketPolicy:\n"
        "    Type: AWS::S3::BucketPolicy\n"
        "    Properties:\n"
        "      Bucket: my-bucket\n"
        "      PolicyDocument:\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        '            Principal: "*"\n'
        "            Action: s3:GetObject\n"
        "            Resource: arn:aws:s3:::my-bucket/*\n",
        encoding="utf-8",
    )
    findings = CfnWildcardPrincipalGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-wildcard-principal/allow-no-condition"
    assert findings[0].severity == "high"


def test_cfn_wildcard_principal_flags_kms_key_policy_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Resources": {"MyKey": {"Type": "AWS::KMS::Key", "Properties": {"KeyPolicy": '
        '{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "kms:Decrypt", '
        '"Resource": "*"}]}}}}}',
        encoding="utf-8",
    )
    findings = CfnWildcardPrincipalGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-wildcard-principal/allow-no-condition"


def test_cfn_wildcard_principal_flags_iam_trust_policy_yaml(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyRole:\n"
        "    Type: AWS::IAM::Role\n"
        "    Properties:\n"
        "      AssumeRolePolicyDocument:\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        '            Principal: "*"\n'
        "            Action: sts:AssumeRole\n",
        encoding="utf-8",
    )
    findings = CfnWildcardPrincipalGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1


def test_cfn_wildcard_principal_flags_nested_aws_wildcard_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Resources": {"MyTopicPolicy": {"Type": "AWS::SNS::TopicPolicy", "Properties": '
        '{"PolicyDocument": {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, '
        '"Action": "sns:Publish"}]}}}}}',
        encoding="utf-8",
    )
    findings = CfnWildcardPrincipalGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1


def test_cfn_wildcard_principal_flags_sqs_queue_policy_yaml(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyQueuePolicy:\n"
        "    Type: AWS::SQS::QueuePolicy\n"
        "    Properties:\n"
        "      Queues:\n"
        "        - !Ref MyQueue\n"
        "      PolicyDocument:\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        '            Principal: "*"\n'
        "            Action: sqs:SendMessage\n",
        encoding="utf-8",
    )
    findings = CfnWildcardPrincipalGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1


def test_cfn_wildcard_principal_silent_with_condition(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyBucketPolicy:\n"
        "    Type: AWS::S3::BucketPolicy\n"
        "    Properties:\n"
        "      Bucket: my-bucket\n"
        "      PolicyDocument:\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        '            Principal: "*"\n'
        "            Action: s3:GetObject\n"
        "            Resource: arn:aws:s3:::my-bucket/*\n"
        "            Condition:\n"
        "              StringEquals:\n"
        "                aws:SourceVpce: vpce-1234\n",
        encoding="utf-8",
    )
    assert CfnWildcardPrincipalGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_wildcard_principal_silent_with_condition_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Resources": {"MyKey": {"Type": "AWS::KMS::Key", "Properties": {"KeyPolicy": '
        '{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "kms:Decrypt", '
        '"Condition": {"StringEquals": {"aws:SourceVpce": "vpce-1234"}}}]}}}}}',
        encoding="utf-8",
    )
    assert CfnWildcardPrincipalGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_wildcard_principal_silent_when_not_wildcard(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyBucketPolicy:\n"
        "    Type: AWS::S3::BucketPolicy\n"
        "    Properties:\n"
        "      Bucket: my-bucket\n"
        "      PolicyDocument:\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        "            Principal:\n"
        "              AWS: arn:aws:iam::123456789012:root\n"
        "            Action: s3:GetObject\n"
        "            Resource: arn:aws:s3:::my-bucket/*\n",
        encoding="utf-8",
    )
    assert CfnWildcardPrincipalGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_wildcard_principal_silent_on_unrelated_resource_type(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyBucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties:\n"
        "      BucketName: my-bucket\n",
        encoding="utf-8",
    )
    assert CfnWildcardPrincipalGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_wildcard_principal_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyBucketPolicy:\n"
        "    Type: AWS::S3::BucketPolicy\n"
        "    Properties:\n"
        "      Bucket: my-bucket  # security: allow-cfn-wildcard-principal\n"
        "      PolicyDocument:\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        '            Principal: "*"\n'
        "            Action: s3:GetObject\n",
        encoding="utf-8",
    )
    assert CfnWildcardPrincipalGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_wildcard_principal_not_applicable_without_cloudformation() -> None:
    prof = mkprofile(Path("/tmp"), features={"terraform"})
    assert CfnWildcardPrincipalGuard().applies(prof) is False
