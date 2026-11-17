from __future__ import annotations

from agentsec.guards.cfn_vpc_flow_log_missing import CfnVpcFlowLogMissingGuard
from tests.guards._common import *  # noqa: F401,F403


def _cfnprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"cloudformation"})


def test_cfn_vpc_flow_log_missing_flags_vpc_without_flow_log(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyVpc:\n"
        "    Type: AWS::EC2::VPC\n"
        "    Properties:\n"
        "      CidrBlock: 10.0.0.0/16\n",
        encoding="utf-8",
    )
    findings = CfnVpcFlowLogMissingGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-vpc-flow-log-missing/no-flow-log"
    assert findings[0].severity == "medium"


def test_cfn_vpc_flow_log_missing_flags_vpc_without_flow_log_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Resources": {"MyVpc": {"Type": "AWS::EC2::VPC", '
        '"Properties": {"CidrBlock": "10.0.0.0/16"}}}}',
        encoding="utf-8",
    )
    findings = CfnVpcFlowLogMissingGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-vpc-flow-log-missing/no-flow-log"


def test_cfn_vpc_flow_log_missing_silent_when_flow_log_present(tmp_path: Path) -> None:
    # FP-bait: a VPC AND a FlowLog resource in the same template -> silent.
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyVpc:\n"
        "    Type: AWS::EC2::VPC\n"
        "    Properties:\n"
        "      CidrBlock: 10.0.0.0/16\n"
        "  MyFlowLog:\n"
        "    Type: AWS::EC2::FlowLog\n"
        "    Properties:\n"
        "      ResourceId: !Ref MyVpc\n"
        "      ResourceType: VPC\n"
        "      TrafficType: ALL\n",
        encoding="utf-8",
    )
    assert CfnVpcFlowLogMissingGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_vpc_flow_log_missing_silent_when_flow_log_present_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Resources": {'
        '"MyVpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": "10.0.0.0/16"}}, '
        '"MyFlowLog": {"Type": "AWS::EC2::FlowLog", '
        '"Properties": {"ResourceId": {"Ref": "MyVpc"}, "ResourceType": "VPC", "TrafficType": "ALL"}}'
        "}}",
        encoding="utf-8",
    )
    assert CfnVpcFlowLogMissingGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_vpc_flow_log_missing_silent_when_no_vpc(tmp_path: Path) -> None:
    # FP-bait: no AWS::EC2::VPC resource at all -> silent.
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n    Properties: {}\n",
        encoding="utf-8",
    )
    assert CfnVpcFlowLogMissingGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_vpc_flow_log_missing_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyVpc:\n"
        "    Type: AWS::EC2::VPC\n"
        "    Properties:\n"
        "      CidrBlock: 10.0.0.0/16 # security: allow-vpc-flow-log-missing\n",
        encoding="utf-8",
    )
    assert CfnVpcFlowLogMissingGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_vpc_flow_log_missing_not_applicable_without_cloudformation() -> None:
    prof = mkprofile(Path("/tmp"), features={"terraform"})
    assert CfnVpcFlowLogMissingGuard().applies(prof) is False
