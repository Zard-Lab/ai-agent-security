from __future__ import annotations

from agentsec.guards.cfn_ec2_subnet_public_ip import CfnEc2SubnetPublicIpGuard
from tests.guards._common import *  # noqa: F401,F403


def _cfnprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"cloudformation"})


def test_cfn_ec2_subnet_public_ip_flags_true(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  PublicSubnet:\n    Type: AWS::EC2::Subnet\n    Properties:\n"
        "      CidrBlock: 10.0.1.0/24\n      VpcId: vpc-123\n      MapPublicIpOnLaunch: true\n",
        encoding="utf-8",
    )
    findings = CfnEc2SubnetPublicIpGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-ec2-subnet-public-ip/map-public-ip-true"
    assert findings[0].severity == "medium"


def test_cfn_ec2_subnet_public_ip_flags_true_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Resources": {"PublicSubnet": {"Type": "AWS::EC2::Subnet", '
        '"Properties": {"CidrBlock": "10.0.1.0/24", "VpcId": "vpc-123", '
        '"MapPublicIpOnLaunch": true}}}}',
        encoding="utf-8",
    )
    findings = CfnEc2SubnetPublicIpGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-ec2-subnet-public-ip/map-public-ip-true"


def test_cfn_ec2_subnet_public_ip_silent_when_false(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  PrivateSubnet:\n    Type: AWS::EC2::Subnet\n    Properties:\n"
        "      CidrBlock: 10.0.1.0/24\n      VpcId: vpc-123\n      MapPublicIpOnLaunch: false\n",
        encoding="utf-8",
    )
    assert CfnEc2SubnetPublicIpGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_ec2_subnet_public_ip_silent_when_property_missing(tmp_path: Path) -> None:
    # AWS's real default for auto-assign-public-IP depends on how the subnet's VPC itself was
    # created (a default VPC's default subnets have it on; a non-default VPC's subnets default it
    # off). The property being absent from the template is not itself evidence of the vulnerable
    # behavior, so a bare omission must not fire.
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  DefaultSubnet:\n    Type: AWS::EC2::Subnet\n    Properties:\n"
        "      CidrBlock: 10.0.1.0/24\n      VpcId: vpc-123\n",
        encoding="utf-8",
    )
    assert CfnEc2SubnetPublicIpGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_ec2_subnet_public_ip_silent_on_non_subnet_resource(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n    Properties: {}\n",
        encoding="utf-8",
    )
    assert CfnEc2SubnetPublicIpGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_ec2_subnet_public_ip_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  PublicSubnet:\n    Type: AWS::EC2::Subnet\n    Properties:\n"
        "      CidrBlock: 10.0.1.0/24\n      VpcId: vpc-123\n"
        "      MapPublicIpOnLaunch: true  # security: allow-ec2-subnet-public-ip\n",
        encoding="utf-8",
    )
    assert CfnEc2SubnetPublicIpGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_ec2_subnet_public_ip_not_applicable_without_cloudformation() -> None:
    prof = mkprofile(Path("/tmp"), features={"terraform"})
    assert CfnEc2SubnetPublicIpGuard().applies(prof) is False
