from __future__ import annotations

from agentsec.findings import _is_review_finding
from agentsec.guards.cfn_nacl_ineffective_deny import CfnNaclIneffectiveDenyGuard
from tests.guards._common import *  # noqa: F401,F403


def _cfnprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"cloudformation"})


def test_cfn_nacl_ineffective_deny_flags_narrow_cidr(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  DenyEntry:\n"
        "    Type: AWS::EC2::NetworkAclEntry\n"
        "    Properties:\n"
        "      RuleAction: deny\n"
        "      CidrBlock: 10.0.0.0/24\n",
        encoding="utf-8",
    )
    findings = CfnNaclIneffectiveDenyGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-nacl-ineffective-deny/narrow-cidr-deny"
    assert findings[0].severity == "low"


def test_cfn_nacl_ineffective_deny_narrow_cidr_is_a_review_signal(tmp_path: Path) -> None:
    # #766: the rule's `surfacing_rule_prefixes` declaration had no behavioral pin, so emptying it
    # left the suite green. The checkmeta gate checks the declaration's text, not what it does.
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  DenyEntry:\n"
        "    Type: AWS::EC2::NetworkAclEntry\n"
        "    Properties:\n"
        "      RuleAction: deny\n"
        "      CidrBlock: 10.0.0.0/24\n",
        encoding="utf-8",
    )
    findings = CfnNaclIneffectiveDenyGuard().run(tmp_path, _cfnprof(tmp_path))
    assert [f.rule for f in findings] == ["cfn-nacl-ineffective-deny/narrow-cidr-deny"]
    assert _is_review_finding(findings[0]) is True


def test_cfn_nacl_ineffective_deny_flags_narrow_cidr_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Resources": {"DenyEntry": {"Type": "AWS::EC2::NetworkAclEntry", '
        '"Properties": {"RuleAction": "deny", "CidrBlock": "10.0.0.0/24"}}}}',
        encoding="utf-8",
    )
    findings = CfnNaclIneffectiveDenyGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-nacl-ineffective-deny/narrow-cidr-deny"


def test_cfn_nacl_ineffective_deny_flags_narrow_ipv6_cidr(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  DenyEntry:\n"
        "    Type: AWS::EC2::NetworkAclEntry\n"
        "    Properties:\n"
        "      RuleAction: deny\n"
        "      Ipv6CidrBlock: '2001:db8::/32'\n",
        encoding="utf-8",
    )
    findings = CfnNaclIneffectiveDenyGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1


def test_cfn_nacl_ineffective_deny_silent_on_full_range_ipv4(tmp_path: Path) -> None:
    # FP-bait: the full-range deny is the intended, correct pattern.
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  DenyEntry:\n"
        "    Type: AWS::EC2::NetworkAclEntry\n"
        "    Properties:\n"
        "      RuleAction: deny\n"
        "      CidrBlock: 0.0.0.0/0\n",
        encoding="utf-8",
    )
    assert CfnNaclIneffectiveDenyGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_nacl_ineffective_deny_silent_on_full_range_ipv6(tmp_path: Path) -> None:
    # FP-bait: the full-range IPv6 deny is the intended, correct pattern.
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  DenyEntry:\n"
        "    Type: AWS::EC2::NetworkAclEntry\n"
        "    Properties:\n"
        "      RuleAction: deny\n"
        "      Ipv6CidrBlock: '::/0'\n",
        encoding="utf-8",
    )
    assert CfnNaclIneffectiveDenyGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_nacl_ineffective_deny_silent_on_allow_rule(tmp_path: Path) -> None:
    # FP-bait: not a deny rule at all.
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  AllowEntry:\n"
        "    Type: AWS::EC2::NetworkAclEntry\n"
        "    Properties:\n"
        "      RuleAction: allow\n"
        "      CidrBlock: 10.0.0.0/24\n",
        encoding="utf-8",
    )
    assert CfnNaclIneffectiveDenyGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_nacl_ineffective_deny_silent_on_unrelated_resource(tmp_path: Path) -> None:
    # FP-bait: unrelated resource type.
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyBucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties: {}\n",
        encoding="utf-8",
    )
    assert CfnNaclIneffectiveDenyGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_nacl_ineffective_deny_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  DenyEntry:\n"
        "    Type: AWS::EC2::NetworkAclEntry\n"
        "    Properties:\n"
        "      RuleAction: deny\n"
        "      CidrBlock: 10.0.0.0/24  # security: allow-nacl-ineffective-deny\n",
        encoding="utf-8",
    )
    assert CfnNaclIneffectiveDenyGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_nacl_ineffective_deny_not_applicable_without_cloudformation() -> None:
    prof = mkprofile(Path("/tmp"), features={"terraform"})
    assert CfnNaclIneffectiveDenyGuard().applies(prof) is False
