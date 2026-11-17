from __future__ import annotations

from agentsec.guards.cfn_waf_default_allow import CfnWafDefaultAllowGuard
from tests.guards._common import *  # noqa: F401,F403


def _cfnprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"cloudformation"})


def test_cfn_waf_default_allow_flags_allow_default(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyWebAcl:\n"
        "    Type: AWS::WAF::WebACL\n"
        "    Properties:\n"
        "      Name: my-web-acl\n"
        "      MetricName: myWebAcl\n"
        "      DefaultAction:\n"
        "        Type: ALLOW\n",
        encoding="utf-8",
    )
    findings = CfnWafDefaultAllowGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-waf-default-allow/default-action-allow"
    assert findings[0].severity == "medium"


def test_cfn_waf_default_allow_flags_allow_default_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Resources": {"MyWebAcl": {"Type": "AWS::WAF::WebACL", "Properties": '
        '{"Name": "my-web-acl", "MetricName": "myWebAcl", '
        '"DefaultAction": {"Type": "ALLOW"}}}}}',
        encoding="utf-8",
    )
    findings = CfnWafDefaultAllowGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-waf-default-allow/default-action-allow"


def test_cfn_waf_default_allow_silent_on_block_default(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyWebAcl:\n"
        "    Type: AWS::WAF::WebACL\n"
        "    Properties:\n"
        "      DefaultAction:\n"
        "        Type: BLOCK\n",
        encoding="utf-8",
    )
    assert CfnWafDefaultAllowGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_waf_default_allow_silent_on_block_default_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Resources": {"MyWebAcl": {"Type": "AWS::WAF::WebACL", "Properties": '
        '{"DefaultAction": {"Type": "BLOCK"}}}}}',
        encoding="utf-8",
    )
    assert CfnWafDefaultAllowGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_waf_default_allow_silent_on_non_waf_resource(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyBucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties:\n"
        "      BucketName: foo\n",
        encoding="utf-8",
    )
    assert CfnWafDefaultAllowGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_waf_default_allow_silent_on_rule_level_action_allow(tmp_path: Path) -> None:
    # FP-bait: a Rules-list entry's own Action.Type: ALLOW is not the WebACL's DefaultAction.
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyWebAcl:\n"
        "    Type: AWS::WAF::WebACL\n"
        "    Properties:\n"
        "      DefaultAction:\n"
        "        Type: BLOCK\n"
        "      Rules:\n"
        "        - Action:\n"
        "            Type: ALLOW\n"
        "          Priority: 1\n"
        "          RuleId: abc123\n",
        encoding="utf-8",
    )
    assert CfnWafDefaultAllowGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_waf_default_allow_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyWebAcl:\n"
        "    Type: AWS::WAF::WebACL\n"
        "    Properties:\n"
        "      DefaultAction:  # security: allow-waf-default-allow\n"
        "        Type: ALLOW\n",
        encoding="utf-8",
    )
    assert CfnWafDefaultAllowGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_waf_default_allow_not_applicable_without_cloudformation() -> None:
    prof = mkprofile(Path("/tmp"), features={"terraform"})
    assert CfnWafDefaultAllowGuard().applies(prof) is False
