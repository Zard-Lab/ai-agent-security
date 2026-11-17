from __future__ import annotations

from agentsec.guards.cfn_rds_publicly_accessible import CfnRdsPubliclyAccessibleGuard
from tests.guards._common import *  # noqa: F401,F403


def _cfnprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"cloudformation"})


def test_cfn_rds_publicly_accessible_flags_true_yaml(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  AppDb:\n    Type: AWS::RDS::DBInstance\n    Properties:\n"
        "      Engine: postgres\n      PubliclyAccessible: true\n",
        encoding="utf-8",
    )
    findings = CfnRdsPubliclyAccessibleGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-rds-publicly-accessible/publicly-accessible-true"
    assert findings[0].severity == "high"


def test_cfn_rds_publicly_accessible_flags_true_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Resources": {"AppDb": {"Type": "AWS::RDS::DBInstance", '
        '"Properties": {"Engine": "postgres", "PubliclyAccessible": true}}}}',
        encoding="utf-8",
    )
    findings = CfnRdsPubliclyAccessibleGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-rds-publicly-accessible/publicly-accessible-true"


def test_cfn_rds_publicly_accessible_silent_when_missing_property(tmp_path: Path) -> None:
    # Reconciled default-handling decision: mirrors the Terraform sibling's own convention
    # (silence is the safe state when the attribute is absent) for consistency between the two
    # guards on the same checklist item — see the guard module docstring for the caveat this
    # creates (CFN's real default depends on subnet placement, which the template alone can't say).
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  AppDb:\n    Type: AWS::RDS::DBInstance\n    Properties:\n"
        "      Engine: postgres\n",
        encoding="utf-8",
    )
    assert CfnRdsPubliclyAccessibleGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_rds_publicly_accessible_silent_when_false(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  AppDb:\n    Type: AWS::RDS::DBInstance\n    Properties:\n"
        "      PubliclyAccessible: false\n",
        encoding="utf-8",
    )
    assert CfnRdsPubliclyAccessibleGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_rds_publicly_accessible_silent_on_unrelated_resource(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n    Properties: {}\n",
        encoding="utf-8",
    )
    assert CfnRdsPubliclyAccessibleGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_rds_publicly_accessible_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  AppDb:\n    Type: AWS::RDS::DBInstance\n    Properties:\n"
        "      PubliclyAccessible: true  # security: allow-rds-public\n",
        encoding="utf-8",
    )
    assert CfnRdsPubliclyAccessibleGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_rds_publicly_accessible_not_applicable_without_cloudformation() -> None:
    prof = mkprofile(Path("/tmp"), features={"terraform"})
    assert CfnRdsPubliclyAccessibleGuard().applies(prof) is False
