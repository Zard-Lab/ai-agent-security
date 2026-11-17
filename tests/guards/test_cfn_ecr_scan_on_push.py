from __future__ import annotations

from agentsec.guards.cfn_ecr_scan_on_push import CfnEcrScanOnPushGuard
from tests.guards._common import *  # noqa: F401,F403


def _cfnprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"cloudformation"})


def test_cfn_ecr_scan_on_push_flags_missing_config(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyRepo:\n    Type: AWS::ECR::Repository\n    Properties:\n"
        "      RepositoryName: app\n",
        encoding="utf-8",
    )
    findings = CfnEcrScanOnPushGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-ecr-scan-on-push/scan-on-push-disabled"
    assert findings[0].severity == "medium"


def test_cfn_ecr_scan_on_push_flags_scan_on_push_false(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyRepo:\n    Type: AWS::ECR::Repository\n    Properties:\n"
        "      ImageScanningConfiguration:\n        ScanOnPush: false\n",
        encoding="utf-8",
    )
    findings = CfnEcrScanOnPushGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-ecr-scan-on-push/scan-on-push-disabled"


def test_cfn_ecr_scan_on_push_flags_missing_config_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Resources": {"MyRepo": {"Type": "AWS::ECR::Repository", '
        '"Properties": {"RepositoryName": "app"}}}}',
        encoding="utf-8",
    )
    findings = CfnEcrScanOnPushGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1


def test_cfn_ecr_scan_on_push_flags_scan_on_push_false_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Resources": {"MyRepo": {"Type": "AWS::ECR::Repository", '
        '"Properties": {"ImageScanningConfiguration": {"ScanOnPush": false}}}}}',
        encoding="utf-8",
    )
    findings = CfnEcrScanOnPushGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1


def test_cfn_ecr_scan_on_push_silent_when_enabled(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyRepo:\n    Type: AWS::ECR::Repository\n    Properties:\n"
        "      ImageScanningConfiguration:\n        ScanOnPush: true\n",
        encoding="utf-8",
    )
    assert CfnEcrScanOnPushGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_ecr_scan_on_push_silent_when_enabled_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Resources": {"MyRepo": {"Type": "AWS::ECR::Repository", '
        '"Properties": {"ImageScanningConfiguration": {"ScanOnPush": true}}}}}',
        encoding="utf-8",
    )
    assert CfnEcrScanOnPushGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_ecr_scan_on_push_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyRepo:\n    Type: AWS::ECR::Repository\n    Properties:\n"
        "      RepositoryName: app # security: allow-ecr-scan-on-push\n",
        encoding="utf-8",
    )
    assert CfnEcrScanOnPushGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_ecr_scan_on_push_silent_on_non_ecr_resource(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n    Properties: {}\n",
        encoding="utf-8",
    )
    assert CfnEcrScanOnPushGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_ecr_scan_on_push_not_applicable_without_cloudformation() -> None:
    prof = mkprofile(Path("/tmp"), features={"terraform"})
    assert CfnEcrScanOnPushGuard().applies(prof) is False
