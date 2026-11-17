from __future__ import annotations

from agentsec.guards.cfn_kms_key_rotation_not_enabled import CfnKmsKeyRotationNotEnabledGuard
from tests.guards._common import *  # noqa: F401,F403


def _cfnprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"cloudformation"})


def test_cfn_kms_key_rotation_flags_missing_property(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyKey:\n    Type: AWS::KMS::Key\n    Properties:\n      Description: x\n",
        encoding="utf-8",
    )
    findings = CfnKmsKeyRotationNotEnabledGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-kms-key-rotation-not-enabled/missing-rotation"
    assert findings[0].severity == "medium"


def test_cfn_kms_key_rotation_flags_explicit_false(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyKey:\n    Type: AWS::KMS::Key\n    Properties:\n      EnableKeyRotation: false\n",
        encoding="utf-8",
    )
    findings = CfnKmsKeyRotationNotEnabledGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1


def test_cfn_kms_key_rotation_flags_missing_property_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Resources": {"MyKey": {"Type": "AWS::KMS::Key", "Properties": {}}}}',
        encoding="utf-8",
    )
    findings = CfnKmsKeyRotationNotEnabledGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1


def test_cfn_kms_key_rotation_silent_when_enabled(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyKey:\n    Type: AWS::KMS::Key\n    Properties:\n      EnableKeyRotation: true\n",
        encoding="utf-8",
    )
    assert CfnKmsKeyRotationNotEnabledGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_kms_key_rotation_silent_when_enabled_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Resources": {"MyKey": {"Type": "AWS::KMS::Key", '
        '"Properties": {"EnableKeyRotation": true}}}}',
        encoding="utf-8",
    )
    assert CfnKmsKeyRotationNotEnabledGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_kms_key_rotation_silent_on_asymmetric_keyspec(tmp_path: Path) -> None:
    # FP-bait: an asymmetric key does not support rotation at all.
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyKey:\n    Type: AWS::KMS::Key\n    Properties:\n      KeySpec: RSA_2048\n",
        encoding="utf-8",
    )
    assert CfnKmsKeyRotationNotEnabledGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_kms_key_rotation_silent_on_hmac_keyspec(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyKey:\n    Type: AWS::KMS::Key\n    Properties:\n      KeySpec: HMAC_256\n",
        encoding="utf-8",
    )
    assert CfnKmsKeyRotationNotEnabledGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_kms_key_rotation_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyKey:\n    Type: AWS::KMS::Key\n    Properties:\n"
        "      Description: x # security: allow-kms-key-rotation\n",
        encoding="utf-8",
    )
    assert CfnKmsKeyRotationNotEnabledGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_kms_key_rotation_silent_on_non_kms_resource(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n    Properties: {}\n",
        encoding="utf-8",
    )
    assert CfnKmsKeyRotationNotEnabledGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_kms_key_rotation_not_applicable_without_cloudformation() -> None:
    prof = mkprofile(Path("/tmp"), features={"terraform"})
    assert CfnKmsKeyRotationNotEnabledGuard().applies(prof) is False
