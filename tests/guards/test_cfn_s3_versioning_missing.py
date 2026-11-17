from __future__ import annotations

from agentsec.guards.cfn_s3_versioning_missing import CfnS3VersioningMissingGuard
from tests.guards._common import *  # noqa: F401,F403


def _cfnprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"cloudformation"})


def test_cfn_s3_versioning_flags_missing_config(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: x\n",
        encoding="utf-8",
    )
    findings = CfnS3VersioningMissingGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-s3-versioning-missing/no-versioning"
    assert findings[0].severity == "medium"


def test_cfn_s3_versioning_flags_missing_config_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Resources": {"MyBucket": {"Type": "AWS::S3::Bucket", "Properties": {}}}}',
        encoding="utf-8",
    )
    findings = CfnS3VersioningMissingGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-s3-versioning-missing/no-versioning"


def test_cfn_s3_versioning_flags_suspended(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n    Properties:\n"
        "      VersioningConfiguration:\n        Status: Suspended\n",
        encoding="utf-8",
    )
    findings = CfnS3VersioningMissingGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1


def test_cfn_s3_versioning_flags_suspended_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Resources": {"MyBucket": {"Type": "AWS::S3::Bucket", "Properties": '
        '{"VersioningConfiguration": {"Status": "Suspended"}}}}}',
        encoding="utf-8",
    )
    findings = CfnS3VersioningMissingGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1


def test_cfn_s3_versioning_silent_when_enabled(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n    Properties:\n"
        "      VersioningConfiguration:\n        Status: Enabled\n",
        encoding="utf-8",
    )
    assert CfnS3VersioningMissingGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_s3_versioning_silent_when_enabled_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Resources": {"MyBucket": {"Type": "AWS::S3::Bucket", "Properties": '
        '{"VersioningConfiguration": {"Status": "Enabled"}}}}}',
        encoding="utf-8",
    )
    assert CfnS3VersioningMissingGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_s3_versioning_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n    Properties:\n"
        "      BucketName: x # security: allow-s3-versioning-missing\n",
        encoding="utf-8",
    )
    assert CfnS3VersioningMissingGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_s3_versioning_silent_on_non_s3_resource(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyKey:\n    Type: AWS::KMS::Key\n    Properties: {}\n",
        encoding="utf-8",
    )
    assert CfnS3VersioningMissingGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_s3_versioning_flags_bucket_with_only_lifecycle_status_enabled(tmp_path: Path) -> None:
    """Still-fires (Dean's review repro): a bucket with a LifecycleConfiguration rule
    (its own unrelated `Status: Enabled`) but genuinely NO VersioningConfiguration must still fire
    -- the pre-fix whole-block search collided on the shared `Status: Enabled` string and read this
    bucket as versioned."""
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n    Properties:\n"
        "      BucketName: x\n"
        "      LifecycleConfiguration:\n"
        "        Rules:\n"
        "          - Id: expire-old\n"
        "            Status: Enabled\n"
        "            ExpirationInDays: 30\n",
        encoding="utf-8",
    )
    findings = CfnS3VersioningMissingGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-s3-versioning-missing/no-versioning"


def test_cfn_s3_versioning_flags_bucket_with_only_lifecycle_status_enabled_json(
    tmp_path: Path,
) -> None:
    """JSON variant of the above."""
    (tmp_path / "template.json").write_text(
        '{"Resources": {"MyBucket": {"Type": "AWS::S3::Bucket", "Properties": '
        '{"LifecycleConfiguration": {"Rules": [{"Id": "expire-old", "Status": "Enabled", '
        '"ExpirationInDays": 30}]}}}}}',
        encoding="utf-8",
    )
    findings = CfnS3VersioningMissingGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1


def test_cfn_s3_versioning_silent_when_enabled_alongside_lifecycle(tmp_path: Path) -> None:
    """Still-silent: a bucket genuinely versioned AND carrying a lifecycle rule must not fire --
    confirms the narrowed scope still finds the real VersioningConfiguration when both properties
    are present side by side."""
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n    Properties:\n"
        "      VersioningConfiguration:\n        Status: Enabled\n"
        "      LifecycleConfiguration:\n"
        "        Rules:\n"
        "          - Id: expire-old\n"
        "            Status: Enabled\n",
        encoding="utf-8",
    )
    assert CfnS3VersioningMissingGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_s3_versioning_silent_on_flow_style_inline(tmp_path: Path) -> None:
    """Still-silent: the rare flow-style single-line form must not regress into a false
    positive now that the scope is narrowed to a carved-out sub-block."""
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n    Properties:\n"
        "      VersioningConfiguration: {Status: Enabled}\n",
        encoding="utf-8",
    )
    assert CfnS3VersioningMissingGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_s3_versioning_not_applicable_without_cloudformation() -> None:
    prof = mkprofile(Path("/tmp"), features={"terraform"})
    assert CfnS3VersioningMissingGuard().applies(prof) is False
