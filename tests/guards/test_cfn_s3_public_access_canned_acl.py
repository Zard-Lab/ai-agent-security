from __future__ import annotations

from agentsec.guards.cfn_s3_public_access_canned_acl import CfnS3PublicAccessCannedAclGuard
from tests.guards._common import *  # noqa: F401,F403


def _cfnprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"cloudformation"})


def test_cfn_s3_public_access_flags_public_read(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n    Properties:\n"
        "      AccessControl: PublicRead\n",
        encoding="utf-8",
    )
    findings = CfnS3PublicAccessCannedAclGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-s3-public-access-canned-acl/public-read"
    assert findings[0].severity == "high"


def test_cfn_s3_public_access_flags_public_read_write(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n    Properties:\n"
        "      AccessControl: PublicReadWrite\n",
        encoding="utf-8",
    )
    findings = CfnS3PublicAccessCannedAclGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-s3-public-access-canned-acl/public-read-write"
    assert findings[0].severity == "high"


def test_cfn_s3_public_access_flags_public_read_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Resources": {"MyBucket": {"Type": "AWS::S3::Bucket", '
        '"Properties": {"AccessControl": "PublicRead"}}}}',
        encoding="utf-8",
    )
    findings = CfnS3PublicAccessCannedAclGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-s3-public-access-canned-acl/public-read"


def test_cfn_s3_public_access_flags_public_read_write_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Resources": {"MyBucket": {"Type": "AWS::S3::Bucket", '
        '"Properties": {"AccessControl": "PublicReadWrite"}}}}',
        encoding="utf-8",
    )
    findings = CfnS3PublicAccessCannedAclGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-s3-public-access-canned-acl/public-read-write"


def test_cfn_s3_public_access_silent_on_private(tmp_path: Path) -> None:
    # FP-bait: Private is not a public canned ACL.
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n    Properties:\n"
        "      AccessControl: Private\n",
        encoding="utf-8",
    )
    assert CfnS3PublicAccessCannedAclGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_s3_public_access_silent_on_authenticated_read(tmp_path: Path) -> None:
    # FP-bait: AuthenticatedRead requires an AWS-authenticated principal, not public.
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n    Properties:\n"
        "      AccessControl: AuthenticatedRead\n",
        encoding="utf-8",
    )
    assert CfnS3PublicAccessCannedAclGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_s3_public_access_silent_when_no_access_control_property(tmp_path: Path) -> None:
    # FP-bait: no AccessControl property at all.
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n    Properties:\n"
        "      BucketName: my-bucket\n",
        encoding="utf-8",
    )
    assert CfnS3PublicAccessCannedAclGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_s3_public_access_silent_on_non_s3_resource(tmp_path: Path) -> None:
    # FP-bait: unrelated resource type, even if it somehow carried the same property text.
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyKey:\n    Type: AWS::KMS::Key\n    Properties:\n"
        "      AccessControl: PublicReadWrite\n",
        encoding="utf-8",
    )
    assert CfnS3PublicAccessCannedAclGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_s3_public_access_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n    Properties:\n"
        "      AccessControl: PublicReadWrite "
        "# security: allow-s3-public-access-canned-acl\n",
        encoding="utf-8",
    )
    assert CfnS3PublicAccessCannedAclGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_s3_public_access_canned_acl_not_applicable_without_cloudformation() -> None:
    prof = mkprofile(Path("/tmp"), features={"terraform"})
    assert CfnS3PublicAccessCannedAclGuard().applies(prof) is False
