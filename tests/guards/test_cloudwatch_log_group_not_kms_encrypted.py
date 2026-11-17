from __future__ import annotations

from agentsec.guards.cloudwatch_log_group_not_kms_encrypted import (
    CloudwatchLogGroupNotKmsEncryptedGuard,
)
from tests.guards._common import *  # noqa: F401,F403


def test_cloudwatch_log_group_not_kms_encrypted_flags_missing_attribute(tmp_path: Path) -> None:
    (tmp_path / "cwlogs.tf").write_text(
        'resource "aws_cloudwatch_log_group" "app" {\n'
        '  name = "/app/prod"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = CloudwatchLogGroupNotKmsEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "cloudwatch-log-group-not-kms-encrypted/missing-kms-encryption"
    assert findings[0].severity == "medium"


def test_cloudwatch_log_group_not_kms_encrypted_silent_when_kms_key_set(tmp_path: Path) -> None:
    (tmp_path / "cwlogs.tf").write_text(
        'resource "aws_cloudwatch_log_group" "app" {\n'
        '  name       = "/app/prod"\n'
        "  kms_key_id = aws_kms_key.app.arn\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert CloudwatchLogGroupNotKmsEncryptedGuard().run(tmp_path, profile) == []


def test_cloudwatch_log_group_not_kms_encrypted_silent_other_resource(tmp_path: Path) -> None:
    (tmp_path / "other.tf").write_text(
        'resource "aws_ecr_repository" "app" {\n'
        '  name = "app"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert CloudwatchLogGroupNotKmsEncryptedGuard().run(tmp_path, profile) == []


def test_cloudwatch_log_group_not_kms_encrypted_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "cwlogs.tf").write_text(
        'resource "aws_cloudwatch_log_group" "app" {\n'
        '  name = "/app/prod"\n'
        "  # security: allow-cloudwatch-logs-non-kms\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert CloudwatchLogGroupNotKmsEncryptedGuard().run(tmp_path, profile) == []


def test_cloudwatch_log_group_not_kms_encrypted_comment_does_not_suppress_finding(
    tmp_path: Path,
) -> None:
    (tmp_path / "cwlogs.tf").write_text(
        'resource "aws_cloudwatch_log_group" "app" {\n'
        '  name = "/app/prod"\n'
        "  # kms_key_id = aws_kms_key.app.arn\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = CloudwatchLogGroupNotKmsEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_cloudwatch_log_group_not_kms_encrypted_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert CloudwatchLogGroupNotKmsEncryptedGuard().applies(profile) is False


def test_cloudwatch_log_group_not_kms_encrypted_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert CloudwatchLogGroupNotKmsEncryptedGuard().applies(profile) is True
