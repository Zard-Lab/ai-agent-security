from __future__ import annotations

from agentsec.guards.sns_topic_not_encrypted import SnsTopicNotEncryptedGuard
from tests.guards._common import *  # noqa: F401,F403


def test_sns_topic_not_encrypted_flags_missing_attribute(tmp_path: Path) -> None:
    (tmp_path / "sns.tf").write_text(
        'resource "aws_sns_topic" "alerts" {\n'
        '  name = "alerts"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = SnsTopicNotEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "sns-topic-not-encrypted/missing-encryption"
    assert findings[0].severity == "high"


def test_sns_topic_not_encrypted_silent_when_kms_key_set(tmp_path: Path) -> None:
    (tmp_path / "sns.tf").write_text(
        'resource "aws_sns_topic" "alerts" {\n'
        '  name              = "alerts"\n'
        "  kms_master_key_id = aws_kms_key.app.id\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert SnsTopicNotEncryptedGuard().run(tmp_path, profile) == []


def test_sns_topic_not_encrypted_silent_with_aws_managed_alias(tmp_path: Path) -> None:
    (tmp_path / "sns.tf").write_text(
        'resource "aws_sns_topic" "alerts" {\n'
        '  name              = "alerts"\n'
        '  kms_master_key_id = "alias/aws/sns"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert SnsTopicNotEncryptedGuard().run(tmp_path, profile) == []


def test_sns_topic_not_encrypted_silent_other_resource(tmp_path: Path) -> None:
    (tmp_path / "other.tf").write_text(
        'resource "aws_sqs_queue" "jobs" {\n'
        '  name = "jobs"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert SnsTopicNotEncryptedGuard().run(tmp_path, profile) == []


def test_sns_topic_not_encrypted_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "sns.tf").write_text(
        'resource "aws_sns_topic" "alerts" {\n'
        '  name = "alerts"\n'
        "  # security: allow-sns-unencrypted\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert SnsTopicNotEncryptedGuard().run(tmp_path, profile) == []


def test_sns_topic_not_encrypted_comment_does_not_suppress_finding(tmp_path: Path) -> None:
    (tmp_path / "sns.tf").write_text(
        'resource "aws_sns_topic" "alerts" {\n'
        '  name = "alerts"\n'
        "  # kms_master_key_id = aws_kms_key.app.id\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = SnsTopicNotEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_sns_topic_not_encrypted_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert SnsTopicNotEncryptedGuard().applies(profile) is False


def test_sns_topic_not_encrypted_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert SnsTopicNotEncryptedGuard().applies(profile) is True
