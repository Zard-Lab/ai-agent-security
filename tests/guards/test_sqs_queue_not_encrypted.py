from __future__ import annotations

from agentsec.guards.sqs_queue_not_encrypted import SqsQueueNotEncryptedGuard
from tests.guards._common import *  # noqa: F401,F403


def test_sqs_queue_not_encrypted_flags_missing_attributes(tmp_path: Path) -> None:
    (tmp_path / "sqs.tf").write_text(
        'resource "aws_sqs_queue" "jobs" {\n'
        '  name = "jobs"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = SqsQueueNotEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "sqs-queue-not-encrypted/missing-encryption"
    assert findings[0].severity == "medium"


def test_sqs_queue_not_encrypted_silent_when_managed_sse(tmp_path: Path) -> None:
    (tmp_path / "sqs.tf").write_text(
        'resource "aws_sqs_queue" "jobs" {\n'
        '  name                    = "jobs"\n'
        "  sqs_managed_sse_enabled = true\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert SqsQueueNotEncryptedGuard().run(tmp_path, profile) == []


def test_sqs_queue_not_encrypted_silent_when_kms_key_set(tmp_path: Path) -> None:
    (tmp_path / "sqs.tf").write_text(
        'resource "aws_sqs_queue" "jobs" {\n'
        '  name               = "jobs"\n'
        "  kms_master_key_id  = aws_kms_key.app.id\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert SqsQueueNotEncryptedGuard().run(tmp_path, profile) == []


def test_sqs_queue_not_encrypted_flags_explicit_managed_sse_false(tmp_path: Path) -> None:
    (tmp_path / "sqs.tf").write_text(
        'resource "aws_sqs_queue" "jobs" {\n'
        '  name                    = "jobs"\n'
        "  sqs_managed_sse_enabled = false\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = SqsQueueNotEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_sqs_queue_not_encrypted_silent_other_resource(tmp_path: Path) -> None:
    (tmp_path / "other.tf").write_text(
        'resource "aws_sns_topic" "alerts" {\n'
        '  name = "alerts"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert SqsQueueNotEncryptedGuard().run(tmp_path, profile) == []


def test_sqs_queue_not_encrypted_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "sqs.tf").write_text(
        'resource "aws_sqs_queue" "jobs" {\n'
        '  name = "jobs"\n'
        "  # security: allow-sqs-unencrypted\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert SqsQueueNotEncryptedGuard().run(tmp_path, profile) == []


def test_sqs_queue_not_encrypted_comment_does_not_suppress_finding(tmp_path: Path) -> None:
    (tmp_path / "sqs.tf").write_text(
        'resource "aws_sqs_queue" "jobs" {\n'
        '  name = "jobs"\n'
        "  # sqs_managed_sse_enabled = true\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = SqsQueueNotEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_sqs_queue_not_encrypted_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert SqsQueueNotEncryptedGuard().applies(profile) is False


def test_sqs_queue_not_encrypted_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert SqsQueueNotEncryptedGuard().applies(profile) is True
