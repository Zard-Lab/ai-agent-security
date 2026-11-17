from __future__ import annotations

from agentsec.guards.kinesis_stream_not_encrypted import KinesisStreamNotEncryptedGuard
from tests.guards._common import *  # noqa: F401,F403


def test_kinesis_stream_not_encrypted_flags_missing_attribute(tmp_path: Path) -> None:
    (tmp_path / "kinesis.tf").write_text(
        'resource "aws_kinesis_stream" "events" {\n'
        '  name             = "events"\n'
        "  shard_count      = 1\n"
        "  retention_period = 24\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = KinesisStreamNotEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "kinesis-stream-not-encrypted/missing-encryption"
    assert findings[0].severity == "high"


def test_kinesis_stream_not_encrypted_flags_explicit_none(tmp_path: Path) -> None:
    (tmp_path / "kinesis.tf").write_text(
        'resource "aws_kinesis_stream" "events" {\n'
        '  name             = "events"\n'
        '  encryption_type  = "NONE"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = KinesisStreamNotEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_kinesis_stream_not_encrypted_silent_when_kms(tmp_path: Path) -> None:
    (tmp_path / "kinesis.tf").write_text(
        'resource "aws_kinesis_stream" "events" {\n'
        '  name             = "events"\n'
        '  encryption_type  = "KMS"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert KinesisStreamNotEncryptedGuard().run(tmp_path, profile) == []


def test_kinesis_stream_not_encrypted_silent_when_variable(tmp_path: Path) -> None:
    # A non-literal value is assumed intentional, same as any other non-NONE literal (review
    # H6) -- it must NOT be treated the same as an absent attribute, which does fire.
    (tmp_path / "kinesis.tf").write_text(
        'resource "aws_kinesis_stream" "events" {\n'
        '  name             = "events"\n'
        "  encryption_type  = var.et\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert KinesisStreamNotEncryptedGuard().run(tmp_path, profile) == []


def test_kinesis_stream_not_encrypted_silent_other_resource(tmp_path: Path) -> None:
    (tmp_path / "other.tf").write_text(
        'resource "aws_sqs_queue" "jobs" {\n'
        '  name = "jobs"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert KinesisStreamNotEncryptedGuard().run(tmp_path, profile) == []


def test_kinesis_stream_not_encrypted_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "kinesis.tf").write_text(
        'resource "aws_kinesis_stream" "events" {\n'
        "  # security: allow-kinesis-unencrypted\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert KinesisStreamNotEncryptedGuard().run(tmp_path, profile) == []


def test_kinesis_stream_not_encrypted_comment_does_not_suppress_finding(tmp_path: Path) -> None:
    (tmp_path / "kinesis.tf").write_text(
        'resource "aws_kinesis_stream" "events" {\n'
        '  name = "events"\n'
        '  # encryption_type = "KMS"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = KinesisStreamNotEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_kinesis_stream_not_encrypted_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert KinesisStreamNotEncryptedGuard().applies(profile) is False


def test_kinesis_stream_not_encrypted_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert KinesisStreamNotEncryptedGuard().applies(profile) is True
