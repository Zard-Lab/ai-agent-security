from __future__ import annotations

from agentsec.guards.dynamodb_table_not_encrypted import DynamodbTableNotEncryptedGuard
from tests.guards._common import *  # noqa: F401,F403


def test_dynamodb_table_not_encrypted_flags_missing_block(tmp_path: Path) -> None:
    (tmp_path / "ddb.tf").write_text(
        'resource "aws_dynamodb_table" "sessions" {\n'
        '  name         = "sessions"\n'
        '  billing_mode = "PAY_PER_REQUEST"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = DynamodbTableNotEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "dynamodb-table-not-encrypted/missing-cmk-encryption"
    assert findings[0].severity == "medium"


def test_dynamodb_table_not_encrypted_flags_enabled_without_key(tmp_path: Path) -> None:
    (tmp_path / "ddb.tf").write_text(
        'resource "aws_dynamodb_table" "sessions" {\n'
        '  name = "sessions"\n'
        "  server_side_encryption {\n"
        "    enabled = true\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = DynamodbTableNotEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_dynamodb_table_not_encrypted_silent_when_cmk_set(tmp_path: Path) -> None:
    (tmp_path / "ddb.tf").write_text(
        'resource "aws_dynamodb_table" "sessions" {\n'
        '  name = "sessions"\n'
        "  server_side_encryption {\n"
        "    enabled     = true\n"
        "    kms_key_arn = aws_kms_key.app.arn\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert DynamodbTableNotEncryptedGuard().run(tmp_path, profile) == []


def test_dynamodb_table_not_encrypted_silent_when_cmk_set_via_dynamic_block(tmp_path: Path) -> None:
    # Dean's review, High 2: the `dynamic "server_side_encryption" { ... content { ... } }`
    # form wraps the real attributes one level deeper than the plain block -- the pre-fix
    # regex's immediate `{` after the keyword never matched a `dynamic` label sitting in between.
    (tmp_path / "ddb.tf").write_text(
        'resource "aws_dynamodb_table" "sessions" {\n'
        '  name = "sessions"\n'
        '  dynamic "server_side_encryption" {\n'
        "    for_each = var.sse\n"
        "    content {\n"
        "      enabled     = true\n"
        "      kms_key_arn = aws_kms_key.app.arn\n"
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert DynamodbTableNotEncryptedGuard().run(tmp_path, profile) == []


def test_dynamodb_table_not_encrypted_flags_dynamic_block_missing_cmk(tmp_path: Path) -> None:
    # Same dynamic-block shape but genuinely missing the CMK -- must still fire, not just
    # go silent whenever a `dynamic` block is present.
    (tmp_path / "ddb.tf").write_text(
        'resource "aws_dynamodb_table" "sessions" {\n'
        '  name = "sessions"\n'
        '  dynamic "server_side_encryption" {\n'
        "    for_each = var.sse\n"
        "    content {\n"
        "      enabled = true\n"
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = DynamodbTableNotEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_dynamodb_table_not_encrypted_silent_other_resource(tmp_path: Path) -> None:
    (tmp_path / "other.tf").write_text(
        'resource "aws_ebs_volume" "data" {\n'
        '  availability_zone = "us-east-1a"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert DynamodbTableNotEncryptedGuard().run(tmp_path, profile) == []


def test_dynamodb_table_not_encrypted_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "ddb.tf").write_text(
        'resource "aws_dynamodb_table" "sessions" {\n'
        '  name = "sessions"\n'
        "  # security: allow-dynamodb-unencrypted\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert DynamodbTableNotEncryptedGuard().run(tmp_path, profile) == []


def test_dynamodb_table_not_encrypted_comment_does_not_suppress_finding(tmp_path: Path) -> None:
    (tmp_path / "ddb.tf").write_text(
        'resource "aws_dynamodb_table" "sessions" {\n'
        '  name = "sessions"\n'
        "  # server_side_encryption { enabled = true, kms_key_arn = \"x\" }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = DynamodbTableNotEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_dynamodb_table_not_encrypted_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert DynamodbTableNotEncryptedGuard().applies(profile) is False


def test_dynamodb_table_not_encrypted_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert DynamodbTableNotEncryptedGuard().applies(profile) is True
