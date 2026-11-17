from __future__ import annotations

from agentsec.guards.ecr_repository_not_kms_encrypted import EcrRepositoryNotKmsEncryptedGuard
from tests.guards._common import *  # noqa: F401,F403


def test_ecr_repository_not_kms_encrypted_flags_missing_block(tmp_path: Path) -> None:
    (tmp_path / "ecr.tf").write_text(
        'resource "aws_ecr_repository" "app" {\n'
        '  name = "app"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = EcrRepositoryNotKmsEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "ecr-repository-not-kms-encrypted/missing-kms-encryption"
    assert findings[0].severity == "medium"


def test_ecr_repository_not_kms_encrypted_flags_aes256(tmp_path: Path) -> None:
    (tmp_path / "ecr.tf").write_text(
        'resource "aws_ecr_repository" "app" {\n'
        '  name = "app"\n'
        "  encryption_configuration {\n"
        '    encryption_type = "AES256"\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = EcrRepositoryNotKmsEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_ecr_repository_not_kms_encrypted_silent_when_kms_set(tmp_path: Path) -> None:
    (tmp_path / "ecr.tf").write_text(
        'resource "aws_ecr_repository" "app" {\n'
        '  name = "app"\n'
        "  encryption_configuration {\n"
        '    encryption_type = "KMS"\n'
        "    kms_key         = aws_kms_key.app.arn\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert EcrRepositoryNotKmsEncryptedGuard().run(tmp_path, profile) == []


def test_ecr_repository_not_kms_encrypted_silent_when_kms_set_via_dynamic_block(tmp_path: Path) -> None:
    # Dean's review, High 2: the `dynamic "encryption_configuration" { ... content { ... } }`
    # form wraps the real attributes one level deeper than the plain block -- the pre-fix
    # regex's immediate `{` after the keyword never matched a `dynamic` label sitting in between.
    (tmp_path / "ecr.tf").write_text(
        'resource "aws_ecr_repository" "app" {\n'
        '  name = "app"\n'
        '  dynamic "encryption_configuration" {\n'
        "    for_each = var.enc\n"
        "    content {\n"
        '      encryption_type = "KMS"\n'
        "      kms_key         = aws_kms_key.app.arn\n"
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert EcrRepositoryNotKmsEncryptedGuard().run(tmp_path, profile) == []


def test_ecr_repository_not_kms_encrypted_flags_dynamic_block_missing_kms(tmp_path: Path) -> None:
    # Same dynamic-block shape but genuinely missing KMS -- must still fire.
    (tmp_path / "ecr.tf").write_text(
        'resource "aws_ecr_repository" "app" {\n'
        '  name = "app"\n'
        '  dynamic "encryption_configuration" {\n'
        "    for_each = var.enc\n"
        "    content {\n"
        '      encryption_type = "AES256"\n'
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = EcrRepositoryNotKmsEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_ecr_repository_not_kms_encrypted_silent_other_resource(tmp_path: Path) -> None:
    (tmp_path / "other.tf").write_text(
        'resource "aws_ebs_volume" "data" {\n'
        '  availability_zone = "us-east-1a"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert EcrRepositoryNotKmsEncryptedGuard().run(tmp_path, profile) == []


def test_ecr_repository_not_kms_encrypted_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "ecr.tf").write_text(
        'resource "aws_ecr_repository" "app" {\n'
        '  name = "app"\n'
        "  # security: allow-ecr-non-kms-encryption\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert EcrRepositoryNotKmsEncryptedGuard().run(tmp_path, profile) == []


def test_ecr_repository_not_kms_encrypted_comment_does_not_suppress_finding(tmp_path: Path) -> None:
    (tmp_path / "ecr.tf").write_text(
        'resource "aws_ecr_repository" "app" {\n'
        '  name = "app"\n'
        '  # encryption_configuration { encryption_type = "KMS" }\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = EcrRepositoryNotKmsEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_ecr_repository_not_kms_encrypted_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert EcrRepositoryNotKmsEncryptedGuard().applies(profile) is False


def test_ecr_repository_not_kms_encrypted_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert EcrRepositoryNotKmsEncryptedGuard().applies(profile) is True
