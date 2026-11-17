from __future__ import annotations

from agentsec.guards.ebs_volume_not_encrypted import EbsVolumeNotEncryptedGuard
from tests.guards._common import *  # noqa: F401,F403


def test_ebs_volume_not_encrypted_flags_missing_attribute(tmp_path: Path) -> None:
    (tmp_path / "ebs.tf").write_text(
        'resource "aws_ebs_volume" "data" {\n'
        '  availability_zone = "us-east-1a"\n'
        "  size              = 100\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = EbsVolumeNotEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "ebs-volume-not-encrypted/missing-encryption"
    assert findings[0].severity == "high"


def test_ebs_volume_not_encrypted_flags_explicit_false(tmp_path: Path) -> None:
    (tmp_path / "ebs.tf").write_text(
        'resource "aws_ebs_volume" "data" {\n'
        '  availability_zone = "us-east-1a"\n'
        "  encrypted         = false\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = EbsVolumeNotEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_ebs_volume_not_encrypted_silent_when_true(tmp_path: Path) -> None:
    (tmp_path / "ebs.tf").write_text(
        'resource "aws_ebs_volume" "data" {\n'
        '  availability_zone = "us-east-1a"\n'
        "  encrypted         = true\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert EbsVolumeNotEncryptedGuard().run(tmp_path, profile) == []


def test_ebs_volume_not_encrypted_silent_other_resource(tmp_path: Path) -> None:
    (tmp_path / "other.tf").write_text(
        'resource "aws_db_instance" "app" {\n'
        '  engine = "postgres"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert EbsVolumeNotEncryptedGuard().run(tmp_path, profile) == []


def test_ebs_volume_not_encrypted_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "ebs.tf").write_text(
        'resource "aws_ebs_volume" "data" {\n'
        "  # security: allow-ebs-unencrypted\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert EbsVolumeNotEncryptedGuard().run(tmp_path, profile) == []


def test_ebs_volume_not_encrypted_comment_does_not_suppress_finding(tmp_path: Path) -> None:
    (tmp_path / "ebs.tf").write_text(
        'resource "aws_ebs_volume" "data" {\n'
        '  availability_zone = "us-east-1a"\n'
        "  # encrypted = true\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = EbsVolumeNotEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_ebs_volume_not_encrypted_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert EbsVolumeNotEncryptedGuard().applies(profile) is False


def test_ebs_volume_not_encrypted_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert EbsVolumeNotEncryptedGuard().applies(profile) is True
