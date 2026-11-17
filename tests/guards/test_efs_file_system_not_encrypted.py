from __future__ import annotations

from agentsec.guards.efs_file_system_not_encrypted import EfsFileSystemNotEncryptedGuard
from tests.guards._common import *  # noqa: F401,F403


def test_efs_file_system_not_encrypted_flags_missing_attribute(tmp_path: Path) -> None:
    (tmp_path / "efs.tf").write_text(
        'resource "aws_efs_file_system" "shared" {\n'
        '  creation_token = "shared-data"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = EfsFileSystemNotEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "efs-file-system-not-encrypted/missing-encryption"
    assert findings[0].severity == "high"


def test_efs_file_system_not_encrypted_flags_explicit_false(tmp_path: Path) -> None:
    (tmp_path / "efs.tf").write_text(
        'resource "aws_efs_file_system" "shared" {\n'
        '  creation_token = "shared-data"\n'
        "  encrypted      = false\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = EfsFileSystemNotEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_efs_file_system_not_encrypted_silent_when_true(tmp_path: Path) -> None:
    (tmp_path / "efs.tf").write_text(
        'resource "aws_efs_file_system" "shared" {\n'
        '  creation_token = "shared-data"\n'
        "  encrypted      = true\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert EfsFileSystemNotEncryptedGuard().run(tmp_path, profile) == []


def test_efs_file_system_not_encrypted_silent_when_quoted_true(tmp_path: Path) -> None:
    # round-2 review M-3: Terraform coerces a quoted "true"/"false" string to the bool, so
    # `encrypted = "true"` is the same as `encrypted = true` and must stay silent, not be
    # read as an absent/non-literal attribute (a false positive `literal_bool_state` used to
    # produce for any quoted-boolean shape).
    (tmp_path / "efs.tf").write_text(
        'resource "aws_efs_file_system" "shared" {\n'
        '  creation_token = "shared-data"\n'
        '  encrypted      = "true"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert EfsFileSystemNotEncryptedGuard().run(tmp_path, profile) == []


def test_efs_file_system_not_encrypted_flags_quoted_false(tmp_path: Path) -> None:
    # Same shape, the real vulnerable case: a quoted "false" must still fire, not be silently
    # read as non-literal.
    (tmp_path / "efs.tf").write_text(
        'resource "aws_efs_file_system" "shared" {\n'
        '  creation_token = "shared-data"\n'
        '  encrypted      = "false"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = EfsFileSystemNotEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_efs_file_system_not_encrypted_silent_when_variable(tmp_path: Path) -> None:
    # A non-literal value cannot be proven unsafe (review H6) -- stays silent, unlike absence.
    (tmp_path / "efs.tf").write_text(
        'resource "aws_efs_file_system" "shared" {\n'
        '  creation_token = "shared-data"\n'
        "  encrypted      = var.enc\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert EfsFileSystemNotEncryptedGuard().run(tmp_path, profile) == []


def test_efs_file_system_not_encrypted_silent_other_resource(tmp_path: Path) -> None:
    (tmp_path / "other.tf").write_text(
        'resource "aws_ebs_volume" "data" {\n'
        '  availability_zone = "us-east-1a"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert EfsFileSystemNotEncryptedGuard().run(tmp_path, profile) == []


def test_efs_file_system_not_encrypted_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "efs.tf").write_text(
        'resource "aws_efs_file_system" "shared" {\n'
        "  # security: allow-efs-unencrypted\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert EfsFileSystemNotEncryptedGuard().run(tmp_path, profile) == []


def test_efs_file_system_not_encrypted_comment_does_not_suppress_finding(tmp_path: Path) -> None:
    (tmp_path / "efs.tf").write_text(
        'resource "aws_efs_file_system" "shared" {\n'
        '  creation_token = "shared-data"\n'
        "  # encrypted = true\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = EfsFileSystemNotEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_efs_file_system_not_encrypted_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert EfsFileSystemNotEncryptedGuard().applies(profile) is False


def test_efs_file_system_not_encrypted_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert EfsFileSystemNotEncryptedGuard().applies(profile) is True


def test_efs_file_system_not_encrypted_tag_key_sharing_the_name_does_not_silence(
    tmp_path: Path,
) -> None:
    # PR #1162 round-3 L-1: `tags = { encrypted = "no" }` read as a non-literal `encrypted`
    # and silenced an unencrypted file system.
    (tmp_path / "efs.tf").write_text(
        'resource "aws_efs_file_system" "shared" {\n'
        '  creation_token = "shared-data"\n'
        "  tags = {\n"
        '    encrypted = "no"\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = EfsFileSystemNotEncryptedGuard().run(tmp_path, profile)
    assert [f.rule for f in findings] == ["efs-file-system-not-encrypted/missing-encryption"]


def _efs_rules(tmp_path: Path, lines: str) -> list[str]:
    (tmp_path / "efs.tf").write_text(
        'resource "aws_efs_file_system" "shared" {\n'
        '  creation_token = "shared-data"\n'
        f"{lines}"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    return [f.rule for f in EfsFileSystemNotEncryptedGuard().run(tmp_path, profile)]


def test_efs_quoted_bool_tag_value_does_not_decide_the_verdict(tmp_path: Path) -> None:
    # PR #1162 round-4 M2: a tag spelled like the attribute with a quoted bool still won as the
    # first match. An unencrypted file system with a "true" tag was silent...
    rule = "efs-file-system-not-encrypted/missing-encryption"
    assert _efs_rules(tmp_path, '  tags = { encrypted = "true" }\n') == [rule]
    assert _efs_rules(tmp_path, '  tags = {\n    encrypted = "true"\n  }\n') == [rule]
    # ...and an encrypted one with a "false" tag above the real attribute fired.
    assert _efs_rules(tmp_path, '  tags = { encrypted = "false" }\n  encrypted = true\n') == []
    assert _efs_rules(tmp_path, '  tags = {\n    encrypted = "false"\n  }\n  encrypted = true\n') == []
    # Still fires: the real attribute off, next to a "true" tag.
    assert _efs_rules(tmp_path, '  tags = { encrypted = "true" }\n  encrypted = false\n') == [rule]
