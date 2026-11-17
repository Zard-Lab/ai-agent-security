from __future__ import annotations

from agentsec.guards.kms_key_disabled import KmsKeyDisabledGuard
from tests.guards._common import *  # noqa: F401,F403


def test_kms_key_disabled_flags_explicit_false(tmp_path: Path) -> None:
    (tmp_path / "kms.tf").write_text(
        'resource "aws_kms_key" "app" {\n'
        '  description = "app data encryption key"\n'
        "  is_enabled  = false\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = KmsKeyDisabledGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "kms-key-disabled/explicitly-disabled"
    assert findings[0].severity == "medium"

def test_kms_key_disabled_silent_true(tmp_path: Path) -> None:
    (tmp_path / "kms.tf").write_text(
        'resource "aws_kms_key" "app" {\n'
        "  is_enabled = true\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert KmsKeyDisabledGuard().run(tmp_path, profile) == []

def test_kms_key_disabled_silent_when_absent(tmp_path: Path) -> None:
    (tmp_path / "kms.tf").write_text(
        'resource "aws_kms_key" "app" {\n'
        '  description = "app data encryption key"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert KmsKeyDisabledGuard().run(tmp_path, profile) == []

def test_kms_key_disabled_silent_other_resource(tmp_path: Path) -> None:
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket" "app" {\n'
        "  is_enabled = false\n"  # not a real S3 attribute, but confirms resource-type scoping
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert KmsKeyDisabledGuard().run(tmp_path, profile) == []

def test_kms_key_disabled_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "kms.tf").write_text(
        'resource "aws_kms_key" "app" {\n'
        "  is_enabled = false  # security: allow-kms-key-disabled\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert KmsKeyDisabledGuard().run(tmp_path, profile) == []

def test_kms_key_disabled_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert KmsKeyDisabledGuard().applies(profile) is False

def test_kms_key_disabled_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert KmsKeyDisabledGuard().applies(profile) is True


def test_kms_key_disabled_pragma_quoted_in_a_string_does_not_suppress(tmp_path: Path) -> None:
    # #424 E4: the per-line check reads the HCL comment-only view of the attribute line, so a
    # string on that line quoting the pragma is content - only a real `#` comment opts out. A
    # conditional expression is the one legal HCL shape that puts a string on a boolean line.
    (tmp_path / "kms.tf").write_text(
        'resource "aws_kms_key" "app" {\n'
        '  is_enabled = false && var.note != "opt out with # security: allow-kms-key-disabled"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert len(KmsKeyDisabledGuard().run(tmp_path, profile)) == 1
