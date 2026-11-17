from __future__ import annotations

from agentsec.guards.kms_key_rotation_not_enabled import KmsKeyRotationNotEnabledGuard
from tests.guards._common import *  # noqa: F401,F403


def test_kms_key_rotation_not_enabled_flags_missing_attribute(tmp_path: Path) -> None:
    (tmp_path / "kms.tf").write_text(
        'resource "aws_kms_key" "app" {\n'
        '  description = "app data key"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = KmsKeyRotationNotEnabledGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "kms-key-rotation-not-enabled/missing-rotation"
    assert findings[0].severity == "medium"


def test_kms_key_rotation_not_enabled_flags_explicit_false(tmp_path: Path) -> None:
    (tmp_path / "kms.tf").write_text(
        'resource "aws_kms_key" "app" {\n'
        "  enable_key_rotation = false\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = KmsKeyRotationNotEnabledGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_kms_key_rotation_not_enabled_silent_when_true(tmp_path: Path) -> None:
    (tmp_path / "kms.tf").write_text(
        'resource "aws_kms_key" "app" {\n'
        "  enable_key_rotation = true\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert KmsKeyRotationNotEnabledGuard().run(tmp_path, profile) == []


def test_kms_key_rotation_not_enabled_silent_asymmetric_spec(tmp_path: Path) -> None:
    (tmp_path / "kms.tf").write_text(
        'resource "aws_kms_key" "app" {\n'
        '  customer_master_key_spec = "ECC_NIST_P256"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert KmsKeyRotationNotEnabledGuard().run(tmp_path, profile) == []


def test_kms_key_rotation_not_enabled_silent_hmac_spec(tmp_path: Path) -> None:
    (tmp_path / "kms.tf").write_text(
        'resource "aws_kms_key" "app" {\n'
        '  customer_master_key_spec = "HMAC_256"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert KmsKeyRotationNotEnabledGuard().run(tmp_path, profile) == []


def test_kms_key_rotation_not_enabled_fires_symmetric_default_spec(tmp_path: Path) -> None:
    # An explicit SYMMETRIC_DEFAULT spec is AWS's implicit default and DOES support
    # rotation -> must still fire when enable_key_rotation is missing.
    (tmp_path / "kms.tf").write_text(
        'resource "aws_kms_key" "app" {\n'
        '  customer_master_key_spec = "SYMMETRIC_DEFAULT"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = KmsKeyRotationNotEnabledGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_kms_key_rotation_not_enabled_silent_other_resource(tmp_path: Path) -> None:
    (tmp_path / "other.tf").write_text(
        'resource "aws_db_instance" "app" {\n'
        '  engine = "postgres"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert KmsKeyRotationNotEnabledGuard().run(tmp_path, profile) == []


def test_kms_key_rotation_not_enabled_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "kms.tf").write_text(
        'resource "aws_kms_key" "app" {\n'
        "  # security: allow-kms-key-rotation\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert KmsKeyRotationNotEnabledGuard().run(tmp_path, profile) == []


def test_kms_key_rotation_not_enabled_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert KmsKeyRotationNotEnabledGuard().applies(profile) is False


def test_kms_key_rotation_not_enabled_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert KmsKeyRotationNotEnabledGuard().applies(profile) is True


def test_kms_key_rotation_brace_in_string_does_not_truncate_block(tmp_path: Path) -> None:
    # An unbalanced `}` inside a tag string used to close the resource block early, dropping
    # the `enable_key_rotation = true` line below it -> false positive on a rotating key.
    (tmp_path / "kms.tf").write_text(
        'resource "aws_kms_key" "app" {\n'
        '  tags                 = { Name = "prod}key" }\n'
        "  enable_key_rotation  = true\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert KmsKeyRotationNotEnabledGuard().run(tmp_path, profile) == []


def test_kms_key_rotation_comment_does_not_suppress_finding(tmp_path: Path) -> None:
    # A commented `# enable_key_rotation = true` must NOT be read as the real attribute on
    # a genuinely non-rotating key (comment-blind blob search -> false negative).
    (tmp_path / "kms.tf").write_text(
        'resource "aws_kms_key" "app" {\n'
        '  description = "app data key"\n'
        "  # TODO: enable_key_rotation = true\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = KmsKeyRotationNotEnabledGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "kms-key-rotation-not-enabled/missing-rotation"


def test_kms_key_rotation_commented_spec_does_not_suppress_finding(tmp_path: Path) -> None:
    # A commented `# customer_master_key_spec = "ECC_NIST_P256"` must NOT be read as a real
    # asymmetric spec on a genuinely non-rotating symmetric key -> false negative otherwise.
    (tmp_path / "kms.tf").write_text(
        'resource "aws_kms_key" "app" {\n'
        '  # customer_master_key_spec = "ECC_NIST_P256"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = KmsKeyRotationNotEnabledGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_kms_key_rotation_pragma_quoted_in_a_string_does_not_suppress(tmp_path: Path) -> None:
    # #424 E4: the per-resource check reads the HCL comment-only view of the block, so a string
    # attribute inside the block quoting the pragma is content - only a real `#` comment opts out.
    (tmp_path / "kms.tf").write_text(
        'resource "aws_kms_key" "app" {\n'
        '  description = "opt out with # security: allow-kms-key-rotation"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert len(KmsKeyRotationNotEnabledGuard().run(tmp_path, profile)) == 1
