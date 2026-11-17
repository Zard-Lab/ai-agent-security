from __future__ import annotations

from agentsec.guards.secrets_manager_default_kms import SecretsManagerDefaultKmsGuard
from tests.guards._common import *  # noqa: F401,F403


def test_secrets_manager_default_kms_flags_missing_attribute(tmp_path: Path) -> None:
    (tmp_path / "secret.tf").write_text(
        'resource "aws_secretsmanager_secret" "db_password" {\n'
        '  name = "db_password"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = SecretsManagerDefaultKmsGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "secrets-manager-default-kms/default-aws-managed-key"
    assert findings[0].severity == "medium"


def test_secrets_manager_default_kms_flags_default_alias(tmp_path: Path) -> None:
    (tmp_path / "secret.tf").write_text(
        'resource "aws_secretsmanager_secret" "db_password" {\n'
        '  name       = "db_password"\n'
        '  kms_key_id = "alias/aws/secretsmanager"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = SecretsManagerDefaultKmsGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_secrets_manager_default_kms_silent_when_cmk_set(tmp_path: Path) -> None:
    (tmp_path / "secret.tf").write_text(
        'resource "aws_secretsmanager_secret" "db_password" {\n'
        '  name       = "db_password"\n'
        '  kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/abcd-1234"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert SecretsManagerDefaultKmsGuard().run(tmp_path, profile) == []


def test_secrets_manager_default_kms_silent_when_cmk_referenced(tmp_path: Path) -> None:
    # Dean's review, Critical 1: the guard's own remediation text tells the user to write
    # `kms_key_id = aws_kms_key.<name>.arn` -- a resource reference, not a quoted literal. The
    # pre-fix regex only matched a quoted string, so following the remediation kept firing forever.
    (tmp_path / "secret.tf").write_text(
        'resource "aws_secretsmanager_secret" "db_password" {\n'
        '  name       = "db_password"\n'
        "  kms_key_id = aws_kms_key.app.arn\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert SecretsManagerDefaultKmsGuard().run(tmp_path, profile) == []


def test_secrets_manager_default_kms_flags_explicit_null(tmp_path: Path) -> None:
    # #687 fix-commit re-review, High 1: the C1 quoted-literal fix's widened `(\S+)` branch
    # accepted the literal HCL keyword `null` as "a value is set", going silent on the exact
    # condition this guard exists to report -- Terraform treats `kms_key_id = null` as absent.
    (tmp_path / "secret.tf").write_text(
        'resource "aws_secretsmanager_secret" "db_password" {\n'
        '  name       = "db_password"\n'
        "  kms_key_id = null\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = SecretsManagerDefaultKmsGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "secrets-manager-default-kms/default-aws-managed-key"


def test_secrets_manager_default_kms_flags_null_with_trailing_comment(tmp_path: Path) -> None:
    (tmp_path / "secret.tf").write_text(
        'resource "aws_secretsmanager_secret" "db_password" {\n'
        '  name       = "db_password"\n'
        "  kms_key_id = null  # explicitly no CMK\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert len(SecretsManagerDefaultKmsGuard().run(tmp_path, profile)) == 1


def test_secrets_manager_default_kms_resource_reference_still_silent_after_null_fix(
    tmp_path: Path,
) -> None:
    # Still fires the OTHER direction correctly: the null-literal fix must not reopen the
    # resource-reference false positive the C1 fix (Critical 1) already closed.
    (tmp_path / "secret.tf").write_text(
        'resource "aws_secretsmanager_secret" "db_password" {\n'
        '  name       = "db_password"\n'
        "  kms_key_id = aws_kms_key.app.arn\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert SecretsManagerDefaultKmsGuard().run(tmp_path, profile) == []


def test_secrets_manager_default_kms_ternary_ending_in_null_is_a_disclosed_gap(
    tmp_path: Path,
) -> None:
    # Disclosed, accepted limitation (see the module docstring): the value-capture regex takes
    # only the first token after `=`, so a multi-token ternary whose false-branch is `null`
    # captures the condition token instead and stays silent. Pinned here so a future change to
    # the regex's capture width doesn't silently start (or fail to start) catching this shape
    # without anyone noticing either way.
    (tmp_path / "secret.tf").write_text(
        'resource "aws_secretsmanager_secret" "db_password" {\n'
        '  name       = "db_password"\n'
        "  kms_key_id = var.use_cmk ? aws_kms_key.app.arn : null\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert SecretsManagerDefaultKmsGuard().run(tmp_path, profile) == []


def test_secrets_manager_default_kms_silent_other_resource(tmp_path: Path) -> None:
    (tmp_path / "other.tf").write_text(
        'resource "aws_sns_topic" "alerts" {\n'
        '  name = "alerts"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert SecretsManagerDefaultKmsGuard().run(tmp_path, profile) == []


def test_secrets_manager_default_kms_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "secret.tf").write_text(
        'resource "aws_secretsmanager_secret" "db_password" {\n'
        '  name = "db_password"\n'
        "  # security: allow-secrets-manager-default-kms\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert SecretsManagerDefaultKmsGuard().run(tmp_path, profile) == []


def test_secrets_manager_default_kms_comment_does_not_suppress_finding(tmp_path: Path) -> None:
    (tmp_path / "secret.tf").write_text(
        'resource "aws_secretsmanager_secret" "db_password" {\n'
        '  name = "db_password"\n'
        '  # kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/abcd-1234"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = SecretsManagerDefaultKmsGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_secrets_manager_default_kms_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert SecretsManagerDefaultKmsGuard().applies(profile) is False


def test_secrets_manager_default_kms_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert SecretsManagerDefaultKmsGuard().applies(profile) is True
