from __future__ import annotations

from agentsec.guards.sagemaker_notebook_not_encrypted import (
    SagemakerNotebookNotEncryptedGuard,
)
from tests.guards._common import *  # noqa: F401,F403


def test_sagemaker_notebook_not_encrypted_flags_missing_attribute(tmp_path: Path) -> None:
    (tmp_path / "sagemaker.tf").write_text(
        'resource "aws_sagemaker_notebook_instance" "experiments" {\n'
        '  instance_type = "ml.t3.medium"\n'
        '  role_arn      = "arn:aws:iam::123456789012:role/sagemaker"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = SagemakerNotebookNotEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "sagemaker-notebook-not-encrypted/missing-kms-key"
    assert findings[0].severity == "medium"


def test_sagemaker_notebook_not_encrypted_silent_when_kms_key_set(tmp_path: Path) -> None:
    (tmp_path / "sagemaker.tf").write_text(
        'resource "aws_sagemaker_notebook_instance" "experiments" {\n'
        '  instance_type = "ml.t3.medium"\n'
        '  role_arn      = "arn:aws:iam::123456789012:role/sagemaker"\n'
        "  kms_key_id    = aws_kms_key.sagemaker.arn\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert SagemakerNotebookNotEncryptedGuard().run(tmp_path, profile) == []


def test_sagemaker_notebook_not_encrypted_silent_other_resource(tmp_path: Path) -> None:
    (tmp_path / "other.tf").write_text(
        'resource "aws_efs_file_system" "shared" {\n'
        '  creation_token = "shared-data"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert SagemakerNotebookNotEncryptedGuard().run(tmp_path, profile) == []


def test_sagemaker_notebook_not_encrypted_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "sagemaker.tf").write_text(
        'resource "aws_sagemaker_notebook_instance" "experiments" {\n'
        "  # security: allow-sagemaker-unencrypted\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert SagemakerNotebookNotEncryptedGuard().run(tmp_path, profile) == []


def test_sagemaker_notebook_not_encrypted_comment_does_not_suppress_finding(
    tmp_path: Path,
) -> None:
    (tmp_path / "sagemaker.tf").write_text(
        'resource "aws_sagemaker_notebook_instance" "experiments" {\n'
        '  instance_type = "ml.t3.medium"\n'
        "  # kms_key_id = aws_kms_key.sagemaker.arn\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = SagemakerNotebookNotEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_sagemaker_notebook_not_encrypted_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert SagemakerNotebookNotEncryptedGuard().applies(profile) is False


def test_sagemaker_notebook_not_encrypted_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert SagemakerNotebookNotEncryptedGuard().applies(profile) is True


def _sagemaker_findings(tmp_path: Path, kms_line: str) -> list[Finding]:
    (tmp_path / "sagemaker.tf").write_text(
        'resource "aws_sagemaker_notebook_instance" "experiments" {\n'
        '  instance_type = "ml.t3.medium"\n'
        '  role_arn      = "arn:aws:iam::123456789012:role/sagemaker"\n'
        f"{kms_line}"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    return SagemakerNotebookNotEncryptedGuard().run(tmp_path, profile)


def test_sagemaker_notebook_not_encrypted_flags_empty_or_null_key(tmp_path: Path) -> None:
    # PR #1162 round-1 M9: an empty string or `null` leaves the notebook on the system-managed
    # key exactly as omission does, so it must fire (it used to count as "set").
    for kms_line in ('  kms_key_id    = ""\n', "  kms_key_id    = null\n"):
        findings = _sagemaker_findings(tmp_path, kms_line)
        assert [f.rule for f in findings] == ["sagemaker-notebook-not-encrypted/missing-kms-key"], kms_line


def test_sagemaker_notebook_not_encrypted_silent_on_reference_or_interpolated_key(
    tmp_path: Path,
) -> None:
    # FP-bait for the empty/null widening: a real key reference, a variable, and a legacy
    # interpolation all stay silent.
    for kms_line in (
        "  kms_key_id    = var.notebook_kms_key\n",
        '  kms_key_id    = "${aws_kms_key.sagemaker.arn}"\n',
        '  kms_key_id    = "arn:aws:kms:us-east-1:123456789012:key/abcd"\n',
    ):
        assert _sagemaker_findings(tmp_path, kms_line) == [], kms_line


def test_sagemaker_notebook_not_encrypted_standards_are_default_key_family(tmp_path: Path) -> None:
    # PR #1162 round-1 M9: AWS encrypts the volume with a system-managed key when `kms_key_id`
    # is omitted, so this is a key-management finding (CWE-320), not missing encryption
    # (CWE-311) -- the same mapping as the ECR / CloudWatch / Secrets Manager default-key guards.
    findings = _sagemaker_findings(tmp_path, "")
    assert len(findings) == 1
    assert findings[0].standards == ["OWASP:A02", "CWE-320"]
    assert findings[0].severity == "medium"
