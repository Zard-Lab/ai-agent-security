from __future__ import annotations

from agentsec.guards.iam_managed_admin_policy_attached import IamManagedAdminPolicyAttachedGuard
from tests.guards._common import *  # noqa: F401,F403


def test_iam_managed_admin_policy_attached_flags_managed_policy_arns(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role" "app" {\n'
        '  name                = "app-role"\n'
        '  managed_policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess"]\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = IamManagedAdminPolicyAttachedGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "iam-managed-admin-policy-attached/administrator-access"
    assert findings[0].severity == "high"

def test_iam_managed_admin_policy_attached_flags_policy_arn_attachment(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy_attachment" "app" {\n'
        "  role       = aws_iam_role.app.name\n"
        '  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = IamManagedAdminPolicyAttachedGuard().run(tmp_path, profile)
    assert len(findings) == 1

def test_iam_managed_admin_policy_attached_silent_other_policy(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role" "app" {\n'
        '  name                = "app-role"\n'
        '  managed_policy_arns = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert IamManagedAdminPolicyAttachedGuard().run(tmp_path, profile) == []

def test_iam_managed_admin_policy_attached_silent_comment_mention(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role" "app" {\n'
        '  name = "app-role"\n'
        "  # do not attach arn:aws:iam::aws:policy/AdministratorAccess here\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert IamManagedAdminPolicyAttachedGuard().run(tmp_path, profile) == []

def test_iam_managed_admin_policy_attached_silent_administrator_access_amplify(tmp_path: Path) -> None:
    # H2 (FP-bait): `AdministratorAccess-Amplify` is a real, much narrower AWS-managed policy —
    # the anchored ARN must NOT substring-match it as full admin.
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role" "app" {\n'
        '  name                = "app-role"\n'
        '  managed_policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess-Amplify"]\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert IamManagedAdminPolicyAttachedGuard().run(tmp_path, profile) == []

def test_iam_managed_admin_policy_attached_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role" "app" {\n'
        '  name                = "app-role"\n'
        '  managed_policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess"]  # security: allow-iam-admin-policy\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert IamManagedAdminPolicyAttachedGuard().run(tmp_path, profile) == []

def test_iam_managed_admin_policy_attached_flags_s3_fullaccess(tmp_path: Path) -> None:
    # Pike batch extension: the *FullAccess family, not just AdministratorAccess.
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy_attachment" "app" {\n'
        "  role       = aws_iam_role.app.name\n"
        '  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = IamManagedAdminPolicyAttachedGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "iam-managed-admin-policy-attached/full-access-family"
    assert findings[0].severity == "high"
    assert "AmazonS3FullAccess" in findings[0].message

def test_iam_managed_admin_policy_attached_flags_iamfullaccess_in_managed_policy_arns(
    tmp_path: Path,
) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role" "app" {\n'
        '  name                = "app-role"\n'
        '  managed_policy_arns = ["arn:aws:iam::aws:policy/IAMFullAccess"]\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = IamManagedAdminPolicyAttachedGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "iam-managed-admin-policy-attached/full-access-family"

def test_iam_managed_admin_policy_attached_silent_readonly_access(tmp_path: Path) -> None:
    # FP-bait: ReadOnlyAccess does not end in FullAccess and grants no write access.
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy_attachment" "app" {\n'
        "  role       = aws_iam_role.app.name\n"
        '  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert IamManagedAdminPolicyAttachedGuard().run(tmp_path, profile) == []

def test_iam_managed_admin_policy_attached_pragma_silences_fullaccess(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy_attachment" "app" {\n'
        "  role       = aws_iam_role.app.name\n"
        '  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2FullAccess"  # security: allow-iam-admin-policy\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert IamManagedAdminPolicyAttachedGuard().run(tmp_path, profile) == []

def test_iam_managed_admin_policy_attached_administrator_access_still_uses_its_own_rule(
    tmp_path: Path,
) -> None:
    # Regression: AdministratorAccess must keep firing its OWN rule id, not the new one,
    # after the *FullAccess branch was added alongside it.
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role" "app" {\n'
        '  name                = "app-role"\n'
        '  managed_policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess"]\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = IamManagedAdminPolicyAttachedGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "iam-managed-admin-policy-attached/administrator-access"

def test_iam_managed_admin_policy_attached_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert IamManagedAdminPolicyAttachedGuard().applies(profile) is False

def test_iam_managed_admin_policy_attached_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert IamManagedAdminPolicyAttachedGuard().applies(profile) is True
