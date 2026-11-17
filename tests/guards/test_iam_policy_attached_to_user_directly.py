from __future__ import annotations

from agentsec.guards.iam_policy_attached_to_user_directly import IamPolicyAttachedToUserDirectlyGuard
from tests.guards._common import *  # noqa: F401,F403


def test_iam_policy_attached_to_user_directly_flags_user_policy_resource(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_user_policy" "app" {\n'
        '  name   = "app-policy"\n'
        "  user   = aws_iam_user.app.name\n"
        "  policy = jsonencode({})\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = IamPolicyAttachedToUserDirectlyGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "iam-policy-attached-to-user-directly/direct-user-attachment"
    assert findings[0].severity == "medium"

def test_iam_policy_attached_to_user_directly_flags_user_policy_attachment(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_user_policy_attachment" "app" {\n'
        "  user       = aws_iam_user.app.name\n"
        "  policy_arn = aws_iam_policy.app.arn\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = IamPolicyAttachedToUserDirectlyGuard().run(tmp_path, profile)
    assert len(findings) == 1

def test_iam_policy_attached_to_user_directly_flags_mixed_attachment_with_users(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_policy_attachment" "app" {\n'
        '  name       = "app-attach"\n'
        "  users      = [aws_iam_user.app.name]\n"
        "  policy_arn = aws_iam_policy.app.arn\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = IamPolicyAttachedToUserDirectlyGuard().run(tmp_path, profile)
    assert len(findings) == 1

def test_iam_policy_attached_to_user_directly_flags_multiline_users_list(tmp_path: Path) -> None:
    # M2: `terraform fmt` splits non-trivial lists across lines; the guard must join the list up
    # to the matching `]` and still see a non-empty users list.
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_policy_attachment" "app" {\n'
        '  name       = "app-attach"\n'
        "  users = [\n"
        "    aws_iam_user.app.name,\n"
        "    aws_iam_user.other.name,\n"
        "  ]\n"
        "  policy_arn = aws_iam_policy.app.arn\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = IamPolicyAttachedToUserDirectlyGuard().run(tmp_path, profile)
    assert len(findings) == 1

def test_iam_policy_attached_to_user_directly_flags_multiline_users_with_bracket_in_comment(
    tmp_path: Path,
) -> None:
    # RH2: a stray `]` inside a comment must not end the multi-line list join early and drop a
    # real user element below it (comments are stripped before the `]`-termination test).
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_policy_attachment" "app" {\n'
        "  users = [\n"
        "    # see other-users.tf] for the rest\n"
        "    aws_iam_user.app.name,\n"
        "  ]\n"
        "  policy_arn = aws_iam_policy.app.arn\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert len(IamPolicyAttachedToUserDirectlyGuard().run(tmp_path, profile)) == 1

def test_iam_policy_attached_to_user_directly_silent_multiline_users_empty(tmp_path: Path) -> None:
    # M2 companion: a multi-line but truly empty (or comment-only) list stays silent.
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_policy_attachment" "app" {\n'
        "  users = [\n"
        "    # no direct users\n"
        "  ]\n"
        "  roles = [aws_iam_role.app.name]\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert IamPolicyAttachedToUserDirectlyGuard().run(tmp_path, profile) == []

def test_iam_policy_attached_to_user_directly_silent_when_users_empty(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_policy_attachment" "app" {\n'
        '  name       = "app-attach"\n'
        "  roles      = [aws_iam_role.app.name]\n"
        "  users      = []\n"
        "  policy_arn = aws_iam_policy.app.arn\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert IamPolicyAttachedToUserDirectlyGuard().run(tmp_path, profile) == []

def test_iam_policy_attached_to_user_directly_silent_group_policy(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_group_policy" "app" {\n'
        "  group  = aws_iam_group.app.name\n"
        "  policy = jsonencode({})\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert IamPolicyAttachedToUserDirectlyGuard().run(tmp_path, profile) == []

def test_iam_policy_attached_to_user_directly_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_user_policy" "app" {\n'
        '  name   = "app-policy"\n'
        "  user   = aws_iam_user.app.name\n"
        "  policy = jsonencode({})\n"
        "  # security: allow-iam-user-policy\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert IamPolicyAttachedToUserDirectlyGuard().run(tmp_path, profile) == []

def test_iam_policy_attached_to_user_directly_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert IamPolicyAttachedToUserDirectlyGuard().applies(profile) is False

def test_iam_policy_attached_to_user_directly_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert IamPolicyAttachedToUserDirectlyGuard().applies(profile) is True
