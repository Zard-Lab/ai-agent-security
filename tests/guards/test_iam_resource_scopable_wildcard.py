from __future__ import annotations

from agentsec.guards.iam_resource_scopable_wildcard import IamResourceScopableWildcardGuard
from tests.guards._common import *  # noqa: F401,F403


def test_iam_resource_scopable_wildcard_flags_s3_getobject(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect   = "Allow"\n'
        '      Action   = "s3:GetObject"\n'
        '      Resource = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    findings = IamResourceScopableWildcardGuard().run(tmp_path, _tf_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "iam-resource-scopable-wildcard/unscoped-resource"
    assert findings[0].severity == "high"
    assert "s3:GetObject" in findings[0].message


def test_iam_resource_scopable_wildcard_flags_action_list(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect   = "Allow"\n'
        '      Action   = ["dynamodb:GetItem", "dynamodb:PutItem"]\n'
        '      Resource = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    findings = IamResourceScopableWildcardGuard().run(tmp_path, _tf_prof(tmp_path))
    assert len(findings) == 1


def test_iam_resource_scopable_wildcard_silent_scoped_to_bucket(tmp_path: Path) -> None:
    # FP-bait: the exact case named in the build brief -- s3:GetObject scoped to a specific
    # bucket ARN must NOT fire.
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect   = "Allow"\n'
        '      Action   = "s3:GetObject"\n'
        '      Resource = "arn:aws:s3:::my-bucket/*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    assert IamResourceScopableWildcardGuard().run(tmp_path, _tf_prof(tmp_path)) == []


def test_iam_resource_scopable_wildcard_silent_non_scopable_action(tmp_path: Path) -> None:
    # FP-bait: an action not on the curated list (e.g. iam:ListRoles, account-wide by nature)
    # with Resource "*" must not fire -- that's iam-wildcard's / a different guard's territory.
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect   = "Allow"\n'
        '      Action   = "iam:ListRoles"\n'
        '      Resource = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    assert IamResourceScopableWildcardGuard().run(tmp_path, _tf_prof(tmp_path)) == []


def test_iam_resource_scopable_wildcard_silent_in_deny_statement(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect   = "Deny"\n'
        '      Action   = "s3:GetObject"\n'
        '      Resource = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    assert IamResourceScopableWildcardGuard().run(tmp_path, _tf_prof(tmp_path)) == []


def test_iam_resource_scopable_wildcard_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        "# security: allow-iam-resource-scopable-wildcard\n"
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect   = "Allow"\n'
        '      Action   = "s3:GetObject"\n'
        '      Resource = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    assert IamResourceScopableWildcardGuard().run(tmp_path, _tf_prof(tmp_path)) == []


def test_iam_resource_scopable_wildcard_applies_gate() -> None:
    guard = IamResourceScopableWildcardGuard()
    assert guard.applies(mkprofile(Path("/tmp"), features={"python"})) is False
    assert guard.applies(_tf_prof(Path("/tmp"))) is True


def test_iam_resource_scopable_wildcard_nonproduct_path_skipped(tmp_path: Path) -> None:
    ex = tmp_path / "examples"
    ex.mkdir()
    (ex / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect   = "Allow"\n'
        '      Action   = "s3:GetObject"\n'
        '      Resource = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    assert IamResourceScopableWildcardGuard().run(tmp_path, _tf_prof(tmp_path)) == []
