from __future__ import annotations

from agentsec.guards.iam_service_wildcard import IamServiceWildcardGuard
from tests.guards._common import *  # noqa: F401,F403


def test_iam_service_wildcard_flags_hcl_form(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "app" {\n'
        '  name = "app-policy"\n'
        "  role = aws_iam_role.app.id\n"
        "  policy = jsonencode({\n"
        '    Version = "2012-10-17"\n'
        "    Statement = [{\n"
        '      Effect   = "Allow"\n'
        '      Action   = "iam:*"\n'
        '      Resource = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    findings = IamServiceWildcardGuard().run(tmp_path, _tf_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "iam-service-wildcard/service-action"
    assert findings[0].severity == "high"
    assert "iam:*" in findings[0].message


def test_iam_service_wildcard_flags_json_literal_form(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = <<POLICY\n"
        '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}\n'
        "POLICY\n"
        "}\n",
        encoding="utf-8",
    )
    findings = IamServiceWildcardGuard().run(tmp_path, _tf_prof(tmp_path))
    assert len(findings) == 1
    assert "s3:*" in findings[0].message


def test_iam_service_wildcard_flags_action_in_list(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect = "Allow"\n'
        '      Action = ["s3:GetObject", "ec2:*"]\n'
        '      Resource = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    findings = IamServiceWildcardGuard().run(tmp_path, _tf_prof(tmp_path))
    assert len(findings) == 1
    assert "ec2:*" in findings[0].message


def test_iam_service_wildcard_silent_on_scoped_action(tmp_path: Path) -> None:
    # FP-bait: a single scoped action is not a service wildcard.
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect = "Allow"\n'
        '      Action = "s3:GetObject"\n'
        '      Resource = "arn:aws:s3:::my-bucket/*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    assert IamServiceWildcardGuard().run(tmp_path, _tf_prof(tmp_path)) == []


def test_iam_service_wildcard_silent_on_all_actions_wildcard(tmp_path: Path) -> None:
    # FP-bait: the bare all-actions "*" is iam-wildcard's territory, not this guard's.
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect = "Allow"\n'
        '      Action = "*"\n'
        '      Resource = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    assert IamServiceWildcardGuard().run(tmp_path, _tf_prof(tmp_path)) == []


def test_iam_service_wildcard_silent_in_deny_statement(tmp_path: Path) -> None:
    # FP-bait: a service wildcard inside an explicit Deny is a lockdown, not a grant.
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect = "Deny"\n'
        '      Action = "iam:*"\n'
        '      Resource = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    assert IamServiceWildcardGuard().run(tmp_path, _tf_prof(tmp_path)) == []


def test_iam_service_wildcard_silent_on_notaction(tmp_path: Path) -> None:
    # FP-bait: NotAction is a different, deliberately separate guard's territory.
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect = "Allow"\n'
        '      NotAction = "iam:*"\n'
        '      Resource = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    assert IamServiceWildcardGuard().run(tmp_path, _tf_prof(tmp_path)) == []


def test_iam_service_wildcard_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        "# security: allow-iam-service-wildcard\n"
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect = "Allow"\n'
        '      Action = "iam:*"\n'
        '      Resource = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    assert IamServiceWildcardGuard().run(tmp_path, _tf_prof(tmp_path)) == []


def test_iam_service_wildcard_applies_gate() -> None:
    assert IamServiceWildcardGuard().applies(mkprofile(Path("/tmp"), features={"python"})) is False
    assert IamServiceWildcardGuard().applies(_tf_prof(Path("/tmp"))) is True


def test_iam_service_wildcard_nonproduct_path_skipped(tmp_path: Path) -> None:
    ex = tmp_path / "examples"
    ex.mkdir()
    (ex / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect = "Allow"\n'
        '      Action = "iam:*"\n'
        '      Resource = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    assert IamServiceWildcardGuard().run(tmp_path, _tf_prof(tmp_path)) == []


def test_iam_service_wildcard_pragma_quoted_in_a_string_does_not_suppress(tmp_path: Path) -> None:
    # #424 E4: the whole-file check reads the HCL comment-only view, so a string attribute quoting
    # the documented `# security: …` form is content - only a real comment opts out.
    (tmp_path / "iam.tf").write_text(
        'variable "doc" { default = "opt out with # security: allow-iam-service-wildcard" }\n'
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect = "Allow"\n'
        '      Action = "iam:*"\n'
        '      Resource = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    assert len(IamServiceWildcardGuard().run(tmp_path, _tf_prof(tmp_path))) == 1
