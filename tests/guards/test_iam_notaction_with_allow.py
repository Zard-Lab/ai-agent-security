from __future__ import annotations

from agentsec.guards.iam_notaction_with_allow import IamNotactionWithAllowGuard
from tests.guards._common import *  # noqa: F401,F403


def test_iam_notaction_with_allow_flags_allow_notaction(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      NotAction = ["iam:*", "organizations:*"]\n'
        '      Resource  = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    findings = IamNotactionWithAllowGuard().run(tmp_path, _tf_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "iam-notaction-with-allow/allow-notaction"
    assert findings[0].severity == "high"


def test_iam_notaction_with_allow_flags_json_literal_form(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = <<POLICY\n"
        '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]}\n'
        "POLICY\n"
        "}\n",
        encoding="utf-8",
    )
    findings = IamNotactionWithAllowGuard().run(tmp_path, _tf_prof(tmp_path))
    assert len(findings) == 1


def test_iam_notaction_with_allow_silent_deny_notaction(tmp_path: Path) -> None:
    # FP-bait: Deny + NotAction is the common, legitimate "deny everything except X" guardrail.
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Deny"\n'
        '      NotAction = ["s3:GetObject"]\n'
        '      Resource  = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    assert IamNotactionWithAllowGuard().run(tmp_path, _tf_prof(tmp_path)) == []


def test_iam_notaction_with_allow_silent_plain_action(tmp_path: Path) -> None:
    # FP-bait: an ordinary Action allow-list is not NotAction at all.
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
    assert IamNotactionWithAllowGuard().run(tmp_path, _tf_prof(tmp_path)) == []


def test_iam_notaction_with_allow_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        "# security: allow-iam-notaction-with-allow\n"
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      NotAction = ["iam:*"]\n'
        '      Resource  = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    assert IamNotactionWithAllowGuard().run(tmp_path, _tf_prof(tmp_path)) == []


def test_iam_notaction_with_allow_applies_gate() -> None:
    # Universal (2026-10-08): a bare IAM policy JSON can live in any repo, with no Terraform
    # feature detected at all -- the same reasoning iam-wildcard already applies.
    guard = IamNotactionWithAllowGuard()
    assert guard.applies(mkprofile(Path("/tmp"), features={"python"})) is True
    assert guard.applies(_tf_prof(Path("/tmp"))) is True


def test_iam_notaction_with_allow_flags_bare_json_policy(tmp_path: Path) -> None:
    (tmp_path / "agent_policy.json").write_text(
        '{\n  "Version": "2012-10-17",\n  "Statement": [{\n'
        '    "Effect": "Allow",\n    "NotAction": ["iam:*", "organizations:*"],\n'
        '    "Resource": "*"\n  }]\n}\n',
        encoding="utf-8",
    )
    findings = IamNotactionWithAllowGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert len(findings) == 1
    assert findings[0].rule == "iam-notaction-with-allow/allow-notaction"


def test_iam_notaction_with_allow_json_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "agent_policy.json").write_text(
        '{\n  "Version": "2012-10-17",\n  "Statement": [{\n'
        '    "Effect": "Allow",\n    "NotAction": ["iam:*"],\n'
        '    "Resource": "*"\n  }]\n}\n'
        "// security: allow-iam-notaction-with-allow\n",
        encoding="utf-8",
    )
    assert IamNotactionWithAllowGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_iam_notaction_with_allow_silent_on_unrelated_json(tmp_path: Path) -> None:
    # FP-bait: an ordinary package.json has no "Statement" key at all.
    (tmp_path / "package.json").write_text(
        '{"name": "app", "version": "1.0.0", "scripts": {"build": "tsc"}}\n', encoding="utf-8"
    )
    assert IamNotactionWithAllowGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_iam_notaction_with_allow_nonproduct_path_skipped(tmp_path: Path) -> None:
    ex = tmp_path / "examples"
    ex.mkdir()
    (ex / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      NotAction = ["iam:*"]\n'
        '      Resource  = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    assert IamNotactionWithAllowGuard().run(tmp_path, _tf_prof(tmp_path)) == []
