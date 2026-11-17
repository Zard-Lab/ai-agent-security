from __future__ import annotations

from agentsec.guards.iam_escalation_action_no_condition import IamEscalationActionNoConditionGuard
from tests.guards._common import *  # noqa: F401,F403


def test_iam_escalation_no_condition_flags_passrole(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect   = "Allow"\n'
        '      Action   = "iam:PassRole"\n'
        '      Resource = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    findings = IamEscalationActionNoConditionGuard().run(tmp_path, _tf_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "iam-escalation-action-no-condition/unconditional-grant"
    assert findings[0].severity == "high"
    assert "iam:PassRole" in findings[0].message


def test_iam_escalation_no_condition_flags_sts_assumerole(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect   = "Allow"\n'
        '      Action   = "sts:AssumeRole"\n'
        '      Resource = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    findings = IamEscalationActionNoConditionGuard().run(tmp_path, _tf_prof(tmp_path))
    assert len(findings) == 1


def test_iam_escalation_no_condition_flags_multiple_actions_once_each(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect   = "Allow"\n'
        '      Action   = ["iam:PutRolePolicy", "iam:AttachRolePolicy"]\n'
        '      Resource = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    findings = IamEscalationActionNoConditionGuard().run(tmp_path, _tf_prof(tmp_path))
    assert len(findings) == 2


def test_iam_escalation_no_condition_silent_with_condition(tmp_path: Path) -> None:
    # FP-bait (named in the build brief): the same escalation action WITH a Condition must
    # NOT fire -- the condition is treated as a plausible, genuine narrowing.
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect   = "Allow"\n'
        '      Action   = "iam:PassRole"\n'
        '      Resource = "*"\n'
        "      Condition = {\n"
        '        StringEquals = { "iam:PassedToService" = "ec2.amazonaws.com" }\n'
        "      }\n"
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    assert IamEscalationActionNoConditionGuard().run(tmp_path, _tf_prof(tmp_path)) == []


def test_iam_escalation_no_condition_silent_non_escalation_action(tmp_path: Path) -> None:
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
    assert IamEscalationActionNoConditionGuard().run(tmp_path, _tf_prof(tmp_path)) == []


def test_iam_escalation_no_condition_silent_in_deny_statement(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect   = "Deny"\n'
        '      Action   = "iam:PassRole"\n'
        '      Resource = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    assert IamEscalationActionNoConditionGuard().run(tmp_path, _tf_prof(tmp_path)) == []


def test_iam_escalation_no_condition_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        "# security: allow-iam-escalation-no-condition\n"
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect   = "Allow"\n'
        '      Action   = "iam:PassRole"\n'
        '      Resource = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    assert IamEscalationActionNoConditionGuard().run(tmp_path, _tf_prof(tmp_path)) == []


def test_iam_escalation_no_condition_applies_gate() -> None:
    # Universal (2026-10-08): a bare IAM policy JSON can live in any repo, with no Terraform
    # feature detected at all -- same reasoning as iam-notaction-with-allow/iam-wildcard.
    guard = IamEscalationActionNoConditionGuard()
    assert guard.applies(mkprofile(Path("/tmp"), features={"python"})) is True
    assert guard.applies(_tf_prof(Path("/tmp"))) is True


def test_iam_escalation_no_condition_flags_bare_json_policy(tmp_path: Path) -> None:
    (tmp_path / "agent_policy.json").write_text(
        '{\n  "Version": "2012-10-17",\n  "Statement": [{\n'
        '    "Effect": "Allow",\n    "Action": "iam:PassRole",\n'
        '    "Resource": "*"\n  }]\n}\n',
        encoding="utf-8",
    )
    findings = IamEscalationActionNoConditionGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert any(f.rule == "iam-escalation-action-no-condition/unconditional-grant" for f in findings)


def test_iam_escalation_no_condition_silent_on_unrelated_json(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"name": "app", "version": "1.0.0"}\n', encoding="utf-8"
    )
    assert IamEscalationActionNoConditionGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_iam_escalation_no_condition_passrole_wrong_condition_fires(tmp_path: Path) -> None:
    # A Condition IS present, but it's not iam:PassedToService -- PassRole is still unscoped
    # against which service can receive it.
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Action    = "iam:PassRole"\n'
        '      Resource  = "*"\n'
        "      Condition = {\n"
        '        StringEquals = { "aws:RequestedRegion" = "us-east-1" }\n'
        "      }\n"
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    findings = IamEscalationActionNoConditionGuard().run(tmp_path, _tf_prof(tmp_path))
    assert any(
        f.rule == "iam-escalation-action-no-condition/passrole-missing-passed-to-service"
        for f in findings
    )
    # The general "no condition at all" rule must NOT also fire -- a Condition IS present.
    assert not any(
        f.rule == "iam-escalation-action-no-condition/unconditional-grant" for f in findings
    )


def test_iam_escalation_no_condition_passrole_with_passed_to_service_stays_silent(
    tmp_path: Path,
) -> None:
    # FP-bait: the actual documented mitigation is present -- stays silent entirely.
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Action    = "iam:PassRole"\n'
        '      Resource  = "*"\n'
        "      Condition = {\n"
        '        StringEquals = { "iam:PassedToService" = "bedrock.amazonaws.com" }\n'
        "      }\n"
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    assert IamEscalationActionNoConditionGuard().run(tmp_path, _tf_prof(tmp_path)) == []


def test_iam_escalation_no_condition_other_action_with_unrelated_condition_stays_silent(
    tmp_path: Path,
) -> None:
    # FP-bait: the PassRole-specific rule must not fire for a DIFFERENT escalation action --
    # the general "any condition is a plausible narrowing" heuristic still governs those.
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Action    = "iam:AttachRolePolicy"\n'
        '      Resource  = "*"\n'
        "      Condition = {\n"
        '        StringEquals = { "aws:RequestedRegion" = "us-east-1" }\n'
        "      }\n"
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    assert IamEscalationActionNoConditionGuard().run(tmp_path, _tf_prof(tmp_path)) == []


def test_iam_escalation_no_condition_nonproduct_path_skipped(tmp_path: Path) -> None:
    ex = tmp_path / "examples"
    ex.mkdir()
    (ex / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect   = "Allow"\n'
        '      Action   = "iam:PassRole"\n'
        '      Resource = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    assert IamEscalationActionNoConditionGuard().run(tmp_path, _tf_prof(tmp_path)) == []


def test_iam_escalation_no_condition_json_trust_policy_is_not_a_grant(tmp_path: Path) -> None:
    # PR #1051 review M3: a trust policy's sts:AssumeRole says who may assume THIS role; it grants
    # no permission to anyone, so it is not an unconditional escalation grant.
    (tmp_path / "ecs-trust.json").write_text(
        '{\n  "Version": "2012-10-17",\n  "Statement": [{\n'
        '    "Effect": "Allow",\n'
        '    "Principal": {"Service": "ecs-tasks.amazonaws.com"},\n'
        '    "Action": "sts:AssumeRole"\n  }]\n}\n',
        encoding="utf-8",
    )
    assert IamEscalationActionNoConditionGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_iam_escalation_no_condition_tf_assume_role_policy_is_not_a_grant(tmp_path: Path) -> None:
    # M3 on the pre-existing .tf path (origin/main flagged this line): this NARROWS .tf behaviour.
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role" "fn" {\n'
        "  assume_role_policy = jsonencode({\n"
        '    Version = "2012-10-17"\n'
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Principal = { Service = "lambda.amazonaws.com" }\n'
        '      Action    = "sts:AssumeRole"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    assert IamEscalationActionNoConditionGuard().run(tmp_path, _tf_prof(tmp_path)) == []


def test_iam_escalation_no_condition_json_identity_assumerole_on_star_still_fires(tmp_path: Path) -> None:
    # Still-fires for the M3 narrowing: an IDENTITY policy (no Principal) letting its holder
    # assume any role, with no Condition, is the escalation grant this guard exists for.
    (tmp_path / "agent_policy.json").write_text(
        '{\n  "Version": "2012-10-17",\n  "Statement": [{\n'
        '    "Effect": "Allow",\n'
        '    "Action": "sts:AssumeRole",\n'
        '    "Resource": "*"\n  }]\n}\n',
        encoding="utf-8",
    )
    findings = IamEscalationActionNoConditionGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert [(f.rule, f.severity) for f in findings] == [
        ("iam-escalation-action-no-condition/unconditional-grant", "high")
    ]
    assert findings[0].location.endswith("agent_policy.json:5")


def test_iam_escalation_no_condition_trust_and_grant_in_one_tf_only_grant_fires(tmp_path: Path) -> None:
    # Still-fires: the role's trust statement is skipped, its policy's unconditional grant is not.
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role" "fn" {\n'
        "  assume_role_policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Principal = { Service = "lambda.amazonaws.com" }\n'
        '      Action    = "sts:AssumeRole"\n'
        "    }]\n"
        "  })\n"
        "}\n"
        'resource "aws_iam_role_policy" "fn" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect   = "Allow"\n'
        '      Action   = "sts:AssumeRole"\n'
        '      Resource = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    findings = IamEscalationActionNoConditionGuard().run(tmp_path, _tf_prof(tmp_path))
    assert [f.rule for f in findings] == ["iam-escalation-action-no-condition/unconditional-grant"]
    assert findings[0].location.endswith("iam.tf:14")
