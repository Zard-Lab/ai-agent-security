from __future__ import annotations

from pathlib import Path

from agentsec.findings import _is_review_finding
from agentsec.guards.agent_iam_killchain_combination import (
    AgentIamKillchainCombinationGuard,
    _allowed_actions_by_document,
)
from tests._timing import assert_growth
from tests.conftest import mkprofile


def test_harvest_plus_lateral_fires_high(tmp_path: Path) -> None:
    # PR #1051 review H3: a heuristic combination is a review signal, capped at high.
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": ['
        '"secretsmanager:GetSecretValue", "sts:AssumeRole"], "Resource": "*"}]}\n',
        encoding="utf-8",
    )
    findings = AgentIamKillchainCombinationGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert [(f.rule, f.severity) for f in findings] == [
        ("agent-iam-killchain-combination/harvest-plus-lateral", "high")
    ]
    assert findings[0].location.endswith("policy.json:1")


def test_guard_is_a_surfacing_review_signal() -> None:
    assert AgentIamKillchainCombinationGuard.surfacing is True


def test_findings_are_review_signals(tmp_path: Path) -> None:
    # #766: this flat `surfacing = True` was pinned by the checkmeta allowlist's own test, which
    # #766 deleted along with the allowlist. This is its replacement, and it runs the guard.
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": ['
        '"secretsmanager:GetSecretValue", "sts:AssumeRole", "ec2:DescribeInstances"'
        '], "Resource": "*"}]}\n',
        encoding="utf-8",
    )
    findings = AgentIamKillchainCombinationGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert len(findings) == 3
    assert all(_is_review_finding(f) for f in findings)


def test_harvest_plus_metadata_fires_high(tmp_path: Path) -> None:
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": ['
        '"ssm:GetParameter", "ec2:DescribeInstances"], "Resource": "*"}]}\n',
        encoding="utf-8",
    )
    findings = AgentIamKillchainCombinationGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert any(
        f.rule == "agent-iam-killchain-combination/harvest-plus-metadata" and f.severity == "high"
        for f in findings
    )


def test_full_chain_fires_all_three_rules(tmp_path: Path) -> None:
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": ['
        '"secretsmanager:GetSecretValue", "sts:AssumeRole", "ec2:DescribeInstances"'
        '], "Resource": "*"}]}\n',
        encoding="utf-8",
    )
    findings = AgentIamKillchainCombinationGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    rules = {f.rule for f in findings}
    assert rules == {
        "agent-iam-killchain-combination/harvest-plus-lateral",
        "agent-iam-killchain-combination/harvest-plus-metadata",
        "agent-iam-killchain-combination/full-chain",
    }
    assert {f.severity for f in findings} == {"high"}


def test_combination_crosses_separate_statements(tmp_path: Path) -> None:
    # The harvest action and the lateral action live in TWO DIFFERENT statements -- the whole
    # point of this guard is catching exactly this cross-statement shape.
    (tmp_path / "policy.json").write_text(
        '{"Statement": ['
        '{"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": "arn:x"},'
        '{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "arn:y"}'
        "]}\n",
        encoding="utf-8",
    )
    findings = AgentIamKillchainCombinationGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert any(f.rule == "agent-iam-killchain-combination/harvest-plus-lateral" for f in findings)


def test_harvest_only_stays_silent(tmp_path: Path) -> None:
    # FP-bait: only ONE category present -- no combination to flag.
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", '
        '"Resource": "arn:x"}]}\n',
        encoding="utf-8",
    )
    assert AgentIamKillchainCombinationGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


def test_lateral_only_stays_silent(tmp_path: Path) -> None:
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "arn:x"}]}\n',
        encoding="utf-8",
    )
    assert AgentIamKillchainCombinationGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


def test_deny_statement_actions_not_counted(tmp_path: Path) -> None:
    (tmp_path / "policy.json").write_text(
        '{"Statement": ['
        '{"Effect": "Deny", "Action": "secretsmanager:GetSecretValue", "Resource": "*"},'
        '{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "arn:x"}'
        "]}\n",
        encoding="utf-8",
    )
    assert AgentIamKillchainCombinationGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


def test_wildcard_action_in_category_matches(tmp_path: Path) -> None:
    # A granted "secretsmanager:*" fnmatches the "secretsmanager:getsecretvalue" category pattern.
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": ["secretsmanager:*", "sts:AssumeRole"], '
        '"Resource": "*"}]}\n',
        encoding="utf-8",
    )
    findings = AgentIamKillchainCombinationGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert any(f.rule == "agent-iam-killchain-combination/harvest-plus-lateral" for f in findings)


def test_terraform_file_flags_same_shape(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect = "Allow"\n'
        '      Action = ["secretsmanager:GetSecretValue", "sts:AssumeRole"]\n'
        '      Resource = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    findings = AgentIamKillchainCombinationGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert any(f.rule == "agent-iam-killchain-combination/harvest-plus-lateral" for f in findings)


def test_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": ['
        '"secretsmanager:GetSecretValue", "sts:AssumeRole"], "Resource": "*"}]}\n'
        "// security: allow-agent-iam-killchain-combination\n",
        encoding="utf-8",
    )
    assert AgentIamKillchainCombinationGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    fixtures = tmp_path / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "sample.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": ['
        '"secretsmanager:GetSecretValue", "sts:AssumeRole"], "Resource": "*"}]}\n',
        encoding="utf-8",
    )
    assert AgentIamKillchainCombinationGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


def test_does_not_apply_without_llm_feature(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features=set())
    assert AgentIamKillchainCombinationGuard().applies(profile) is False


def test_unrelated_json_stays_silent(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name": "app"}\n', encoding="utf-8")
    assert AgentIamKillchainCombinationGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


_ROLE_WITH_LAMBDA_TRUST = (
    'resource "aws_iam_role" "fn" {\n'
    '  name = "fn"\n'
    "  assume_role_policy = jsonencode({\n"
    '    Version = "2012-10-17"\n'
    "    Statement = [{\n"
    '      Effect    = "Allow"\n'
    '      Principal = { Service = "lambda.amazonaws.com" }\n'
    '      Action    = "sts:AssumeRole"\n'
    "    }]\n"
    "  })\n"
    "}\n"
)


def test_terraform_role_trust_plus_scoped_secret_read_stays_silent(tmp_path: Path) -> None:
    # H3 (the round-1 iam.tf): every role's TRUST statement carries sts:AssumeRole. A trust
    # statement is not a grant, so a plain role + one scoped secret read is not a kill chain.
    (tmp_path / "iam.tf").write_text(
        _ROLE_WITH_LAMBDA_TRUST
        + 'resource "aws_iam_role_policy" "fn" {\n'
        "  role = aws_iam_role.fn.id\n"
        "  policy = jsonencode({\n"
        '    Version = "2012-10-17"\n'
        "    Statement = [{\n"
        '      Effect   = "Allow"\n'
        '      Action   = "secretsmanager:GetSecretValue"\n'
        '      Resource = "arn:aws:secretsmanager:us-east-1:111111111111:secret:app/db-AbCdEf"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    assert AgentIamKillchainCombinationGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


def test_json_trust_statement_is_not_counted_as_a_grant(tmp_path: Path) -> None:
    (tmp_path / "policy.json").write_text(
        '{"Statement": ['
        '{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, '
        '"Action": "sts:AssumeRole"},'
        '{"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": "arn:x"}'
        "]}\n",
        encoding="utf-8",
    )
    assert AgentIamKillchainCombinationGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


def test_separate_policy_resources_in_one_file_are_not_pooled(tmp_path: Path) -> None:
    # H3: two unrelated roles' policies in one main.tf; one reads a secret, the other may assume a
    # role. Neither identity holds both capabilities, so nothing fires.
    (tmp_path / "main.tf").write_text(
        'resource "aws_iam_role_policy" "reader" {\n'
        "  role = aws_iam_role.reader.id\n"
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect   = "Allow"\n'
        '      Action   = ["secretsmanager:GetSecretValue", "ec2:DescribeInstances"]\n'
        '      Resource = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n"
        'resource "aws_iam_role_policy" "deployer" {\n'
        "  role = aws_iam_role.deployer.id\n"
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect   = "Allow"\n'
        '      Action   = "sts:AssumeRole"\n'
        '      Resource = "arn:aws:iam::222222222222:role/deploy"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    findings = AgentIamKillchainCombinationGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    # Only the reader's OWN harvest+metadata pair is in one document; the lateral action is not.
    assert [f.rule for f in findings] == ["agent-iam-killchain-combination/harvest-plus-metadata"]
    assert findings[0].location.endswith("main.tf:3")


def test_bare_star_action_is_left_to_iam_wildcard(tmp_path: Path) -> None:
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}\n',
        encoding="utf-8",
    )
    assert AgentIamKillchainCombinationGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


def test_single_terraform_policy_with_chain_still_fires_next_to_a_role(tmp_path: Path) -> None:
    # Still-fires for the H3 narrowing: ONE policy resource whose own two statements combine
    # credential read, role pivot and identity discovery fires all three rules, even with a
    # trust-bearing aws_iam_role in the same file.
    (tmp_path / "iam.tf").write_text(
        _ROLE_WITH_LAMBDA_TRUST
        + 'resource "aws_iam_role_policy" "agent" {\n'
        "  role = aws_iam_role.fn.id\n"
        "  policy = jsonencode({\n"
        "    Statement = [\n"
        '      { Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = "*" },\n'
        '      { Effect = "Allow", Action = ["sts:AssumeRole", "ec2:DescribeInstances"], Resource = "*" }\n'
        "    ]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    findings = AgentIamKillchainCombinationGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert sorted(f.rule for f in findings) == [
        "agent-iam-killchain-combination/full-chain",
        "agent-iam-killchain-combination/harvest-plus-lateral",
        "agent-iam-killchain-combination/harvest-plus-metadata",
    ]
    assert all(f.location.endswith("iam.tf:14") for f in findings)
    assert {f.severity for f in findings} == {"high"}


def test_document_grouping_is_linear_in_the_number_of_documents() -> None:
    # Re-review L1: each statement used to scan EVERY policy root to find its innermost parent, so
    # a JSON holding N policy documents cost O(N^2) (3000 documents: 7 to 21 s, against 0.8 s for
    # the whole-file pooling it replaced). The assignment is now one ordered sweep.
    sizes = [1000, 2000, 4000, 8000]
    doc = '{"Statement": [{"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"], "Resource": "*"}]}'
    texts = {n: "[\n" + ",\n".join([doc] * n) + "\n]\n" for n in sizes}

    def scan(n: int) -> None:
        _allowed_actions_by_document(texts[n])

    assert_growth(scan, sizes, expected="linear")
    # The behavioural half: every document is still its own unit.
    assert len(_allowed_actions_by_document(texts[1000])) == 1000
