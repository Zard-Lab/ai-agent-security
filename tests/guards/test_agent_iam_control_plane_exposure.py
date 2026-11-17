from __future__ import annotations

from pathlib import Path

from agentsec.findings import _is_review_finding
from agentsec.guards.agent_iam_control_plane_exposure import AgentIamControlPlaneExposureGuard
from tests.conftest import mkprofile


def test_bedrock_control_plane_fires_high(tmp_path: Path) -> None:
    # PR #1051 review M1: the guard cannot tell an agent runtime role from a deployment/CI role,
    # so a control-plane grant is a HIGH review signal, not CRITICAL.
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": "bedrock:CreateGuardrail", "Resource": "*"}]}\n',
        encoding="utf-8",
    )
    findings = AgentIamControlPlaneExposureGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert [(f.rule, f.severity) for f in findings] == [
        ("agent-iam-control-plane-exposure/bedrock-control-plane", "high")
    ]
    assert findings[0].location.endswith("policy.json:1")


def test_one_finding_per_statement_not_per_action(tmp_path: Path) -> None:
    # M1: a CI deploy role granting three control-plane actions in one statement is ONE finding.
    (tmp_path / "deploy.json").write_text(
        '{\n  "Statement": [{\n    "Effect": "Allow",\n'
        '    "Action": ["bedrock:CreateAgent", "bedrock:UpdateAgent", "bedrock:CreateGuardrail"],\n'
        '    "Resource": "*"\n  }]\n}\n',
        encoding="utf-8",
    )
    findings = AgentIamControlPlaneExposureGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert [(f.rule, f.severity) for f in findings] == [
        ("agent-iam-control-plane-exposure/bedrock-control-plane", "high")
    ]
    assert findings[0].location.endswith("deploy.json:4")
    for action in ("bedrock:CreateAgent", "bedrock:UpdateAgent", "bedrock:CreateGuardrail"):
        assert action in findings[0].message


def test_two_statements_give_two_findings(tmp_path: Path) -> None:
    # Still-fires for the per-statement collapse: each statement keeps its own finding.
    (tmp_path / "policy.json").write_text(
        '{"Statement": [\n'
        '{"Effect": "Allow", "Action": "bedrock:CreateAgent", "Resource": "*"},\n'
        '{"Effect": "Allow", "Action": "sagemaker:CreateModel", "Resource": "*"}\n]}\n',
        encoding="utf-8",
    )
    findings = AgentIamControlPlaneExposureGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert [f.rule for f in findings] == [
        "agent-iam-control-plane-exposure/bedrock-control-plane",
        "agent-iam-control-plane-exposure/sagemaker-control-plane",
    ]


def test_guard_is_a_surfacing_review_signal() -> None:
    assert AgentIamControlPlaneExposureGuard.surfacing is True


def test_findings_are_review_signals(tmp_path: Path) -> None:
    # #766: this flat `surfacing = True` was pinned by the checkmeta allowlist's own test, which
    # #766 deleted along with the allowlist. This is its replacement, and it runs the guard.
    (tmp_path / "policy.json").write_text(
        '{"Statement": [\n'
        '{"Effect": "Allow", "Action": "bedrock:CreateAgent", "Resource": "*"},\n'
        '{"Effect": "Allow", "Action": "sagemaker:CreateModel", "Resource": "*"}\n]}\n',
        encoding="utf-8",
    )
    findings = AgentIamControlPlaneExposureGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert len(findings) == 2
    assert all(_is_review_finding(f) for f in findings)


def test_sagemaker_control_plane_fires_high(tmp_path: Path) -> None:
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": "sagemaker:CreateTrainingJob", "Resource": "*"}]}\n',
        encoding="utf-8",
    )
    findings = AgentIamControlPlaneExposureGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert any(
        f.rule == "agent-iam-control-plane-exposure/sagemaker-control-plane" and f.severity == "high"
        for f in findings
    )


def test_flags_in_terraform_file(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect   = "Allow"\n'
        '      Action   = "bedrock:UpdateGuardrail"\n'
        '      Resource = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    findings = AgentIamControlPlaneExposureGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert any(f.rule == "agent-iam-control-plane-exposure/bedrock-control-plane" for f in findings)


def test_data_plane_action_stays_silent(tmp_path: Path) -> None:
    # FP-bait: the legitimate runtime action an agent actually needs.
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": "bedrock:InvokeModel", "Resource": "*"}]}\n',
        encoding="utf-8",
    )
    assert AgentIamControlPlaneExposureGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


def test_sagemaker_data_plane_action_stays_silent(tmp_path: Path) -> None:
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": "sagemaker-runtime:InvokeEndpoint", "Resource": "*"}]}\n',
        encoding="utf-8",
    )
    assert AgentIamControlPlaneExposureGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


def test_deny_statement_stays_silent(tmp_path: Path) -> None:
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Deny", "Action": "bedrock:CreateGuardrail", "Resource": "*"}]}\n',
        encoding="utf-8",
    )
    assert AgentIamControlPlaneExposureGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


def test_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": "bedrock:CreateGuardrail", "Resource": "*"}]}\n'
        "// security: allow-agent-iam-control-plane-exposure\n",
        encoding="utf-8",
    )
    assert AgentIamControlPlaneExposureGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    fixtures = tmp_path / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "sample.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": "bedrock:CreateGuardrail", "Resource": "*"}]}\n',
        encoding="utf-8",
    )
    assert AgentIamControlPlaneExposureGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


def test_does_not_apply_without_llm_feature(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features=set())
    assert AgentIamControlPlaneExposureGuard().applies(profile) is False


def test_unrelated_json_stays_silent(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name": "app"}\n', encoding="utf-8")
    assert AgentIamControlPlaneExposureGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


def test_mixed_service_statement_gives_one_finding_per_service(tmp_path: Path) -> None:
    # Re-review L2: a statement mixing SageMaker and Bedrock control-plane actions was reported
    # entirely as bedrock-control-plane, so a rule-id exception for the SageMaker half could not
    # match. One finding per service present in the statement, each naming only its own actions.
    (tmp_path / "policy.json").write_text(
        '{\n  "Statement": [{\n    "Effect": "Allow",\n'
        '    "Action": ["sagemaker:CreateModel",\n'
        '               "bedrock:CreateAgent", "sagemaker:CreateEndpoint"],\n'
        '    "Resource": "*"\n  }]\n}\n',
        encoding="utf-8",
    )
    findings = AgentIamControlPlaneExposureGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    by_rule = {f.rule: f for f in findings}
    assert sorted(by_rule) == [
        "agent-iam-control-plane-exposure/bedrock-control-plane",
        "agent-iam-control-plane-exposure/sagemaker-control-plane",
    ]
    bedrock = by_rule["agent-iam-control-plane-exposure/bedrock-control-plane"]
    sagemaker = by_rule["agent-iam-control-plane-exposure/sagemaker-control-plane"]
    assert bedrock.location.endswith("policy.json:5")
    assert sagemaker.location.endswith("policy.json:4")
    assert "bedrock:CreateAgent" in bedrock.message and "sagemaker:" not in bedrock.message
    assert "sagemaker:CreateModel" in sagemaker.message and "sagemaker:CreateEndpoint" in sagemaker.message
    assert "bedrock:" not in sagemaker.message
    assert {f.severity for f in findings} == {"high"}
