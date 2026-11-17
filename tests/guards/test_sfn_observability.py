from __future__ import annotations

from agentsec.guards.sfn_observability import SfnObservabilityGuard
from tests.guards._common import *  # noqa: F401,F403


def test_sfn_observability_flags_missing_logging_and_tracing(tmp_path: Path) -> None:
    (tmp_path / "sfn.tf").write_text(
        'resource "aws_sfn_state_machine" "workflow" {\n'
        '  name     = "order-workflow"\n'
        '  role_arn = "arn:aws:iam::123456789012:role/sfn-role"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = SfnObservabilityGuard().run(tmp_path, profile)
    assert len(findings) == 2
    rules = {f.rule for f in findings}
    assert rules == {
        "sfn-observability/logging-disabled",
        "sfn-observability/tracing-disabled",
    }
    for f in findings:
        assert f.severity == "medium"
        assert f.location.endswith(":1")  # anchored on the resource opening line


def test_sfn_observability_flags_logging_level_off(tmp_path: Path) -> None:
    (tmp_path / "sfn.tf").write_text(
        'resource "aws_sfn_state_machine" "workflow" {\n'
        '  name     = "order-workflow"\n'
        '  role_arn = "arn:aws:iam::123456789012:role/sfn-role"\n'
        "  logging_configuration {\n"
        '    level = "OFF"\n'
        "  }\n"
        "  tracing_configuration {\n"
        "    enabled = true\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = SfnObservabilityGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "sfn-observability/logging-disabled"


def test_sfn_observability_flags_tracing_disabled(tmp_path: Path) -> None:
    (tmp_path / "sfn.tf").write_text(
        'resource "aws_sfn_state_machine" "workflow" {\n'
        '  name     = "order-workflow"\n'
        '  role_arn = "arn:aws:iam::123456789012:role/sfn-role"\n'
        "  logging_configuration {\n"
        '    level = "ALL"\n'
        "  }\n"
        "  tracing_configuration {\n"
        "    enabled = false\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = SfnObservabilityGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "sfn-observability/tracing-disabled"


def test_sfn_observability_silent_when_fully_configured(tmp_path: Path) -> None:
    (tmp_path / "sfn.tf").write_text(
        'resource "aws_sfn_state_machine" "workflow" {\n'
        '  name     = "order-workflow"\n'
        '  role_arn = "arn:aws:iam::123456789012:role/sfn-role"\n'
        "  logging_configuration {\n"
        '    log_destination        = "${aws_cloudwatch_log_group.sfn.arn}:*"\n'
        "    include_execution_data = true\n"
        '    level                  = "ERROR"\n'
        "  }\n"
        "  tracing_configuration {\n"
        "    enabled = true\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert SfnObservabilityGuard().run(tmp_path, profile) == []


def test_sfn_observability_silent_other_resource(tmp_path: Path) -> None:
    (tmp_path / "lambda.tf").write_text(
        'resource "aws_lambda_function" "app" {\n'
        '  function_name = "app"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert SfnObservabilityGuard().run(tmp_path, profile) == []


def test_sfn_observability_logging_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "sfn.tf").write_text(
        'resource "aws_sfn_state_machine" "workflow" {  # security: allow-sfn-logging\n'
        '  name     = "order-workflow"\n'
        '  role_arn = "arn:aws:iam::123456789012:role/sfn-role"\n'
        "  tracing_configuration {\n"
        "    enabled = true\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert SfnObservabilityGuard().run(tmp_path, profile) == []


def test_sfn_observability_tracing_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "sfn.tf").write_text(
        'resource "aws_sfn_state_machine" "workflow" {  # security: allow-sfn-tracing\n'
        '  name     = "order-workflow"\n'
        '  role_arn = "arn:aws:iam::123456789012:role/sfn-role"\n'
        "  logging_configuration {\n"
        '    level = "ALL"\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert SfnObservabilityGuard().run(tmp_path, profile) == []


def test_sfn_observability_comment_does_not_suppress_finding(tmp_path: Path) -> None:
    (tmp_path / "sfn.tf").write_text(
        'resource "aws_sfn_state_machine" "workflow" {\n'
        '  name     = "order-workflow"\n'
        '  role_arn = "arn:aws:iam::123456789012:role/sfn-role"\n'
        "  # tracing_configuration { enabled = true }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = SfnObservabilityGuard().run(tmp_path, profile)
    rules = {f.rule for f in findings}
    assert "sfn-observability/tracing-disabled" in rules


def test_sfn_observability_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert SfnObservabilityGuard().applies(profile) is False


def test_sfn_observability_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert SfnObservabilityGuard().applies(profile) is True
