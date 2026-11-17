from __future__ import annotations

from pathlib import Path

import pytest

from agentsec.guards.agent_iam_tool_resource_unscoped import AgentIamToolResourceUnscopedGuard
from tests.conftest import mkprofile


def test_tool_execution_unscoped_fires(tmp_path: Path) -> None:
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": "*"}]}\n',
        encoding="utf-8",
    )
    findings = AgentIamToolResourceUnscopedGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert any(f.rule == "agent-iam-tool-resource-unscoped/tool-execution-unscoped" for f in findings)


def test_tool_execution_scoped_stays_silent(tmp_path: Path) -> None:
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": "lambda:InvokeFunction", '
        '"Resource": "arn:aws:lambda:us-east-1:111:function:agent-tool-*"}]}\n',
        encoding="utf-8",
    )
    assert AgentIamToolResourceUnscopedGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


def test_s3_write_single_bucket_stays_silent(tmp_path: Path) -> None:
    # PR #1051 review M2: `bucket/*` is ONE bucket's objects, the ordinary scoped write grant.
    # A bucket ARN with no object path cannot be the target of PutObject at all.
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": ["s3:PutObject", "s3:DeleteObject"], '
        '"Resource": ["arn:aws:s3:::my-bucket/*", "arn:aws:s3:::my-bucket"]}]}\n',
        encoding="utf-8",
    )
    assert AgentIamToolResourceUnscopedGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


@pytest.mark.parametrize("resource", ['"*"', '"arn:aws:s3:::*"', '"arn:aws:s3:::*/*"', '["arn:aws:s3:::a/*", "*"]'])
def test_s3_write_any_bucket_fires(tmp_path: Path, resource: str) -> None:
    # Still-fires for the M2 narrowing: every bucket in the account.
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": "s3:PutObject", '
        f'"Resource": {resource}}}]}}\n',
        encoding="utf-8",
    )
    findings = AgentIamToolResourceUnscopedGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert [f.rule for f in findings] == ["agent-iam-tool-resource-unscoped/s3-write-unscoped"]
    assert findings[0].location.endswith("policy.json:1")


def test_not_resource_value_is_not_read_as_resource(tmp_path: Path) -> None:
    # M2: `NotResource: "*"` excludes everything (grants nothing); reading it as `Resource: "*"`
    # reported the opposite of its meaning.
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "NotResource": "*"}]}\n',
        encoding="utf-8",
    )
    assert AgentIamToolResourceUnscopedGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


def test_unresolvable_hcl_resource_is_not_reported_unscoped(tmp_path: Path) -> None:
    # M2: `Resource = aws_x.arn` yields no literal to judge; "not provably scoped" is not
    # "unscoped", so bedrock-model-unscoped must stay silent.
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "agent" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect   = "Allow"\n'
        '      Action   = ["bedrock:InvokeModel"]\n'
        "      Resource = data.aws_bedrock_foundation_model.claude.model_arn\n"
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    assert AgentIamToolResourceUnscopedGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


def test_s3_write_scoped_to_prefix_stays_silent(tmp_path: Path) -> None:
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": "s3:PutObject", '
        '"Resource": "arn:aws:s3:::my-bucket/agent-workspace/*"}]}\n',
        encoding="utf-8",
    )
    assert AgentIamToolResourceUnscopedGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


def test_bedrock_invoke_unscoped_fires(tmp_path: Path) -> None:
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": "bedrock:InvokeModel", "Resource": "*"}]}\n',
        encoding="utf-8",
    )
    findings = AgentIamToolResourceUnscopedGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert any(f.rule == "agent-iam-tool-resource-unscoped/bedrock-model-unscoped" for f in findings)


def test_bedrock_invoke_scoped_to_model_stays_silent(tmp_path: Path) -> None:
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": "bedrock:InvokeModel", '
        '"Resource": "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-haiku*"}]}\n',
        encoding="utf-8",
    )
    assert AgentIamToolResourceUnscopedGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


def test_database_scan_unscoped_fires(tmp_path: Path) -> None:
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": "dynamodb:Scan", "Resource": "*"}]}\n',
        encoding="utf-8",
    )
    findings = AgentIamToolResourceUnscopedGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert any(f.rule == "agent-iam-tool-resource-unscoped/database-unscoped" for f in findings)


def test_database_scan_with_leading_keys_condition_stays_silent(tmp_path: Path) -> None:
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": "dynamodb:Scan", "Resource": "*", '
        '"Condition": {"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": ["${aws:userid}"]}}}]}\n',
        encoding="utf-8",
    )
    assert AgentIamToolResourceUnscopedGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


def test_database_scan_scoped_to_table_stays_silent(tmp_path: Path) -> None:
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": "dynamodb:Scan", '
        '"Resource": "arn:aws:dynamodb:us-east-1:111:table/agent-table"}]}\n',
        encoding="utf-8",
    )
    assert AgentIamToolResourceUnscopedGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


def test_deny_statement_stays_silent(tmp_path: Path) -> None:
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Deny", "Action": "s3:PutObject", "Resource": "*"}]}\n',
        encoding="utf-8",
    )
    assert AgentIamToolResourceUnscopedGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


def test_terraform_file_flags_same_shape(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect   = "Allow"\n'
        '      Action   = "s3:DeleteObject"\n'
        '      Resource = "arn:aws:s3:::*/*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    findings = AgentIamToolResourceUnscopedGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert any(f.rule == "agent-iam-tool-resource-unscoped/s3-write-unscoped" for f in findings)


def test_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": "*"}]}\n'
        "// security: allow-agent-iam-tool-resource-unscoped\n",
        encoding="utf-8",
    )
    assert AgentIamToolResourceUnscopedGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    fixtures = tmp_path / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "sample.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": "*"}]}\n',
        encoding="utf-8",
    )
    assert AgentIamToolResourceUnscopedGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


def test_does_not_apply_without_llm_feature(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features=set())
    assert AgentIamToolResourceUnscopedGuard().applies(profile) is False


@pytest.mark.parametrize(
    "arn",
    [
        "arn:aws:bedrock:us-east-1:111122223333:inference-profile/us.anthropic.claude-3-5-sonnet-20241022-v2:0",
        "arn:aws:bedrock:us-east-1:111122223333:application-inference-profile/abc123",
    ],
)
def test_bedrock_invoke_scoped_to_inference_profile_stays_silent(tmp_path: Path, arn: str) -> None:
    # Follow-up to the re-review fixtures (s4b): an inference-profile ARN is model-scoped (newer
    # Claude models are only invocable through one), so it is not "any model in the account".
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": ["bedrock:InvokeModel"], '
        f'"Resource": ["{arn}"]}}]}}\n',
        encoding="utf-8",
    )
    assert AgentIamToolResourceUnscopedGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


def test_bedrock_invoke_on_non_model_arn_still_fires(tmp_path: Path) -> None:
    # Still-fires for the narrowing above: a Bedrock ARN that names no model is not model scoping.
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": "bedrock:InvokeModel", '
        '"Resource": "arn:aws:bedrock:us-east-1:111122223333:*"}]}\n',
        encoding="utf-8",
    )
    findings = AgentIamToolResourceUnscopedGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert [f.rule for f in findings] == ["agent-iam-tool-resource-unscoped/bedrock-model-unscoped"]


@pytest.mark.parametrize(
    "arn",
    [
        "arn:aws:bedrock:*:*:inference-profile/*",
        "arn:aws:bedrock:us-east-1:111122223333:application-inference-profile/*",
        "arn:aws:bedrock:us-east-1:111122223333:inference-profile/us.anthropic.*",
        # Round-3 re-review: `?` is an IAM wildcard too (one character).
        "arn:aws:bedrock:us-east-1:111122223333:inference-profile/us.anthropic.claude-3-5-sonnet-2024102?-v2:0",
        "arn:aws:bedrock:us-east-1:111122223333:application-inference-profile/abc12?",
    ],
)
def test_bedrock_invoke_on_wildcard_inference_profile_fires(tmp_path: Path, arn: str) -> None:
    # Round-2 re-review: a wildcard profile id is every profile (so every model reachable through
    # one), not model scoping. Only a concrete profile id counts.
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": "bedrock:InvokeModel", '
        f'"Resource": "{arn}"}}]}}\n',
        encoding="utf-8",
    )
    findings = AgentIamToolResourceUnscopedGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert [f.rule for f in findings] == ["agent-iam-tool-resource-unscoped/bedrock-model-unscoped"]


def test_known_gap_foundation_model_wildcard_is_accepted_as_scoped(tmp_path: Path) -> None:
    # KNOWN GAP, pinned on purpose (round-2 re-review): `foundation-model/*` reaches every
    # foundation model, yet the pre-existing substring check accepts it as scoped. Changing that
    # is out of this PR's scope; the guard doc records it. If this test starts failing because
    # the gap was closed, update the doc and flip the assertion.
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": "bedrock:InvokeModel", '
        '"Resource": "arn:aws:bedrock:*::foundation-model/*"}]}\n',
        encoding="utf-8",
    )
    assert AgentIamToolResourceUnscopedGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


_PROFILE = "arn:aws:bedrock:us-east-1:111122223333:inference-profile/us.anthropic.claude-3-5-sonnet-20241022-v2:0"
_MODEL = "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0"


@pytest.mark.parametrize(
    "resources",
    [
        [_PROFILE, "arn:aws:bedrock:us-east-1:111122223333:inference-profile/*"],
        [_MODEL, "*"],
        [_MODEL, "arn:aws:bedrock:us-east-1:111122223333:*"],
    ],
)
def test_bedrock_invoke_any_unscoped_resource_fires(tmp_path: Path, resources: list[str]) -> None:
    # Round-3 re-review: one scoped resource used to vouch for the whole list, so a concrete
    # profile next to `inference-profile/*` was silent. Each resource is judged on its own, like
    # the S3 rule (`["arn:aws:s3:::a/*", "*"]` fires).
    res = ", ".join(f'"{r}"' for r in resources)
    (tmp_path / "policy.json").write_text(
        f'{{"Statement": [{{"Effect": "Allow", "Action": "bedrock:InvokeModel", "Resource": [{res}]}}]}}\n',
        encoding="utf-8",
    )
    findings = AgentIamToolResourceUnscopedGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    # (`"*"` also fires the separate tool-execution-unscoped rule for bedrock:InvokeModel.)
    assert "agent-iam-tool-resource-unscoped/bedrock-model-unscoped" in [f.rule for f in findings]


@pytest.mark.parametrize(
    "resources",
    [
        [_MODEL, _PROFILE],
        [
            _MODEL,
            "arn:aws:bedrock:us-east-1:111122223333:agent/AGENT12345",
            "arn:aws:bedrock:us-east-1:111122223333:knowledge-base/KB12345678",
        ],
    ],
)
def test_bedrock_invoke_all_resources_scoped_stays_silent(tmp_path: Path, resources: list[str]) -> None:
    # FP-bait for the per-resource judgement: concrete model/profile ARNs, and agent/ or
    # knowledge-base/ ARNs (not model resources at all) next to a concrete model, stay silent.
    res = ", ".join(f'"{r}"' for r in resources)
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": ["bedrock:InvokeModel", "bedrock:InvokeAgent", '
        f'"bedrock:Retrieve"], "Resource": [{res}]}}]}}\n',
        encoding="utf-8",
    )
    assert AgentIamToolResourceUnscopedGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


def test_known_gap_foundation_model_wildcard_in_a_list_is_accepted_as_scoped(tmp_path: Path) -> None:
    # KNOWN GAP, same one as test_known_gap_foundation_model_wildcard_is_accepted_as_scoped: the
    # pre-existing model-ARN check is a substring test, so `foundation-model/*` counts as scoped
    # whether it stands alone or sits next to a concrete model. Judging resources one by one does
    # not change that; closing the gap is out of this PR's scope. Flip both pins together.
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": "bedrock:InvokeModel", '
        f'"Resource": ["{_MODEL}", "arn:aws:bedrock:*::foundation-model/*"]}}]}}\n',
        encoding="utf-8",
    )
    assert AgentIamToolResourceUnscopedGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


def _invoke_policy(resources: list[str]) -> str:
    res = ", ".join(f'"{r}"' for r in resources)
    return f'{{"Statement": [{{"Effect": "Allow", "Action": "bedrock:InvokeModel", "Resource": [{res}]}}]}}\n'


_ACCT = "arn:aws:bedrock:us-east-1:111122223333"


@pytest.mark.parametrize(
    "arn",
    [
        f"{_ACCT}:imported-model/abcd1234efgh",
        f"{_ACCT}:default-prompt-router/anthropic.claude:1",
        f"{_ACCT}:prompt-router/abcd1234",
    ],
)
def test_bedrock_invoke_on_concrete_imported_model_or_router_stays_silent(tmp_path: Path, arn: str) -> None:
    # Round-4 re-review m1: imported models and prompt routers are model-scoped resources too.
    (tmp_path / "policy.json").write_text(_invoke_policy([arn]), encoding="utf-8")
    assert AgentIamToolResourceUnscopedGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


@pytest.mark.parametrize(
    "arn",
    [f"{_ACCT}:imported-model/*", f"{_ACCT}:default-prompt-router/*", f"{_ACCT}:prompt-router/ab?d"],
)
def test_bedrock_invoke_on_wildcard_imported_model_or_router_fires(tmp_path: Path, arn: str) -> None:
    (tmp_path / "policy.json").write_text(_invoke_policy([arn]), encoding="utf-8")
    findings = AgentIamToolResourceUnscopedGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert [f.rule for f in findings] == ["agent-iam-tool-resource-unscoped/bedrock-model-unscoped"]


def test_bedrock_invoke_on_whole_interpolation_resource_stays_silent(tmp_path: Path) -> None:
    # A resource that is one whole `${...}` is not statically evaluable: scoped, like a bare HCL
    # reference (which yields no literal at all).
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "agent" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect   = "Allow"\n'
        '      Action   = ["bedrock:InvokeModel"]\n'
        '      Resource = ["${aws_bedrock_custom_model.m.custom_model_arn}"]\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    assert AgentIamToolResourceUnscopedGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


def test_bedrock_invoke_on_whole_interpolation_plus_star_fires(tmp_path: Path) -> None:
    (tmp_path / "policy.json").write_text(_invoke_policy(["${var.model_arn}", "*"]), encoding="utf-8")
    findings = AgentIamToolResourceUnscopedGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert "agent-iam-tool-resource-unscoped/bedrock-model-unscoped" in [f.rule for f in findings]


@pytest.mark.parametrize(
    "arn",
    [f"{_ACCT}:agent/AGENT12345", "arn:aws:s3:::model-artifacts/*"],
    ids=["agent-only", "non-bedrock-only"],
)
def test_bedrock_invoke_with_no_model_resource_at_all_fires(tmp_path: Path, arn: str) -> None:
    # Round-4 re-review m2: pins the "no scoped model resource at all" half of the rule. A neutral
    # resource (an agent ARN, a non-Bedrock ARN) does not scope bedrock:InvokeModel.
    (tmp_path / "policy.json").write_text(_invoke_policy([arn]), encoding="utf-8")
    findings = AgentIamToolResourceUnscopedGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert [f.rule for f in findings] == ["agent-iam-tool-resource-unscoped/bedrock-model-unscoped"]
