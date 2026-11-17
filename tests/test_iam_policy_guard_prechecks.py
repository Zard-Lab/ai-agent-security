"""Cross-guard checks for the seven IAM-policy guards PR #1051 added or widened.

They all walk every `.json` (and most every `.tf`) file in a repo, so two properties are pinned
here once rather than seven times: the cheap no-policy precheck runs BEFORE the costly
comment/heredoc blanking (review M4), and the output is identical across hash seeds (review L1).
"""
from __future__ import annotations

from pathlib import Path

import pytest

import agentsec.guards.base as base_mod
from agentsec.guards.agent_iam_control_plane_exposure import AgentIamControlPlaneExposureGuard
from agentsec.guards.agent_iam_killchain_combination import AgentIamKillchainCombinationGuard
from agentsec.guards.agent_iam_tool_resource_unscoped import AgentIamToolResourceUnscopedGuard
from agentsec.guards.base import Guard
from agentsec.guards.iam_escalation_action_no_condition import IamEscalationActionNoConditionGuard
from agentsec.guards.iam_notaction_with_allow import IamNotactionWithAllowGuard
from agentsec.guards.iam_role_public_assume import IamRolePublicAssumeGuard
from agentsec.guards.iam_wildcard import IamWildcardGuard
from tests._timing import assert_growth
from tests.conftest import mkprofile

_GUARDS: list[type[Guard]] = [
    AgentIamControlPlaneExposureGuard,
    AgentIamKillchainCombinationGuard,
    AgentIamToolResourceUnscopedGuard,
    IamEscalationActionNoConditionGuard,
    IamNotactionWithAllowGuard,
    IamRolePublicAssumeGuard,
    IamWildcardGuard,
]


@pytest.mark.parametrize("guard_cls", _GUARDS, ids=lambda g: g.id)
def test_non_policy_files_skip_the_blanking_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, guard_cls: type[Guard]
) -> None:
    # Review M4: blank_policy_noise ran on EVERY .json before the "Statement" check (2.3 to 7.0 s
    # per guard on a 14.8 MB no-Statement JSON). A file with no `"Statement"` (JSON) or no `Effect`
    # key (HCL) cannot hold a policy statement, so the blanking pass must never run on it.
    calls: list[int] = []

    def _spy(text: str) -> str:
        calls.append(len(text))
        return text

    module = __import__(guard_cls.__module__, fromlist=["_"])
    monkeypatch.setattr(base_mod, "blank_policy_noise", _spy)
    if hasattr(module, "blank_policy_noise"):
        monkeypatch.setattr(module, "blank_policy_noise", _spy)
    (tmp_path / "package.json").write_text(
        '{"name": "app", "scripts": {"build": "tsc"}, "Effect": "x"}\n', encoding="utf-8"
    )
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "b" {\n  bucket = "b"\n}\n', encoding="utf-8"
    )
    findings = guard_cls().run(tmp_path, mkprofile(tmp_path, features={"llm", "terraform"}))
    assert findings == []
    assert calls == [], f"{guard_cls.id} blanked a file that cannot hold a policy statement"


_DETERMINISM_SCRIPT = """
import json, sys
from pathlib import Path
from tests.conftest import mkprofile
from tests.test_iam_policy_guard_prechecks import _GUARDS
root = Path(sys.argv[1])
profile = mkprofile(root, features={"llm", "terraform"})
out = []
for g in _GUARDS:
    for f in g().run(root, profile):
        out.append([f.rule, f.severity, f.location, f.title, f.message, f.remediation, f.standards])
print(json.dumps(sorted(out)))
"""


@pytest.mark.slow
def test_findings_are_identical_across_hash_seeds(tmp_path: Path) -> None:
    # Review L1: iam-wildcard's partial-wildcard match once iterated a frozenset, so "first
    # dangerous action a pattern covers" differed per process (PYTHONHASHSEED) whenever a pattern
    # covered several. Only test_guard_budget's parallel-vs-single identity check caught it. This
    # pins it directly: one multi-match fixture, every finding field, two seeds, byte-identical.
    import os
    import subprocess
    import sys

    (tmp_path / "policy.json").write_text(
        '{"Version": "2012-10-17", "Statement": [\n'
        '  {"Effect": "Allow", "Action": ["iam:*Role*", "iam:*Policy*"], "Resource": "arn:aws:iam::1:role/x"},\n'
        '  {"Effect": "Allow", "Action": ["secretsmanager:*", "ssm:Get*", "sts:AssumeRole", "iam:PassRole",'
        ' "ec2:Describe*", "iam:*InstanceProfile*", "bedrock:CreateAgent", "bedrock:UpdateGuardrail"],'
        ' "Resource": "*"},\n'
        '  {"Effect": "Allow", "Action": ["s3:PutObject", "lambda:InvokeFunction"], "Resource": "*"}\n'
        "]}\n",
        encoding="utf-8",
    )
    repo = Path(__file__).resolve().parents[1]
    outputs = []
    for seed in ("0", "1", "2", "3"):
        env = {**os.environ, "PYTHONHASHSEED": seed, "PYTHONIOENCODING": "utf-8"}
        r = subprocess.run(  # noqa: S603
            [sys.executable, "-c", _DETERMINISM_SCRIPT, str(tmp_path)],
            cwd=repo, env=env, capture_output=True, text=True, encoding="utf-8", check=False,
        )
        assert r.returncode == 0, r.stderr
        outputs.append(r.stdout)
    assert outputs[0].count('"iam-wildcard/partial-wildcard-dangerous"') == 1  # the fixture really matches
    assert all(o == outputs[0] for o in outputs), "guard output depends on PYTHONHASHSEED"


@pytest.mark.parametrize("guard_cls", _GUARDS, ids=lambda g: g.id)
@pytest.mark.parametrize("unit", ['"Action": [', '"Resource": ['])
def test_unterminated_list_runs_stay_linear(tmp_path: Path, guard_cls: type[Guard], unit: str) -> None:
    # Round-4 re-review: every `\[[^\]]*\]` list pattern rescanned to the end of the statement from
    # each unterminated `[`, so a run of them was quadratic, and the round-3 length caps that fixed
    # it were a silent bypass. Lists are now scanned once, uncapped, by
    # base.iter_policy_key_values; this pins the cost for all seven guards.
    sizes = [2000, 4000, 8000, 16000]
    roots: dict[int, Path] = {}
    for n in sizes:
        d = tmp_path / str(n)
        d.mkdir()
        (d / "p.json").write_text(
            '{"Statement": [{"Effect": "Allow", '
            '"Condition": {"StringEquals": {' + unit * n + '}}, "Action": "s3:GetObject", '
            '"Resource": "arn:aws:s3:::b/*"}]}\n',
            encoding="utf-8",
        )
        roots[n] = d
    profile = mkprofile(tmp_path, features={"llm"})

    def scan(n: int) -> None:
        guard_cls().run(roots[n], profile)

    assert_growth(scan, sizes, expected="linear")


def _tf_policy(first_line: str) -> str:
    return (
        'resource "aws_iam_role_policy" "p" {\n  policy = jsonencode({\n    Statement = [{\n'
        '      Effect   = "Allow"\n'
        f"      {first_line}\n"
        '      Action   = ["iam:PassRole"]\n'
        "    }]\n  })\n}\n"
    )


_SID_GAP = '"Sid": "x${", '
_KNOWN_GAP_CASES = [
    # (guard, file name, text with the gap marker, the same text without it, rule that goes silent)
    (
        IamEscalationActionNoConditionGuard, "iam.tf",
        _tf_policy('Resource = "${replace(var.arn, "{", "")}"'), _tf_policy('Resource = "*"'),
        "iam-escalation-action-no-condition/unconditional-grant",
    ),
    (
        IamEscalationActionNoConditionGuard, "iam.tf",
        _tf_policy('Sid      = "x$${"'), _tf_policy('Sid      = "x"'),
        "iam-escalation-action-no-condition/unconditional-grant",
    ),
    (
        AgentIamToolResourceUnscopedGuard, "p.json",
        '{"Statement": [{' + _SID_GAP + '"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": "*"}]}\n',
        '{"Statement": [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": "*"}]}\n',
        "agent-iam-tool-resource-unscoped/tool-execution-unscoped",
    ),
    (
        AgentIamControlPlaneExposureGuard, "p.json",
        '{"Statement": [{' + _SID_GAP + '"Effect": "Allow", "Action": "bedrock:CreateGuardrail", "Resource": "*"}]}\n',
        '{"Statement": [{"Effect": "Allow", "Action": "bedrock:CreateGuardrail", "Resource": "*"}]}\n',
        "agent-iam-control-plane-exposure/bedrock-control-plane",
    ),
    (
        AgentIamKillchainCombinationGuard, "p.json",
        '{"Statement": [{' + _SID_GAP + '"Effect": "Allow", '
        '"Action": ["secretsmanager:GetSecretValue", "sts:AssumeRole"], "Resource": "*"}]}\n',
        '{"Statement": [{"Effect": "Allow", '
        '"Action": ["secretsmanager:GetSecretValue", "sts:AssumeRole"], "Resource": "*"}]}\n',
        "agent-iam-killchain-combination/harvest-plus-lateral",
    ),
    (
        IamWildcardGuard, "p.json",
        '{"Statement": [{' + _SID_GAP + '"Effect": "Allow", "Action": "iam:*Role*", "Resource": "arn:aws:iam::1:role/x"}]}\n',
        '{"Statement": [{"Effect": "Allow", "Action": "iam:*Role*", "Resource": "arn:aws:iam::1:role/x"}]}\n',
        "iam-wildcard/partial-wildcard-dangerous",
    ),
    (
        IamRolePublicAssumeGuard, "p.json",
        '{"Statement": [{' + _SID_GAP + '"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]}\n',
        '{"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]}\n',
        "iam-role-public-assume/wildcard-principal",
    ),
]


@pytest.mark.parametrize(
    "guard_cls,name,gap_text,control_text,rule",
    _KNOWN_GAP_CASES,
    ids=[
        "escalation-replace-brace", "escalation-hcl-escape", "unscoped-sid", "control-plane-sid",
        "killchain-sid", "iam-wildcard-sid", "role-assume-sid",
    ],
)
def test_known_gap_brace_in_interpolation_string_hides_later_values(
    tmp_path: Path, guard_cls: type[Guard], name: str, gap_text: str, control_text: str, rule: str
) -> None:
    # KNOWN GAP, pinned on purpose (PR #1051 final review F1; deferred, not fixed). The brace-depth
    # scan in base.neutralize_interpolations counts a `{`/`}` inside a QUOTED string within `${...}`
    # as structure, and an unterminated `${` (`"x${"`, HCL `"x$${"`) neutralises up to the end of
    # the text, so Action/Resource/Principal values LATER in the same enclosing object go unread.
    # Scope: the rest of that enclosing object (statement) only; other statements are unaffected.
    # When a string-aware scan fixes it, this test fails: flip it to assert `rule` fires and update
    # the guards' "Known bypasses" rows.
    profile = mkprofile(tmp_path, features={"llm", "terraform"})
    gap, control = tmp_path / "gap", tmp_path / "control"
    gap.mkdir()
    control.mkdir()
    (gap / name).write_text(gap_text, encoding="utf-8")
    (control / name).write_text(control_text, encoding="utf-8")
    assert rule in [f.rule for f in guard_cls().run(control, profile)]  # the shape itself is detected
    assert rule not in [f.rule for f in guard_cls().run(gap, profile)]  # ...but not behind the gap
