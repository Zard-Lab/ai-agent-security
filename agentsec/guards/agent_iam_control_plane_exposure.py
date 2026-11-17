"""Guard: an AI agent's IAM policy grants a Bedrock or SageMaker CONTROL-PLANE action instead of
only the data-plane action its runtime actually needs (checklist §6c, new item).

An agent that only needs to RUN inference (`bedrock:InvokeModel`, `sagemaker-runtime:
InvokeEndpoint`) has no legitimate runtime reason to also hold the actions that CREATE or MODIFY
the thing it runs on: `bedrock:CreateAgent`/`UpdateAgent`/`CreateGuardrail`/`DeleteGuardrail`
(the agent can reconfigure its own capabilities or disable its own safety guardrails) or
`sagemaker:CreateEndpoint`/`CreateTrainingJob`/`CreateModel` (an agent that can deploy an
endpoint or start a training job could substitute a poisoned model or exfiltrate training data).
These are the ONLY AWS APIs that let an identity change what a Bedrock agent or a SageMaker
model actually IS, as opposed to merely calling it: the control-plane/data-plane distinction AWS
itself draws between the two API families. Deployment/CI pipelines legitimately need these
actions; an agent's own RUNTIME execution role never does.

Statically detectable from the action NAME alone: no condition-key nuance is relevant here (unlike
`iam-escalation-action-no-condition`'s scoping question): the finding is that the action is
granted AT ALL to a runtime role, not that it is granted without a condition. The guard cannot
tell an agent's runtime role from a deployment/CI role that legitimately needs these actions, so it
is a surfacing (review) signal: HIGH for both services, one finding per statement and service
naming every control-plane action of that service (PR #1051 review M1 and re-review L2; it was
CRITICAL for Bedrock and one finding per action, so a CI role granting three actions produced
three CRITICALs). Ported (with the action lists carried over near-verbatim) from poojakira/aws-agent-identity-guard's
`BEDROCK_CONTROL_PLANE`/`SAGEMAKER_CONTROL_PLANE` sets, under its MIT license.

Scans Terraform `.tf` files and bare IAM policy `.json` documents via the shared
`iter_policy_statement_blocks` walker (the same one `iam-wildcard` uses for both formats).
Suppress an audited statement with a `# security: allow-agent-iam-control-plane-exposure`
comment in a `.tf` file, or the literal string anywhere in a `.json` file (JSON has no comment
syntax, #424).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity

from .base import (
    CanaryPlant,
    Guard,
    blank_policy_noise,
    comment_dialect_for,
    is_nonproduct_path,
    iter_files,
    iter_policy_key_values,
    iter_policy_statement_blocks,
    pragma_present,
    read,
    rel,
)

_EXTENSIONS = (".tf", ".json")
_IS_POLICY = re.compile(r'"Statement"', re.IGNORECASE)
_EFFECT_WORD = re.compile(r"Effect", re.IGNORECASE)
_EFFECT_ALLOW = re.compile(r'"?Effect"?\s*[:=]\s*"Allow"', re.IGNORECASE)
# The Action key head; its list/string value is read by base.iter_policy_key_values, uncapped
# and linear (a `\[[^\]]*\]` value regex is quadratic on a run of unterminated `[`, #1051 round 4).
_ACTION_HEAD = re.compile(r'"?(?<!Not)Action"?\s*[:=]\s*', re.IGNORECASE)
_QUOTED = re.compile(r'"([^"]*)"')
_PRAGMA = re.compile(r"(?:#|//)\s*security:\s*allow-agent-iam-control-plane-exposure")

# Ported from aws-agent-identity-guard's BEDROCK_CONTROL_PLANE / SAGEMAKER_CONTROL_PLANE:
# the APIs that let an identity CREATE or MODIFY an agent/guardrail/model, as opposed to merely
# invoking one that already exists.
_BEDROCK_CONTROL_PLANE = frozenset({
    a.lower() for a in (
        "bedrock:CreateAgent", "bedrock:UpdateAgent", "bedrock:CreateAgentActionGroup",
        "bedrock:UpdateAgentActionGroup", "bedrock:CreateKnowledgeBase",
        "bedrock:UpdateKnowledgeBase", "bedrock:AssociateAgentKnowledgeBase",
        "bedrock:CreateGuardrail", "bedrock:UpdateGuardrail", "bedrock:DeleteGuardrail",
        "bedrock:CreateModelCustomizationJob", "bedrock:CreateProvisionedModelThroughput",
    )
})
_SAGEMAKER_CONTROL_PLANE = frozenset({
    a.lower() for a in (
        "sagemaker:CreateEndpoint", "sagemaker:UpdateEndpoint", "sagemaker:CreateEndpointConfig",
        "sagemaker:CreateModel", "sagemaker:CreateTrainingJob", "sagemaker:CreateProcessingJob",
        "sagemaker:CreateNotebookInstance", "sagemaker:StartNotebookInstance",
        "sagemaker:CreatePresignedNotebookInstanceUrl",
    )
})

_STANDARDS_BEDROCK = ["OWASP:A01", "CWE-269"]
_STANDARDS_SAGEMAKER = ["OWASP:A01", "CWE-269"]


class AgentIamControlPlaneExposureGuard(Guard):
    id = "agent-iam-control-plane-exposure"
    title = "Agent IAM policy grants a Bedrock/SageMaker control-plane action instead of data-plane only"
    area = "AI agent"
    # The action name alone cannot say whether the role is an agent runtime or a CI deploy role.
    surfacing = True

    # canary-bedrock.json: Action "bedrock:CreateGuardrail" -> fires
    # agent-iam-control-plane-exposure/bedrock-control-plane.
    # canary-sagemaker.tf: Action "sagemaker:CreateTrainingJob" -> fires
    # agent-iam-control-plane-exposure/sagemaker-control-plane.
    canary_plant = CanaryPlant(
        files={
            "canary-bedrock.json": (
                "{\n"
                '  "Version": "2012-10-17",\n'
                '  "Statement": [{\n'
                '    "Effect": "Allow",\n'
                '    "Action": "bedrock:CreateGuardrail",\n'
                '    "Resource": "*"\n'
                "  }]\n"
                "}\n"
            ),
            "canary-sagemaker.tf": (
                'resource "aws_iam_role_policy" "canary" {\n'
                "  policy = jsonencode({\n"
                "    Statement = [{\n"
                '      Effect   = "Allow"\n'
                '      Action   = "sagemaker:CreateTrainingJob"\n'
                '      Resource = "*"\n'
                "    }]\n"
                "  })\n"
                "}\n"
            ),
        },
        expects=frozenset({
            "agent-iam-control-plane-exposure/bedrock-control-plane",
            "agent-iam-control-plane-exposure/sagemaker-control-plane",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _EXTENSIONS):
            rel_path = rel(root, f)
            if is_nonproduct_path(rel_path, profile.archive_segments):
                continue
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
            return out
        # Cheap raw precheck before the blanking pass (#1051 review M4). Blanking only turns
        # characters into spaces, so a file whose RAW text has no `"Statement"` (JSON) or no
        # `Effect` key word (HCL) cannot hold a policy statement once blanked either.
        if not (_IS_POLICY if f.suffix == ".json" else _EFFECT_WORD).search(text):
            return out
        if f.suffix == ".json" and not _IS_POLICY.search(blank_policy_noise(text)):
            return out
        for start, _end, block in iter_policy_statement_blocks(text):
            if not _EFFECT_ALLOW.search(block):
                continue
            # One finding per SERVICE present in the statement (#1051 re-review L2), so a rule-id
            # exception for one service never hides, or is voided by, the other's actions.
            hits: dict[str, list[str]] = {"bedrock-control-plane": [], "sagemaker-control-plane": []}
            first: dict[str, int] = {}
            seen: set[str] = set()
            for m, val in iter_policy_key_values(block, _ACTION_HEAD):
                val_start = m.end()
                for qm in _QUOTED.finditer(val or ""):
                    action = qm.group(1)
                    key = action.lower()
                    kind = (
                        "bedrock-control-plane" if key in _BEDROCK_CONTROL_PLANE
                        else "sagemaker-control-plane" if key in _SAGEMAKER_CONTROL_PLANE
                        else None
                    )
                    if kind is None or key in seen:
                        continue
                    seen.add(key)
                    hits[kind].append(action)
                    first.setdefault(kind, start + val_start + qm.start())
            for kind, actions in hits.items():
                if not actions:
                    continue
                line = text.count("\n", 0, first[kind]) + 1
                out.append(self._finding(f"{rel(root, f)}:{line}", actions, kind, "high"))
        return out

    def _finding(self, location: str, actions: list[str], kind: str, severity: Severity) -> Finding:
        service = "Bedrock" if kind == "bedrock-control-plane" else "SageMaker"
        if kind == "bedrock-control-plane":
            detail = (
                "create or modify agents, knowledge bases, or guardrails -- it can "
                "reconfigure its own capabilities or disable its own safety guardrails"
            )
        else:
            detail = (
                "deploy endpoints or start training jobs -- it could substitute a "
                "poisoned model or exfiltrate training data"
            )
        named = ", ".join(f"`{a}`" for a in actions)
        return Finding(
            check_id=self.id,
            severity=severity,
            title=self.title,
            location=location,
            message=(
                f"This Allow statement grants {named}: {service} control-plane access. If this is "
                f"an agent's runtime role, the agent can {detail}. A deployment/CI role that "
                "creates these resources legitimately needs them."
            ),
            remediation=(
                f"Agent runtime roles should only hold {service} DATA-plane actions "
                f"({'bedrock:InvokeModel / bedrock-agent-runtime:*' if service == 'Bedrock' else 'sagemaker-runtime:InvokeEndpoint'}). "
                "Move control-plane actions to a separate deployment/CI pipeline role."
            ),
            rule=f"agent-iam-control-plane-exposure/{kind}",
            standards=list(_STANDARDS_BEDROCK if kind == "bedrock-control-plane" else _STANDARDS_SAGEMAKER),
        )
