"""Guard: an AI agent's IAM policy grants a tool-execution/data-access action with no
resource-level scoping -- `Resource: "*"` or an equivalently unscoped ARN (checklist §6c, new
item).

A policy that passes `iam-wildcard`'s bare-`*` check can still hand an agent far more than it
needs at the SERVICE level: `lambda:InvokeFunction` against `Resource: "*"` lets the agent invoke
ANY Lambda in the account -- including admin utilities, data pipelines, or credential-rotation
functions, not just its intended tools; `s3:PutObject`/`DeleteObject` against `*` or an
every-bucket ARN (`arn:aws:s3:::*/*`) lets it overwrite or delete objects in every bucket of the
account; `bedrock:InvokeModel` with no foundation/provisioned/custom-model ARN
scoping lets it call any model in the account, including expensive ones, leading to unexpected
cost or capability escalation; `dynamodb:Scan`/`Query` (or the RDS Data API equivalent) with no
row/attribute-level condition and `Resource: "*"` lets it read entire tables rather than its own
tenant's rows.

Ported (with the action sets carried over near-verbatim) from
poojakira/aws-agent-identity-guard's `TOOL_EXECUTION_PATTERNS` (AIG006), the S3 key-prefix check
(AIG014), the Bedrock model-ID check (AIG015), and the DynamoDB/RDS full-table check (AIG018),
under its MIT license. The source's Lambda-specific resource-naming check (AIG016) is deliberately
NOT ported separately -- read against the source itself, it fires on the same `lambda:
InvokeFunction` + `Resource: "*"` shape the generic tool-execution rule below already catches; a
dedicated second finding for the identical condition would be a self-duplicate, not a
narrower/independent signal.

The S3 rule was narrowed in the PR #1051 review (M2): the source's key-prefix check flagged a
single-bucket `arn:aws:s3:::bucket/*` grant, which is the ordinary scoped write, so only `*` and
an every-bucket ARN now fire. A statement whose `Resource` holds no quoted literal (HCL
`Resource = aws_s3_bucket.x.arn`) is not judged at all, because "not provably scoped" is not
"unscoped"; and `NotResource` is never read as `Resource`.

Scans Terraform `.tf` files and bare IAM policy `.json` documents via the shared
`iter_policy_statement_blocks` walker. Suppress an audited statement with a
`# security: allow-agent-iam-tool-resource-unscoped` comment in a `.tf` file, or the literal
string anywhere in a `.json` file (JSON has no comment syntax, #424).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

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
# The Action/Resource key heads; their list/string values are read by base.iter_policy_key_values,
# uncapped and linear (a `\[[^\]]*\]` value regex is quadratic on a run of unterminated `[`, #1051
# round 4).
_ACTION_HEAD = re.compile(r'"?(?<!Not)Action"?\s*[:=]\s*', re.IGNORECASE)
_RESOURCE_HEAD = re.compile(r'"?(?<!Not)Resource"?\s*[:=]\s*', re.IGNORECASE)
_CONDITION_PRESENT = re.compile(r'"?Condition"?\s*[:=]', re.IGNORECASE)
_QUOTED = re.compile(r'"([^"]*)"')
_PRAGMA = re.compile(r"(?:#|//)\s*security:\s*allow-agent-iam-tool-resource-unscoped")

# Ported from aws-agent-identity-guard's TOOL_EXECUTION_PATTERNS (AIG006).
_TOOL_EXECUTION_ACTIONS = frozenset({
    a.lower() for a in (
        "lambda:InvokeFunction", "lambda:InvokeAsync", "ssm:SendCommand", "ssm:StartSession",
        "ssm:StartAutomationExecution", "states:StartExecution", "states:StartSyncExecution",
        "ecs:RunTask", "ecs:StartTask", "bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream",
        "bedrock-agent:InvokeAgent", "bedrock-agent-runtime:InvokeAgent",
        "bedrock-agent-runtime:Retrieve", "bedrock-agent-runtime:RetrieveAndGenerate",
        "sagemaker-runtime:InvokeEndpoint", "sagemaker-runtime:InvokeEndpointAsync",
        "execute-api:Invoke",
    )
})
_S3_WRITE_ACTIONS = frozenset({"s3:putobject", "s3:deleteobject", "s3:putobjectacl"})
_BEDROCK_INVOKE_ACTIONS = frozenset({"bedrock:invokemodel", "bedrock:invokemodelwithresponsestream"})
_DB_SCAN_ACTIONS = frozenset({"dynamodb:scan", "dynamodb:query", "rds-data:executestatement"})
_DB_SCOPE_CONDITION = re.compile(
    r'"?(?:dynamodb:LeadingKeys|dynamodb:Attributes|aws:PrincipalTag)"?', re.IGNORECASE
)

_STANDARDS = ["OWASP:A01", "CWE-269"]


def _values(block: str, head: re.Pattern[str]) -> list[str]:
    """Every quoted string in the list/string value of each `head` key in `block`."""
    out: list[str] = []
    for _m, val in iter_policy_key_values(block, head):
        for qm in _QUOTED.finditer(val or ""):
            out.append(qm.group(1))
    return out


def _s3_write_unscoped(resources: list[str]) -> bool:
    """True if any resource reaches every bucket in the account: `*`, `arn:aws:s3:::*` or
    `arn:aws:s3:::*/...`. One bucket's objects (`arn:aws:s3:::bucket/*`) is a scoped grant, and a
    bucket-level ARN with no object path is not a valid PutObject/DeleteObject target at all."""
    for r in resources:
        if r == "*":
            return True
        if r.startswith("arn:aws:s3:::"):
            bucket = r[len("arn:aws:s3:::") :].split("/", 1)[0]
            if bucket == "*":
                return True
    return False


# ARN segments that name a model. KNOWN GAP (pre-existing, recorded in the guard doc): this is a
# substring test, so `foundation-model/*` (every foundation model) is accepted as scoped.
_BEDROCK_MODEL_SEGMENTS = (":foundation-model/", ":provisioned-model/", ":custom-model/")
# Inference profiles route to named models (newer Claude models are invocable only through one;
# added after the PR #1051 re-review). Only a CONCRETE profile id is scoping: a `*` or `?` (both
# IAM wildcards) anywhere in the id (`inference-profile/*`, `inference-profile/us.anthropic.*`)
# reaches every matching profile (round-2 and round-3 re-reviews).
# Imported models and (default) prompt routers are judged the same way (round-4 re-review).
_BEDROCK_PROFILE_SEGMENTS = (
    ":inference-profile/", ":application-inference-profile/", ":imported-model/",
    ":default-prompt-router/", ":prompt-router/",
)


def _bedrock_resource_scope(r: str) -> bool | None:
    """Judge ONE resource for model scoping: True scoped, False unscoped, None not a model
    resource at all (an `agent/` or `knowledge-base/` ARN, a non-Bedrock ARN)."""
    if r == "*":
        return False
    if r.startswith("$(") and r.endswith(")") and r.count("$(") == 1:
        return True  # one whole `${...}` (neutralised): not statically evaluable, counts as scoped
    if any(seg in r for seg in _BEDROCK_MODEL_SEGMENTS):
        return True  # KNOWN GAP: substring test, so `foundation-model/*` counts as scoped
    for seg in _BEDROCK_PROFILE_SEGMENTS:
        i = r.find(seg)
        if i >= 0:
            profile_id = r[i + len(seg) :]
            return bool(profile_id) and "*" not in profile_id and "?" not in profile_id
    if r.startswith("arn:aws:bedrock:") and "*" in r.rsplit(":", 1)[-1].split("/", 1)[0]:
        return False  # e.g. `arn:aws:bedrock:us-east-1:111:*`: every Bedrock resource type
    return None


def _bedrock_model_unscoped(resources: list[str]) -> bool:
    """Each resource is judged on its own (round-3 re-review): fire when ANY resource is a `*`
    or an unscoped model/profile ARN, or when no resource is a scoped model resource at all. One
    concrete ARN no longer vouches for a wildcard sibling (the S3 rule's own semantics)."""
    verdicts = [_bedrock_resource_scope(r) for r in resources]
    return False in verdicts or True not in verdicts


class AgentIamToolResourceUnscopedGuard(Guard):
    id = "agent-iam-tool-resource-unscoped"
    title = "Agent IAM policy grants a tool-execution/data-access action with no resource scoping"
    area = "AI agent"

    # canary-tool-exec.json: lambda:InvokeFunction + Resource "*" -> fires tool-execution-unscoped.
    # canary-s3-write.tf: s3:PutObject on every bucket's objects -> fires s3-write-unscoped.
    # canary-bedrock-model.json: bedrock:InvokeModel + Resource "*" -> fires bedrock-model-unscoped.
    # canary-db-scan.tf: dynamodb:Scan + Resource "*" + no scoping condition -> fires database-unscoped.
    canary_plant = CanaryPlant(
        files={
            "canary-tool-exec.json": (
                '{"Statement": [{"Effect": "Allow", "Action": "lambda:InvokeFunction", '
                '"Resource": "*"}]}\n'
            ),
            "canary-s3-write.tf": (
                'resource "aws_iam_role_policy" "canary" {\n'
                "  policy = jsonencode({\n"
                "    Statement = [{\n"
                '      Effect   = "Allow"\n'
                '      Action   = "s3:PutObject"\n'
                '      Resource = "arn:aws:s3:::*/*"\n'
                "    }]\n"
                "  })\n"
                "}\n"
            ),
            "canary-bedrock-model.json": (
                '{"Statement": [{"Effect": "Allow", "Action": "bedrock:InvokeModel", '
                '"Resource": "*"}]}\n'
            ),
            "canary-db-scan.tf": (
                'resource "aws_iam_role_policy" "canary2" {\n'
                "  policy = jsonencode({\n"
                "    Statement = [{\n"
                '      Effect   = "Allow"\n'
                '      Action   = "dynamodb:Scan"\n'
                '      Resource = "*"\n'
                "    }]\n"
                "  })\n"
                "}\n"
            ),
        },
        expects=frozenset({
            "agent-iam-tool-resource-unscoped/tool-execution-unscoped",
            "agent-iam-tool-resource-unscoped/s3-write-unscoped",
            "agent-iam-tool-resource-unscoped/bedrock-model-unscoped",
            "agent-iam-tool-resource-unscoped/database-unscoped",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _EXTENSIONS):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
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
            actions = [a.lower() for a in _values(block, _ACTION_HEAD)]
            resources = _values(block, _RESOURCE_HEAD)
            if not resources:
                continue  # NotResource, or an unresolvable HCL reference: nothing literal to judge
            lineno = text.count("\n", 0, start) + 1
            location = f"{rel(root, f)}:{lineno}"
            has_wildcard_resource = any(r == "*" for r in resources)

            if has_wildcard_resource:
                matched_tool = next((a for a in actions if a in _TOOL_EXECUTION_ACTIONS), None)
                if matched_tool:
                    out.append(self._finding(location, "tool-execution-unscoped", matched_tool))

            if any(a in _S3_WRITE_ACTIONS for a in actions) and _s3_write_unscoped(resources):
                matched = next(a for a in actions if a in _S3_WRITE_ACTIONS)
                out.append(self._finding(location, "s3-write-unscoped", matched))

            if (
                any(a in _BEDROCK_INVOKE_ACTIONS for a in actions)
                and _bedrock_model_unscoped(resources)
            ):
                matched = next(a for a in actions if a in _BEDROCK_INVOKE_ACTIONS)
                out.append(self._finding(location, "bedrock-model-unscoped", matched))

            if (
                any(a in _DB_SCAN_ACTIONS for a in actions)
                and has_wildcard_resource
                and not _DB_SCOPE_CONDITION.search(block)
                and not _CONDITION_PRESENT.search(block)
            ):
                matched = next(a for a in actions if a in _DB_SCAN_ACTIONS)
                out.append(self._finding(location, "database-unscoped", matched))
        return out

    def _finding(self, location: str, kind: str, action: str) -> Finding:
        detail = {
            "tool-execution-unscoped": (
                'targets `Resource: "*"` -- the agent can invoke ANY matching resource in '
                "the account, not just its intended tools.",
                "Restrict to specific ARNs: the Lambda functions, state machines, or Bedrock "
                "agents this tool is allowed to call.",
            ),
            "s3-write-unscoped": (
                "targets every bucket in the account -- the agent can overwrite or delete "
                "objects in any of them.",
                "Scope the S3 resource to the bucket (ideally a prefix) the agent writes to, e.g. "
                "`arn:aws:s3:::bucket-name/agent-workspace/*`.",
            ),
            "bedrock-model-unscoped": (
                "has no model-ID resource scoping -- the agent can call any foundation model in "
                "the account, including expensive ones.",
                "Scope Resource to specific model ARNs, e.g. "
                "`arn:aws:bedrock:*::foundation-model/anthropic.claude-3-haiku*`.",
            ),
            "database-unscoped": (
                "has no row/attribute-level scoping and targets `Resource: \"*\"` -- the agent "
                "can scan entire tables.",
                "Use DynamoDB fine-grained access (`dynamodb:LeadingKeys` condition) or "
                "restrict to specific table ARNs.",
            ),
        }[kind]
        message, remediation = detail
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=location,
            message=f"`{action}` {message}",
            remediation=(
                f"{remediation} Suppress an audited exception with "
                "`# security: allow-agent-iam-tool-resource-unscoped`."
            ),
            rule=f"agent-iam-tool-resource-unscoped/{kind}",
            standards=list(_STANDARDS),
        )
