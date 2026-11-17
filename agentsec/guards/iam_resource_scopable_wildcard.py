"""Guard: Terraform AWS IAM policy statement grants Resource: "*" for an action that AWS lets you
scope to a specific ARN (checklist §6c).

    resource "aws_iam_role_policy" "app" {
      name = "app-policy"
      role = aws_iam_role.app.id
      policy = jsonencode({
        Statement = [{
          Effect   = "Allow"
          Action   = "s3:GetObject"   # AWS supports "Resource": "<bucket-arn>/*" for this action
          Resource = "*"              # ...but every bucket in the account was granted instead
        }]
      })
    }

`iam-wildcard` only fires on the bare `Resource: "*"` when paired with `Action: "*"`/an all-actions
grant — a statement whose Action is a single, ordinary permission (`s3:GetObject`,
`dynamodb:GetItem`, `kms:Decrypt`) with `Resource: "*"` is invisible to it. That is a real gap: AWS's
own IAM Action reference marks each of these actions as supporting "resource-level permissions" —
the API accepts an ARN in `Resource`, so `Resource: "*"` is a choice, not a limitation of the
action, and it multiplies the blast radius of a stolen credential from "one bucket" to "every bucket
the account owns." CWE-269 (Improper Privilege Management), OWASP:A01. Modeled on Pike's `AWS003`
audit rule (github.com/JamesWoolfenden/pike, `src/audit_aws.go`,
`hasResourceScopableAction`).

`_RESOURCE_SCOPABLE_ACTIONS` is a curated, conservative list of common data-plane actions across
S3/DynamoDB/KMS/Secrets Manager/SSM/Lambda/SQS/SNS/EC2/RDS/CloudWatch Logs that AWS documents as
resource-level-permission-eligible and that appear routinely in application IAM policies — NOT an
attempt to enumerate every such action in the AWS API surface (that list runs into the thousands
and changes as AWS ships new services). Missing an eligible action here is a false negative, not a
false positive risk, so the list favors precision (real, common, unambiguous entries) over recall.

Scans Terraform `.tf` files via the shared `iter_policy_statement_blocks` walker (string/comment/
heredoc-aware, tolerant of both the JSON-literal and idiomatic HCL `jsonencode()` key forms). Fires
HIGH once per statement when an `Effect: Allow` statement's `Resource` value contains a bare `"*"`
AND its `Action` value contains at least one action from the curated list. Suppress an audited
statement with a `# security: allow-iam-resource-scopable-wildcard` line in the file.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    iter_policy_statement_blocks,
    pragma_present,
    read,
    rel,
)

_EFFECT_ALLOW = re.compile(r'"?Effect"?\s*[:=]\s*"Allow"', re.IGNORECASE)
_ACTION_ASSIGN = re.compile(
    r'(?<!Not)"?Action"?\s*[:=]\s*(?P<val>\[[^\]]*\]|"[^"]*")', re.IGNORECASE
)
_RESOURCE_ASSIGN = re.compile(
    r'(?<!Not)"?Resource"?\s*[:=]\s*(?P<val>\[[^\]]*\]|"[^"]*")', re.IGNORECASE
)
_QUOTED = re.compile(r'"([^"]*)"')
_PRAGMA = re.compile(r"#\s*security:\s*allow-iam-resource-scopable-wildcard")

# Curated, resource-level-permission-eligible actions — see module docstring for the selection
# rationale. Lowercase for a case-insensitive membership check.
_RESOURCE_SCOPABLE_ACTIONS = frozenset({
    "s3:getobject", "s3:putobject", "s3:deleteobject", "s3:putobjectacl",
    "dynamodb:getitem", "dynamodb:putitem", "dynamodb:deleteitem", "dynamodb:updateitem",
    "dynamodb:query", "dynamodb:scan",
    "kms:decrypt", "kms:encrypt", "kms:generatedatakey", "kms:reencryptfrom", "kms:reencryptto",
    "secretsmanager:getsecretvalue", "secretsmanager:putsecretvalue",
    "secretsmanager:describesecret",
    "ssm:getparameter", "ssm:getparameters", "ssm:putparameter",
    "lambda:invokefunction", "lambda:updatefunctioncode",
    "sqs:sendmessage", "sqs:receivemessage", "sqs:deletemessage",
    "sns:publish", "sns:subscribe",
    "ec2:terminateinstances", "ec2:stopinstances", "ec2:startinstances",
    "rds:deletedbinstance", "rds:modifydbinstance",
    "logs:putlogevents",
})

_STANDARDS = ["OWASP:A01", "CWE-269"]


def _quoted_values(val: str) -> list[str]:
    return [m.group(1) for m in _QUOTED.finditer(val)]


class IamResourceScopableWildcardGuard(Guard):
    id = "iam-resource-scopable-wildcard"
    title = 'IAM policy grants a resource-scopable action with Resource: "*"'
    area = "Cloud & IaC"

    # iam_resource_scopable_wildcard.tf: Effect Allow, Action "s3:GetObject", Resource "*" ->
    # fires iam-resource-scopable-wildcard.
    canary_plant = CanaryPlant(
        files={
            "iam_resource_scopable_wildcard.tf": (
                'resource "aws_iam_role_policy" "canary" {\n'
                '  name = "canary-policy"\n'
                "  role = aws_iam_role.canary.id\n"
                "  policy = jsonencode({\n"
                '    Version = "2012-10-17"\n'
                "    Statement = [{\n"
                '      Effect   = "Allow"\n'
                '      Action   = "s3:GetObject"\n'
                '      Resource = "*"\n'
                "    }]\n"
                "  })\n"
                "}\n"
            ),
        },
        expects=frozenset({"iam-resource-scopable-wildcard/unscoped-resource"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "terraform" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".tf",)):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        if pragma_present(_PRAGMA, text, dialect="hcl"):
            return out
        for start, _end, block in iter_policy_statement_blocks(text):
            if not _EFFECT_ALLOW.search(block):
                continue
            actions: list[str] = []
            for m in _ACTION_ASSIGN.finditer(block):
                actions.extend(_quoted_values(m.group("val")))
            hits = [a for a in actions if a.lower() in _RESOURCE_SCOPABLE_ACTIONS]
            if not hits:
                continue
            resource_star: int | None = None
            for m in _RESOURCE_ASSIGN.finditer(block):
                val = m.group("val")
                val_start = m.start("val")
                for qm in _QUOTED.finditer(val):
                    if qm.group(1) == "*":
                        resource_star = start + val_start + qm.start()
                        break
                if resource_star is not None:
                    break
            if resource_star is None:
                continue
            line = text.count("\n", 0, resource_star) + 1
            hit = hits[0]
            extra = f" (and {len(hits) - 1} more)" if len(hits) > 1 else ""
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}:{line}",
                    message=(
                        f'This Allow statement grants `{hit}`{extra} with `Resource: "*"` — '
                        "every matching resource in the account, even though AWS supports "
                        "restricting this action to a specific ARN."
                    ),
                    remediation=(
                        "Scope `Resource` to the specific ARN(s) this role/user actually needs "
                        "(e.g. a bucket ARN + `/*` prefix, a table ARN, a key ARN). Suppress an "
                        "audited exception with `# security: allow-iam-resource-scopable-"
                        "wildcard` in the file."
                    ),
                    rule="iam-resource-scopable-wildcard/unscoped-resource",
                    standards=list(_STANDARDS),
                )
            )
        return out
