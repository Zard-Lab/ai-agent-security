"""Guard: CloudFormation IAM policy statement combines `Effect: Allow` with `NotAction`
(checklist §6c).

The CloudFormation counterpart to agentsec's existing (Terraform-only) `iam-notaction-with-allow`
guard (same requirement: `Allow` + `NotAction` grants every IAM action EXCEPT the ones listed — an
"allowlist-everything-except" pattern that reads, at a glance, like a short restrictive deny list
but is actually the opposite. AWS adds new actions and services continuously, and every one of them
is silently INCLUDED in the grant the moment it exists, with no change to the template ever needed
for the blast radius to grow. CWE-269 (Improper Privilege Management), OWASP:A01), a genuinely
different code surface (CFN's `AWS::IAM::Policy` / `AWS::IAM::ManagedPolicy` / `AWS::IAM::Role`
resources instead of Terraform's `aws_iam_role_policy` / `jsonencode()` blocks), so it extends the
same `6c-iam-notaction-with-allow` checklist item rather than duplicating it.

Pattern verified against cfripper's real source (`IamRoleNotActionOnPermissionsPolicyRule.rb`,
`IamRoleNotActionOnTrustPolicyRule.rb`, `IamPolicyNotActionRule.rb`, `IamManagedPolicyNotActionRule.rb`
— the cfn_nag rule family) — cited for provenance; detection logic and test fixtures here
are original, developed independently against the pattern description.

Fires HIGH when an `AWS::IAM::Policy`, `AWS::IAM::ManagedPolicy`, or `AWS::IAM::Role` resource has
a SINGLE policy statement combining `Effect: Allow` (or `"Effect": "Allow"`) with a `NotAction` key
(`NotAction:` in YAML, `"NotAction"` in JSON) — scoped per-statement via
`agentsec.cfn.iter_statement_blocks` (Dean's review repro), not to the whole resource
block. `Effect: Deny` combined with `NotAction` is a legitimate, common guardrail pattern ("deny
everything except these") and is deliberately NOT flagged — and, since the Deny-FP fix, a `Deny`+
`NotAction` guardrail statement sitting ALONGSIDE an unrelated `Allow` statement elsewhere in the
same resource (a different `Policies` entry, or a different statement in the same
`PolicyDocument.Statement` list) no longer false-fires either: before the per-statement scope, the
whole-block search matched `Effect: Allow` in one statement and `NotAction` in a completely
different one and treated the co-occurrence as if it were one dangerous statement.

**Known limitation (disclosed not fixed): flow-style `Statement` lists are not scoped.**
The per-statement scoping above relies on `agentsec.cfn.iter_statement_blocks`, which recognizes a
YAML block-style list and a JSON array or single-object form, but not a flow-style single-line
`Statement` (`Statement: [{...}]` or `Statement: {...}` entirely on one line) — that returns no
statements at all, so a genuine same-statement `Allow`+`NotAction` on a flow-style template
produces no finding (a false negative), the opposite failure from the original whole-block false
positive this scoping exists to close. Flow-style single-line policies are uncommon in practice but
not exotic; closing this gap needs brace-counting to split a single line into items (see
`iter_statement_blocks`'s own docstring in `agentsec.cfn`), not a change local to this guard.

Suppress an audited case with a comment containing `security: allow-cfn-iam-notaction-with-allow`
anywhere in the resource's block (YAML `#` comment; not meaningful in JSON, which has no comment
syntax — a JSON template can't carry this pragma at all, a known, documented limitation shared by
every CFN guard in this batch).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.cfn import cfn_resources, iter_statement_blocks
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_files, pragma_present, read, rel

_RESOURCE_TYPES = frozenset({
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy",
    "AWS::IAM::Role",
})

_EFFECT_ALLOW = re.compile(r'"?Effect"?\s*:\s*["\']?Allow\b', re.IGNORECASE)
_NOT_ACTION = re.compile(r'"?NotAction"?\s*:', re.IGNORECASE)
_PRAGMA = "security: allow-cfn-iam-notaction-with-allow"

_STANDARDS = ["OWASP:A01", "CWE-269"]


class CfnIamNotactionWithAllowGuard(Guard):
    id = "cfn-iam-notaction-with-allow"
    title = 'IAM policy statement combines Effect: "Allow" with NotAction (CloudFormation)'
    area = "Cloud & IaC"

    # cfn_iam_notaction_with_allow.yaml: AWS::IAM::Role with an inline policy statement combining
    # Effect: Allow + NotAction -> fires cfn-iam-notaction-with-allow/allow-notaction.
    canary_plant = CanaryPlant(
        files={
            "cfn_iam_notaction_with_allow.yaml": (
                "AWSTemplateFormatVersion: '2010-09-09'\n"
                "Resources:\n"
                "  CanaryRole:\n"
                "    Type: AWS::IAM::Role\n"
                "    Properties:\n"
                "      AssumeRolePolicyDocument:\n"
                "        Version: '2012-10-17'\n"
                "        Statement:\n"
                "          - Effect: Allow\n"
                "            Principal:\n"
                "              Service: ec2.amazonaws.com\n"
                "            Action: sts:AssumeRole\n"
                "      Policies:\n"
                "        - PolicyName: canary-policy\n"
                "          PolicyDocument:\n"
                "            Version: '2012-10-17'\n"
                "            Statement:\n"
                "              - Effect: Allow\n"
                "                NotAction:\n"
                "                  - iam:*\n"
                "                  - organizations:*\n"
                "                Resource: '*'\n"
            ),
        },
        expects=frozenset({
            "cfn-iam-notaction-with-allow/allow-notaction",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "cloudformation" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".yaml", ".yml", ".json")):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        for resource in cfn_resources(text):
            if resource.resource_type not in _RESOURCE_TYPES:
                continue
            if pragma_present(_PRAGMA, resource.block, dialect=resource.pragma_dialect):
                continue
            statements = iter_statement_blocks(resource.block)
            if not any(
                _EFFECT_ALLOW.search(stmt) and _NOT_ACTION.search(stmt) for stmt in statements
            ):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}",
                    message=(
                        f"`{resource.logical_id}` ({resource.resource_type}) has a policy "
                        'statement that combines `Effect: "Allow"` with `NotAction` -- it grants '
                        "every AWS action EXCEPT the ones listed, including every action AWS adds "
                        "to any service in the future. The grant silently widens over time with no "
                        "change to this template."
                    ),
                    remediation=(
                        "Replace `NotAction` with an explicit `Action` allow-list naming only the "
                        "actions actually needed (least privilege). Suppress an audited exception "
                        "with a `security: allow-cfn-iam-notaction-with-allow` comment anywhere in "
                        "the resource (YAML templates only)."
                    ),
                    rule="cfn-iam-notaction-with-allow/allow-notaction",
                    standards=list(_STANDARDS),
                )
            )
        return out
