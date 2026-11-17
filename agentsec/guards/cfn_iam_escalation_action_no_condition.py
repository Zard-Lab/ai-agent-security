"""Guard: CloudFormation IAM policy statement grants a privilege-escalation-class action under
`Effect: Allow` with no scoping Condition (checklist §6c).

The CloudFormation counterpart to agentsec's existing (Terraform-only)
`iam-escalation-action-no-condition` guard — same requirement, a genuinely different code surface
(CFN's `AWS::IAM::Policy` / `AWS::IAM::ManagedPolicy` / `AWS::IAM::Role` inline `Policies`, instead
of Terraform's `aws_iam_role_policy`/`jsonencode()`), so it extends the same `6c-iam-escalation-
action-no-condition` checklist item rather than duplicating it. cfripper's own source flags the same
technique (`privilege_escalation.py`, `Skyscanner/cfripper`, cited in this repo's own research batch
as a candidate) — cited for provenance; detection logic here is original, developed independently
against the pattern description and the Terraform sibling guard's curated action list.

Uses the SAME curated 15-action privilege-escalation list as the Terraform sibling (Spencer
Gietzen's 2018 "AWS IAM Privilege Escalation" research) so the two guards agree on what counts as
dangerous: `iam:PutRolePolicy`, `iam:AttachRolePolicy`, `iam:CreatePolicyVersion`,
`iam:SetDefaultPolicyVersion`, `iam:UpdateAssumeRolePolicy`, `iam:PassRole`, `iam:CreateAccessKey`,
`sts:AssumeRole`, `iam:AttachUserPolicy`, `iam:AttachGroupPolicy`, `iam:PutUserPolicy`,
`iam:PutGroupPolicy`, `iam:AddUserToGroup`, `iam:CreateLoginProfile`, `iam:UpdateLoginProfile`.

Unlike the Terraform sibling (which walks individual policy *statement* blocks via
`iter_policy_statement_blocks`), this guard uses a pragmatic **whole-resource-block** scope, the
same granularity every `cfn-*` guard in this batch uses (see `agentsec.cfn`'s module docstring):
fires when a resource's block contains `Effect: Allow` / `"Effect": "Allow"` ANYWHERE in the block,
one of the curated dangerous actions as an `Action` value (singular or inside an `Action` list, and
not a `NotAction` value) ANYWHERE in the block, and NO `Condition` key anywhere in the whole block —
not scoped to the individual statement that grants the action. This is coarser than the Terraform
guard's per-statement scope (a documented, known limitation — see the wiki design doc), traded for
not having to build a real CFN policy-statement parser.

**The `AssumeRolePolicyDocument` (trust policy) is carved out and excluded from this scan**
(Dean's review repro): an `AWS::IAM::Role`'s trust policy states who may assume the
role (`Effect: Allow` + `Action: sts:AssumeRole` under `AssumeRolePolicyDocument` is the single
commonest role shape in all of AWS — every role needs one), which is the opposite direction of
trust from a *permissions* policy granting an identity the power to escalate ITS OWN access. Before
this exclusion, every ordinary role's trust statement false-fired on `sts:AssumeRole` (itself in
the curated escalation list, since a permissions-policy grant of `sts:AssumeRole` onto some OTHER
role genuinely is escalation-shaped) purely because the trust document also uses `Effect: Allow`
and carries no `Condition` of its own. Only the resource's `Policies`/`PolicyDocument` (permissions)
side is now scanned for the curated actions.

**Known limitation (disclosed not fixed): flow-style trust policies are not excluded.**
The exclusion above relies on `agentsec.cfn.nested_property_block`, which only recognizes an
indented block-style `AssumeRolePolicyDocument:` value. A flow-style single-line value
(`AssumeRolePolicyDocument: {...}`) is not carved out, so the same false positive this exclusion
exists to close still fires on a flow-style trust policy exactly as it did before this fix. Flow-
style IAM policy documents in CloudFormation templates are uncommon in practice but not exotic;
closing this gap needs the same brace-counting `nested_property_block` itself would need (see its
docstring in `agentsec.cfn`), not a change local to this guard.

Suppress an audited resource with a comment containing `security: allow-iam-escalation-no-condition`
anywhere in the resource's block (YAML `#` comment; not meaningful in JSON, which has no comment
syntax — a JSON template can't carry this pragma at all, the same known limitation every CFN guard
in this batch discloses).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.cfn import cfn_resources, nested_property_block
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_files, pragma_present, read, rel

_IAM_RESOURCE_TYPES = frozenset({
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy",
    "AWS::IAM::Role",
})

_EFFECT_ALLOW = re.compile(r'"?Effect"?\s*[:=]\s*["\']?Allow["\']?\b', re.IGNORECASE)
_CONDITION_PRESENT = re.compile(r'"?Condition"?\s*[:=]', re.IGNORECASE)
_ACTION_KEYWORD = re.compile(r'"?(Not)?Action"?\s*[:=]', re.IGNORECASE)
_ACTION_TOKEN = re.compile(r'["\']?([A-Za-z0-9_]+:[A-Za-z0-9_*]+)["\']?')
_PRAGMA = "security: allow-iam-escalation-no-condition"

# The exact same 15-action escalation list the Terraform sibling guard uses, so the two guards
# agree on what counts as dangerous. Compared case-insensitively (AWS action names are
# conventionally PascalCase, but a policy author's casing is not load-bearing to AWS's own API).
_ESCALATION_ACTIONS = frozenset({
    a.lower() for a in (
        "iam:PutRolePolicy",
        "iam:AttachRolePolicy",
        "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion",
        "iam:UpdateAssumeRolePolicy",
        "iam:PassRole",
        "iam:CreateAccessKey",
        "sts:AssumeRole",
        "iam:AttachUserPolicy",
        "iam:AttachGroupPolicy",
        "iam:PutUserPolicy",
        "iam:PutGroupPolicy",
        "iam:AddUserToGroup",
        "iam:CreateLoginProfile",
        "iam:UpdateLoginProfile",
    )
})

_STANDARDS = ["OWASP:A01", "CWE-269"]


def _action_context(block: str, pos: int) -> str | None:
    """The nearest `Action`/`NotAction` keyword before `pos` in `block`: "action", "not_action",
    or None if no such keyword precedes this position at all (so the matched token isn't inside
    any Action list context)."""
    last: re.Match[str] | None = None
    for m in _ACTION_KEYWORD.finditer(block, 0, pos):
        last = m
    if last is None:
        return None
    return "not_action" if last.group(1) else "action"


class CfnIamEscalationActionNoConditionGuard(Guard):
    id = "cfn-iam-escalation-action-no-condition"
    title = "Privilege-escalation IAM action granted with no scoping Condition (CloudFormation)"
    area = "Cloud & IaC"

    # cfn_iam_escalation.yaml: AWS::IAM::Role inline policy, Effect Allow, Action iam:PassRole,
    # no Condition -> fires cfn-iam-escalation-action-no-condition/allow-no-condition.
    canary_plant = CanaryPlant(
        files={
            "cfn_iam_escalation.yaml": (
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
                "        - PolicyName: canary-escalation\n"
                "          PolicyDocument:\n"
                "            Version: '2012-10-17'\n"
                "            Statement:\n"
                "              - Effect: Allow\n"
                "                Action: iam:PassRole\n"
                "                Resource: '*'\n"
            ),
        },
        expects=frozenset({
            "cfn-iam-escalation-action-no-condition/allow-no-condition",
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
            if resource.resource_type not in _IAM_RESOURCE_TYPES:
                continue
            block = resource.block
            if pragma_present(_PRAGMA, block, dialect=resource.pragma_dialect):
                continue
            # Carve out the trust policy: it states who may assume this role, not what this
            # role/identity is permitted to do, so it must never be read as a permissions grant.
            trust_block = nested_property_block(block, "AssumeRolePolicyDocument")
            if trust_block:
                block = block.replace(trust_block, "", 1)
            if not _EFFECT_ALLOW.search(block):
                continue
            if _CONDITION_PRESENT.search(block):
                continue  # a Condition anywhere in the resource is treated as a plausible narrowing
            seen: set[str] = set()
            for m in _ACTION_TOKEN.finditer(block):
                action = m.group(1)
                key = action.lower()
                if key not in _ESCALATION_ACTIONS:
                    continue
                if _action_context(block, m.start()) != "action":
                    continue
                if key in seen:
                    continue
                seen.add(key)
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title=self.title,
                        location=f"{rel(root, f)}",
                        message=(
                            f"`{resource.logical_id}` ({resource.resource_type}) grants "
                            f"`{action}` — a privilege-escalation-class action — under "
                            "`Effect: Allow` with no `Condition` anywhere in the resource to "
                            "scope it. An identity holding this permission can use it to expand "
                            "its own (or another principal's) access."
                        ),
                        remediation=(
                            "Add a scoping Condition (e.g. `iam:PassedToService`, "
                            "`aws:ResourceTag/...`, `aws:PrincipalOrgID`) that genuinely narrows "
                            "this grant to its intended use, or remove the action if it isn't "
                            "needed. Suppress an audited exception with a "
                            "`security: allow-iam-escalation-no-condition` comment anywhere in "
                            "the resource (YAML templates only)."
                        ),
                        rule="cfn-iam-escalation-action-no-condition/allow-no-condition",
                        standards=list(_STANDARDS),
                    )
                )
        return out
