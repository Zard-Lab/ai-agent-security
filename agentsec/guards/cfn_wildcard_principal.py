"""Guard: CloudFormation resource policy grants an action to any AWS principal (checklist §6a).

The CloudFormation counterpart to agentsec's existing (Terraform-only)
`s3-bucket-policy-wildcard-principal` guard — same requirement (a resource policy statement with
`Effect: Allow` and `Principal: "*"` grants the action to every AWS account in existence, and to
anyone on the internet if the resource isn't otherwise locked down), a genuinely different code
surface (CFN's own resource-policy shapes instead of Terraform's `jsonencode()` policy bodies), so
it extends the same `6a-s3-bucket-policy-wildcard-principal` checklist item rather than duplicating
it.

Pattern verified against cfripper's real source (`wildcard_principals.py`, `Skyscanner/cfripper`,
in the research batch) — cited for provenance; detection logic and test fixtures here are
original, developed independently against the pattern description.

Scans five CFN resource-policy surfaces: `AWS::S3::BucketPolicy`, `AWS::KMS::Key` (its embedded
`KeyPolicy`), `AWS::SNS::TopicPolicy`, `AWS::SQS::QueuePolicy`, and `AWS::IAM::Role` (its
`AssumeRolePolicyDocument` trust policy).

Fires HIGH when a scanned resource's block contains BOTH an `Effect: Allow` occurrence (or
`"Effect": "Allow"`) AND a wildcard-principal occurrence — `Principal: "*"` / `"Principal": "*"`,
or the nested `Principal: {AWS: "*"}` / `{"AWS": "*"}` shape — AND the block contains no
`Condition` key anywhere. This is a pragmatic, text-block scope (agentsec does regex/text-block
scanning over each resource's `block`, not a real JSON-path-aware statement walker, per
`agentsec.cfn`'s module docstring): the guard does not pair a specific `Effect`/`Principal` to a
specific `Statement` entry, so a resource with multiple statements is judged as a whole, not
statement-by-statement — see the wiki doc's "Known bypasses" section.

Suppress an audited case (e.g. a deliberately public bucket policy, or a `Condition` shape this
heuristic doesn't recognize) with a comment containing `security: allow-cfn-wildcard-principal`
anywhere in the resource's block (YAML `#` comment; not meaningful in JSON, which has no comment
syntax — a JSON template can't carry this pragma at all, a known, documented limitation shared by
every CFN guard in this batch).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.cfn import cfn_resources
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_files, pragma_present, read, rel

_WILDCARD_PRINCIPAL_RESOURCE_TYPES = frozenset(
    {
        "AWS::S3::BucketPolicy",
        "AWS::KMS::Key",
        "AWS::SNS::TopicPolicy",
        "AWS::SQS::QueuePolicy",
        "AWS::IAM::Role",
    }
)

_EFFECT_ALLOW = re.compile(r'"?Effect"?\s*:\s*"?Allow"?\b', re.IGNORECASE)
# "Principal": "*"  or  Principal: "*"  (JSON or YAML quoting).
_PRINCIPAL_WILDCARD = re.compile(r'"?Principal"?\s*:\s*"\*"')
# "Principal": {"AWS": "*"}  or  Principal: {AWS: "*"}  (nested-map form, either quoting style).
_PRINCIPAL_AWS_WILDCARD = re.compile(
    r'"?Principal"?\s*:\s*\{?\s*"?AWS"?\s*:\s*"\*"', re.DOTALL
)
_CONDITION_PRESENT = re.compile(r'"?Condition"?\s*:', re.IGNORECASE)
_PRAGMA = "security: allow-cfn-wildcard-principal"

_STANDARDS = ["OWASP:A01", "CWE-284"]


class CfnWildcardPrincipalGuard(Guard):
    id = "cfn-wildcard-principal"
    title = "Resource policy grants an action to any AWS principal (CloudFormation)"
    area = "Cloud & IaC"

    # cfn_wildcard_principal.yaml: AWS::S3::BucketPolicy with Effect: Allow, Principal: "*", and
    # no Condition -> fires cfn-wildcard-principal/allow-no-condition.
    canary_plant = CanaryPlant(
        files={
            "cfn_wildcard_principal.yaml": (
                "AWSTemplateFormatVersion: '2010-09-09'\n"
                "Resources:\n"
                "  CanaryBucketPolicy:\n"
                "    Type: AWS::S3::BucketPolicy\n"
                "    Properties:\n"
                "      Bucket: canary-bucket\n"
                "      PolicyDocument:\n"
                "        Statement:\n"
                "          - Effect: Allow\n"
                '            Principal: "*"\n'
                "            Action: s3:GetObject\n"
                "            Resource: arn:aws:s3:::canary-bucket/*\n"
            ),
        },
        expects=frozenset({
            "cfn-wildcard-principal/allow-no-condition",
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
            if resource.resource_type not in _WILDCARD_PRINCIPAL_RESOURCE_TYPES:
                continue
            if pragma_present(_PRAGMA, resource.block, dialect=resource.pragma_dialect):
                continue
            if not _EFFECT_ALLOW.search(resource.block):
                continue
            has_wildcard = _PRINCIPAL_WILDCARD.search(
                resource.block
            ) or _PRINCIPAL_AWS_WILDCARD.search(resource.block)
            if not has_wildcard:
                continue
            if _CONDITION_PRESENT.search(resource.block):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}",
                    message=(
                        f"`{resource.logical_id}` ({resource.resource_type}) grants an action "
                        'to `Principal: "*"` — every AWS account in existence, and to anyone on '
                        "the internet if the resource isn't otherwise locked down. No "
                        "`Condition` was found anywhere in this resource to narrow the grant."
                    ),
                    remediation=(
                        "Scope `Principal` to specific account IDs, IAM roles, or a service "
                        "principal, or add a `Condition` that genuinely narrows the grant (e.g. "
                        "`aws:SourceVpce`, `aws:PrincipalOrgID`, `aws:PrincipalArn`). Suppress "
                        "an audited exception with a `security: allow-cfn-wildcard-principal` "
                        "comment anywhere in the resource (YAML templates only)."
                    ),
                    rule="cfn-wildcard-principal/allow-no-condition",
                    standards=list(_STANDARDS),
                )
            )
        return out
