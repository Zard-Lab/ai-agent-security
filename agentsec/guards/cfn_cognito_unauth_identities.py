"""Guard: CloudFormation Cognito Identity Pool allows unauthenticated identities (checklist §6c).

An `AWS::Cognito::IdentityPool` resource with `AllowUnauthenticatedIdentities: true` lets ANYONE —
no login, no credentials, no identity check of any kind — call `GetId`/`GetCredentialsForIdentity`
against the pool and receive temporary AWS credentials scoped to the pool's unauthenticated IAM
role. AWS's own default for this property is `false`; a template that sets it to `true` (or, in
some hand-authored templates, a bare intrinsic reference the author believes is conditional but
which this guard cannot resolve) is opting an anonymous caller into real AWS access. The blast
radius is exactly whatever the unauthenticated role's IAM policy grants — in practice this has
ranged from harmless (an empty role) to a real attack surface (S3 read/write, DynamoDB access,
Lambda invoke) when a team wires up broader permissions without realizing the identity pool has
no login requirement at all.

Pattern verified against cfn_nag's real source
(`CognitoIdentityPoolAllowUnauthenticatedIdentitiesRule.rb`, rule `W57` in the research
batch) — cited for provenance; detection logic and test fixtures here are original, developed
independently against the pattern description.

Fires HIGH when an `AWS::Cognito::IdentityPool` resource contains
`AllowUnauthenticatedIdentities: true` / `"AllowUnauthenticatedIdentities": true` anywhere in its
block. AWS's implicit default when the property is omitted entirely is `false` (unauthenticated
access is opt-in, not opt-out), so a missing property is NOT flagged — this is the documented,
deliberate FP-avoidance choice for this guard, mirroring the CFN KMS-rotation sibling's own
default-aware design.

Suppress an audited case (e.g. a public read-only demo/preview identity pool by design) with a
comment containing `security: allow-cognito-unauth-identities` anywhere in the resource's block
(YAML `#` comment; not meaningful in JSON, which has no comment syntax — a JSON template can't
carry this pragma at all, a known, documented limitation shared by every CFN guard in this batch).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.cfn import cfn_resources
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_files, pragma_present, read, rel

_ALLOW_UNAUTH_TRUE = re.compile(r'"?AllowUnauthenticatedIdentities"?\s*:\s*true\b', re.IGNORECASE)
_PRAGMA = "security: allow-cognito-unauth-identities"

_STANDARDS = ["OWASP:A01", "CWE-284"]


class CfnCognitoUnauthIdentitiesGuard(Guard):
    id = "cfn-cognito-unauth-identities"
    title = "Cognito Identity Pool allows unauthenticated identities (CloudFormation)"
    area = "Cloud & IaC"

    # cfn_cognito_identity_pool.yaml: AWS::Cognito::IdentityPool with
    # AllowUnauthenticatedIdentities: true -> fires cfn-cognito-unauth-identities/allow-unauthenticated.
    canary_plant = CanaryPlant(
        files={
            "cfn_cognito_identity_pool.yaml": (
                "AWSTemplateFormatVersion: '2010-09-09'\n"
                "Resources:\n"
                "  CanaryIdentityPool:\n"
                "    Type: AWS::Cognito::IdentityPool\n"
                "    Properties:\n"
                "      IdentityPoolName: canary-pool\n"
                "      AllowUnauthenticatedIdentities: true\n"
            ),
        },
        expects=frozenset({
            "cfn-cognito-unauth-identities/allow-unauthenticated",
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
            if resource.resource_type != "AWS::Cognito::IdentityPool":
                continue
            if pragma_present(_PRAGMA, resource.block, dialect=resource.pragma_dialect):
                continue
            if not _ALLOW_UNAUTH_TRUE.search(resource.block):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}",
                    message=(
                        f"`{resource.logical_id}` (AWS::Cognito::IdentityPool) sets "
                        "`AllowUnauthenticatedIdentities: true`. Any caller, with no login or "
                        "credentials, can obtain temporary AWS credentials scoped to this pool's "
                        "unauthenticated IAM role."
                    ),
                    remediation=(
                        "Set `AllowUnauthenticatedIdentities: false` (or omit the property, since "
                        "AWS's default is already `false`) unless anonymous access is genuinely "
                        "required. If it is required, ensure the pool's unauthenticated IAM role "
                        "grants no more than the minimum needed. Suppress an audited exception "
                        "with a `security: allow-cognito-unauth-identities` comment anywhere in "
                        "the resource (YAML templates only)."
                    ),
                    rule="cfn-cognito-unauth-identities/allow-unauthenticated",
                    standards=list(_STANDARDS),
                )
            )
        return out
