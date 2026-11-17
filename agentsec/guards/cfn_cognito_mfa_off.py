"""Guard: CloudFormation Cognito User Pool with MFA disabled (checklist §6c).

Amazon Cognito User Pools authenticate end users of an application. `MfaConfiguration` controls
whether those users are required (`ON`) or permitted (`OPTIONAL`) to enrol a second factor, or are
never asked for one at all (`OFF`). A user pool stuck at `OFF` means every account in it is
protected by a password alone — the single most common initial-access vector (credential stuffing,
phishing, password reuse) has no second gate. AWS's own default for `MfaConfiguration` when the
property is omitted entirely is `OFF` (confirmed by the `AWS::Cognito::UserPool` resource
documentation), so an author who never sets the property gets the vulnerable state silently, not a
safe default — the same "missing means insecure" shape as `EnableKeyRotation` on `AWS::KMS::Key`.

Pattern verified against cfn_nag's real source (`CognitoUserPoolMfaConfigurationOnorOptionalRule.rb`,
rule `F78`, `stelligent/cfn_nag`) — cited for provenance; detection logic and test fixtures here are
original, developed independently against the pattern description. cfn_nag's own rule name
("MfaConfigurationOnorOptional") implies the rule passes only when the value is explicitly `ON` or
`OPTIONAL` — this guard mirrors that: missing and explicit `OFF` are both treated as failures.

Fires HIGH when an `AWS::Cognito::UserPool` resource's block either sets `MfaConfiguration: OFF` /
`"MfaConfiguration": "OFF"` explicitly, OR has no `MfaConfiguration` property at all.

Suppress an audited case (e.g. a throwaway/internal pool by design) with a comment containing
`security: allow-cfn-cognito-mfa-off` anywhere in the resource's block (YAML `#` comment; not
meaningful in JSON, which has no comment syntax — a JSON template can't carry this pragma at all,
a known, documented limitation shared by every CFN guard in this batch).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.cfn import cfn_resources
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_files, pragma_present, read, rel

_MFA_CONFIGURATION = re.compile(r'"?MfaConfiguration"?\s*[:=]\s*["\']?([A-Za-z_]+)["\']?')
_PRAGMA = "security: allow-cfn-cognito-mfa-off"

_STANDARDS = ["OWASP:A07", "CWE-308"]


class CfnCognitoMfaOffGuard(Guard):
    id = "cfn-cognito-mfa-off"
    title = "Cognito User Pool with MFA disabled (CloudFormation)"
    area = "Cloud & IaC"

    # cfn_cognito_pool.yaml: AWS::Cognito::UserPool with MfaConfiguration: OFF -> fires
    # cfn-cognito-mfa-off/mfa-disabled.
    canary_plant = CanaryPlant(
        files={
            "cfn_cognito_pool.yaml": (
                "AWSTemplateFormatVersion: '2010-09-09'\n"
                "Resources:\n"
                "  CanaryUserPool:\n"
                "    Type: AWS::Cognito::UserPool\n"
                "    Properties:\n"
                "      UserPoolName: canary-pool\n"
                "      MfaConfiguration: OFF\n"
            ),
        },
        expects=frozenset({
            "cfn-cognito-mfa-off/mfa-disabled",
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
            if resource.resource_type != "AWS::Cognito::UserPool":
                continue
            if pragma_present(_PRAGMA, resource.block, dialect=resource.pragma_dialect):
                continue
            mfa_match = _MFA_CONFIGURATION.search(resource.block)
            if mfa_match and mfa_match.group(1).strip().upper() != "OFF":
                # Explicit ON or OPTIONAL — MFA is enabled or offered. Not a finding.
                continue
            # Either MfaConfiguration is missing entirely (AWS default: OFF) or it is
            # explicitly OFF — both are the vulnerable state.
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}",
                    message=(
                        f"`{resource.logical_id}` (AWS::Cognito::UserPool) does not enable MFA. "
                        "`MfaConfiguration` is either missing (AWS defaults to `OFF`) or explicitly "
                        "`OFF` — every account in this user pool is protected by a password alone."
                    ),
                    remediation=(
                        "Set `MfaConfiguration: ON` (require MFA) or `MfaConfiguration: OPTIONAL` "
                        "(let users enrol) and configure at least one factor via `MfaTypes` / "
                        "`SoftwareTokenMfaConfiguration` / `SmsConfiguration`. Suppress an audited "
                        "exception with a `security: allow-cfn-cognito-mfa-off` comment anywhere in "
                        "the resource (YAML templates only)."
                    ),
                    rule="cfn-cognito-mfa-off/mfa-disabled",
                    standards=list(_STANDARDS),
                )
            )
        return out
