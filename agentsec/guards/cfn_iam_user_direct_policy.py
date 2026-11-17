"""Guard: CloudFormation IAM policy attached directly to a user, not via a group (checklist §6c).

A NEW checklist item, not a CFN counterpart to the existing Terraform-only `iam-policy-attached-
to-user-directly` guard: this combines two distinct cfn_nag rules into one guard, a shape the
Terraform sibling doesn't share, so it maps to its own `6c-cfn-iam-user-direct-policy` item rather
than extending the Terraform one.

Pattern verified against cfn_nag's real source (`Stelligent/cfn_nag`) — cited for provenance;
detection logic and test fixtures here are original, developed independently against the pattern
description:

- **`UserHasInlinePolicyRule.rb`** (rule `F10`) — an `AWS::IAM::User` resource with a `Policies`
  property set directly on it: an inline policy attached straight to the user, bypassing a group.
- **`ManagedPolicyOnUserRule.rb`** (rule `F12`) — an `AWS::IAM::ManagedPolicy` (or the older
  `AWS::IAM::Policy`) resource whose `Users` property is set: a managed/customer policy attached
  directly to one or more users instead of via that resource's `Groups` property.

Both represent the same underlying anti-pattern: permissions granted to an individual user
directly instead of through a group, which doesn't scale and is easy to lose track of as people
join, change roles, and leave. CWE-269 (Improper Privilege Management), OWASP:A01.

Fires MEDIUM as two distinct rules:

- `cfn-iam-user-direct-policy/inline-policy-on-user` — an `AWS::IAM::User` resource whose block
  contains a `Policies:`/`"Policies":` key.
- `cfn-iam-user-direct-policy/managed-policy-on-user` — an `AWS::IAM::ManagedPolicy` or
  `AWS::IAM::Policy` resource whose block contains a `Users:`/`"Users":` key.

Suppress an audited case (e.g. a break-glass user by design) with a comment containing
`security: allow-iam-user-direct-policy` anywhere in the resource's block (YAML `#` comment; not
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

_POLICIES_KEY = re.compile(r'"?Policies"?\s*:', re.IGNORECASE)
_USERS_KEY = re.compile(r'"?Users"?\s*:', re.IGNORECASE)
_PRAGMA = "security: allow-iam-user-direct-policy"

_MANAGED_POLICY_TYPES = frozenset({"AWS::IAM::ManagedPolicy", "AWS::IAM::Policy"})

_STANDARDS = ["OWASP:A01", "CWE-269"]


class CfnIamUserDirectPolicyGuard(Guard):
    id = "cfn-iam-user-direct-policy"
    title = "IAM policy attached directly to a user instead of via a group (CloudFormation)"
    area = "Cloud & IaC"

    # cfn_iam_user_direct_policy.yaml: AWS::IAM::User with an inline Policies property -> fires
    # cfn-iam-user-direct-policy/inline-policy-on-user.
    canary_plant = CanaryPlant(
        files={
            "cfn_iam_user_direct_policy.yaml": (
                "AWSTemplateFormatVersion: '2010-09-09'\n"
                "Resources:\n"
                "  CanaryUser:\n"
                "    Type: AWS::IAM::User\n"
                "    Properties:\n"
                "      UserName: canary-user\n"
                "      Policies:\n"
                "        - PolicyName: canary-inline-policy\n"
                "          PolicyDocument: {}\n"
            ),
        },
        expects=frozenset({
            "cfn-iam-user-direct-policy/inline-policy-on-user",
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
            if pragma_present(_PRAGMA, resource.block, dialect=resource.pragma_dialect):
                continue
            if resource.resource_type == "AWS::IAM::User":
                if _POLICIES_KEY.search(resource.block):
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="medium",
                            title=self.title,
                            location=f"{rel(root, f)}",
                            message=(
                                f"`{resource.logical_id}` (AWS::IAM::User) has an inline "
                                "`Policies` property attached directly to it. Permissions granted "
                                "this way drift silently as people join, change roles, and leave, "
                                "with no single group to audit."
                            ),
                            remediation=(
                                "Move the policy to an `AWS::IAM::Group` (or a role the user "
                                "assumes) and add the user via the group's `Users` property "
                                "instead. Suppress an audited exception with a `security: "
                                "allow-iam-user-direct-policy` comment anywhere in the resource "
                                "(YAML templates only)."
                            ),
                            rule="cfn-iam-user-direct-policy/inline-policy-on-user",
                            standards=list(_STANDARDS),
                        )
                    )
            elif resource.resource_type in _MANAGED_POLICY_TYPES and _USERS_KEY.search(resource.block):
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="medium",
                        title=self.title,
                        location=f"{rel(root, f)}",
                        message=(
                            f"`{resource.logical_id}` ({resource.resource_type}) sets a "
                            "`Users` property, attaching this managed policy directly to one "
                            "or more users instead of via a `Groups` property. Permissions "
                            "granted this way drift silently as people join, change roles, "
                            "and leave, with no single group to audit."
                        ),
                        remediation=(
                            "Attach this policy via the resource's `Groups` property instead "
                            "of `Users`. Suppress an audited exception with a `security: "
                            "allow-iam-user-direct-policy` comment anywhere in the resource "
                            "(YAML templates only)."
                        ),
                        rule="cfn-iam-user-direct-policy/managed-policy-on-user",
                        standards=list(_STANDARDS),
                    )
                )
        return out
