"""Guard: Terraform attaches the AWS-managed AdministratorAccess policy, or one of the
`*FullAccess` family (checklist §6c).

    resource "aws_iam_role" "app" {
      name                = "app-role"
      managed_policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess"]
    }

The AWS-managed `AdministratorAccess` policy grants unrestricted `Action: "*"` /
`Resource: "*"` on every AWS service — attaching it directly to a role, user, or group
is the single-ARN equivalent of the wildcard IAM statement `iam-wildcard` already
catches, but expressed as a managed-policy reference rather than an inline JSON
statement, so the existing guard's `"Statement"`/`"Effect"` gate never sees it.
CWE-269 (Improper Privilege Management), OWASP:A01.

Extended (Pike batch, `AWS006` — github.com/JamesWoolfenden/pike, `src/audit_aws.go`) to also
flag the AWS-managed `*FullAccess` family — `AmazonS3FullAccess`, `AmazonEC2FullAccess`,
`IAMFullAccess`, and every other AWS-managed policy whose name ends in `FullAccess`. These are a
real, distinct escalation surface from `AdministratorAccess`: each one grants unrestricted
`Action: "*"` on ONE service rather than every service (the managed-policy equivalent of the
`iam-service-wildcard` inline-statement guard, this same batch), which is still enough to delete
every S3 bucket, terminate every EC2 instance, or (for `IAMFullAccess`) grant the attached
identity a direct path to full account takeover via `iam:*`. Kept in this same guard/file rather
than split into a new one — extending the existing `AdministratorAccess`-only scope, not a new
detection technique — see `wiki/guards/iam-managed-admin-policy-attached.md`.

Fires HIGH when a `policy_arn`, `managed_policy_arn`, or `managed_policy_arns` attribute
on an IAM role/attachment resource contains the literal ARN
`arn:aws:iam::aws:policy/AdministratorAccess`, or an AWS-managed policy ARN whose name
ends in `FullAccess` (`arn:aws:iam::aws:policy/<Name>FullAccess`).

Suppress an audited case with `# security: allow-iam-admin-policy` on the attribute line.
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
    iter_terraform_resources,
    pragma_present,
    read,
    rel,
)

_ADMIN_ATTACH_RESOURCE_TYPES = frozenset({
    "aws_iam_role",
    "aws_iam_policy_attachment",
    "aws_iam_role_policy_attachment",
    "aws_iam_user_policy_attachment",
    "aws_iam_group_policy_attachment",
    "aws_ssoadmin_managed_policy_attachment",
})
# Anchor the end so this matches ONLY the full-admin `AdministratorAccess` policy, not the
# many narrower AWS-managed policies whose name merely starts with it (`AdministratorAccess-Amplify`,
# `AdministratorAccess-AWSElasticBeanstalk`, ...). In HCL the ARN is always a quoted string, so the
# real policy is always followed by a quote/whitespace/end; a `-<suffix>` never is.
_ADMIN_ARN = re.compile(r"""arn:aws:iam::aws:policy/AdministratorAccess(?=["'\s]|$)""")
# The AWS-managed `*FullAccess` family (Pike `AWS006`) — any AWS-managed policy ARN whose name
# ends in the literal `FullAccess` suffix, same end-anchoring discipline as `_ADMIN_ARN` above so
# a hypothetical narrower `...FullAccess-ReadOnly`-style variant isn't substring-matched. This is
# a DIFFERENT policy family from `AdministratorAccess` (a per-service `Action: "*"`, not an
# every-service one), so the two regexes are mutually exclusive by construction: no ARN can match
# both, and `_scan` below checks `_ADMIN_ARN` first purely to keep the existing rule/message
# unchanged for that exact ARN.
_FULLACCESS_ARN = re.compile(
    r"""arn:aws:iam::aws:policy/(?P<policy>[A-Za-z0-9]+FullAccess)(?=["'\s]|$)"""
)
_ATTR_LINE = re.compile(r"\b(?:policy_arn|managed_policy_arns?)\b")
_PRAGMA = re.compile(r"#\s*security:\s*allow-iam-admin-policy")

_STANDARDS = ["OWASP:A01", "CWE-269"]


class IamManagedAdminPolicyAttachedGuard(Guard):
    id = "iam-managed-admin-policy-attached"
    title = "AWS-managed AdministratorAccess policy attached directly"
    area = "Cloud & IaC"

    # iam_admin.tf: aws_iam_role managed_policy_arns includes AdministratorAccess ->
    # fires iam-managed-admin-policy-attached. Must NOT contain: allow-iam-admin-policy pragma.
    # iam_fullaccess.tf: aws_iam_role_policy_attachment policy_arn is AmazonS3FullAccess ->
    # fires iam-managed-admin-policy-attached/full-access-family.
    canary_plant = CanaryPlant(
        files={
            "iam_admin.tf": (
                'resource "aws_iam_role" "canary" {\n'
                '  name                = "canary-role"\n'
                '  managed_policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess"]\n'
                "}\n"
            ),
            "iam_fullaccess.tf": (
                'resource "aws_iam_role_policy_attachment" "canary" {\n'
                "  role       = aws_iam_role.canary.name\n"
                '  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"\n'
                "}\n"
            ),
        },
        expects=frozenset({
            "iam-managed-admin-policy-attached/administrator-access",
            "iam-managed-admin-policy-attached/full-access-family",
        }),
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
        for resource_type, resource_name, _start, body in iter_terraform_resources(text):
            if resource_type not in _ADMIN_ATTACH_RESOURCE_TYPES:
                continue
            for lineno, line in body:
                if line.lstrip().startswith("#"):
                    continue
                if not _ATTR_LINE.search(line):
                    continue
                if pragma_present(_PRAGMA, line, dialect="hcl"):
                    continue
                admin_match = _ADMIN_ARN.search(line)
                # Checked only when `_ADMIN_ARN` did not match: the two are mutually exclusive
                # by construction (see `_FULLACCESS_ARN`'s comment), so this never double-fires.
                fullaccess_match = None if admin_match else _FULLACCESS_ARN.search(line)
                if admin_match is not None:
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="high",
                            title=self.title,
                            location=f"{rel(root, f)}:{lineno}",
                            message=(
                                f"`{resource_type}.{resource_name}` attaches the AWS-managed "
                                "`AdministratorAccess` policy, which grants unrestricted "
                                "`Action: \"*\"` / `Resource: \"*\"` on every AWS service — "
                                "anything that assumes this role or acts as this user/group has "
                                "near-total account access."
                            ),
                            remediation=(
                                "Replace with a scoped custom policy granting only the specific "
                                "actions and resources needed (least privilege). Suppress an "
                                "audited exception with `# security: allow-iam-admin-policy` on "
                                "the attribute line."
                            ),
                            rule="iam-managed-admin-policy-attached/administrator-access",
                            standards=list(_STANDARDS),
                        )
                    )
                elif fullaccess_match is not None:
                    policy_name = fullaccess_match.group("policy")
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="high",
                            title="AWS-managed *FullAccess policy attached directly",
                            location=f"{rel(root, f)}:{lineno}",
                            message=(
                                f"`{resource_type}.{resource_name}` attaches the AWS-managed "
                                f"`{policy_name}` policy, which grants unrestricted "
                                '`Action: "*"` on that entire service — anything that assumes '
                                "this role or acts as this user/group can create, modify, or "
                                "delete every resource that service has."
                            ),
                            remediation=(
                                "Replace with a scoped custom policy granting only the specific "
                                "actions and resources needed (least privilege). Suppress an "
                                "audited exception with `# security: allow-iam-admin-policy` on "
                                "the attribute line."
                            ),
                            rule="iam-managed-admin-policy-attached/full-access-family",
                            standards=list(_STANDARDS),
                        )
                    )
        return out
