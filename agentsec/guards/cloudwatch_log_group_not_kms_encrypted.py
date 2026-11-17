"""Guard: Terraform CloudWatch Log Group without a customer-managed KMS key (checklist §7).

    resource "aws_cloudwatch_log_group" "app" {
      name = "/app/prod"
      # no kms_key_id -> encrypted with CloudWatch Logs' own managed key
    }

CloudWatch Log Groups are encrypted at rest by default using an AWS-managed key the
account cannot narrow or independently audit. Application logs routinely capture request
bodies, stack traces, or (accidentally) secrets — a log group without a customer-managed
CMK has no independent key-policy control over who can decrypt that history. CWE-320 (Key
Management Errors), OWASP:A02.

Sourced from checkov's `CloudWatchLogGroupKMSKey` check (`CKV_AWS_158`, a
`BaseResourceValueCheck` requiring `kms_key_id` to be set to ANY value; confirmed against
the real fetched source).

Fires MEDIUM when an `aws_cloudwatch_log_group` resource block does NOT set a non-empty
`kms_key_id` anywhere in its body.

Suppress an audited case with `# security: allow-cloudwatch-logs-non-kms` anywhere in the
resource block.
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

_KMS_KEY_ID = re.compile(r"\bkms_key_id\s*=\s*\S")
_PRAGMA = re.compile(r"#\s*security:\s*allow-cloudwatch-logs-non-kms")

_STANDARDS = ["OWASP:A02", "CWE-320"]


class CloudwatchLogGroupNotKmsEncryptedGuard(Guard):
    id = "cloudwatch-log-group-not-kms-encrypted"
    title = "CloudWatch Log Group without a customer-managed KMS key"
    area = "Cloud & IaC"

    canary_plant = CanaryPlant(
        files={
            "cloudwatch_logs_kms.tf": (
                'resource "aws_cloudwatch_log_group" "canary" {\n'
                '  name = "/canary/app"\n'
                "}\n"
            ),
        },
        expects=frozenset({"cloudwatch-log-group-not-kms-encrypted/missing-kms-encryption"}),
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
        for resource_type, resource_name, start_line, body in iter_terraform_resources(text):
            if resource_type != "aws_cloudwatch_log_group":
                continue
            body_text = "\n".join(line for _, line in body)
            if pragma_present(_PRAGMA, body_text, dialect="hcl"):
                continue
            code_body = "\n".join(
                "" if line.lstrip().startswith(("#", "//")) else line for _, line in body
            )
            if _KMS_KEY_ID.search(code_body):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=f"{rel(root, f)}:{start_line}",
                    message=(
                        f"`aws_cloudwatch_log_group.{resource_name}` does not set `kms_key_id`. "
                        "The log group is still encrypted at rest (AWS-managed key), but there "
                        "is no independently auditable customer-managed key for the log data "
                        "it retains."
                    ),
                    remediation=(
                        "Set `kms_key_id = aws_kms_key.<name>.arn` referencing a customer-"
                        "managed CMK. Suppress an audited exception with "
                        "`# security: allow-cloudwatch-logs-non-kms` anywhere in the resource "
                        "block."
                    ),
                    rule="cloudwatch-log-group-not-kms-encrypted/missing-kms-encryption",
                    standards=list(_STANDARDS),
                )
            )
        return out
