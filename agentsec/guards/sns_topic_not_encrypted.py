"""Guard: Terraform SNS topic without encryption at rest (checklist §7).

    resource "aws_sns_topic" "alerts" {
      name = "alerts"
      # no kms_master_key_id -> messages stored in plaintext
    }

SNS server-side encryption is opt-in: a topic without `kms_master_key_id` set stores
published message bodies unencrypted at rest. Topics routinely fan out payloads carrying
PII, webhook secrets, or internal event data to multiple subscribers — anyone with access
to the underlying storage reads them directly. CWE-311 (Missing Encryption of Sensitive
Data), OWASP:A02.

Sourced from checkov's `SNSTopicEncryption` check (`CKV_AWS_26`, a
`BaseResourceValueCheck` requiring `kms_master_key_id` to be set to ANY value; confirmed
against the real fetched source).

Fires HIGH when an `aws_sns_topic` resource block does NOT set a non-empty
`kms_master_key_id` anywhere in its body.

Suppress an audited case (e.g. a genuinely non-sensitive scratch topic) with
`# security: allow-sns-unencrypted` anywhere in the resource block.
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

_KMS_MASTER_KEY_ID = re.compile(r"\bkms_master_key_id\s*=\s*\S")
_PRAGMA = re.compile(r"#\s*security:\s*allow-sns-unencrypted")

_STANDARDS = ["OWASP:A02", "CWE-311"]


class SnsTopicNotEncryptedGuard(Guard):
    id = "sns-topic-not-encrypted"
    title = "SNS topic without encryption at rest"
    area = "Cloud & IaC"

    canary_plant = CanaryPlant(
        files={
            "sns_encryption.tf": (
                'resource "aws_sns_topic" "canary" {\n'
                '  name = "canary-alerts"\n'
                "}\n"
            ),
        },
        expects=frozenset({"sns-topic-not-encrypted/missing-encryption"}),
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
            if resource_type != "aws_sns_topic":
                continue
            body_text = "\n".join(line for _, line in body)
            if pragma_present(_PRAGMA, body_text, dialect="hcl"):
                continue
            code_body = "\n".join(
                "" if line.lstrip().startswith(("#", "//")) else line for _, line in body
            )
            if _KMS_MASTER_KEY_ID.search(code_body):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}:{start_line}",
                    message=(
                        f"`aws_sns_topic.{resource_name}` does not set `kms_master_key_id`. "
                        "SNS server-side encryption is opt-in — published message bodies are "
                        "stored in plaintext, readable by anyone with access to the underlying "
                        "storage."
                    ),
                    remediation=(
                        "Set `kms_master_key_id = aws_kms_key.<name>.arn` (or `\"alias/aws/sns\"` "
                        "for AWS-managed encryption at minimum). Suppress an audited exception "
                        "(e.g. a genuinely non-sensitive scratch topic) with "
                        "`# security: allow-sns-unencrypted` anywhere in the resource block."
                    ),
                    rule="sns-topic-not-encrypted/missing-encryption",
                    standards=list(_STANDARDS),
                )
            )
        return out
