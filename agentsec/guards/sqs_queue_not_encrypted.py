"""Guard: Terraform SQS queue without customer-managed KMS encryption (checklist §7).

    resource "aws_sqs_queue" "jobs" {
      name = "jobs"
      # no sqs_managed_sse_enabled and no kms_master_key_id -> encrypted with an AWS-owned key, not a CMK
    }

AWS made SSE-SQS (an AWS-owned key) the default for every newly created queue over the
TLS/SigV4 endpoints Terraform uses, since October 2022 — a queue with neither attribute
set is NOT plaintext; it is encrypted, but with a key the account cannot independently
audit, narrow, or revoke. That puts this guard in the same "AWS-owned-key-by-default,
missing-CMK" bucket as DynamoDB, Secrets Manager, ECR, and CloudWatch Logs, not alongside
guards for resources that ship genuinely unencrypted by default (EBS, SNS). CWE-320 (Key
Management Errors), OWASP:A02.

Sourced from checkov's `SQSQueueEncryption` check (`CKV_AWS_27`, a `BaseResourceCheck`
that fails unless `sqs_managed_sse_enabled` is truthy OR `kms_master_key_id` is set;
confirmed against the real fetched source, including the note that setting
`kms_master_key_id` implicitly sets `sqs_managed_sse_enabled` to false server-side, so
either alone is sufficient). checkov's own severity for this check does not distinguish
the 2022 default-encryption change either — this guard's MEDIUM grading is agentsec's own
call, matching the missing-CMK guards it now sits beside (Dean's review).

Fires MEDIUM when an `aws_sqs_queue` resource block sets neither
`sqs_managed_sse_enabled = true` nor a non-empty `kms_master_key_id` — the queue is still
encrypted at rest by AWS's own default key, but the account has no independent control
over or audit trail for who can decrypt it.

Suppress an audited case (e.g. a genuinely non-sensitive scratch queue) with
`# security: allow-sqs-unencrypted` anywhere in the resource block.
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

_MANAGED_SSE_TRUE = re.compile(r"\bsqs_managed_sse_enabled\s*=\s*true\b")
_KMS_MASTER_KEY_ID = re.compile(r"\bkms_master_key_id\s*=\s*\S")
_PRAGMA = re.compile(r"#\s*security:\s*allow-sqs-unencrypted")

_STANDARDS = ["OWASP:A02", "CWE-320"]


class SqsQueueNotEncryptedGuard(Guard):
    id = "sqs-queue-not-encrypted"
    title = "SQS queue without encryption at rest"
    area = "Cloud & IaC"

    canary_plant = CanaryPlant(
        files={
            "sqs_encryption.tf": (
                'resource "aws_sqs_queue" "canary" {\n'
                '  name = "canary-jobs"\n'
                "}\n"
            ),
        },
        expects=frozenset({"sqs-queue-not-encrypted/missing-encryption"}),
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
            if resource_type != "aws_sqs_queue":
                continue
            body_text = "\n".join(line for _, line in body)
            if pragma_present(_PRAGMA, body_text, dialect="hcl"):
                continue
            code_body = "\n".join(
                "" if line.lstrip().startswith(("#", "//")) else line for _, line in body
            )
            if _MANAGED_SSE_TRUE.search(code_body) or _KMS_MASTER_KEY_ID.search(code_body):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=f"{rel(root, f)}:{start_line}",
                    message=(
                        f"`aws_sqs_queue.{resource_name}` sets neither "
                        "`sqs_managed_sse_enabled = true` nor `kms_master_key_id`. The queue "
                        "is still encrypted at rest by AWS's own default key (SSE-SQS, the "
                        "default since Oct 2022), but the account has no independent control "
                        "over or audit trail for who can decrypt it."
                    ),
                    remediation=(
                        "Add `kms_master_key_id = aws_kms_key.<name>.arn` (SSE-KMS, customer-"
                        "managed) to the resource, referencing a customer-managed CMK. "
                        "Suppress an audited exception (e.g. a genuinely non-sensitive scratch "
                        "queue) with `# security: allow-sqs-unencrypted` anywhere in the "
                        "resource block."
                    ),
                    rule="sqs-queue-not-encrypted/missing-encryption",
                    standards=list(_STANDARDS),
                )
            )
        return out
