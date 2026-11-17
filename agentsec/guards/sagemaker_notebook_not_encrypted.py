"""Guard: Terraform SageMaker notebook instance without a customer-managed encryption
key (checklist §7).

    resource "aws_sagemaker_notebook_instance" "experiments" {
      instance_type = "ml.t3.medium"
      role_arn      = aws_iam_role.sagemaker.arn
      # no kms_key_id attribute at all -> storage encrypted with a system-managed key
    }

A SageMaker notebook instance's attached storage volumes are encrypted with a system-managed
key when `kms_key_id` is omitted. AWS: "For notebook instances, if you don't specify a KMS
key, SageMaker AI encrypts both OS volumes and ML data volumes with a system-managed KMS key"
(https://docs.aws.amazon.com/sagemaker/latest/dg/encryption-at-rest-nbi.html). So the volume
is not plaintext, and this is NOT a missing-encryption finding: the account has no
independent control over, or audit trail for, who can decrypt the notebook's own data,
training artifacts, and the credentials often staged on it. It belongs to the same
default-key family as `ecr-repository-not-kms-encrypted`,
`cloudwatch-log-group-not-kms-encrypted` and `secrets-manager-default-kms`, and carries their
mapping and severity: CWE-320 (Key Management Errors), OWASP:A02 (PR #1162 round-1 M9 -- the
earlier CWE-311 "Missing Encryption" mapping overclaimed).

Sourced from checkov's `SageMakerNotebookEncryption` check (`CKV_AWS_32`, a
`BaseResourceValueCheck` inspecting `kms_key_id`; confirmed against the real fetched
source).

Fires MEDIUM when an `aws_sagemaker_notebook_instance` resource block does NOT set a
`kms_key_id`. Unlike the other encryption guards in this family, there is no boolean "off"
value to also check here -- any non-empty `kms_key_id` is sufficient. An empty string
(`kms_key_id = ""`) or `null` is the same as omitting it, so both fire. The attribute is read
from the comment-blanked view, so a `# kms_key_id = ...` comment does not count as set.

Suppress an audited case (e.g. a genuinely non-sensitive scratch notebook) with
`# security: allow-sagemaker-unencrypted` anywhere in the resource block.
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
    terraform_code_view,
)

# Set to something other than an empty string or `null`, both of which leave the provider on
# the system-managed key exactly as omission does.
_KMS_KEY_ID = re.compile(r'\bkms_key_id\s*=\s*(?!""|null\b)\S')
_PRAGMA = re.compile(r"#\s*security:\s*allow-sagemaker-unencrypted")

_STANDARDS = ["OWASP:A02", "CWE-320"]


class SagemakerNotebookNotEncryptedGuard(Guard):
    id = "sagemaker-notebook-not-encrypted"
    title = "SageMaker notebook instance without a customer-managed encryption key"
    area = "Cloud & IaC"

    canary_plant = CanaryPlant(
        files={
            "sagemaker_encryption.tf": (
                'resource "aws_sagemaker_notebook_instance" "canary" {\n'
                '  instance_type = "ml.t3.medium"\n'
                "  role_arn      = \"arn:aws:iam::123456789012:role/canary-sagemaker\"\n"
                "}\n"
            ),
        },
        expects=frozenset({"sagemaker-notebook-not-encrypted/missing-kms-key"}),
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
            if resource_type != "aws_sagemaker_notebook_instance":
                continue
            body_text = "\n".join(line for _, line in body)
            if pragma_present(_PRAGMA, body_text, dialect="hcl"):
                continue
            if _KMS_KEY_ID.search(terraform_code_view(body_text)):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=f"{rel(root, f)}:{start_line}",
                    message=(
                        f"`aws_sagemaker_notebook_instance.{resource_name}` does not set "
                        "`kms_key_id`. The notebook's attached storage is encrypted with a "
                        "system-managed key, so the account has no independent control over or "
                        "audit trail for who can decrypt the notebook's data, training "
                        "artifacts, or staged credentials."
                    ),
                    remediation=(
                        "Add `kms_key_id = aws_kms_key.<name>.arn` referencing a "
                        "customer-managed CMK. Suppress an audited exception (e.g. a "
                        "genuinely non-sensitive scratch notebook) with "
                        "`# security: allow-sagemaker-unencrypted` anywhere in the "
                        "resource block."
                    ),
                    rule="sagemaker-notebook-not-encrypted/missing-kms-key",
                    standards=list(_STANDARDS),
                )
            )
        return out
