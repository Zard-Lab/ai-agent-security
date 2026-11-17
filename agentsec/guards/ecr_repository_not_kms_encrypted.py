"""Guard: Terraform ECR repository without KMS encryption (checklist §7).

    resource "aws_ecr_repository" "app" {
      name = "app"
      # no encryption_configuration block -> AES256 (AWS-owned key), not KMS
    }

ECR repositories are encrypted at rest by default using AES256 with an AWS-owned key —
the account has no visibility into or control over it. Container images can embed
secrets, private source, or proprietary model weights; a repository without an explicit
`encryption_configuration { encryption_type = "KMS" }` block has no independently
auditable key for that data. CWE-320 (Key Management Errors), OWASP:A02.

Sourced from checkov's `ECRRepositoryEncrypted` check (`CKV_AWS_136`, a
`BaseResourceValueCheck` requiring `encryption_configuration/[0]/encryption_type ==
"KMS"`; confirmed against the real fetched source).

Fires MEDIUM when an `aws_ecr_repository` resource block does NOT contain an
`encryption_configuration { ... }` block with `encryption_type = "KMS"`.

Suppress an audited case with `# security: allow-ecr-non-kms-encryption` anywhere in the
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

_ENC_CONFIG_BLOCK = re.compile(r"\bencryption_configuration\s*\{([^{}]*)\}", re.S)
# The `dynamic "encryption_configuration" { ... content { ... } }` form wraps the real
# attributes inside a nested `content` block, one level deeper than the plain form above
# -- the plain regex's immediate `{` after the keyword never matches a `dynamic` label
# sitting in between. Matches lazily up to the first `content {` inside the dynamic block
# and captures THAT block's body (Dean's review, High 2).
_DYNAMIC_ENC_CONFIG_BLOCK = re.compile(
    r'\bdynamic\s*"encryption_configuration"\s*\{.*?\bcontent\s*\{([^{}]*)\}', re.S
)
_ENCRYPTION_TYPE_KMS = re.compile(r'\bencryption_type\s*=\s*"KMS"')
_PRAGMA = re.compile(r"#\s*security:\s*allow-ecr-non-kms-encryption")

_STANDARDS = ["OWASP:A02", "CWE-320"]


class EcrRepositoryNotKmsEncryptedGuard(Guard):
    id = "ecr-repository-not-kms-encrypted"
    title = "ECR repository without KMS encryption"
    area = "Cloud & IaC"

    canary_plant = CanaryPlant(
        files={
            "ecr_encryption.tf": (
                'resource "aws_ecr_repository" "canary" {\n'
                '  name = "canary-app"\n'
                "}\n"
            ),
        },
        expects=frozenset({"ecr-repository-not-kms-encrypted/missing-kms-encryption"}),
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
            if resource_type != "aws_ecr_repository":
                continue
            body_text = "\n".join(line for _, line in body)
            if pragma_present(_PRAGMA, body_text, dialect="hcl"):
                continue
            code_body = "\n".join(
                "" if line.lstrip().startswith(("#", "//")) else line for _, line in body
            )
            m = _ENC_CONFIG_BLOCK.search(code_body) or _DYNAMIC_ENC_CONFIG_BLOCK.search(code_body)
            if m and _ENCRYPTION_TYPE_KMS.search(m.group(1)):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=f"{rel(root, f)}:{start_line}",
                    message=(
                        f"`aws_ecr_repository.{resource_name}` has no `encryption_configuration` "
                        'block with `encryption_type = "KMS"`. The repository is still '
                        "encrypted at rest (AES256, AWS-owned key), but there is no "
                        "independently auditable customer-managed key for the images stored "
                        "in it."
                    ),
                    remediation=(
                        'Add `encryption_configuration { encryption_type = "KMS"; kms_key = '
                        "aws_kms_key.<name>.arn } ` to the resource. Suppress an audited "
                        "exception with `# security: allow-ecr-non-kms-encryption` anywhere in "
                        "the resource block."
                    ),
                    rule="ecr-repository-not-kms-encrypted/missing-kms-encryption",
                    standards=list(_STANDARDS),
                )
            )
        return out
