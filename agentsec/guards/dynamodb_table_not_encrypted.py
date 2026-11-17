"""Guard: Terraform DynamoDB table without customer-managed KMS encryption (checklist §7).

    resource "aws_dynamodb_table" "sessions" {
      name         = "sessions"
      billing_mode = "PAY_PER_REQUEST"
      hash_key     = "id"
      # no server_side_encryption block -> encrypted with an AWS-owned key, not a CMK
    }

DynamoDB tables are encrypted at rest by default using an AWS-owned key (free, but the
account has no visibility into or control over it — no separate audit trail, no ability
to restrict or revoke access to the key itself, no cross-account key-policy narrowing).
A table holding session/user data without a customer-managed key means the account can't
independently prove or control who can decrypt the table's storage layer. CWE-320 (Key
Management Errors), OWASP:A02.

Sourced from checkov's `DynamoDBTablesEncrypted` check (`CKV_AWS_119`, a `BaseResourceCheck`
requiring `server_side_encryption[0].enabled == [True]` AND `kms_key_arn` both present;
confirmed against the real fetched source).

Fires MEDIUM when an `aws_dynamodb_table` resource block does NOT contain a
`server_side_encryption { ... }` block with both `enabled = true` and a `kms_key_arn`
set — whether the block is missing entirely or only partially configured.

Suppress an audited case (e.g. a genuinely non-sensitive scratch table) with
`# security: allow-dynamodb-unencrypted` anywhere in the resource block.
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

_SSE_BLOCK = re.compile(r"\bserver_side_encryption\s*\{([^{}]*)\}", re.S)
# The `dynamic "server_side_encryption" { ... content { ... } }` form wraps the real
# attributes inside a nested `content` block, one level deeper than the plain form above
# -- the plain regex's immediate `{` after the keyword never matches a `dynamic` label
# sitting in between. Matches lazily up to the first `content {` inside the dynamic block
# and captures THAT block's body (Dean's review, High 2).
_DYNAMIC_SSE_BLOCK = re.compile(
    r'\bdynamic\s*"server_side_encryption"\s*\{.*?\bcontent\s*\{([^{}]*)\}', re.S
)
_ENABLED_TRUE = re.compile(r"\benabled\s*=\s*true\b")
_KMS_KEY_ARN = re.compile(r"\bkms_key_arn\s*=\s*\S")
_PRAGMA = re.compile(r"#\s*security:\s*allow-dynamodb-unencrypted")

_STANDARDS = ["OWASP:A02", "CWE-320"]


class DynamodbTableNotEncryptedGuard(Guard):
    id = "dynamodb-table-not-encrypted"
    title = "DynamoDB table without customer-managed KMS encryption"
    area = "Cloud & IaC"

    canary_plant = CanaryPlant(
        files={
            "dynamodb_encryption.tf": (
                'resource "aws_dynamodb_table" "canary" {\n'
                '  name         = "canary"\n'
                '  billing_mode = "PAY_PER_REQUEST"\n'
                '  hash_key     = "id"\n'
                "  attribute {\n"
                '    name = "id"\n'
                '    type = "S"\n'
                "  }\n"
                "}\n"
            ),
        },
        expects=frozenset({"dynamodb-table-not-encrypted/missing-cmk-encryption"}),
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
            if resource_type != "aws_dynamodb_table":
                continue
            body_text = "\n".join(line for _, line in body)
            if pragma_present(_PRAGMA, body_text, dialect="hcl"):
                continue
            code_body = "\n".join(
                "" if line.lstrip().startswith(("#", "//")) else line for _, line in body
            )
            m = _SSE_BLOCK.search(code_body) or _DYNAMIC_SSE_BLOCK.search(code_body)
            if m and _ENABLED_TRUE.search(m.group(1)) and _KMS_KEY_ARN.search(m.group(1)):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=f"{rel(root, f)}:{start_line}",
                    message=(
                        f"`aws_dynamodb_table.{resource_name}` has no `server_side_encryption` "
                        "block with both `enabled = true` and a `kms_key_arn` set. The table is "
                        "still encrypted at rest by AWS's own default key, but the account has "
                        "no independent control over or audit trail for who can decrypt it."
                    ),
                    remediation=(
                        "Add a `server_side_encryption { enabled = true; kms_key_arn = "
                        "aws_kms_key.<name>.arn }` block referencing a customer-managed CMK. "
                        "Suppress an audited exception (e.g. a genuinely non-sensitive scratch "
                        "table) with `# security: allow-dynamodb-unencrypted` anywhere in the "
                        "resource block."
                    ),
                    rule="dynamodb-table-not-encrypted/missing-cmk-encryption",
                    standards=list(_STANDARDS),
                )
            )
        return out
