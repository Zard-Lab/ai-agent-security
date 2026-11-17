"""Guard: Terraform Secrets Manager secret without a customer-managed KMS key (checklist §7).

    resource "aws_secretsmanager_secret" "db_password" {
      name = "db_password"
      # no kms_key_id -> encrypted with the account's default aws/secretsmanager alias
    }

Secrets Manager encrypts every secret at rest by default using the AWS-managed
`aws/secretsmanager` key. That key's key policy is controlled by AWS, not the account —
there is no way to write a narrower grant, add a deny condition, or audit access to it
independently of the secret's own IAM policy. A secret without a customer-managed CMK
means the only access control is IAM on the secret itself; a customer-managed key adds a
second, independently auditable control point. CWE-320 (Key Management Errors), OWASP:A02.

Sourced from checkov's `SecretManagerSecretEncrypted` check (`CKV_AWS_149`, a
`BaseResourceCheck` that fails when `kms_key_id` is absent OR its value contains the
literal substring `aws/` — the default alias prefix; confirmed against the real fetched
source).

Fires MEDIUM when an `aws_secretsmanager_secret` resource block does NOT set `kms_key_id`
to a value (a quoted literal ARN/id OR a resource reference such as
`aws_kms_key.<name>.arn`), sets it to a quoted value containing `aws/` (the default-alias
prefix, e.g. `"alias/aws/secretsmanager"`), or sets it to the bare HCL keyword `null`
(Terraform treats a `null`-valued attribute as absent, so the secret still falls back to
the default AWS-managed key — #687 fix-commit re-review, High 1).

**Disclosed, accepted gap:** the value-capture regex takes only the FIRST token after
`=`, so `kms_key_id = var.use_cmk ? aws_kms_key.app.arn : null` reads as
`var.use_cmk` (truthy, no `aws/` substring) and stays silent even on the branch that
resolves to `null` — a multi-token ternary/conditional expression is not evaluated,
only a single bare token or quoted literal. Not fixed here: closing it needs capturing
the whole remaining line rather than one token, a larger change than this fix's scope.

Suppress an audited case with `# security: allow-secrets-manager-default-kms` anywhere in
the resource block.
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

_KMS_KEY_ID_VALUE = re.compile(r'\bkms_key_id\s*=\s*(?:"([^"]*)"|(\S+))')
_PRAGMA = re.compile(r"#\s*security:\s*allow-secrets-manager-default-kms")

_STANDARDS = ["OWASP:A02", "CWE-320"]


class SecretsManagerDefaultKmsGuard(Guard):
    id = "secrets-manager-default-kms"
    title = "Secrets Manager secret without a customer-managed KMS key"
    area = "Cloud & IaC"

    canary_plant = CanaryPlant(
        files={
            "secretsmanager_kms.tf": (
                'resource "aws_secretsmanager_secret" "canary" {\n'
                '  name = "canary-secret"\n'
                "}\n"
            ),
        },
        expects=frozenset({"secrets-manager-default-kms/default-aws-managed-key"}),
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
            if resource_type != "aws_secretsmanager_secret":
                continue
            body_text = "\n".join(line for _, line in body)
            if pragma_present(_PRAGMA, body_text, dialect="hcl"):
                continue
            code_body = "\n".join(
                "" if line.lstrip().startswith(("#", "//")) else line for _, line in body
            )
            m = _KMS_KEY_ID_VALUE.search(code_body)
            if m:
                value = (m.group(1) or m.group(2) or "").strip()
                # `kms_key_id = null` (or any expression ending in it, e.g. a ternary) is
                # Terraform's own way of saying "no value" -- the secret still falls back to the
                # AWS-managed default key, the exact condition this guard exists to report. The
                # original `value and "aws/" not in value` check treated the literal string
                # "null" as "a value is set" and went silent on it (#687 fix-commit re-review,
                # High 1).
                if value and value != "null" and "aws/" not in value:
                    continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=f"{rel(root, f)}:{start_line}",
                    message=(
                        f"`aws_secretsmanager_secret.{resource_name}` does not set "
                        "`kms_key_id` to a customer-managed CMK — it is encrypted with the "
                        "account's default `aws/secretsmanager` key, whose key policy the "
                        "account cannot narrow or independently audit."
                    ),
                    remediation=(
                        "Set `kms_key_id = aws_kms_key.<name>.arn` (or key id) referencing a "
                        "customer-managed CMK. Suppress an audited exception with "
                        "`# security: allow-secrets-manager-default-kms` anywhere in the "
                        "resource block."
                    ),
                    rule="secrets-manager-default-kms/default-aws-managed-key",
                    standards=list(_STANDARDS),
                )
            )
        return out
