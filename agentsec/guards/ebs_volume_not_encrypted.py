"""Guard: Terraform EBS volume without encryption at rest (checklist §7).

    resource "aws_ebs_volume" "data" {
      availability_zone = "us-east-1a"
      size              = 100
      # no encrypted attribute at all -> AWS defaults it to false
    }

Unlike RDS storage or many other AWS resources, EBS volume encryption is opt-in per
volume: the `encrypted` attribute on `aws_ebs_volume` defaults to `false` if never set.
An unencrypted volume means anyone with access to the underlying storage (a snapshot, a
detached-and-reattached volume, a misconfigured IAM grant on the storage layer) reads the
raw data directly — no application-level bug required. CWE-311 (Missing Encryption of
Sensitive Data), OWASP:A02.

Sourced from checkov's `EBSEncryption` check (`CKV_AWS_3`, a `BaseResourceValueCheck`
inspecting `encrypted`; confirmed against the real fetched source).

Fires HIGH when an `aws_ebs_volume` resource block does NOT contain `encrypted = true`
anywhere in its body — whether the attribute is missing entirely or explicitly set to
`false`.

Suppress an audited case (e.g. a genuinely non-sensitive scratch volume) with
`# security: allow-ebs-unencrypted` anywhere in the resource block.
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

_ENCRYPTED_TRUE = re.compile(r"\bencrypted\s*=\s*true\b")
_PRAGMA = re.compile(r"#\s*security:\s*allow-ebs-unencrypted")

_STANDARDS = ["OWASP:A02", "CWE-311"]


class EbsVolumeNotEncryptedGuard(Guard):
    id = "ebs-volume-not-encrypted"
    title = "EBS volume without encryption at rest"
    area = "Cloud & IaC"

    canary_plant = CanaryPlant(
        files={
            "ebs_encryption.tf": (
                'resource "aws_ebs_volume" "canary" {\n'
                '  availability_zone = "us-east-1a"\n'
                "  size              = 10\n"
                "}\n"
            ),
        },
        expects=frozenset({"ebs-volume-not-encrypted/missing-encryption"}),
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
            if resource_type != "aws_ebs_volume":
                continue
            body_text = "\n".join(line for _, line in body)
            if pragma_present(_PRAGMA, body_text, dialect="hcl"):
                continue
            code_body = "\n".join(
                "" if line.lstrip().startswith(("#", "//")) else line for _, line in body
            )
            if _ENCRYPTED_TRUE.search(code_body):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}:{start_line}",
                    message=(
                        f"`aws_ebs_volume.{resource_name}` does not set `encrypted = true`. "
                        "EBS encryption is opt-in and defaults to false — anyone with access "
                        "to the underlying storage (a snapshot, a detached volume, a "
                        "misconfigured storage-layer grant) reads the raw, unencrypted data "
                        "directly."
                    ),
                    remediation=(
                        "Add `encrypted = true` to the resource. Suppress an audited exception "
                        "(e.g. a genuinely non-sensitive scratch volume) with "
                        "`# security: allow-ebs-unencrypted` anywhere in the resource block."
                    ),
                    rule="ebs-volume-not-encrypted/missing-encryption",
                    standards=list(_STANDARDS),
                )
            )
        return out
