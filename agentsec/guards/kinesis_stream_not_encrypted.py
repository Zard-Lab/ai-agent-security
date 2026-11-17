"""Guard: Terraform Kinesis data stream without server-side encryption (checklist §7).

    resource "aws_kinesis_stream" "events" {
      name             = "events"
      shard_count      = 1
      retention_period = 24
      # no encryption_type attribute at all -> stream is created unencrypted
    }

A Kinesis data stream is NOT encrypted at rest by default — unlike several other AWS data
stores in this family, there is no AWS-owned-key fallback here; an `aws_kinesis_stream`
resource with no `encryption_type` set (or `encryption_type = "NONE"`) stores every record
written to every shard in plaintext. Kinesis streams commonly carry event/clickstream or
telemetry payloads that include PII or session data, so anyone with read access to the
underlying shard storage reads the raw data directly — no application-level bug required.
CWE-311 (Missing Encryption of Sensitive Data), OWASP:A02.

Sourced from checkov's `KinesisStreamEncryptionType` check (`CKV_AWS_43`, a
`BaseResourceValueCheck` inspecting `encryption_type`, expecting `"KMS"`; confirmed against
the real fetched source).

Fires HIGH when an `aws_kinesis_stream` resource block does NOT set
`encryption_type = "KMS"` — whether the attribute is missing entirely or explicitly set to
the literal `"NONE"`. Any other literal value is treated as addressed (this guard cannot
evaluate a variable reference, so a non-`"NONE"` literal value is assumed intentional,
matching this file family's convention). A non-literal value (e.g.
`encryption_type = var.et`, no quotes) is likewise assumed intentional and stays silent —
it must NOT be treated the same as an absent attribute, which does fire.

Suppress an audited case (e.g. a genuinely non-sensitive scratch stream) with
`# security: allow-kinesis-unencrypted` anywhere in the resource block.
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

_ENCRYPTION_TYPE = re.compile(r'\bencryption_type\s*=\s*"([^"]*)"')
_ENCRYPTION_TYPE_PRESENT = re.compile(r"\bencryption_type\s*=")
_PRAGMA = re.compile(r"#\s*security:\s*allow-kinesis-unencrypted")

_STANDARDS = ["OWASP:A02", "CWE-311"]


class KinesisStreamNotEncryptedGuard(Guard):
    id = "kinesis-stream-not-encrypted"
    title = "Kinesis data stream without server-side encryption"
    area = "Cloud & IaC"

    canary_plant = CanaryPlant(
        files={
            "kinesis_encryption.tf": (
                'resource "aws_kinesis_stream" "canary" {\n'
                '  name             = "canary-events"\n'
                "  shard_count      = 1\n"
                "  retention_period = 24\n"
                "}\n"
            ),
        },
        expects=frozenset({"kinesis-stream-not-encrypted/missing-encryption"}),
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
            if resource_type != "aws_kinesis_stream":
                continue
            body_text = "\n".join(line for _, line in body)
            if pragma_present(_PRAGMA, body_text, dialect="hcl"):
                continue
            code_body = "\n".join(
                "" if line.lstrip().startswith(("#", "//")) else line for _, line in body
            )
            m = _ENCRYPTION_TYPE.search(code_body)
            if m:
                if m.group(1) != "NONE":
                    continue  # literal non-NONE value -> assumed intentional
            elif _ENCRYPTION_TYPE_PRESENT.search(code_body):
                continue  # present as a non-literal (e.g. a variable) -> cannot be proven unsafe
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}:{start_line}",
                    message=(
                        f"`aws_kinesis_stream.{resource_name}` does not set "
                        '`encryption_type = "KMS"`. The stream is created unencrypted by '
                        "default — anyone with read access to the underlying shard storage "
                        "reads every record written to every shard directly, in plaintext."
                    ),
                    remediation=(
                        'Add `encryption_type = "KMS"` (optionally with `kms_key_id` for a '
                        "customer-managed key). Suppress an audited exception (e.g. a "
                        "genuinely non-sensitive scratch stream) with "
                        "`# security: allow-kinesis-unencrypted` anywhere in the resource "
                        "block."
                    ),
                    rule="kinesis-stream-not-encrypted/missing-encryption",
                    standards=list(_STANDARDS),
                )
            )
        return out
