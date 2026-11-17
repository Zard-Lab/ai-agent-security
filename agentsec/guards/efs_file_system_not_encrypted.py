"""Guard: Terraform EFS file system without encryption at rest (checklist §7).

    resource "aws_efs_file_system" "shared" {
      creation_token = "shared-data"
      # no encrypted attribute at all -> AWS defaults it to false
    }

Like EBS, EFS encryption at rest is opt-in per file system: the `encrypted` attribute on
`aws_efs_file_system` defaults to `false` if never set. An unencrypted EFS file system
means anyone with access to the underlying storage layer reads the raw file contents
directly — no application-level bug required. This guard checks only the file system
resource's own at-rest flag; it is NOT about transit encryption on an EFS mount inside an
ECS task, which is a separate, narrower concern. CWE-311 (Missing Encryption of Sensitive
Data), OWASP:A02.

Sourced from checkov's `EFSEncryptionEnabled` check (`CKV_AWS_42`, a
`BaseResourceValueCheck` inspecting `encrypted`; confirmed against the real fetched
source).

Fires HIGH when an `aws_efs_file_system` resource block does NOT contain a literal
`encrypted = true` — whether the attribute is missing entirely or explicitly `false`. A
non-literal value (e.g. `encrypted = var.enc`) cannot be proven unsafe and stays silent.

Suppress an audited case (e.g. a genuinely non-sensitive scratch file system) with
`# security: allow-efs-unencrypted` anywhere in the resource block.
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
    literal_bool_state,
    pragma_present,
    read,
    rel,
    terraform_code_view,
    top_level_attribute_text,
)

_PRAGMA = re.compile(r"#\s*security:\s*allow-efs-unencrypted")

_STANDARDS = ["OWASP:A02", "CWE-311"]


class EfsFileSystemNotEncryptedGuard(Guard):
    id = "efs-file-system-not-encrypted"
    title = "EFS file system without encryption at rest"
    area = "Cloud & IaC"

    canary_plant = CanaryPlant(
        files={
            "efs_encryption.tf": (
                'resource "aws_efs_file_system" "canary" {\n'
                '  creation_token = "canary-shared-data"\n'
                "}\n"
            ),
        },
        expects=frozenset({"efs-file-system-not-encrypted/missing-encryption"}),
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
            if resource_type != "aws_efs_file_system":
                continue
            body_text = "\n".join(line for _, line in body)
            if pragma_present(_PRAGMA, body_text, dialect="hcl"):
                continue
            # The resource's own top-level attributes, comments blanked: a same-named key in a
            # `tags` map (one-line or multi-line) is not the attribute (PR #1162 round-4 M2).
            code_body = top_level_attribute_text(terraform_code_view(body_text))
            # A non-literal value (e.g. a variable) cannot be proven unsafe -> stays silent.
            if literal_bool_state("encrypted", code_body) in ("true", "nonliteral"):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}:{start_line}",
                    message=(
                        f"`aws_efs_file_system.{resource_name}` does not set "
                        "`encrypted = true`. EFS encryption at rest is opt-in and defaults "
                        "to false — anyone with access to the underlying storage layer "
                        "reads the raw file contents directly."
                    ),
                    remediation=(
                        "Add `encrypted = true` to the resource. Suppress an audited "
                        "exception (e.g. a genuinely non-sensitive scratch file system) "
                        "with `# security: allow-efs-unencrypted` anywhere in the resource "
                        "block."
                    ),
                    rule="efs-file-system-not-encrypted/missing-encryption",
                    standards=list(_STANDARDS),
                )
            )
        return out
