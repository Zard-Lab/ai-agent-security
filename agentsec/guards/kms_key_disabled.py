"""Guard: Terraform KMS key explicitly disabled (checklist §7).

    resource "aws_kms_key" "app" {
      description = "app data encryption key"
      is_enabled  = false          # the key can no longer encrypt or decrypt anything
    }

`is_enabled = false` on an `aws_kms_key` Terraform resource explicitly disables the key.
A disabled KMS key cannot be used for any cryptographic operation — any resource still
configured to encrypt/decrypt with it (S3 bucket encryption, RDS storage encryption, Secrets
Manager, application-level envelope encryption, ...) breaks the moment the key state takes
effect, and any data already encrypted under it becomes unreadable until it is re-enabled.
CWE-320 (Key Management Errors), OWASP:A04 (Insecure Design).

Fires LOW when a `resource "aws_kms_key" "..."` block sets `is_enabled = false` literally.
A block that omits the attribute entirely is safe and does NOT fire — the AWS provider
defaults `is_enabled` to `true`, so silence is the safe state (unlike a check where an
omitted attribute would itself be the risk); only an explicit `false` is a deliberate
disable and worth flagging.

Suppress an audited case (e.g. a deliberately retired key kept around for historical
decrypt-only access review) with `# security: allow-kms-key-disabled` on the `is_enabled`
line.
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

_KMS_RESOURCE_TYPES = frozenset({"aws_kms_key"})
_IS_ENABLED_FALSE = re.compile(r"\bis_enabled\s*=\s*false\b")
_PRAGMA = re.compile(r"#\s*security:\s*allow-kms-key-disabled")

_STANDARDS = ["OWASP:A05", "CWE-320"]


class KmsKeyDisabledGuard(Guard):
    id = "kms-key-disabled"
    title = "KMS key explicitly disabled"
    area = "Cloud & IaC"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `kms_key_disabled.tf`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # kms_key_disabled.tf: aws_kms_key with is_enabled = false -> fires explicitly-disabled.
    canary_plant = CanaryPlant(expects=frozenset({"kms-key-disabled/explicitly-disabled"}))

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
        for resource_type, resource_name, _start, body in iter_terraform_resources(text):
            if resource_type not in _KMS_RESOURCE_TYPES:
                continue
            for lineno, line in body:
                if line.lstrip().startswith(("#", "//")):
                    continue
                if not _IS_ENABLED_FALSE.search(line):
                    continue
                if pragma_present(_PRAGMA, line, dialect="hcl"):  # a comment on it, never a string (#424)
                    continue
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="medium",
                        title=self.title,
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            f"`{resource_type}.{resource_name}` sets `is_enabled = false`, "
                            "explicitly disabling the KMS key. Any resource still relying on "
                            "it for encryption or decryption breaks, and data already "
                            "encrypted under it becomes unreadable until it is re-enabled."
                        ),
                        remediation=(
                            "Remove `is_enabled = false` (or set it to `true`) unless the key "
                            "is being deliberately retired. Suppress an audited exception "
                            "(e.g. a retired key kept for decrypt-only historical review) with "
                            "`# security: allow-kms-key-disabled` on the attribute line."
                        ),
                        rule="kms-key-disabled/explicitly-disabled",
                        standards=list(_STANDARDS),
                    )
                )
        return out
