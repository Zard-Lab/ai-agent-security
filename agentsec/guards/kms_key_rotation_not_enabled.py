"""Guard: Terraform customer-managed KMS key without automatic rotation.

    resource "aws_kms_key" "app" {
      description = "app data key"
      # no enable_key_rotation attribute at all -> key material is never rotated
    }

A customer-managed `aws_kms_key` that never rotates its key material means the same
cryptographic key protects data indefinitely — the longer a single key is used, the
larger the blast radius if it is ever compromised (a leaked key, an over-broad IAM grant,
a misissued grant to a compromised principal all decrypt everything the key ever touched,
not just data encrypted after the compromise). CWE-320 (Key Management Errors), OWASP:A04.

Sourced from checkov's `KMSRotation` check (`CKV_AWS_7`), a `BaseResourceValueCheck` whose
default `missing_block_result` is FAILED — an omitted `enable_key_rotation` attribute fires
just like an explicit `false` (confirmed against the real fetched source).

Fires MEDIUM when an `aws_kms_key` resource block does NOT contain
`enable_key_rotation = true` anywhere in its body — whether the attribute is missing
entirely or explicitly set to `false` — UNLESS the block's `customer_master_key_spec`
attribute is set to a literal value other than `SYMMETRIC_DEFAULT` (AWS's implicit
default when the attribute is omitted). Only a symmetric-default CMK supports automatic
rotation; any other spec (`RSA_*`, `ECC_*`, `SM2`, `HMAC_*`) cannot rotate at all, so
flagging one would be a false positive.

Note this deliberately diverges from checkov's real `scan_resource_conf`, which skips
(`CheckResult.UNKNOWN`) only when the spec is present, is not `SYMMETRIC_DEFAULT`, AND does
not contain `HMAC` — i.e. real checkov still runs the normal rotation check against HMAC
keys, which is itself arguably a checkov bug, since AWS never allows `enable_key_rotation`
on an HMAC CMK either. This guard treats "spec present and not SYMMETRIC_DEFAULT" as the
single skip condition (covering asymmetric AND HMAC specs alike) to avoid reproducing that
false-positive class.

Suppress an audited case (e.g. a short-lived key by design) with
`# security: allow-kms-key-rotation` anywhere in the resource block.
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

_ROTATION_TRUE = re.compile(r"\benable_key_rotation\s*=\s*true\b")
# A literal, quoted `customer_master_key_spec` value. Only a literal string can be judged
# here — a variable-/expression-driven value (`customer_master_key_spec = var.spec`) is left
# unresolved and falls through to the normal rotation check, which is the conservative choice
# (better a possible false positive on an unknown spec than silently suppressing a real one).
_CMKS_VALUE = re.compile(r"\bcustomer_master_key_spec\s*=\s*\"([^\"]*)\"")
_PRAGMA = re.compile(r"#\s*security:\s*allow-kms-key-rotation")

_STANDARDS = ["OWASP:A02", "CWE-320"]


class KmsKeyRotationNotEnabledGuard(Guard):
    id = "kms-key-rotation-not-enabled"
    title = "Customer-managed KMS key without rotation enabled"
    area = "Cloud & IaC"

    # kms_key_rotation.tf: aws_kms_key with no enable_key_rotation attribute -> fires
    # kms-key-rotation-not-enabled. Must NOT contain: allow-kms-key-rotation pragma.
    # kms_key_rotation.tf: aws_kms_key with no enable_key_rotation -> fires missing-rotation.
    canary_plant = CanaryPlant(
        files={
            "kms_key_rotation.tf": (
                'resource "aws_kms_key" "canary" {\n'
                '  description = "canary data key"\n'
                "}\n"
            ),
        },
        expects=frozenset({
            "kms-key-rotation-not-enabled/missing-rotation",
        }),
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
            if resource_type != "aws_kms_key":
                continue
            body_text = "\n".join(line for _, line in body)
            if pragma_present(_PRAGMA, body_text, dialect="hcl"):
                continue
            # Search a comment-blanked view (pragma already handled on the comment-only view above, #424) so a
            # commented `# enable_key_rotation = true` or `# customer_master_key_spec = "..."`
            # can't influence the decision on a genuinely non-rotating key. Blank, don't drop,
            # so nothing downstream shifts.
            code_body = "\n".join(
                "" if line.lstrip().startswith(("#", "//")) else line for _, line in body
            )
            cmks_match = _CMKS_VALUE.search(code_body)
            if cmks_match and cmks_match.group(1).strip().upper() != "SYMMETRIC_DEFAULT":
                # A non-default, non-symmetric spec (asymmetric RSA/ECC/SM2, or HMAC) — none
                # of these support automatic rotation at all, so flagging them would be a
                # false positive. Skip the block entirely.
                continue
            if _ROTATION_TRUE.search(code_body):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=f"{rel(root, f)}:{start_line}",
                    message=(
                        f"`aws_kms_key.{resource_name}` does not set "
                        "`enable_key_rotation = true`. This customer-managed KMS key never "
                        "rotates its key material — the longer a single key is used, the "
                        "larger the blast radius if it is ever compromised."
                    ),
                    remediation=(
                        "Add `enable_key_rotation = true` to the resource (skip this for "
                        "asymmetric or HMAC keys, which do not support automatic rotation). "
                        "Suppress an audited exception with `# security: allow-kms-key-rotation` "
                        "anywhere in the resource block."
                    ),
                    rule="kms-key-rotation-not-enabled/missing-rotation",
                    standards=list(_STANDARDS),
                )
            )
        return out
