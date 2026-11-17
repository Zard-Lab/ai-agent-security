"""Guard: CloudFormation customer-managed KMS key without automatic rotation (checklist §7).

The CloudFormation counterpart to agentsec's existing (Terraform-only) `kms-key-rotation-not-
enabled` guard — same requirement (a customer-managed KMS key that never rotates its key material
means the same cryptographic key protects data indefinitely, so a leaked key or an over-broad IAM
grant decrypts everything the key ever touched, not just data encrypted after the compromise), a
genuinely different code surface (CFN's `AWS::KMS::Key` resource instead of Terraform's
`aws_kms_key`), so it extends the same `7-kms-key-rotation-not-enabled` checklist item rather than
duplicating it. This is agentsec's first CloudFormation-format guard — CFN template
detection (`has_cfn_template`/`cloudformation` feature) and the shared `agentsec.cfn` resource-
block parser landed in this same PR to support it.

Pattern verified against cfripper's real source (`kms_key_rotation_enabled.py`,
`Skyscanner/cfripper`) — cited for provenance; detection logic and test fixtures here are
original, developed independently against the pattern description.

Fires MEDIUM when an `AWS::KMS::Key` resource does NOT contain `EnableKeyRotation: true` /
`"EnableKeyRotation": true` anywhere in its block — whether the property is missing entirely or
explicitly `false` — UNLESS the resource's `KeySpec` property is set to a literal value other than
`SYMMETRIC_DEFAULT` (AWS's implicit default when the property is omitted): only a symmetric-default
CMK supports automatic rotation, so an asymmetric (`RSA_*`/`ECC_*`/`SM2_*`) or `HMAC_*` key would
be a false positive — the same exclusion the Terraform sibling guard applies, for the same reason.

Suppress an audited case (e.g. a short-lived key by design) with a comment containing
`security: allow-kms-key-rotation` anywhere in the resource's block (YAML `#` comment; not
meaningful in JSON, which has no comment syntax — a JSON template can't carry this pragma at all,
a known, documented limitation shared by every CFN guard in this batch).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.cfn import cfn_resources
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_files, pragma_present, read, rel

_ROTATION_TRUE = re.compile(r'"?EnableKeyRotation"?\s*:\s*true\b', re.IGNORECASE)
_KEY_SPEC_VALUE = re.compile(r'"?KeySpec"?\s*:\s*["\']?([A-Za-z0-9_]+)["\']?')
_PRAGMA = "security: allow-kms-key-rotation"

_STANDARDS = ["OWASP:A02", "CWE-320"]


class CfnKmsKeyRotationNotEnabledGuard(Guard):
    id = "cfn-kms-key-rotation-not-enabled"
    title = "Customer-managed KMS key without rotation enabled (CloudFormation)"
    area = "Cloud & IaC"

    # cfn_kms_key.yaml: AWS::KMS::Key with no EnableKeyRotation property -> fires
    # cfn-kms-key-rotation-not-enabled/missing-rotation.
    canary_plant = CanaryPlant(
        files={
            "cfn_kms_key.yaml": (
                "AWSTemplateFormatVersion: '2010-09-09'\n"
                "Resources:\n"
                "  CanaryKey:\n"
                "    Type: AWS::KMS::Key\n"
                "    Properties:\n"
                "      Description: canary data key\n"
            ),
        },
        expects=frozenset({
            "cfn-kms-key-rotation-not-enabled/missing-rotation",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "cloudformation" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".yaml", ".yml", ".json")):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        for resource in cfn_resources(text):
            if resource.resource_type != "AWS::KMS::Key":
                continue
            if pragma_present(_PRAGMA, resource.block, dialect=resource.pragma_dialect):
                continue
            spec_match = _KEY_SPEC_VALUE.search(resource.block)
            if spec_match and spec_match.group(1).strip().upper() != "SYMMETRIC_DEFAULT":
                # An asymmetric or HMAC KeySpec — none support automatic rotation at all, so
                # flagging them would be a false positive. Skip the resource entirely.
                continue
            if _ROTATION_TRUE.search(resource.block):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=f"{rel(root, f)}",
                    message=(
                        f"`{resource.logical_id}` (AWS::KMS::Key) does not set "
                        "`EnableKeyRotation: true`. This customer-managed KMS key never rotates "
                        "its key material — the longer a single key is used, the larger the "
                        "blast radius if it is ever compromised."
                    ),
                    remediation=(
                        "Add `EnableKeyRotation: true` to the resource's Properties (skip this "
                        "for asymmetric or HMAC keys, which do not support automatic rotation). "
                        "Suppress an audited exception with a `security: allow-kms-key-rotation` "
                        "comment anywhere in the resource (YAML templates only)."
                    ),
                    rule="cfn-kms-key-rotation-not-enabled/missing-rotation",
                    standards=list(_STANDARDS),
                )
            )
        return out
