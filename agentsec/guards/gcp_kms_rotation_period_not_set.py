"""Guard: Terraform GCP KMS crypto key without a rotation period set (checklist §7).

    resource "google_kms_crypto_key" "app" {
      name     = "app-key"
      key_ring = google_kms_key_ring.ring.id
      # no rotation_period attribute at all -> the key is never automatically rotated
    }

A `google_kms_crypto_key` with no `rotation_period` set is never rotated automatically —
the same symmetric key stays in use indefinitely, so a single leaked/compromised key
version can decrypt every ciphertext ever produced under it, past and future, until
someone notices and rotates manually. checkov's own `CKV_GCP_43`
(`GoogleKMSRotationPeriod.py`) exists for the same reason. CWE-320 (Key Management
Errors), OWASP:A04.

checkov's real check parses the `rotation_period` duration string (format `"NNNNNNNs"`)
and bounds-checks it to 1-90 days, skipping keys whose `purpose` is asymmetric
(`ASYMMETRIC_DECRYPT`/`ASYMMETRIC_SIGN` — those don't support rotation at all). This
guard is a **deliberate scope-narrowing port**: it does not parse or bounds-check the
duration value. It fires only when `rotation_period` is missing from the resource block
entirely — any value present, however long or short, is treated as satisfying this
guard (validating the actual duration is out of scope here). It still skips asymmetric
keys, matching checkov's "skip a class that structurally can't be rotated" logic.

Suppress an audited case (e.g. a deliberately unrotated key, HSM-backed, or a key that
predates this guard and is tracked for manual rotation) with
`# security: allow-gcp-kms-rotation-period` anywhere in the resource block.
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

_ROTATION_PERIOD = re.compile(r"\brotation_period\s*=")
_PURPOSE_ASYMMETRIC = re.compile(r"\bpurpose\s*=\s*\"[^\"]*ASYMMETRIC[^\"]*\"", re.IGNORECASE)
_PRAGMA = re.compile(r"#\s*security:\s*allow-gcp-kms-rotation-period")

_STANDARDS = ["OWASP:A02", "CWE-320"]


class GcpKmsRotationPeriodNotSetGuard(Guard):
    id = "gcp-kms-rotation-period-not-set"
    title = "GCP KMS crypto key without a rotation period"
    area = "Cloud & IaC"

    # gcp_kms_key.tf: google_kms_crypto_key with no rotation_period attribute -> fires
    # gcp-kms-rotation-period-not-set. Must NOT contain: allow-gcp-kms-rotation-period pragma.
    canary_plant = CanaryPlant(
        files={
            "gcp_kms_key.tf": (
                'resource "google_kms_crypto_key" "canary" {\n'
                '  name     = "canary-key"\n'
                "  key_ring = google_kms_key_ring.canary.id\n"
                "}\n"
            ),
        },
        expects=frozenset({"gcp-kms-rotation-period-not-set/missing-rotation-period"}),
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
            if resource_type != "google_kms_crypto_key":
                continue
            body_text = "\n".join(line for _, line in body)
            if pragma_present(_PRAGMA, body_text, dialect="hcl"):
                continue
            # Comment-blank the body before searching so a commented-out `# rotation_period = ...`
            # can't be read as the real attribute (would silently suppress a genuine finding) and
            # a commented-out `# purpose = "ASYMMETRIC_SIGN"` can't be read as a real skip either.
            code_body = "\n".join(
                "" if line.lstrip().startswith(("#", "//")) else line for _, line in body
            )
            if _PURPOSE_ASYMMETRIC.search(code_body):
                continue
            if _ROTATION_PERIOD.search(code_body):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=f"{rel(root, f)}:{start_line}",
                    message=(
                        f"`google_kms_crypto_key.{resource_name}` does not set "
                        "`rotation_period`. Without it the key is never automatically "
                        "rotated — a single leaked or compromised key version can decrypt "
                        "every ciphertext ever produced under it, indefinitely."
                    ),
                    remediation=(
                        "Add `rotation_period = \"7776000s\"` (90 days) or shorter to the "
                        "resource, unless the key's `purpose` is asymmetric (asymmetric keys "
                        "don't support rotation). Suppress an audited exception with "
                        "`# security: allow-gcp-kms-rotation-period` anywhere in the block."
                    ),
                    rule="gcp-kms-rotation-period-not-set/missing-rotation-period",
                    standards=list(_STANDARDS),
                )
            )
        return out
