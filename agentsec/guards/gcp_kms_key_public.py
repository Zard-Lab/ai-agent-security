"""Guard: GCP KMS crypto key / Cloud Storage bucket IAM policy grants access to
`allUsers`/`allAuthenticatedUsers`.

    resource "google_kms_crypto_key_iam_member" "bad" {
      crypto_key_id = google_kms_crypto_key.key.id
      role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
      member        = "allUsers"
    }

A GCP KMS crypto key's IAM policy/binding/member is how encrypt/decrypt access to that
key is granted. Setting the `member`/`members` (or an inline `policy_data`) to the
special identity `allUsers` grants that access to literally anyone on the internet, no
Google account required; `allAuthenticatedUsers` grants it to anyone holding any Google
account, not just principals in this project or org. Either one turns a KMS key —
typically the root of trust for other encrypted data — into a resource any anonymous
or arbitrary-Google-account caller can use for encrypt/decrypt operations. CWE-284
(Improper Access Control), OWASP:A01. Sourced from checkov's `GoogleKMSKeyIsPublic`
(`CKV_GCP_112`), which does the same literal-string search across the same three
resource-type variants — no JSON policy parsing needed, unlike
`s3-bucket-policy-wildcard-principal`'s `Effect`/`Principal`/`Condition` parse, because
these Terraform resources carry the member(s) as a plain string/list attribute rather
than a JSON policy document.

Originally scoped to the KMS IAM resource family; extended to also cover
`google_storage_bucket_iam_policy`/`_binding`/`_member` (KICS's
`cloud_storage_anonymous_or_publicly_accessible`, verified against the real
`query.rego`) because it is the exact same `members`/`member`/`policy_data`
literal-string shape applied to a different GCP resource, not a new detection
technique — an anonymous or public grant on a Cloud Storage bucket's IAM policy is the
GCP analog of an S3 bucket's public-access-block being disabled (checklist
`6a-s3-public-access-block-disabled`). Guard id kept stable for check_id/checklist
continuity even though the guard now also covers Cloud Storage buckets — same rationale
as `s3-bucket-policy-wildcard-principal` keeping its id after gaining KMS coverage.

Fires HIGH when a `google_kms_crypto_key_iam_policy`, `google_kms_crypto_key_iam_binding`,
`google_kms_crypto_key_iam_member`, `google_storage_bucket_iam_policy`,
`google_storage_bucket_iam_binding`, or `google_storage_bucket_iam_member` resource block
contains the literal string `allUsers` or `allAuthenticatedUsers` anywhere in its body
(its `member`, `members`, or `policy_data` attribute) — matching checkov's/KICS's own
approach for this check. A block naming only specific principals
(`user:foo@example.com`, `serviceAccount:...`, `group:...`) does not fire, nor does a
`#`-comment line merely mentioning either string.

Suppress an audited case with `# security: allow-gcp-kms-key-public` anywhere in the
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

_KMS_IAM_RESOURCE_TYPES = frozenset(
    {
        "google_kms_crypto_key_iam_policy",
        "google_kms_crypto_key_iam_binding",
        "google_kms_crypto_key_iam_member",
    }
)
# google_storage_bucket_iam_* — same members/member/policy_data literal-string shape as the
# KMS IAM family above, applied to a Cloud Storage bucket's IAM policy instead of a KMS key
# (KICS `cloud_storage_anonymous_or_publicly_accessible`).
_STORAGE_IAM_RESOURCE_TYPES = frozenset(
    {
        "google_storage_bucket_iam_policy",
        "google_storage_bucket_iam_binding",
        "google_storage_bucket_iam_member",
    }
)
_PUBLIC_IAM_RESOURCE_TYPES = _KMS_IAM_RESOURCE_TYPES | _STORAGE_IAM_RESOURCE_TYPES
_PUBLIC_MEMBER = re.compile(r"\b(?:allUsers|allAuthenticatedUsers)\b")
_PRAGMA = re.compile(r"#\s*security:\s*allow-gcp-kms-key-public")

_STANDARDS = ["OWASP:A01", "CWE-284"]


class GcpKmsKeyPublicGuard(Guard):
    id = "gcp-kms-key-public"
    title = (
        "GCP KMS key / Cloud Storage bucket IAM policy grants access to "
        "allUsers/allAuthenticatedUsers"
    )
    area = "Cloud & IaC"

    # gcp_kms_iam.tf: google_kms_crypto_key_iam_member with member = "allUsers" -> fires
    # gcp-kms-key-public. gcp_storage_iam.tf: google_storage_bucket_iam_member with the same ->
    # fires the same rule (extension). Must NOT contain: allow-gcp-kms-key-public pragma.
    canary_plant = CanaryPlant(
        files={
            "gcp_kms_iam.tf": (
                'resource "google_kms_crypto_key_iam_member" "canary" {\n'
                "  crypto_key_id = google_kms_crypto_key.canary.id\n"
                '  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"\n'
                '  member        = "allUsers"\n'
                "}\n"
            ),
            "gcp_storage_iam.tf": (
                'resource "google_storage_bucket_iam_member" "canary" {\n'
                "  bucket = google_storage_bucket.canary.name\n"
                '  role   = "roles/storage.objectViewer"\n'
                '  member = "allUsers"\n'
                "}\n"
            ),
        },
        expects=frozenset({"gcp-kms-key-public/public-member"}),
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
        for resource_type, resource_name, _start, body in iter_terraform_resources(text):
            if resource_type not in _PUBLIC_IAM_RESOURCE_TYPES:
                continue
            raw_body = "\n".join(line for _, line in body)
            if pragma_present(_PRAGMA, raw_body, dialect="hcl"):
                continue
            for lineno, line in body:
                if line.lstrip().startswith(("#", "//")):
                    continue
                match = _PUBLIC_MEMBER.search(line)
                if not match:
                    continue
                out.append(self._finding(root, f, resource_type, resource_name, lineno, match.group(0)))
                break
        return out

    def _finding(
        self,
        root: Path,
        f: Path,
        resource_type: str,
        resource_name: str,
        lineno: int,
        member: str,
    ) -> Finding:
        who = (
            "literally anyone on the internet"
            if member == "allUsers"
            else "anyone with any Google account"
        )
        # The KMS-resource wording is held BYTE-IDENTICAL to what this rule shipped before
        # storage-bucket support was added — `Finding.fingerprint()` hashes `message[:120]`,
        # so rewording an already-released finding silently invalidates every downstream
        # baseline and pinned exception keyed to it (see s3-bucket-policy-wildcard-principal
        # for the same rule). Only the NEW storage-bucket branch may word itself freely.
        if resource_type in _STORAGE_IAM_RESOURCE_TYPES:
            message = (
                f"`{resource_type}.{resource_name}` grants Cloud Storage bucket access to "
                f"`{member}` — {who} can perform this IAM binding's granted role against the "
                "bucket (read/write/admin, depending on the role)."
            )
        else:
            message = (
                f"`{resource_type}.{resource_name}` grants KMS access to `{member}` — {who} "
                "can perform this key's encrypt/decrypt operations."
            )
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=message,
            remediation=(
                "Scope the IAM member(s) to specific principals (`user:...`, "
                "`serviceAccount:...`, `group:...`) instead of `allUsers`/"
                "`allAuthenticatedUsers`. Suppress an audited exception with "
                "`# security: allow-gcp-kms-key-public` anywhere in the resource block."
            ),
            rule="gcp-kms-key-public/public-member",
            standards=list(_STANDARDS),
        )
