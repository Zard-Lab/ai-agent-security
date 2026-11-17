"""Guard: Terraform S3 bucket AccessControl set to a public canned ACL (checklist §6a).

    resource "aws_s3_bucket_acl" "data" {
      bucket = aws_s3_bucket.data.id
      acl    = "public-read"
    }

The Terraform sibling of `cfn_s3_public_access_canned_acl.py`: the same legacy S3 **canned ACL**
mechanism, flagged for the same reason, expressed through Terraform's HCL `acl` attribute instead
of CloudFormation's `AccessControl` property. A canned ACL of `public-read` or
`public-read-write` grants read (or read+write) access to anyone, including anonymous,
unauthenticated requests — independently of any bucket policy. `authenticated-read` is also
flagged: it grants read access to any authenticated AWS user in any AWS account on the planet, not
just this account, which is a materially public grant even though it technically requires some
AWS identity. CWE-284 (Improper Access Control), OWASP:A01.

Covers Terraform's two generations of setting a bucket's ACL, the same old/new split as
`s3_mfa_delete_disabled.py`'s versioning check:

1. **Legacy inline form** (provider v3 and earlier) — the `acl` attribute set directly on the
   `aws_s3_bucket` resource itself:

       resource "aws_s3_bucket" "data" {
         bucket = "app-data"
         acl    = "public-read"
       }

2. **Split-resource form** (provider v4+, which removed `acl` from `aws_s3_bucket` entirely) — a
   separate `aws_s3_bucket_acl` resource:

       resource "aws_s3_bucket_acl" "data" {
         bucket = aws_s3_bucket.data.id
         acl    = "public-read"
       }

Both forms fire on the exact same three literal, case-sensitive string values —
`"public-read"`, `"public-read-write"`, `"authenticated-read"` — matching Terraform's own `acl`
enum. Every other valid value (`"private"`, `"log-delivery-write"`, `"aws-exec-read"`,
`"bucket-owner-read"`, `"bucket-owner-full-control"`) is not public in this sense and must not
fire.

For the split-resource form, the bucket it targets is resolved for reporting purposes only, via
the same `bucket = aws_s3_bucket.<name>.` reference pattern used elsewhere in this guard family
(`aws_observability_hygiene.py`, `s3_mfa_delete_disabled.py`) — but unlike those guards, the
bucket resource itself does not need to exist or be found for this guard to fire: the
`aws_s3_bucket_acl` resource's own `acl` value is sufficient on its own. A reference that can't be
resolved (a variable, a `for_each`-derived name) just falls back to reporting the `aws_s3_bucket_acl`
resource's own name.

Fires HIGH (a direct, unconditionally public grant, no "depends on what else is configured"
nuance — mirrors `cfn-s3-public-access-canned-acl`). Rule ids:
`s3-bucket-canned-acl/inline-acl-attribute` (legacy form),
`s3-bucket-canned-acl/acl-resource` (split-resource form).

Pattern verified against cfripper's real source for the CloudFormation equivalent
(`Skyscanner/cfripper`, `s3_public_access.py`) — cited for provenance, same as the CFN sibling;
detection logic and test fixtures here are original, developed independently for Terraform's HCL
shape.

Suppress an audited case (e.g. a deliberately public static-website bucket) with
`# security: allow-s3-canned-acl` anywhere in the resource block carrying the `acl` attribute.
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
    top_level_attribute_text,
)

# Anchored to the `acl` attribute line itself (not a substring elsewhere in the block); the
# captured value is checked against the public-ACL set below as an exact, case-sensitive match —
# never a loose substring (a value like "public-read-extra" cannot exist in the real enum, but the
# anchoring keeps the match honest regardless).
_ACL_ATTR = re.compile(r'(?m)^[^\S\n]*acl\s*=\s*"(?P<value>[^"]*)"')
_PUBLIC_ACLS = frozenset({"public-read", "public-read-write", "authenticated-read"})
_BUCKET_REF = re.compile(r"(?m)^[^\S\n]*bucket\s*=\s*aws_s3_bucket\.(?P<name>[A-Za-z0-9_-]+)\.")
_PRAGMA = re.compile(r"#\s*security:\s*allow-s3-canned-acl")

_STANDARDS = ["OWASP:A01", "CWE-284"]


class S3BucketCannedAclGuard(Guard):
    id = "s3-bucket-canned-acl"
    title = "S3 bucket AccessControl is not set to a public canned ACL (PublicRead/PublicReadWrite)"
    area = "Cloud & IaC"

    # s3_canned_acl.tf: aws_s3_bucket_acl with acl = "public-read" -> fires
    # s3-bucket-canned-acl/acl-resource.
    canary_plant = CanaryPlant(
        files={
            "s3_canned_acl.tf": (
                # Resource label deliberately NOT "canary" — aws_observability_hygiene's own
                # canary cross-matches ANY aws_s3_bucket resource named "canary" across the
                # whole merged canary repo; a unique label avoids that cross-guard collision
                # (see s3_mfa_delete_disabled.py's canary_plant for the concrete incident).
                'resource "aws_s3_bucket" "canned_acl_canary" {\n'
                '  bucket = "canary-canned-acl-bucket"\n'
                "}\n"
                "\n"
                'resource "aws_s3_bucket_acl" "canned_acl_canary" {\n'
                "  bucket = aws_s3_bucket.canned_acl_canary.id\n"
                '  acl    = "public-read"\n'
                "}\n"
            ),
        },
        expects=frozenset({"s3-bucket-canned-acl/acl-resource"}),
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
        for resource_type, resource_name, start, body in iter_terraform_resources(text):
            if resource_type == "aws_s3_bucket":
                rule = "s3-bucket-canned-acl/inline-acl-attribute"
                subject = f"aws_s3_bucket.{resource_name}"
            elif resource_type == "aws_s3_bucket_acl":
                rule = "s3-bucket-canned-acl/acl-resource"
                subject = f"aws_s3_bucket_acl.{resource_name}"
            else:
                continue

            body_text = "\n".join(line for _, line in body)
            if pragma_present(_PRAGMA, body_text, dialect="hcl"):
                continue

            # Fires when ANY `acl` line in the body carries a public value, wherever it sits and
            # whatever precedes it (fail-closed: the brace scanner behind top_level_attribute_text
            # does not understand `/* */`, so reading through it alone let a `{` in a block
            # comment hide the attribute). The top-level view adds a one-line resource's own
            # `acl`, which does not start its line.
            acl = next(
                (
                    m.group("value")
                    for view in (body_text, top_level_attribute_text(body_text))
                    for m in _ACL_ATTR.finditer(view)
                    if m.group("value") in _PUBLIC_ACLS
                ),
                None,
            )
            if acl is None:
                continue

            bucket_name = None
            if resource_type == "aws_s3_bucket_acl":
                ref = _BUCKET_REF.search(body_text)
                if ref is not None:
                    bucket_name = ref.group("name")

            target = f"aws_s3_bucket.{bucket_name}" if bucket_name else subject
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}:{start}",
                    message=(
                        f"`{subject}` sets `acl = \"{acl}\"` on {target}. This legacy canned ACL "
                        "grants "
                        + (
                            "read"
                            if acl == "public-read"
                            else "read and write" if acl == "public-read-write"
                            else "read"
                        )
                        + " access to "
                        + (
                            "anyone, including anonymous, unauthenticated requests"
                            if acl != "authenticated-read"
                            else "any authenticated AWS user in any AWS account, not just this one"
                        )
                        + "."
                    ),
                    remediation=(
                        'Remove the public canned ACL — set `acl = "private"` (or omit the '
                        "attribute) and use a scoped bucket policy or presigned URLs for any "
                        "access that must be granted. Suppress an audited exception (e.g. a "
                        "deliberately public static-website bucket) with "
                        "`# security: allow-s3-canned-acl` anywhere in the resource block."
                    ),
                    rule=rule,
                    standards=list(_STANDARDS),
                )
            )
        return out
