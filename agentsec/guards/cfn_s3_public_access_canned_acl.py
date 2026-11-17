"""Guard: CloudFormation S3 bucket using a public canned ACL (checklist §6a).

A DIFFERENT mechanism from the existing `s3-bucket-policy-wildcard-principal` guard: that guard
looks for an explicit bucket-policy statement granting an action to `Principal: "*"`. This guard
looks for S3's older, legacy **canned ACL** mechanism — the `AccessControl` property on an
`AWS::S3::Bucket` resource itself, set to one of the two dangerous predefined ACLs (`PublicRead` /
`PublicReadWrite`). A bucket can be made public through either mechanism independently, so both are
distinct checklist items with distinct guards; a template that sets neither, one, or both is
possible.

Pattern verified against cfripper's real source (`s3_public_access.py`, `Skyscanner/cfripper`) —
cited for provenance; detection logic and test fixtures here are original, developed independently
against the pattern description.

Fires HIGH when an `AWS::S3::Bucket` resource's block contains `AccessControl: PublicRead` or
`AccessControl: PublicReadWrite` (YAML) / `"AccessControl": "PublicRead"` or
`"AccessControl": "PublicReadWrite"` (JSON) — the two canned ACL values that grant read (or
read+write) access to everyone, including anonymous, unauthenticated requests. Other named ACLs
(`Private`, `AuthenticatedRead`, `BucketOwnerFullControl`, ...) are not public in this sense and
must not fire. `PublicRead` is a strict string prefix of `PublicReadWrite`, so the two are matched
as distinct, anchored enum values (not a loose substring match) to avoid a third, unrelated value
that merely contains the text "Public" being mistaken for one of these two.

Suppress an audited case (e.g. a deliberately public static-website bucket) with a comment
containing `security: allow-s3-public-access-canned-acl` anywhere in the resource's block (YAML `#`
comment; not meaningful in JSON, which has no comment syntax — a JSON template can't carry this
pragma at all, a known, documented limitation shared by every CFN guard in this batch).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.cfn import cfn_resources
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_files, pragma_present, read, rel

# A trailing `\b` word boundary anchors the exact enum value: "PublicRead" is immediately followed
# by "Write" (another word char) inside "PublicReadWrite", so there is no boundary there and
# _PUBLIC_READ does NOT match it — while `_PUBLIC_READ_WRITE` (checked first, below) does. Both
# still tolerate a trailing quote/comma (JSON) or newline (YAML) after the value, since a comma or
# newline is itself a non-word character and satisfies the boundary. No third, unrelated value that
# merely contains the substring "Public" (e.g. a hypothetical `PublicReadSomethingElse`) can be
# mistaken for either of these two specific, dangerous canned ACLs.
_PUBLIC_READ = re.compile(r'"?AccessControl"?\s*:\s*["\']?PublicRead\b')
_PUBLIC_READ_WRITE = re.compile(r'"?AccessControl"?\s*:\s*["\']?PublicReadWrite\b')
_PRAGMA = "security: allow-s3-public-access-canned-acl"

_STANDARDS = ["OWASP:A01", "CWE-284"]


class CfnS3PublicAccessCannedAclGuard(Guard):
    id = "cfn-s3-public-access-canned-acl"
    title = "S3 bucket AccessControl set to a public canned ACL (CloudFormation)"
    area = "Cloud & IaC"

    # cfn_s3_public_acl.yaml: AWS::S3::Bucket with AccessControl: PublicReadWrite -> fires
    # cfn-s3-public-access-canned-acl/public-read-write.
    canary_plant = CanaryPlant(
        files={
            "cfn_s3_public_acl.yaml": (
                "AWSTemplateFormatVersion: '2010-09-09'\n"
                "Resources:\n"
                "  CanaryBucket:\n"
                "    Type: AWS::S3::Bucket\n"
                "    Properties:\n"
                "      AccessControl: PublicReadWrite\n"
            ),
        },
        expects=frozenset({
            "cfn-s3-public-access-canned-acl/public-read-write",
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
            if resource.resource_type != "AWS::S3::Bucket":
                continue
            if pragma_present(_PRAGMA, resource.block, dialect=resource.pragma_dialect):
                continue
            if _PUBLIC_READ_WRITE.search(resource.block):
                acl, rule = "PublicReadWrite", "cfn-s3-public-access-canned-acl/public-read-write"
            elif _PUBLIC_READ.search(resource.block):
                acl, rule = "PublicRead", "cfn-s3-public-access-canned-acl/public-read"
            else:
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}",
                    message=(
                        f"`{resource.logical_id}` (AWS::S3::Bucket) sets "
                        f"`AccessControl: {acl}`. This legacy canned ACL grants "
                        + ("read" if acl == "PublicRead" else "read and write")
                        + " access to anyone, including anonymous, unauthenticated requests."
                    ),
                    remediation=(
                        "Remove the public canned ACL — set `AccessControl: Private` (or omit the "
                        "property) and use a scoped bucket policy or presigned URLs for any access "
                        "that must be granted. Suppress an audited exception with a "
                        "`security: allow-s3-public-access-canned-acl` comment anywhere in the "
                        "resource (YAML templates only)."
                    ),
                    rule=rule,
                    standards=list(_STANDARDS),
                )
            )
        return out
