"""Guard: CloudFormation S3 bucket without versioning enabled (checklist §7).

The CloudFormation counterpart to agentsec's existing (Terraform-only) `aws-observability-hygiene`
guard's S3-versioning check (checklist item `7-s3-versioning-missing`) — same requirement (an S3
bucket with no versioning means an accidental delete, an accidental overwrite, or a
ransomware-style mass-encrypt of the bucket's objects has no rollback path — the previous object
version is simply gone), a genuinely different code surface (CFN's `AWS::S3::Bucket` resource and
its inline `VersioningConfiguration` property, instead of Terraform's split
`aws_s3_bucket`/`aws_s3_bucket_versioning` resources), so it extends the same checklist item rather
than duplicating it.

Pattern verified against cfripper's real source (`s3_object_versioning.py`, `Skyscanner/cfripper`)
— cited for provenance; detection logic and test fixtures here are original, developed
independently against the pattern description.

Fires MEDIUM when an `AWS::S3::Bucket` resource's `VersioningConfiguration` property — carved out
on its own, not the whole resource block (Dean's review repro) — does not contain the
exact string `Status: Enabled` (YAML) / `"Status": "Enabled"` (JSON), with reasonable whitespace
flexibility around the colon: whether `VersioningConfiguration` is missing entirely, or present
with `Status: Suspended` or no `Status` at all. The match is case-sensitive, per CFN's own
`Status` enum (`Enabled` / `Suspended`).

Scoping the match to `VersioningConfiguration` specifically (rather than searching the whole
resource block for a bare `Status: Enabled`) closes a false negative: an `AWS::S3::Bucket` commonly
carries its OWN unrelated `Status: Enabled` inside a `LifecycleConfiguration` rule (a lifecycle
rule's enabled/disabled flag, nothing to do with object versioning) — a bucket with lifecycle rules
but genuinely no `VersioningConfiguration` at all used to read as versioned purely because the two
properties share the same `Status: Enabled` string. A rare flow-style single-line
`VersioningConfiguration: {Status: Enabled}` (nothing follows the key on its own line, so the
indentation-scoped carve can't treat it as a nested block) is matched by a narrow fallback pattern
requiring both the key and `Status: Enabled` on that one line — this cannot collide with a sibling
`LifecycleConfiguration` the same way the pre-fix whole-block search could, since the fallback
still anchors on `VersioningConfiguration` specifically.

Suppress an audited case (e.g. a deliberately unversioned scratch bucket) with a comment containing
`security: allow-s3-versioning-missing` anywhere in the resource's block (YAML `#` comment; not
meaningful in JSON, which has no comment syntax — a JSON template can't carry this pragma at all, a
known, documented limitation shared by every CFN guard in this batch).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.cfn import cfn_resources, nested_property_block
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_files, pragma_present, read, rel

_STATUS_ENABLED = re.compile(r'"?Status"?\s*:\s*"?Enabled"?\b')
# The rare flow-style single-line form (`VersioningConfiguration: {Status: Enabled}` / JSON's
# `"VersioningConfiguration": {"Status": "Enabled"}` collapsed onto one line by a hand-written,
# non-`json.dumps`-formatted template) that `nested_property_block` can't carve out as a nested
# block, since nothing follows the key on its own line is exactly what that helper requires.
_VERSIONING_INLINE = re.compile(
    r'"?VersioningConfiguration"?\s*:\s*\{[^{}]*"?Status"?\s*:\s*"?Enabled"?\b'
)
_PRAGMA = "security: allow-s3-versioning-missing"

_STANDARDS = ["OWASP:A05", "CWE-693"]


class CfnS3VersioningMissingGuard(Guard):
    id = "cfn-s3-versioning-missing"
    title = "S3 bucket without versioning enabled (CloudFormation)"
    area = "Cloud & IaC"

    # cfn_s3_bucket.yaml: AWS::S3::Bucket with no VersioningConfiguration -> fires
    # cfn-s3-versioning-missing/no-versioning.
    canary_plant = CanaryPlant(
        files={
            "cfn_s3_bucket.yaml": (
                "AWSTemplateFormatVersion: '2010-09-09'\n"
                "Resources:\n"
                "  CanaryBucket:\n"
                "    Type: AWS::S3::Bucket\n"
                "    Properties:\n"
                "      BucketName: canary-data-bucket\n"
            ),
        },
        expects=frozenset({
            "cfn-s3-versioning-missing/no-versioning",
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
            versioning_block = nested_property_block(resource.block, "VersioningConfiguration")
            if versioning_block and _STATUS_ENABLED.search(versioning_block):
                continue
            if versioning_block is None and _VERSIONING_INLINE.search(resource.block):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=f"{rel(root, f)}",
                    message=(
                        f"`{resource.logical_id}` (AWS::S3::Bucket) does not set "
                        "`VersioningConfiguration` with `Status: Enabled`. An accidental delete, "
                        "an accidental overwrite, or a ransomware-style mass-encrypt of this "
                        "bucket's objects has no rollback path — the previous object version is "
                        "simply gone."
                    ),
                    remediation=(
                        "Add a `VersioningConfiguration: {Status: Enabled}` property to the "
                        "bucket. Suppress an audited exception (e.g. a deliberately unversioned "
                        "scratch bucket) with a `security: allow-s3-versioning-missing` comment "
                        "anywhere in the resource's block (YAML templates only)."
                    ),
                    rule="cfn-s3-versioning-missing/no-versioning",
                    standards=list(_STANDARDS),
                )
            )
        return out
