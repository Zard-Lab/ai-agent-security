"""Guard: Terraform S3 bucket with a public-access-block control not enforced (checklist §6a).

    resource "aws_s3_bucket_public_access_block" "app" {
      bucket = aws_s3_bucket.app.id
      # all four controls omitted -> the Terraform AWS provider defaults them to FALSE
      # -> this resource provides NO protection at all
    }

AWS's S3 "Block Public Access" feature has four independent controls
(`block_public_acls`, `block_public_policy`, `ignore_public_acls`,
`restrict_public_buckets`) that together prevent a bucket ACL or bucket policy from
ever making the bucket's objects public — even if a later change to the bucket's own
policy or ACL tries to. Leaving any one of the four unenforced re-opens that specific
path to a public bucket, which is how a huge number of real-world S3 data leaks have
happened: a developer (or a later teammate) accidentally applies a public ACL or
policy, and nothing stops it. CWE-284 (Improper Access Control), OWASP:A05.

**Critically, the Terraform AWS provider defaults all four controls to `false`** (unlike
the AWS Console, which defaults new buckets to all-on). So a control that is *omitted*
is just as unprotected as one explicitly set to `false` — the common real-world mistake
is an `aws_s3_bucket_public_access_block` that sets only `bucket` and none of the four
controls, which silently provides no protection. This guard therefore fires HIGH for
each of the four controls that is not *explicitly* enabled — whether it is set to `false`
or omitted entirely. A control set to `true` (or to a non-literal value such as a
variable/expression, which this guard can't evaluate and conservatively treats as
addressed) does not fire.

Suppress an audited case (e.g. a deliberately public static-asset bucket) with
`# security: allow-s3-public-access` anywhere in the resource block.
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

_CONTROLS = (
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
)
# Any assignment of one of the four controls, capturing its value token so we can tell
# `= true` (enforced) from `= false` (explicitly disabled) from anything else.
_ATTR_ASSIGN = re.compile(
    r"\b(?P<attr>block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)"
    r"\s*=\s*(?P<val>\S+)"
)
_PRAGMA = re.compile(r"#\s*security:\s*allow-s3-public-access")

_STANDARDS = ["OWASP:A05", "CWE-284"]


class S3PublicAccessBlockDisabledGuard(Guard):
    id = "s3-public-access-block-disabled"
    title = "S3 public-access-block control not enforced"
    area = "Cloud & IaC"

    # s3_access.tf: aws_s3_bucket_public_access_block with block_public_acls = false ->
    # fires s3-public-access-block-disabled. Must NOT contain: allow-s3-public-access pragma.
    canary_plant = CanaryPlant(
        files={
            "s3_access.tf": (
                'resource "aws_s3_bucket_public_access_block" "canary" {\n'
                "  block_public_acls = false\n"
                "}\n"
            ),
        },
        expects=frozenset({"s3-public-access-block-disabled/control-disabled"}),
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
            if resource_type != "aws_s3_bucket_public_access_block":
                continue
            body_text = "\n".join(line for _, line in body)
            # A single pragma anywhere in the block suppresses the whole resource (e.g. a
            # deliberately public bucket) — an omitted control has no line of its own to
            # anchor a per-line pragma to.
            if pragma_present(_PRAGMA, body_text, dialect="hcl"):
                continue
            # Classify each control: explicit `= false` (with its line), some other explicit
            # value (`= true`, or a variable/expression this guard can't evaluate → treated
            # as addressed), or omitted entirely.
            false_line: dict[str, int] = {}
            addressed: set[str] = set()
            for lineno, line in body:
                if line.lstrip().startswith(("#", "//")):
                    continue
                m = _ATTR_ASSIGN.search(line)
                if not m:
                    continue
                attr = m.group("attr")
                if m.group("val").rstrip(",").lower() == "false":
                    false_line.setdefault(attr, lineno)
                else:
                    addressed.add(attr)
            for control in _CONTROLS:
                if control in addressed:
                    continue
                if control in false_line:
                    lineno = false_line[control]
                    reason = f"sets `{control} = false`"
                else:
                    lineno = start_line
                    reason = (
                        f"does not set `{control}` (the Terraform AWS provider defaults it "
                        "to `false`)"
                    )
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title=self.title,
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            f"`aws_s3_bucket_public_access_block.{resource_name}` {reason}, "
                            "leaving a path open to a public bucket. AWS's Block Public Access "
                            "feature exists specifically so a later accidental public ACL or "
                            "bucket policy can't actually make the bucket public — each of its "
                            "four controls must be explicitly `true`, because the Terraform "
                            "provider defaults them all to `false`."
                        ),
                        remediation=(
                            f"Set `{control} = true` unless this bucket is deliberately public "
                            "(e.g. static website assets, in which case scope the exception "
                            "narrowly and document why). Suppress an audited exception with "
                            "`# security: allow-s3-public-access` anywhere in the block."
                        ),
                        rule="s3-public-access-block-disabled/control-disabled",
                        standards=list(_STANDARDS),
                    )
                )
        return out
