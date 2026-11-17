"""Guard: CloudFormation ECR repository without scan-on-push vulnerability scanning (checklist §7).

The CloudFormation counterpart to one specific check inside agentsec's existing (Terraform-only)
`ecr-repository-hygiene` guard — same requirement (an ECR repository with no automated vulnerability
scan on push lets an image with known CVEs reach the registry, and from there a deployment, with no
check at all), a genuinely different code surface (CFN's `AWS::ECR::Repository` resource instead of
Terraform's `aws_ecr_repository`), so it extends the same `7-ecr-repository-hygiene` checklist item
rather than duplicating it. This guard is deliberately narrower than its Terraform sibling: it
covers ONLY scan-on-push, not the sibling's other two bundled checks (immutable tags, lifecycle
policy) — those are Terraform-surface concerns this guard does not attempt to replicate for CFN.

Pattern verified against cfn_nag's real source (`ECRRepositoryScanOnPushRule.rb`, rule `W79`,
`stelligent/cfn_nag`) — cited for provenance; detection logic and test fixtures here are original,
developed independently against the pattern description.

Fires MEDIUM when an `AWS::ECR::Repository` resource does NOT contain `ScanOnPush: true` /
`"ScanOnPush": true` anywhere in its block — whether `ImageScanningConfiguration` is missing
entirely, or present but `ScanOnPush` isn't `true`.

Suppress an audited case (e.g. scanning enforced by an external pipeline stage instead) with a
comment containing `security: allow-ecr-scan-on-push` anywhere in the resource's block (YAML `#`
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

_SCAN_ON_PUSH_TRUE = re.compile(r'"?ScanOnPush"?\s*:\s*true\b', re.IGNORECASE)
_PRAGMA = "security: allow-ecr-scan-on-push"

_STANDARDS = ["OWASP:A05", "OWASP:A06", "OWASP:A08"]


class CfnEcrScanOnPushGuard(Guard):
    id = "cfn-ecr-scan-on-push"
    title = "ECR repository missing vulnerability scanning on push (CloudFormation)"
    area = "Cloud & IaC"

    # cfn_ecr_repo.yaml: AWS::ECR::Repository with no ImageScanningConfiguration -> fires
    # cfn-ecr-scan-on-push/scan-on-push-disabled.
    canary_plant = CanaryPlant(
        files={
            "cfn_ecr_repo.yaml": (
                "AWSTemplateFormatVersion: '2010-09-09'\n"
                "Resources:\n"
                "  CanaryRepo:\n"
                "    Type: AWS::ECR::Repository\n"
                "    Properties:\n"
                "      RepositoryName: canary-image\n"
            ),
        },
        expects=frozenset({
            "cfn-ecr-scan-on-push/scan-on-push-disabled",
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
            if resource.resource_type != "AWS::ECR::Repository":
                continue
            if pragma_present(_PRAGMA, resource.block, dialect=resource.pragma_dialect):
                continue
            if _SCAN_ON_PUSH_TRUE.search(resource.block):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=f"{rel(root, f)}",
                    message=(
                        f"`{resource.logical_id}` (AWS::ECR::Repository) does not set "
                        "`ImageScanningConfiguration.ScanOnPush: true`. An image with known CVEs "
                        "can reach the registry, and from there a deployment, with no automated "
                        "vulnerability check."
                    ),
                    remediation=(
                        "Add `ImageScanningConfiguration: {ScanOnPush: true}` to the resource's "
                        "Properties. Suppress an audited exception with a "
                        "`security: allow-ecr-scan-on-push` comment anywhere in the resource "
                        "(YAML templates only)."
                    ),
                    rule="cfn-ecr-scan-on-push/scan-on-push-disabled",
                    standards=list(_STANDARDS),
                )
            )
        return out
