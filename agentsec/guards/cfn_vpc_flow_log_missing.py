"""Guard: CloudFormation VPC with no AWS::EC2::FlowLog resource anywhere in the template.

Without VPC Flow Logs, network traffic to/from ENIs in the VPC generates no audit trail — an
attacker's lateral movement, data exfiltration, or reconnaissance inside the VPC is invisible
after the fact. This is a **new** checklist item (`7-cfn-vpc-flow-log-missing`) — no existing
agentsec item covers VPC flow logging, CloudFormation or otherwise.

Pattern verified against cfn_nag's real source (`VpcHasFlowLogRule.rb`, rule `W60` in the
research batch) — cited for provenance; detection logic and test fixtures here are original,
developed independently against the pattern description.

Fires MEDIUM **once per template file** when the file's `cfn_resources()` list contains at least
one `AWS::EC2::VPC` resource and zero `AWS::EC2::FlowLog` resources anywhere in the same file.
This is a deliberately **template-wide presence check**, not a per-VPC resolution: a `FlowLog`
resource's `ResourceId`/`Ref` points at whatever VPC (or subnet, or ENI) it monitors, and
resolving that back to a specific VPC's logical id would need real cross-resource reference
reasoning this codebase's text-block scanning does not do (see `agentsec/cfn.py`'s module
docstring for the same limitation applied elsewhere). A template-level "is there a VPC with NO
FlowLog resource declared anywhere in the same template" check is the defensible, honestly-scoped
v1 — see the wiki design doc for the bypasses this leaves open (a multi-VPC template where only
some VPCs lack a FlowLog stays silent; a FlowLog declared in a separate/nested template
false-positives).

Suppress an audited case (e.g. flow logs shipped via a separate stack, or intentionally omitted
for a throwaway/sandbox VPC) with a comment containing `security: allow-vpc-flow-log-missing`
anywhere in the FILE (not scoped to one resource's block, since this is a file-level check) — YAML
templates only; JSON has no comment syntax, so a JSON template can't carry this pragma at all, a
known, documented limitation shared by every CFN guard in this batch.
"""
from __future__ import annotations

from pathlib import Path

from agentsec.cfn import cfn_resources
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    read,
    rel,
)

_PRAGMA = "security: allow-vpc-flow-log-missing"

_STANDARDS = ["OWASP:A09", "CWE-778"]


class CfnVpcFlowLogMissingGuard(Guard):
    id = "cfn-vpc-flow-log-missing"
    title = "VPC has no AWS::EC2::FlowLog resource (CloudFormation)"
    area = "Cloud & IaC"

    # cfn_vpc_no_flow_log.yaml: AWS::EC2::VPC with no AWS::EC2::FlowLog anywhere in the template
    # -> fires cfn-vpc-flow-log-missing/no-flow-log.
    canary_plant = CanaryPlant(
        files={
            "cfn_vpc_no_flow_log.yaml": (
                "AWSTemplateFormatVersion: '2010-09-09'\n"
                "Resources:\n"
                "  CanaryVpc:\n"
                "    Type: AWS::EC2::VPC\n"
                "    Properties:\n"
                "      CidrBlock: 10.0.0.0/16\n"
            ),
        },
        expects=frozenset({
            "cfn-vpc-flow-log-missing/no-flow-log",
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
        text = read(f)
        if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
            return []
        resources = cfn_resources(text)
        vpcs = [r for r in resources if r.resource_type == "AWS::EC2::VPC"]
        if not vpcs:
            return []
        has_flow_log = any(r.resource_type == "AWS::EC2::FlowLog" for r in resources)
        if has_flow_log:
            return []
        vpc_ids = ", ".join(f"`{r.logical_id}`" for r in vpcs)
        return [
            Finding(
                check_id=self.id,
                severity="medium",
                title=self.title,
                location=f"{rel(root, f)}",
                message=(
                    f"This template defines a VPC ({vpc_ids}, AWS::EC2::VPC) but no "
                    "AWS::EC2::FlowLog resource anywhere in the same file. Without VPC Flow "
                    "Logs, network traffic to/from ENIs in the VPC generates no audit trail — "
                    "lateral movement, data exfiltration, or reconnaissance inside the VPC is "
                    "invisible after the fact."
                ),
                remediation=(
                    "Add an AWS::EC2::FlowLog resource targeting the VPC (ResourceType: VPC, "
                    "ResourceId: the VPC's logical id) with a destination (CloudWatch Logs or "
                    "S3). Suppress an audited exception with a `security: "
                    "allow-vpc-flow-log-missing` comment anywhere in the file (YAML templates "
                    "only)."
                ),
                rule="cfn-vpc-flow-log-missing/no-flow-log",
                standards=list(_STANDARDS),
            )
        ]
