"""Guard: CloudFormation EC2 subnet auto-assigns public IPs on instance launch (checklist §7).

`AWS::EC2::Subnet` resources support a `MapPublicIpOnLaunch` property — when `true`, EVERY EC2
instance launched into that subnet automatically receives a public IP address, even if the launch
config (or the ASG/launch template behind it) never asked for one. That silently widens the network
exposure of anything deployed there, independent of whatever the instance's own security groups or
NACLs say — the subnet-level setting overrides the instance author's intent.

Pattern verified against cfn_nag's real source (`EC2SubnetMapPublicIpOnLaunchRule.rb`, rule `W33`,
`stelligent/cfn_nag`) — cited for provenance; detection logic and test fixtures here are original,
developed independently against the pattern description.

Fires MEDIUM when an `AWS::EC2::Subnet` resource's block contains `MapPublicIpOnLaunch: true` /
`"MapPublicIpOnLaunch": true`. A missing property is NOT flagged: AWS's actual default for a new
subnet's auto-assign-public-IP setting depends on how the subnet's VPC itself was created (a
default VPC's default subnets have it on; a non-default VPC's subnets default it to off), so the
property being absent from the template is not itself evidence of the vulnerable behavior — only
an explicit `true` is an unambiguous, textually-verifiable hit.

Suppress an audited case (e.g. a deliberately public-facing subnet, such as a load-balancer subnet
where every instance is meant to be internet-reachable) with a comment containing
`security: allow-ec2-subnet-public-ip` anywhere in the resource's block (YAML `#` comment; not
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

_MAP_PUBLIC_IP_TRUE = re.compile(r'"?MapPublicIpOnLaunch"?\s*:\s*true\b', re.IGNORECASE)
_PRAGMA = "security: allow-ec2-subnet-public-ip"

_STANDARDS = ["OWASP:A05"]


class CfnEc2SubnetPublicIpGuard(Guard):
    id = "cfn-ec2-subnet-public-ip"
    title = "EC2 subnet auto-assigns public IPs on instance launch (CloudFormation)"
    area = "Cloud & IaC"

    # cfn_subnet.yaml: AWS::EC2::Subnet with MapPublicIpOnLaunch: true -> fires
    # cfn-ec2-subnet-public-ip/map-public-ip-true.
    canary_plant = CanaryPlant(
        files={
            "cfn_subnet.yaml": (
                "AWSTemplateFormatVersion: '2010-09-09'\n"
                "Resources:\n"
                "  CanarySubnet:\n"
                "    Type: AWS::EC2::Subnet\n"
                "    Properties:\n"
                "      CidrBlock: 10.0.1.0/24\n"
                "      VpcId: vpc-canary\n"
                "      MapPublicIpOnLaunch: true\n"
            ),
        },
        expects=frozenset({
            "cfn-ec2-subnet-public-ip/map-public-ip-true",
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
            if resource.resource_type != "AWS::EC2::Subnet":
                continue
            if pragma_present(_PRAGMA, resource.block, dialect=resource.pragma_dialect):
                continue
            if not _MAP_PUBLIC_IP_TRUE.search(resource.block):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=f"{rel(root, f)}",
                    message=(
                        f"`{resource.logical_id}` (AWS::EC2::Subnet) sets "
                        "`MapPublicIpOnLaunch: true`. Every EC2 instance launched into this "
                        "subnet automatically receives a public IP address, even if its own "
                        "launch config never requested one — widening the network exposure of "
                        "anything deployed there regardless of the instance's own security "
                        "group or NACL configuration."
                    ),
                    remediation=(
                        "Set `MapPublicIpOnLaunch: false` (or remove the property) unless every "
                        "instance in this subnet is intentionally internet-facing. Suppress an "
                        "audited exception (e.g. a deliberate public-facing subnet) with a "
                        "`security: allow-ec2-subnet-public-ip` comment anywhere in the "
                        "resource (YAML templates only)."
                    ),
                    rule="cfn-ec2-subnet-public-ip/map-public-ip-true",
                    standards=list(_STANDARDS),
                )
            )
        return out
