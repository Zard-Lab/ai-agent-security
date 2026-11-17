"""Guard: CloudFormation RDS instance directly reachable from the internet (checklist §7).

The CloudFormation counterpart to agentsec's existing (Terraform-only) `rds-publicly-accessible`
guard — same requirement (`PubliclyAccessible: true` on an `AWS::RDS::DBInstance` assigns the
database a public IP and opens its port to any address that can also pass the attached security
group, one of the most common real-world causes of an internet-exposed production database), a
genuinely different code surface (CFN's `AWS::RDS::DBInstance` resource instead of Terraform's
`aws_db_instance`), so it extends the same `7-rds-not-publicly-accessible` checklist item rather
than duplicating it.

Pattern verified against cfn_nag's real source (`RDSInstancePubliclyAccessibleRule.rb`, rule
`F22`, `stelligent/cfn_nag`) — cited for provenance; detection logic and test fixtures here are
original, developed independently against the pattern description.

Fires HIGH when an `AWS::RDS::DBInstance` resource's block has `PubliclyAccessible: true` /
`"PubliclyAccessible": true`. A resource that omits the property entirely, or sets it to `false`,
does NOT fire — mirroring the Terraform sibling guard's own convention (its docstring: "The
Terraform AWS provider defaults `publicly_accessible` to `false`, so silence is the safe state"),
kept for consistency between the two guards on the same checklist item. This is a deliberate
default-handling choice, not a claim about AWS's actual CFN-level default: `AWS::RDS::DBInstance`'s
real default `PubliclyAccessible` value depends on whether the DB subnet group sits in a public or
private VPC subnet, which this guard cannot determine from the template alone — see the wiki design
doc for the honest false-negative disclosure this creates.

Suppress an audited case (e.g. a deliberately public read-replica behind its own firewalling) with
a comment containing `security: allow-rds-public` anywhere in the resource's block (YAML `#`
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

_PUBLICLY_ACCESSIBLE_TRUE = re.compile(r'"?PubliclyAccessible"?\s*:\s*true\b', re.IGNORECASE)
_PRAGMA = "security: allow-rds-public"

_STANDARDS = ["OWASP:A05", "CWE-284"]


class CfnRdsPubliclyAccessibleGuard(Guard):
    id = "cfn-rds-publicly-accessible"
    title = "RDS instance directly reachable from the internet (CloudFormation)"
    area = "Cloud & IaC"

    # cfn_rds_public.yaml: AWS::RDS::DBInstance with PubliclyAccessible: true -> fires
    # cfn-rds-publicly-accessible/publicly-accessible-true.
    canary_plant = CanaryPlant(
        files={
            "cfn_rds_public.yaml": (
                "AWSTemplateFormatVersion: '2010-09-09'\n"
                "Resources:\n"
                "  CanaryDb:\n"
                "    Type: AWS::RDS::DBInstance\n"
                "    Properties:\n"
                "      Engine: postgres\n"
                "      PubliclyAccessible: true\n"
            ),
        },
        expects=frozenset({
            "cfn-rds-publicly-accessible/publicly-accessible-true",
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
            if resource.resource_type != "AWS::RDS::DBInstance":
                continue
            if pragma_present(_PRAGMA, resource.block, dialect=resource.pragma_dialect):
                continue
            if not _PUBLICLY_ACCESSIBLE_TRUE.search(resource.block):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}",
                    message=(
                        f"`{resource.logical_id}` (AWS::RDS::DBInstance) sets "
                        "`PubliclyAccessible: true`, assigning the database a public IP address "
                        "reachable from the internet. Combined with any permissive security-group "
                        "rule, this is one of the most common causes of a real-world exposed "
                        "production database."
                    ),
                    remediation=(
                        "Remove `PubliclyAccessible: true` (or set it to `false`) and reach the "
                        "database through a VPN, bastion host, or a security group scoped to the "
                        "application's own subnet. Suppress an audited exception with a "
                        "`security: allow-rds-public` comment anywhere in the resource (YAML "
                        "templates only)."
                    ),
                    rule="cfn-rds-publicly-accessible/publicly-accessible-true",
                    standards=list(_STANDARDS),
                )
            )
        return out
