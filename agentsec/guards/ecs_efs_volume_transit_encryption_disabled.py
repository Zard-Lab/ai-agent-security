"""Guard: Terraform ECS task definition's EFS volume mount without transit encryption
(checklist §7).

    resource "aws_ecs_task_definition" "app" {
      family = "app"

      volume {
        name = "efs-mount"

        efs_volume_configuration {
          file_system_id = aws_efs_file_system.app.id
          # no transit_encryption -> defaults to DISABLED
        }
      }
    }

An ECS task's `volume` block can mount an EFS file system via a nested
`efs_volume_configuration` sub-block. That sub-block's `transit_encryption` attribute
controls whether the NFS traffic between the ECS task and the EFS mount target is wrapped in
TLS. Terraform/AWS defaults this to `"DISABLED"` when omitted, so an unencrypted EFS mount is
silent at `terraform apply` time: anyone positioned on the network path between the task's
ENI and the EFS mount target (another workload in the same VPC, a compromised sidecar, a
misconfigured security-group-based "trusted subnet" assumption) reads the file contents and
any traffic metadata in the clear. CWE-319 (Cleartext Transmission of Sensitive Information),
OWASP:A05.

A non-literal `transit_encryption` value (e.g. a variable reference) cannot be proven unsafe
and stays silent — it must NOT be treated the same as an absent attribute, which does fire.

An `aws_ecs_task_definition` resource can declare MULTIPLE top-level `volume` blocks (one
task can mount several file systems); each is checked independently, and a finding fires
once per offending `volume` block. A `volume` block with no `efs_volume_configuration`
sub-block at all (a plain Docker/host volume, not EFS-backed) is out of scope for this guard
and never fires — this guard only cares about EFS-backed volumes specifically.

Suppress an audited case (e.g. the EFS mount and the task both live in a locked-down,
single-tenant VPC where the in-transit hop is accepted) with
`# security: allow-ecs-efs-plaintext` anywhere in the `aws_ecs_task_definition` resource
block.
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

# Up to two levels of brace nesting inside a `volume { ... }` block — covers the
# `efs_volume_configuration { ... authorization_config { ... } }` real-world shape, not just
# the one-level `efs_volume_configuration { transit_encryption = ... }` form this guard checks.
_VOLUME_BLOCK = re.compile(
    r"\bvolume\s*\{(?P<inner>(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*)\}", re.DOTALL,
)
_EFS_CONFIG_BLOCK = re.compile(
    r"\befs_volume_configuration\s*\{(?P<inner>(?:[^{}]|\{[^{}]*\})*)\}", re.DOTALL,
)
_VOLUME_NAME = re.compile(r'\bname\s*=\s*"(?P<name>[^"]*)"')
_TRANSIT_ENCRYPTION = re.compile(r'\btransit_encryption\s*=\s*"(?P<val>[^"]*)"')
_TRANSIT_ENCRYPTION_PRESENT = re.compile(r"\btransit_encryption\s*=")

_PRAGMA = re.compile(r"#\s*security:\s*allow-ecs-efs-plaintext")

_STANDARDS = ["OWASP:A05", "CWE-319"]


class EcsEfsVolumeTransitEncryptionDisabledGuard(Guard):
    id = "ecs-efs-volume-transit-encryption-disabled"
    title = "ECS task's EFS volume mount is not encrypted in transit"
    area = "Cloud & IaC"

    canary_plant = CanaryPlant(
        files={
            "ecs_efs_volume_transit_encryption_disabled.tf": (
                'resource "aws_ecs_task_definition" "canary" {\n'
                '  family = "canary"\n'
                "\n"
                "  volume {\n"
                '    name = "efs-mount"\n'
                "\n"
                "    efs_volume_configuration {\n"
                "      file_system_id = aws_efs_file_system.canary.id\n"
                "    }\n"
                "  }\n"
                "}\n"
            ),
        },
        expects=frozenset(
            {"ecs-efs-volume-transit-encryption-disabled/missing-encryption"}
        ),
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
            if resource_type != "aws_ecs_task_definition":
                continue
            body_text = "\n".join(line for _, line in body)
            if pragma_present(_PRAGMA, body_text, dialect="hcl"):
                continue
            for volume_match in _VOLUME_BLOCK.finditer(body_text):
                inner = volume_match.group("inner")
                efs_match = _EFS_CONFIG_BLOCK.search(inner)
                if efs_match is None:
                    # Not an EFS-backed volume (plain Docker/host volume) -> out of scope.
                    continue
                efs_inner = efs_match.group("inner")
                transit = _TRANSIT_ENCRYPTION.search(efs_inner)
                if transit is not None:
                    if transit.group("val") != "DISABLED":
                        continue
                elif _TRANSIT_ENCRYPTION_PRESENT.search(efs_inner):
                    # Non-literal value (e.g. a variable) -- cannot be proven unsafe.
                    continue
                name_match = _VOLUME_NAME.search(inner)
                volume_name = name_match.group("name") if name_match else "<unnamed>"
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="medium",
                        title=self.title,
                        location=f"{rel(root, f)}:{start_line}",
                        message=(
                            f"`aws_ecs_task_definition.{resource_name}` volume "
                            f'"{volume_name}" mounts EFS via `efs_volume_configuration` without '
                            "transit encryption enabled — `transit_encryption` is either absent "
                            '(AWS defaults it to `"DISABLED"`) or explicitly set to '
                            '`"DISABLED"`. NFS traffic between the task and the EFS mount target '
                            "is readable in the clear to anyone on the network path."
                        ),
                        remediation=(
                            'Add `transit_encryption = "ENABLED"` to the `efs_volume_configuration` '
                            "block. Suppress an audited case with "
                            "`# security: allow-ecs-efs-plaintext` anywhere in the "
                            "`aws_ecs_task_definition` resource block."
                        ),
                        rule="ecs-efs-volume-transit-encryption-disabled/missing-encryption",
                        standards=list(_STANDARDS),
                    )
                )
        return out
