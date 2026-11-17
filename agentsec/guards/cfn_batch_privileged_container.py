"""Guard: AWS Batch job definition runs its container in privileged mode (§6c).

`ContainerProperties.Privileged: true` on an `AWS::Batch::JobDefinition` is the CloudFormation/AWS
Batch analogue of Kubernetes' `securityContext.privileged: true` (see `k8s_privileged_container.py`
for that sibling's threat framing) — a genuinely different resource type (AWS Batch job containers,
not K8s pods), but the same underlying container-escape risk: a privileged container gets full
access to the host's devices and kernel capabilities, so a container breakout to full host/instance
compromise is straightforward if the container is ever compromised (a supply-chain-compromised
image, an app-level RCE in the job's own code, a poisoned job input). This is adjacent to the
existing `6c-k8s-privileged-container` checklist item conceptually but ships as its own new item,
`6c-cfn-batch-privileged-container`, since the resource type and code surface are entirely
different.

Pattern verified against cfripper's real source (`BatchJobDefinitionContainerPropertiesPrivilegedRule.rb`,
`Skyscanner/cfripper`, rule `W34`) — cited for provenance; detection logic and test fixtures here
are original, developed independently against the pattern description.

Fires CRITICAL when an `AWS::Batch::JobDefinition` resource's block contains `Privileged: true` /
`"Privileged": true` (nested under `ContainerProperties`) — a pragmatic text-block scope, since a
resource is unlikely to carry any OTHER unrelated `Privileged: true` key, matching it anywhere in
the resource's own block is a reasonable, low-FP-risk scope, consistent with this codebase's
existing precision/scope tradeoffs (see `agentsec.cfn`'s module docstring).

Suppress an audited case with a comment containing `security: allow-cfn-batch-privileged-container`
anywhere in the resource's block (YAML `#` comment; not meaningful in JSON, which has no comment
syntax — a JSON template can't carry this pragma at all, a known, documented limitation shared by
every CFN guard in this batch).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.cfn import cfn_resources
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_files, pragma_present, read, rel

_PRIVILEGED_TRUE = re.compile(r'"?Privileged"?\s*:\s*true\b', re.IGNORECASE)
_PRAGMA = "security: allow-cfn-batch-privileged-container"

_STANDARDS = ["OWASP:A05"]


class CfnBatchPrivilegedContainerGuard(Guard):
    id = "cfn-batch-privileged-container"
    title = "AWS Batch job definition container runs in privileged mode (CloudFormation)"
    area = "Cloud & IaC"

    # cfn_batch_job.yaml: AWS::Batch::JobDefinition with ContainerProperties.Privileged: true
    # -> fires cfn-batch-privileged-container/privileged-true.
    canary_plant = CanaryPlant(
        files={
            "cfn_batch_job.yaml": (
                "AWSTemplateFormatVersion: '2010-09-09'\n"
                "Resources:\n"
                "  CanaryBatchJob:\n"
                "    Type: AWS::Batch::JobDefinition\n"
                "    Properties:\n"
                "      Type: container\n"
                "      ContainerProperties:\n"
                "        Image: canary-image:latest\n"
                "        Privileged: true\n"
            ),
        },
        expects=frozenset({
            "cfn-batch-privileged-container/privileged-true",
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
            if resource.resource_type != "AWS::Batch::JobDefinition":
                continue
            if pragma_present(_PRAGMA, resource.block, dialect=resource.pragma_dialect):
                continue
            if not _PRIVILEGED_TRUE.search(resource.block):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="critical",
                    title=self.title,
                    location=f"{rel(root, f)}",
                    message=(
                        f"`{resource.logical_id}` (AWS::Batch::JobDefinition) sets "
                        "`ContainerProperties.Privileged: true`. This disables container "
                        "isolation for the job's container — full host device/kernel access — "
                        "making a container breakout to host/instance compromise straightforward "
                        "if the container is ever compromised."
                    ),
                    remediation=(
                        "Remove `Privileged: true` from `ContainerProperties`. If specific host "
                        "access is genuinely needed, grant only the exact Linux capability the job "
                        "requires instead of full privileged mode. Suppress an intentional, "
                        "reviewed case with a `security: allow-cfn-batch-privileged-container` "
                        "comment anywhere in the resource (YAML templates only)."
                    ),
                    rule="cfn-batch-privileged-container/privileged-true",
                    standards=list(_STANDARDS),
                )
            )
        return out
