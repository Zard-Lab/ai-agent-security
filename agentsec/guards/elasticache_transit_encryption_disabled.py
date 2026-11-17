"""Guard: Terraform ElastiCache replication group with transit encryption disabled (§7).

    resource "aws_elasticache_replication_group" "sessions" {
      replication_group_id = "sessions"
      engine                = "redis"
      node_type             = "cache.r6g.large"
      # no transit_encryption_enabled attribute at all -> defaults to false
    }

`transit_encryption_enabled` on `aws_elasticache_replication_group` controls whether clients
talk to the Redis/Valkey cluster over TLS. Like `aws_ebs_volume.encrypted`, it is a plain
top-level attribute that is opt-in and defaults to `false` when never set — `terraform apply`
succeeds either way, so the omission is silent. A cache holding session tokens, rate-limit
counters, or cached query results sent in the clear is readable by anyone who can observe the
network path to the cluster (a shared VPC, a misconfigured security group, a compromised node
on the same subnet). CWE-319 (Cleartext Transmission of Sensitive Information), OWASP:A02.

Fires HIGH when an `aws_elasticache_replication_group` resource block does NOT contain a
literal `transit_encryption_enabled = true` — whether the attribute is missing entirely or
explicitly `false`. A non-literal value (e.g. `transit_encryption_enabled = var.tls`) cannot
be proven unsafe and stays silent.

The default is AWS's own: the `CreateReplicationGroup` API reference documents
`TransitEncryptionEnabled` as "Default: `false`" (PR #1162 round-1 M8). The Terraform provider doc
states no default of its own. For `engine_version` below `7.0.5` the setting can only be chosen at
creation (changing it forces a replacement); from `7.0.5` it can be turned on in place through
`transit_encryption_mode = "preferred"`.

`aws_elasticache_cluster` (a single-node cluster resource) is out of scope: this guard reads
`aws_elasticache_replication_group` only.

Suppress an audited case (e.g. a genuinely non-sensitive cache confined to an isolated,
trusted network) with `# security: allow-elasticache-plaintext` anywhere in the resource
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
    literal_bool_state,
    pragma_present,
    read,
    rel,
    terraform_code_view,
    top_level_attribute_text,
)

_PRAGMA = re.compile(r"#\s*security:\s*allow-elasticache-plaintext")

_STANDARDS = ["OWASP:A02", "CWE-319"]

_RULE_MISSING_ENCRYPTION = "elasticache-transit-encryption-disabled/missing-encryption"


class ElasticacheTransitEncryptionDisabledGuard(Guard):
    id = "elasticache-transit-encryption-disabled"
    title = "ElastiCache replication group has transit encryption disabled"
    area = "Cloud & IaC"

    canary_plant = CanaryPlant(
        files={
            "elasticache_transit_encryption.tf": (
                'resource "aws_elasticache_replication_group" "canary" {\n'
                '  replication_group_id = "canary-sessions"\n'
                '  engine                = "redis"\n'
                '  node_type             = "cache.r6g.large"\n'
                "}\n"
            ),
        },
        expects=frozenset({_RULE_MISSING_ENCRYPTION}),
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
            if resource_type != "aws_elasticache_replication_group":
                continue
            body_text = "\n".join(line for _, line in body)
            if pragma_present(_PRAGMA, body_text, dialect="hcl"):
                continue
            # The resource's own top-level attributes, comments blanked: a same-named key in a
            # `tags` map (one-line or multi-line) is not the attribute (PR #1162 round-4 M2).
            code_body = top_level_attribute_text(terraform_code_view(body_text))
            # A non-literal value (e.g. a variable) cannot be proven unsafe -> stays silent.
            if literal_bool_state("transit_encryption_enabled", code_body) in ("true", "nonliteral"):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}:{start_line}",
                    message=(
                        f"`aws_elasticache_replication_group.{resource_name}` does not set "
                        "`transit_encryption_enabled = true`. This attribute is opt-in and "
                        "defaults to `false` — clients talking to this Redis/Valkey cluster "
                        "over the network do so in the clear, readable by anyone who can "
                        "observe the path to it."
                    ),
                    remediation=(
                        "Add `transit_encryption_enabled = true` to the resource. Suppress an "
                        "audited exception (e.g. a genuinely non-sensitive, network-isolated "
                        "cache) with `# security: allow-elasticache-plaintext` anywhere in the "
                        "resource block."
                    ),
                    rule=_RULE_MISSING_ENCRYPTION,
                    standards=list(_STANDARDS),
                )
            )
        return out
