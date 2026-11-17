"""Guard: Terraform RDS instance directly reachable from the internet (checklist §7).

    resource "aws_db_instance" "app" {
      engine             = "postgres"
      publicly_accessible = true          # anyone on the internet can reach the DB port
      ...
    }

`publicly_accessible = true` on an `aws_db_instance`/`aws_rds_cluster_instance` assigns
the database a public IP and opens its port to any address that can also pass the
attached security group — combined with a permissive security group (or simply the
default AWS behavior of the port being reachable once the instance is public), this is
one of the most common real-world causes of an internet-exposed production database.
CWE-284 (Improper Access Control), OWASP:A05.

Fires HIGH when a `resource "aws_db_instance" "..."`, `resource "aws_rds_cluster_instance" "..."`,
or `resource "aws_redshift_cluster" "..."` block sets `publicly_accessible = true`.
A block that omits the attribute entirely, or sets it to `false`, does not fire — the
Terraform AWS provider defaults `publicly_accessible` to `false`, so silence is the
safe state.

Suppress an audited case (e.g. a deliberately public read-replica behind its own
firewalling) with `# security: allow-rds-public` on the `publicly_accessible` line.

**2026-10-25 (this session's extension):** added `aws_redshift_cluster` to the covered resource
types. Redshift uses the exact same `publicly_accessible` attribute name and the exact same
"fires when true" trigger logic as the RDS resource types above, so this was a one-line addition
to the resource-type set with no other logic changes.

**Redshift's "absent is safe" depends on the AWS provider major version** (PR #1162 round-1 M3).
The provider v6 upgrade guide says "`publicly_accessible` now defaults to `false`" for
`aws_redshift_cluster`; the v5 resource doc said "Default is `true`". So silence on an omitted
attribute is right on provider v6 and later, and a false negative on v5 and earlier, where an
omitted attribute meant a public cluster. This guard assumes v6 and does not read the repo's
`required_providers` pin; firing on absence would be a mass false positive on v6.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    blank_block_comments,
    is_nonproduct_path,
    iter_files,
    iter_terraform_resources,
    pragma_present,
    read,
    rel,
)

_RDS_RESOURCE_TYPES = frozenset(
    {"aws_db_instance", "aws_rds_cluster_instance", "aws_redshift_cluster"}
)
_PUBLICLY_ACCESSIBLE_TRUE = re.compile(r"\bpublicly_accessible\s*=\s*true\b")
_PRAGMA = re.compile(r"#\s*security:\s*allow-rds-public")

_STANDARDS = ["OWASP:A05", "CWE-284"]


class RdsPubliclyAccessibleGuard(Guard):
    id = "rds-publicly-accessible"
    title = "RDS instance directly reachable from the internet"
    area = "Cloud & IaC"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `rds.tf`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # rds.tf: aws_db_instance with publicly_accessible = true -> fires public-instance.
    canary_plant = CanaryPlant(expects=frozenset({"rds-publicly-accessible/public-instance"}))

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
        # Blank `/* … */` HCL block comments before the scan, line- and length-preserving so
        # every offset and line number below is unchanged. The per-line skip below handles `#`
        # and `//` only, so a commented-OUT `/* publicly_accessible = true */` still fired
        # (#441 review) — the guard reported a misconfiguration on a resource that has it
        # correctly set to false two lines down. The shared helper is string-aware AT THE OPENER
        # and refuses to blank past an unmatched one: a raw `/\*.*?\*/` re.sub would treat a `/*`
        # inside an ordinary string (`"configs/*catalog"`) as an opener and blank every real
        # resource block up to the next `*/` anywhere later in the file — a silent HIGH miss.
        # The CLOSING `*/` is deliberately not string-aware (see the helper's invariant): HCL, like
        # C, does not lex strings inside a comment, so `/* use a " here */ publicly_accessible =
        # true` must still fire.
        text = blank_block_comments(read(f), dialect="hcl")
        for resource_type, resource_name, _start, body in iter_terraform_resources(text):
            if resource_type not in _RDS_RESOURCE_TYPES:
                continue
            for lineno, line in body:
                # Skip whole-line HCL comments, both `#` and `//` (issue #424; the sibling
                # rds/s3 guards skip both, this one only skipped `#`). NOTE: only WHOLE-line
                # comments are skipped, matching the siblings; a trailing `# / //` comment after
                # real code is not stripped, so `x = false  // publicly_accessible = true` is a
                # known residual FP (shared with the sibling guards).
                if line.lstrip().startswith(("#", "//")):
                    continue
                if not _PUBLICLY_ACCESSIBLE_TRUE.search(line):
                    continue
                if pragma_present(_PRAGMA, line, dialect="hcl"):  # a comment on it, never a string (#424)
                    continue
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title=self.title,
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            f"`{resource_type}.{resource_name}` sets `publicly_accessible = true`, "
                            "assigning the database a public IP address reachable from the internet. "
                            "Combined with any permissive security-group rule, this is one of the "
                            "most common causes of a real-world exposed production database."
                        ),
                        remediation=(
                            "Remove `publicly_accessible = true` (or set it to `false`) and reach "
                            "the database through a VPN, bastion host, or a security group scoped "
                            "to the application's own subnet. Suppress an audited exception with "
                            "`# security: allow-rds-public` on the attribute line."
                        ),
                        rule="rds-publicly-accessible/public-instance",
                        standards=list(_STANDARDS),
                    )
                )
        return out
