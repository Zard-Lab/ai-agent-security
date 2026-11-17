"""Guard: Terraform RDS/Aurora backup retention period is too short or unset (checklist §7).

    resource "aws_db_instance" "app" {
      engine = "postgres"
      # no backup_retention_period at all -> the provider defaults it to 0 (backups off)
    }

    resource "aws_rds_cluster" "app" {
      engine                  = "aurora-postgresql"
      backup_retention_period = 1   # too short to matter for a real incident window
    }

Automated backups are how a database recovers from an accidental `DROP TABLE`, a bad migration,
or a ransomware-style mass-write — but only as far back as the configured retention window
reaches. When the attribute is never set, the Terraform AWS provider defaults
`backup_retention_period` to `0` on `aws_db_instance` ("Default is `0`": automated backups off)
and to `1` day on `aws_rds_cluster` ("Default `1`"). Neither is enough time for anyone to notice
the damage, let alone restore from it. The `7`-day floor below is this project's own policy, not
a provider or AWS default (PR #1162 round-1 M7). CWE-19 (Data
Processing Errors broadly covers inadequate recovery controls), OWASP:A05 (Security
Misconfiguration).

Two resource types, same attribute, each with its own exclusion to avoid flagging a setting
that doesn't actually apply to that resource:

1. **`aws_db_instance`** — fires when `backup_retention_period` is absent (provider default is
   `0`: backups disabled entirely), or present with a numeric value less than `7`, UNLESS the
   instance is one of:
   - a **read replica** (`replicate_source_db` is set) — a replica inherits its retention
     behavior from its source instance; its own `backup_retention_period` setting is
     meaningless. (`source_db_instance_identifier` is a different attribute, used only inside a
     `restore_to_point_in_time { ... }` block on a point-in-time-restored primary — it does NOT
     mark a resource as a replica, and must not be used for this exclusion.)
   - an **Aurora instance** (`engine` is `"aurora"`, `"aurora-mysql"`, or `"aurora-postgresql"`)
     — an Aurora instance does not control its own backup retention; that is set on the parent
     `aws_rds_cluster`, which rule 2 below covers.
2. **`aws_rds_cluster`** — fires when `backup_retention_period` is absent, or present with a
   numeric value less than `7`. No exclusion: every cluster resource controls its own retention
   directly.

A `backup_retention_period` set through a variable or other non-literal expression (rather than
a literal integer) is treated as "present, value unresolved" and does NOT fire — no expression
evaluation, consistent with every other regex/text-scoped Terraform guard in this codebase (an
accepted false negative, not a bug).

Suppress an audited case (e.g. a deliberately short-retention scratch/dev database) with
`# security: allow-rds-short-backup-retention` anywhere in the resource block.
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

_MIN_RETENTION_DAYS = 7

_RETENTION_LITERAL = re.compile(r"\bbackup_retention_period\s*=\s*(-?\d+)\b")
_RETENTION_PRESENT = re.compile(r"\bbackup_retention_period\s*=")
_SOURCE_REPLICA = re.compile(r"\breplicate_source_db\s*=")
_ENGINE_AURORA = re.compile(r'\bengine\s*=\s*"(?:aurora|aurora-mysql|aurora-postgresql)"')
_PRAGMA = re.compile(r"#\s*security:\s*allow-rds-short-backup-retention")

_STANDARDS = ["OWASP:A05"]

_TfBody = list[tuple[int, str]]


def _code_body(body: _TfBody) -> str:
    """Comment-blind view of a resource body: whole-line `#`/`//` comments blanked so a
    commented-out attribute can't participate in the trigger or exclusion checks."""
    return "\n".join(
        "" if line.lstrip().startswith(("#", "//")) else line for _, line in body
    )


def _retention_too_short(code_body: str) -> bool:
    m = _RETENTION_LITERAL.search(code_body)
    if m:
        return int(m.group(1)) < _MIN_RETENTION_DAYS
    # Present but not a literal integer (e.g. `backup_retention_period = var.retention`) — no
    # expression evaluation, so this is left unresolved rather than guessed at. Absent entirely
    # takes the provider default (0 on aws_db_instance, 1 on aws_rds_cluster), both below
    # _MIN_RETENTION_DAYS, so that case stays True.
    return not _RETENTION_PRESENT.search(code_body)


class RdsBackupRetentionTooShortGuard(Guard):
    id = "rds-backup-retention-too-short"
    title = "RDS/Aurora backup retention period is too short or unset"
    area = "Cloud & IaC"

    canary_plant = CanaryPlant(
        files={
            # Label deliberately NOT "canary": rds_storage_not_encrypted's own plant already
            # declares `aws_rds_cluster.canary` in the same merged canary repo, and a duplicate
            # resource address is the collision family that once killed an unrelated guard's
            # canary (see s3_mfa_delete_disabled.py's plant). PR #1162 round-1 Low.
            "rds_backup_retention.tf": (
                'resource "aws_rds_cluster" "backup_retention_canary" {\n'
                '  engine                   = "aurora-postgresql"\n'
                "  backup_retention_period  = 1\n"
                "}\n"
            ),
        },
        expects=frozenset({"rds-backup-retention-too-short/rds-cluster"}),
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
            if resource_type == "aws_db_instance":
                out.extend(self._check_db_instance(root, f, resource_name, start_line, body))
            elif resource_type == "aws_rds_cluster":
                out.extend(self._check_rds_cluster(root, f, resource_name, start_line, body))
        return out

    def _check_db_instance(
        self, root: Path, f: Path, name: str, start_line: int, body: _TfBody,
    ) -> list[Finding]:
        body_text = "\n".join(line for _, line in body)
        if pragma_present(_PRAGMA, body_text, dialect="hcl"):
            return []
        code_body = _code_body(body)
        if _SOURCE_REPLICA.search(code_body):
            return []  # a read replica inherits retention from its source instance
        if _ENGINE_AURORA.search(code_body):
            return []  # Aurora instances don't control their own retention; the cluster does
        if not _retention_too_short(code_body):
            return []
        return [Finding(
            check_id=self.id,
            severity="medium",
            title=self.title,
            location=f"{rel(root, f)}:{start_line}",
            message=(
                f"`aws_db_instance.{name}` does not set `backup_retention_period` to at least "
                f"{_MIN_RETENTION_DAYS} days. The Terraform AWS provider defaults this to `0` "
                "when unset (automated backups disabled entirely) — the 7-day floor here is "
                "this project's own policy, not a provider default."
            ),
            remediation=(
                f"Set `backup_retention_period = {_MIN_RETENTION_DAYS}` (or higher) on the "
                "instance. Suppress an audited exception (e.g. a deliberately short-retention "
                "scratch/dev database) with `# security: allow-rds-short-backup-retention` "
                "anywhere in the resource block."
            ),
            rule="rds-backup-retention-too-short/db-instance",
            standards=list(_STANDARDS),
        )]

    def _check_rds_cluster(
        self, root: Path, f: Path, name: str, start_line: int, body: _TfBody,
    ) -> list[Finding]:
        body_text = "\n".join(line for _, line in body)
        if pragma_present(_PRAGMA, body_text, dialect="hcl"):
            return []
        code_body = _code_body(body)
        if not _retention_too_short(code_body):
            return []
        return [Finding(
            check_id=self.id,
            severity="medium",
            title=self.title,
            location=f"{rel(root, f)}:{start_line}",
            message=(
                f"`aws_rds_cluster.{name}` does not set `backup_retention_period` to at least "
                f"{_MIN_RETENTION_DAYS} days. The Terraform AWS provider defaults this to `1` "
                "day when unset — rarely enough time to notice damage from a bad migration or "
                "accidental write, let alone restore from it. (The 7-day floor itself is this "
                "project's own policy, not a provider default.)"
            ),
            remediation=(
                f"Set `backup_retention_period = {_MIN_RETENTION_DAYS}` (or higher) on the "
                "cluster. Suppress an audited exception (e.g. a deliberately short-retention "
                "scratch/dev cluster) with `# security: allow-rds-short-backup-retention` "
                "anywhere in the resource block."
            ),
            rule="rds-backup-retention-too-short/rds-cluster",
            standards=list(_STANDARDS),
        )]
