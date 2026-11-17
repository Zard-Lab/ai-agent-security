"""Guard: Terraform RDS instance without encryption at rest (checklist §7).

    resource "aws_db_instance" "app" {
      engine = "postgres"
      # no storage_encrypted attribute at all -> AWS defaults it to false
    }

Unlike most AWS resource encryption settings, RDS storage encryption is opt-in: the
`storage_encrypted` attribute on `aws_db_instance` defaults to `false` if never set.
A database holding customer data with disk-level encryption disabled means anyone with
access to the underlying storage (a snapshot, a volume backup, a misconfigured IAM
grant on the storage layer) reads the raw data directly — no application-level bug
required. CWE-311 (Missing Encryption of Sensitive Data), OWASP:A02.

Fires HIGH when an `aws_db_instance` resource block does NOT contain
`storage_encrypted = true` anywhere in its body — whether the attribute is missing
entirely (the common case: a developer never thought about it, so it silently
defaults to unencrypted) or explicitly set to `false`.

Suppress an audited case (e.g. a genuinely non-sensitive scratch/ephemeral database)
with `# security: allow-rds-unencrypted` anywhere in the resource block.

**2026-10-25 (this session's extension):** two additions.

1. **Aurora-engine exclusion on `aws_db_instance`** — an `aws_db_instance` whose `engine`
   attribute is literally `"aurora"`, `"aurora-mysql"`, or `"aurora-postgresql"` is now skipped
   entirely by the check above, even with `storage_encrypted` missing or `false`. An Aurora
   *instance* doesn't control its own storage encryption -- that's set on the owning
   `aws_rds_cluster` -- so the check would be flagging a setting that doesn't apply at the
   instance level. This is a rare shape: real Aurora instances are normally declared as
   `aws_rds_cluster_instance`, which this guard has never scanned, so the exclusion closes an
   edge case rather than a common false positive (PR #1162 round-1 M4).
2. **New rule for `aws_rds_cluster.storage_encrypted`** — fires when `storage_encrypted` is
   absent or explicitly `false`, unless the cluster's `engine_mode` attribute is exactly
   `"serverless"` (Aurora Serverless v1 doesn't support configuring this attribute the same way,
   so it is excluded rather than guessed at). A cluster created from an existing source -- a
   `snapshot_identifier` restore, a `replication_source_identifier` replica, or a
   `restore_to_point_in_time` clone -- takes its encryption from that source, which this file
   cannot see, so it stays silent rather than guess (PR #1162 round-1 M4). The source must be
   one of the cluster's own top-level attributes and actually set: `= null` or `= ""` means no
   source and still fires, and so does a same-named `tags` key (round-4 M1). A source given
   through a variable (`= var.snapshot_identifier`, the module-wrapper idiom) cannot be proven
   absent and stays silent, a documented false negative when the variable is `null`. The same inheritance
   applies to an `aws_db_instance` restored from a snapshot or created as a replica; that rule
   predates this extension and is unchanged here.
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
    terraform_code_view,
    top_level_attribute_text,
)

_STORAGE_ENCRYPTED_TRUE = re.compile(r"\bstorage_encrypted\s*=\s*true\b")
_PRAGMA = re.compile(r"#\s*security:\s*allow-rds-unencrypted")
_ENGINE_AURORA = re.compile(r'\bengine\s*=\s*"(?:aurora|aurora-mysql|aurora-postgresql)"')
_ENGINE_MODE_SERVERLESS = re.compile(r'\bengine_mode\s*=\s*"serverless"')
# A cluster created from an existing source inherits that source's encryption. Matched on the
# cluster's own top-level attributes (line-anchored, so a same-named `tags` key is not one), and
# only when the source is actually set: `null` and `""` mean "no source" (PR #1162 round-4 M1).
# A non-literal source (`var.snapshot_identifier`) cannot be proven absent and stays excluded.
_CLUSTER_SOURCE_ATTR = re.compile(
    r'(?m)^[ \t]*(?:snapshot_identifier|replication_source_identifier)[ \t]*=[ \t]*(?!null\b|""[ \t]*$)\S'
)
_CLUSTER_PITR_BLOCK = re.compile(r"(?m)^[ \t]*restore_to_point_in_time[ \t]*\{")

_STANDARDS = ["OWASP:A02", "CWE-311"]


class RdsStorageNotEncryptedGuard(Guard):
    id = "rds-storage-not-encrypted"
    title = "RDS instance without encryption at rest"
    area = "Cloud & IaC"

    # Canary plant: the `aws_db_instance` rule is EXPECTS-ONLY — its violation is planted in the
    # canary's shared `rds.tf` and `tf_secret.tf`, which several guards trip at once, so that
    # file stays in `canary.py`'s base owned by no guard (ownership rule documented on
    # `xxe_safe.py`). rds.tf: same aws_db_instance block has no storage_encrypted = true ->
    # fires missing-encryption. The new `aws_rds_cluster` rule owns its own small file below.
    # rds_cluster_encryption.tf: aws_rds_cluster with no storage_encrypted and no
    # engine_mode = "serverless" -> fires cluster-missing-encryption.
    canary_plant = CanaryPlant(
        files={
            "rds_cluster_encryption.tf": (
                'resource "aws_rds_cluster" "canary" {\n'
                '  engine = "aurora-postgresql"\n'
                "}\n"
            ),
        },
        expects=frozenset({
            "rds-storage-not-encrypted/missing-encryption",
            "rds-storage-not-encrypted/cluster-missing-encryption",
        }),
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
        self, root: Path, f: Path, resource_name: str, start_line: int, body: list[tuple[int, str]],
    ) -> list[Finding]:
        body_text = "\n".join(line for _, line in body)
        if pragma_present(_PRAGMA, body_text, dialect="hcl"):
            return []
        # Search a comment-blanked view (pragma already handled on the comment-only view above, #424) so a
        # commented `# storage_encrypted = true` can't suppress a finding on a genuinely
        # unencrypted DB. Blank, don't drop, so nothing downstream shifts.
        code_body = "\n".join(
            "" if line.lstrip().startswith(("#", "//")) else line for _, line in body
        )
        if _ENGINE_AURORA.search(code_body):
            # Aurora instances don't control their own storage encryption — that's set on the
            # owning aws_rds_cluster (see `_check_rds_cluster` below), so flagging the instance
            # here would be checking a setting that doesn't apply at this level at all.
            return []
        if _STORAGE_ENCRYPTED_TRUE.search(code_body):
            return []
        return [Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{start_line}",
            message=(
                f"`aws_db_instance.{resource_name}` does not set "
                "`storage_encrypted = true`. RDS storage encryption is opt-in and "
                "defaults to false — anyone with access to the underlying storage "
                "(a snapshot, a volume backup, a misconfigured storage-layer grant) "
                "reads the raw, unencrypted data directly."
            ),
            remediation=(
                "Add `storage_encrypted = true` to the resource. Note this cannot be "
                "changed on an existing unencrypted instance — a new encrypted "
                "instance must be created from an encrypted snapshot. Suppress an "
                "audited exception (e.g. a genuinely non-sensitive scratch database) "
                "with `# security: allow-rds-unencrypted` anywhere in the block."
            ),
            rule="rds-storage-not-encrypted/missing-encryption",
            standards=list(_STANDARDS),
        )]

    def _check_rds_cluster(
        self, root: Path, f: Path, resource_name: str, start_line: int, body: list[tuple[int, str]],
    ) -> list[Finding]:
        body_text = "\n".join(line for _, line in body)
        if pragma_present(_PRAGMA, body_text, dialect="hcl"):
            return []
        code_body = "\n".join(
            "" if line.lstrip().startswith(("#", "//")) else line for _, line in body
        )
        if _ENGINE_MODE_SERVERLESS.search(code_body):
            # Aurora Serverless v1 doesn't support configuring storage_encrypted the same way —
            # same exclusion logic as the db-instance check above, a different reason.
            return []
        top_level = top_level_attribute_text(terraform_code_view(body_text))
        if _CLUSTER_SOURCE_ATTR.search(top_level) or _CLUSTER_PITR_BLOCK.search(top_level):
            # Restored, replicated or cloned from a source whose encryption this file cannot
            # see -- the cluster inherits it, so firing here would be a guess.
            return []
        if _STORAGE_ENCRYPTED_TRUE.search(code_body):
            return []
        return [Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{start_line}",
            message=(
                f"`aws_rds_cluster.{resource_name}` does not set "
                "`storage_encrypted = true`. RDS/Aurora cluster storage encryption is opt-in "
                "and defaults to false — anyone with access to the underlying storage (a "
                "snapshot, a volume backup, a misconfigured storage-layer grant) reads the "
                "raw, unencrypted data directly."
            ),
            remediation=(
                "Add `storage_encrypted = true` to the cluster resource. Note this cannot be "
                "changed on an existing unencrypted cluster — a new encrypted cluster must be "
                "created from an encrypted snapshot. Suppress an audited exception (e.g. a "
                "genuinely non-sensitive scratch cluster) with `# security: allow-rds-unencrypted` "
                "anywhere in the block."
            ),
            rule="rds-storage-not-encrypted/cluster-missing-encryption",
            standards=list(_STANDARDS),
        )]
