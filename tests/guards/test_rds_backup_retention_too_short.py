from __future__ import annotations

from agentsec.guards.rds_backup_retention_too_short import RdsBackupRetentionTooShortGuard
from tests.guards._common import *  # noqa: F401,F403

_DB_INSTANCE_RULE = "rds-backup-retention-too-short/db-instance"
_RDS_CLUSTER_RULE = "rds-backup-retention-too-short/rds-cluster"


def test_db_instance_missing_retention_fires(tmp_path: Path) -> None:
    (tmp_path / "rds.tf").write_text(
        'resource "aws_db_instance" "app" {\n'
        '  engine = "postgres"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = RdsBackupRetentionTooShortGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == _DB_INSTANCE_RULE
    assert findings[0].severity == "medium"


def test_db_instance_short_retention_fires(tmp_path: Path) -> None:
    (tmp_path / "rds.tf").write_text(
        'resource "aws_db_instance" "app" {\n'
        '  engine                  = "postgres"\n'
        "  backup_retention_period = 3\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = RdsBackupRetentionTooShortGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == _DB_INSTANCE_RULE


def test_db_instance_sufficient_retention_silent(tmp_path: Path) -> None:
    (tmp_path / "rds.tf").write_text(
        'resource "aws_db_instance" "app" {\n'
        '  engine                  = "postgres"\n'
        "  backup_retention_period = 7\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert RdsBackupRetentionTooShortGuard().run(tmp_path, profile) == []


def test_db_instance_aurora_engine_missing_retention_stays_silent(tmp_path: Path) -> None:
    # FP-bait: an Aurora-engine aws_db_instance does not control its own retention -- the
    # exclusion must actually suppress this, even with the attribute missing entirely.
    (tmp_path / "rds.tf").write_text(
        'resource "aws_db_instance" "app" {\n'
        '  engine = "aurora-postgresql"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert RdsBackupRetentionTooShortGuard().run(tmp_path, profile) == []


def test_db_instance_aurora_engine_short_retention_stays_silent(tmp_path: Path) -> None:
    # Same FP-bait, with an explicit short value present -- still excluded.
    (tmp_path / "rds.tf").write_text(
        'resource "aws_db_instance" "app" {\n'
        '  engine                  = "aurora-mysql"\n'
        "  backup_retention_period = 1\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert RdsBackupRetentionTooShortGuard().run(tmp_path, profile) == []


def test_db_instance_read_replica_short_retention_stays_silent(tmp_path: Path) -> None:
    # FP-bait: a read replica inherits retention from its source; its own setting is
    # meaningless, so even a short/missing value here must not fire. A replica is marked by
    # `replicate_source_db` (review H3 -- the old test used the wrong attribute).
    (tmp_path / "rds.tf").write_text(
        'resource "aws_db_instance" "replica" {\n'
        '  replicate_source_db     = "arn:aws:rds:us-east-1:123:db:primary"\n'
        "  backup_retention_period = 1\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert RdsBackupRetentionTooShortGuard().run(tmp_path, profile) == []


def test_db_instance_read_replica_missing_retention_stays_silent(tmp_path: Path) -> None:
    (tmp_path / "rds.tf").write_text(
        'resource "aws_db_instance" "replica" {\n'
        '  replicate_source_db = "arn:aws:rds:us-east-1:123:db:primary"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert RdsBackupRetentionTooShortGuard().run(tmp_path, profile) == []


def test_db_instance_point_in_time_restore_source_attribute_still_fires(tmp_path: Path) -> None:
    # `source_db_instance_identifier` only appears inside a `restore_to_point_in_time { ... }`
    # block on a RESTORED PRIMARY -- it does not mark a replica, and must not be excluded
    # (review H3: the old code wrongly keyed the replica exclusion on this attribute).
    (tmp_path / "rds.tf").write_text(
        'resource "aws_db_instance" "restored" {\n'
        "  restore_to_point_in_time {\n"
        '    source_db_instance_identifier = "arn:aws:rds:us-east-1:123:db:primary"\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = RdsBackupRetentionTooShortGuard().run(tmp_path, profile)
    assert any(f.rule == "rds-backup-retention-too-short/db-instance" for f in findings)


def test_rds_cluster_missing_retention_fires(tmp_path: Path) -> None:
    (tmp_path / "cluster.tf").write_text(
        'resource "aws_rds_cluster" "app" {\n'
        '  engine = "aurora-postgresql"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = RdsBackupRetentionTooShortGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == _RDS_CLUSTER_RULE
    assert findings[0].severity == "medium"


def test_rds_cluster_short_retention_fires(tmp_path: Path) -> None:
    (tmp_path / "cluster.tf").write_text(
        'resource "aws_rds_cluster" "app" {\n'
        '  engine                  = "aurora-postgresql"\n'
        "  backup_retention_period = 1\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = RdsBackupRetentionTooShortGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == _RDS_CLUSTER_RULE


def test_rds_cluster_sufficient_retention_silent(tmp_path: Path) -> None:
    (tmp_path / "cluster.tf").write_text(
        'resource "aws_rds_cluster" "app" {\n'
        '  engine                  = "aurora-postgresql"\n'
        "  backup_retention_period = 7\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert RdsBackupRetentionTooShortGuard().run(tmp_path, profile) == []


def test_rds_cluster_high_retention_silent(tmp_path: Path) -> None:
    (tmp_path / "cluster.tf").write_text(
        'resource "aws_rds_cluster" "app" {\n'
        '  engine                  = "aurora-postgresql"\n'
        "  backup_retention_period = 30\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert RdsBackupRetentionTooShortGuard().run(tmp_path, profile) == []


def test_pragma_silences_db_instance(tmp_path: Path) -> None:
    (tmp_path / "rds.tf").write_text(
        'resource "aws_db_instance" "app" {\n'
        "  # security: allow-rds-short-backup-retention\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert RdsBackupRetentionTooShortGuard().run(tmp_path, profile) == []


def test_pragma_silences_rds_cluster(tmp_path: Path) -> None:
    (tmp_path / "cluster.tf").write_text(
        'resource "aws_rds_cluster" "app" {\n'
        "  backup_retention_period = 1  # security: allow-rds-short-backup-retention\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert RdsBackupRetentionTooShortGuard().run(tmp_path, profile) == []


def test_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert RdsBackupRetentionTooShortGuard().applies(profile) is False


def test_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert RdsBackupRetentionTooShortGuard().applies(profile) is True
