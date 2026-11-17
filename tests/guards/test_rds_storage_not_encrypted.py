from __future__ import annotations

from agentsec.guards.rds_storage_not_encrypted import RdsStorageNotEncryptedGuard
from tests.guards._common import *  # noqa: F401,F403


def test_rds_storage_not_encrypted_flags_missing_attribute(tmp_path: Path) -> None:
    (tmp_path / "rds.tf").write_text(
        'resource "aws_db_instance" "app" {\n'
        '  engine = "postgres"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = RdsStorageNotEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "rds-storage-not-encrypted/missing-encryption"
    assert findings[0].severity == "high"

def test_rds_storage_not_encrypted_flags_explicit_false(tmp_path: Path) -> None:
    (tmp_path / "rds.tf").write_text(
        'resource "aws_db_instance" "app" {\n'
        "  storage_encrypted = false\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = RdsStorageNotEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1

def test_rds_storage_not_encrypted_silent_when_true(tmp_path: Path) -> None:
    (tmp_path / "rds.tf").write_text(
        'resource "aws_db_instance" "app" {\n'
        "  storage_encrypted = true\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert RdsStorageNotEncryptedGuard().run(tmp_path, profile) == []

def test_rds_storage_not_encrypted_silent_other_resource(tmp_path: Path) -> None:
    (tmp_path / "cluster.tf").write_text(
        'resource "aws_rds_cluster_instance" "app" {\n'
        "  engine = \"aurora-postgresql\"\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert RdsStorageNotEncryptedGuard().run(tmp_path, profile) == []

def test_rds_storage_not_encrypted_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "rds.tf").write_text(
        'resource "aws_db_instance" "app" {\n'
        "  # security: allow-rds-unencrypted\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert RdsStorageNotEncryptedGuard().run(tmp_path, profile) == []

def test_rds_storage_not_encrypted_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert RdsStorageNotEncryptedGuard().applies(profile) is False

def test_rds_storage_not_encrypted_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert RdsStorageNotEncryptedGuard().applies(profile) is True

def test_rds_storage_brace_in_string_does_not_truncate_block(tmp_path: Path) -> None:
    # An unbalanced `}` inside a tag string used to close the resource block early, dropping
    # the `storage_encrypted = true` line below it -> false positive on an encrypted DB.
    (tmp_path / "db.tf").write_text(
        'resource "aws_db_instance" "app" {\n'
        '  tags              = { Name = "prod}db" }\n'
        "  storage_encrypted = true\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert RdsStorageNotEncryptedGuard().run(tmp_path, profile) == []

def test_rds_storage_stray_double_angle_does_not_swallow_next_resource(tmp_path: Path) -> None:
    # A stray `<<` (not a real `attr = <<EOF` heredoc opener) must NOT open a phantom heredoc
    # that runs the block to EOF and swallows the following resource — that silently dropped a
    # real unencrypted-DB finding. The heredoc opener is anchored to an assignment RHS + EOL.
    (tmp_path / "s.tf").write_text(
        'resource "aws_s3_bucket" "a" {\n'
        "  count  = 1 << 2\n"
        '  bucket = "x"\n'
        "}\n"
        "\n"
        'resource "aws_db_instance" "b" {\n'
        "  storage_encrypted = false\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = RdsStorageNotEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "rds-storage-not-encrypted/missing-encryption"


def test_rds_storage_real_heredoc_body_braces_ignored(tmp_path: Path) -> None:
    # A genuine `user_data = <<EOF` heredoc whose body contains braces (and resource-like text)
    # must still be skipped so the block is parsed whole and `storage_encrypted = true` is seen.
    (tmp_path / "s.tf").write_text(
        'resource "aws_db_instance" "app" {\n'
        "  user_data = <<EOF\n"
        "    { braces } and resource \"fake\" \"x\" {\n"
        "  EOF\n"
        "  storage_encrypted = true\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert RdsStorageNotEncryptedGuard().run(tmp_path, profile) == []


def test_rds_storage_comment_does_not_suppress_finding(tmp_path: Path) -> None:
    # A commented `# storage_encrypted = true` must NOT be read as the real attribute on a
    # genuinely unencrypted DB (comment-blind blob search -> false negative).
    (tmp_path / "db.tf").write_text(
        'resource "aws_db_instance" "app" {\n'
        "  engine = \"postgres\"\n"
        "  # TODO: storage_encrypted = true\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = RdsStorageNotEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "rds-storage-not-encrypted/missing-encryption"


def test_rds_storage_not_encrypted_aurora_engine_instance_stays_silent(tmp_path: Path) -> None:
    # FP-bait (this session's extension): an Aurora-engine aws_db_instance doesn't control its
    # own storage encryption — that's set on the owning aws_rds_cluster — so the exclusion must
    # actually suppress this, even with storage_encrypted missing entirely.
    (tmp_path / "rds.tf").write_text(
        'resource "aws_db_instance" "app" {\n'
        '  engine = "aurora-postgresql"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert RdsStorageNotEncryptedGuard().run(tmp_path, profile) == []


def test_rds_storage_not_encrypted_non_aurora_instance_still_fires(tmp_path: Path) -> None:
    # Regression: the common case (a plain, non-Aurora aws_db_instance missing
    # storage_encrypted) must still fire after adding the Aurora exclusion above.
    (tmp_path / "rds.tf").write_text(
        'resource "aws_db_instance" "app" {\n'
        '  engine = "postgres"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = RdsStorageNotEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "rds-storage-not-encrypted/missing-encryption"


def test_rds_cluster_missing_storage_encrypted_fires(tmp_path: Path) -> None:
    (tmp_path / "cluster.tf").write_text(
        'resource "aws_rds_cluster" "app" {\n'
        '  engine = "aurora-postgresql"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = RdsStorageNotEncryptedGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "rds-storage-not-encrypted/cluster-missing-encryption"
    assert findings[0].severity == "high"


def test_rds_cluster_serverless_engine_mode_missing_encryption_stays_silent(tmp_path: Path) -> None:
    # FP-bait: Aurora Serverless v1 (engine_mode = "serverless") doesn't support configuring
    # storage_encrypted the same way, so this must stay silent even with the attribute missing.
    (tmp_path / "cluster.tf").write_text(
        'resource "aws_rds_cluster" "app" {\n'
        '  engine      = "aurora-postgresql"\n'
        '  engine_mode = "serverless"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert RdsStorageNotEncryptedGuard().run(tmp_path, profile) == []


def test_rds_cluster_storage_encrypted_true_stays_silent(tmp_path: Path) -> None:
    (tmp_path / "cluster.tf").write_text(
        'resource "aws_rds_cluster" "app" {\n'
        '  engine            = "aurora-postgresql"\n'
        "  storage_encrypted = true\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert RdsStorageNotEncryptedGuard().run(tmp_path, profile) == []


def test_rds_storage_not_encrypted_pragma_quoted_in_a_string_does_not_suppress(tmp_path: Path) -> None:
    # #424 E4: the per-resource check reads the HCL comment-only view of the block, so a string
    # attribute inside the block quoting the pragma is content - only a real `#` comment opts out.
    (tmp_path / "rds.tf").write_text(
        'resource "aws_db_instance" "app" {\n'
        '  identifier = "scratch-db, opt out with # security: allow-rds-unencrypted"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert len(RdsStorageNotEncryptedGuard().run(tmp_path, profile)) == 1


_CLUSTER_RULE = "rds-storage-not-encrypted/cluster-missing-encryption"


def _cluster_rules(tmp_path: Path, extra_lines: str) -> list[str]:
    (tmp_path / "cluster.tf").write_text(
        'resource "aws_rds_cluster" "app" {\n'
        '  engine = "aurora-postgresql"\n'
        f"{extra_lines}"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    return [f.rule for f in RdsStorageNotEncryptedGuard().run(tmp_path, profile)]


def test_rds_cluster_created_from_a_source_stays_silent(tmp_path: Path) -> None:
    # PR #1162 round-1 M4: a restored, replicated or cloned cluster inherits its source's
    # encryption, which this file cannot see -- it used to fire HIGH.
    for extra in (
        '  snapshot_identifier = "arn:aws:rds:us-east-1:123456789012:cluster-snapshot:prod"\n',
        "  replication_source_identifier = aws_rds_cluster.primary.arn\n",
        "  restore_to_point_in_time {\n"
        "    source_cluster_identifier = aws_rds_cluster.primary.cluster_identifier\n"
        "  }\n",
    ):
        assert _cluster_rules(tmp_path, extra) == [], extra


def test_rds_cluster_with_explicit_false_still_fires(tmp_path: Path) -> None:
    # The direction the source-inheritance narrowing trades against: a fresh cluster with
    # encryption explicitly off still fires, and so does a COMMENTED-OUT snapshot restore (a
    # comment is not a source).
    assert _cluster_rules(tmp_path, "  storage_encrypted = false\n") == [_CLUSTER_RULE]
    assert _cluster_rules(tmp_path, '  # snapshot_identifier = "old-snap"\n') == [_CLUSTER_RULE]


def test_rds_cluster_pragma_silences(tmp_path: Path) -> None:
    # PR #1162 round-1 M4: the cluster branch had no pragma test of its own.
    assert _cluster_rules(tmp_path, "  # security: allow-rds-unencrypted\n") == []
    # A pragma inside a string is not a pragma.
    assert _cluster_rules(tmp_path, '  tags = { note = "# security: allow-rds-unencrypted" }\n') == [
        _CLUSTER_RULE
    ]


def test_rds_cluster_source_attribute_without_a_source_still_fires(tmp_path: Path) -> None:
    # PR #1162 round-4 M1: the "created from a source" exclusion matched on the attribute NAME,
    # so a fresh unencrypted cluster went silent on `= null`, `= ""`, or a same-named tag key.
    for extra in (
        "  snapshot_identifier = null\n",
        '  snapshot_identifier = ""\n',
        "  replication_source_identifier = null\n",
        '  tags = { replication_source_identifier = "x" }\n',
        "  tags = {\n    snapshot_identifier = \"x\"\n  }\n",
    ):
        assert _cluster_rules(tmp_path, extra) == [_CLUSTER_RULE], extra


def test_rds_cluster_source_set_through_a_variable_stays_silent(tmp_path: Path) -> None:
    # The documented choice for a non-literal source (the module-wrapper idiom): it cannot be
    # proven absent, so the cluster may inherit an encrypted source -- silent, like every other
    # non-literal value in this batch.
    assert _cluster_rules(tmp_path, "  snapshot_identifier = var.snapshot_identifier\n") == []
