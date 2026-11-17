"""A Terraform resource's findings must not depend on its layout (PR #1162 round-5 M1).

HCL allows a block to be written on one line only when it holds at most one attribute and no
nested block (`resource "t" "n" { attr = value }`). Every such resource is therefore also
writable as the ordinary multi-line block, and the two spellings mean the same thing to
Terraform. This is the principle test for that invariant: each single-attribute resource below
is audited in both layouts, through `detect()` and every guard whose `applies()` is true, and the
two finding sets must be identical.

It replaced a run of per-shape fixes: rounds 3 to 5 of the #1162 review each found a new
one-line edge in the shared Terraform helpers (`top_level_attribute_text` dropped a one-line
resource's own attributes, so an encrypted one-line EFS file system fired HIGH). Each case also
pins whether its guard of interest fires. For a case expected to fire, that rules out passing by
both layouts going silent; a case expected to stay silent proves layout equality only.

It covers the cases listed below, not every Terraform guard: a guard that is not exercised here
can still diverge (a one-line `password = "..."` under `terraform-hardcoded-secret-literal`,
tracked in #1166).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentsec.detect import detect
from agentsec.registry import ALL_GUARDS

# (resource type, its single attribute, {guard id: fires?}) -- the expectation is the guard's
# verdict on the multi-line layout, which every rule here was written against.
_CASES: list[tuple[str, str, dict[str, bool]]] = [
    ("aws_efs_file_system", "encrypted = true", {"efs-file-system-not-encrypted": False}),
    ("aws_efs_file_system", "encrypted = false", {"efs-file-system-not-encrypted": True}),
    ("aws_efs_file_system", 'creation_token = "x"', {"efs-file-system-not-encrypted": True}),
    (
        "aws_elasticache_replication_group",
        "transit_encryption_enabled = true",
        {"elasticache-transit-encryption-disabled": False},
    ),
    (
        "aws_elasticache_replication_group",
        "transit_encryption_enabled = false",
        {"elasticache-transit-encryption-disabled": True},
    ),
    ("aws_rds_cluster", "storage_encrypted = true", {"rds-storage-not-encrypted": False}),
    ("aws_rds_cluster", "storage_encrypted = false", {"rds-storage-not-encrypted": True}),
    (
        "aws_rds_cluster",
        'snapshot_identifier = "arn:aws:rds:us-east-1:1:cluster-snapshot:s"',
        {"rds-storage-not-encrypted": False},
    ),
    ("aws_rds_cluster", "snapshot_identifier = null", {"rds-storage-not-encrypted": True}),
    ("aws_rds_cluster", 'snapshot_identifier = ""', {"rds-storage-not-encrypted": True}),
    ("aws_rds_cluster", "backup_retention_period = 1", {"rds-backup-retention-too-short": True}),
    ("aws_rds_cluster", "backup_retention_period = 14", {"rds-backup-retention-too-short": False}),
    ("aws_db_instance", "storage_encrypted = true", {"rds-storage-not-encrypted": False}),
    ("aws_db_instance", "publicly_accessible = true", {"rds-publicly-accessible": True}),
    ("aws_db_instance", "backup_retention_period = 0", {"rds-backup-retention-too-short": True}),
    (
        "aws_lb_listener",
        'protocol = "HTTP"',
        {"alb-listener-http-protocol": True, "aws-weak-tls-policy": False},
    ),
    (
        "aws_lb_listener",
        'protocol = "HTTPS"',
        {"alb-listener-http-protocol": False, "aws-weak-tls-policy": True},
    ),
    (
        "aws_lb_listener",
        'ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"',
        {"aws-weak-tls-policy": False},
    ),
    ("aws_api_gateway_domain_name", 'security_policy = "TLS_1_0"', {"aws-weak-tls-policy": True}),
    ("aws_api_gateway_domain_name", 'security_policy = "TLS_1_2"', {"aws-weak-tls-policy": False}),
    ("aws_api_gateway_domain_name", 'domain_name = "x"', {"aws-weak-tls-policy": True}),
    ("aws_opensearch_domain", 'domain_name = "x"', {"opensearch-domain-encryption-disabled": True}),
    ("aws_elasticsearch_domain", 'domain_name = "x"', {"opensearch-domain-encryption-disabled": True}),
    ("aws_kinesis_stream", 'encryption_type = "KMS"', {"kinesis-stream-not-encrypted": False}),
    ("aws_kinesis_stream", 'encryption_type = "NONE"', {"kinesis-stream-not-encrypted": True}),
    ("aws_kinesis_stream", 'name = "x"', {"kinesis-stream-not-encrypted": True}),
    ("aws_msk_cluster", 'cluster_name = "x"', {"msk-cluster-transit-encryption-disabled": False}),
    ("aws_s3_bucket", 'acl = "public-read"', {"s3-bucket-canned-acl": True}),
    ("aws_s3_bucket", 'bucket = "x"', {"s3-bucket-canned-acl": False}),
    ("aws_s3_bucket_acl", 'acl = "public-read"', {"s3-bucket-canned-acl": True}),
    ("aws_s3_bucket_acl", 'acl = "private"', {"s3-bucket-canned-acl": False}),
    (
        "aws_s3_bucket_policy",
        'policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "s3:GetObject" }] })',
        {"s3-bucket-insecure-transport-allowed": True},
    ),
    (
        "aws_sagemaker_notebook_instance",
        'kms_key_id = "arn:aws:kms:us-east-1:1:key/k"',
        {"sagemaker-notebook-not-encrypted": False},
    ),
    ("aws_sagemaker_notebook_instance", 'name = "x"', {"sagemaker-notebook-not-encrypted": True}),
    ("aws_cloudwatch_log_group", "retention_in_days = 1", {"aws-observability-hygiene": True}),
    ("aws_cloudwatch_log_group", "retention_in_days = 365", {"aws-observability-hygiene": False}),
    ("aws_ecs_task_definition", 'family = "x"', {"ecs-efs-volume-transit-encryption-disabled": False}),
]


def _audit(root: Path, text: str) -> list[tuple[str, str, str, str, str]]:
    root.mkdir()
    (root / "main.tf").write_text(text, encoding="utf-8")
    profile = detect(root)
    findings = [f for g in ALL_GUARDS if g.applies(profile) for f in g.run(root, profile)]
    # The file, not the line: a finding anchored on the attribute's own line legitimately moves
    # from line 2 to line 1 when the resource is written on one line.
    return sorted(
        (f.check_id, f.rule, f.severity, f.location.rsplit(":", 1)[0], f.message) for f in findings
    )


@pytest.mark.parametrize(("resource_type", "attribute", "expect"), _CASES)
def test_one_line_resource_gets_the_same_findings_as_its_multi_line_form(
    tmp_path: Path, resource_type: str, attribute: str, expect: dict[str, bool]
) -> None:
    one_line = _audit(tmp_path / "one", f'resource "{resource_type}" "x" {{ {attribute} }}\n')
    multi_line = _audit(tmp_path / "multi", f'resource "{resource_type}" "x" {{\n  {attribute}\n}}\n')
    assert one_line == multi_line
    fired = {check_id for check_id, *_ in multi_line}
    assert {guard_id: guard_id in fired for guard_id in expect} == expect
