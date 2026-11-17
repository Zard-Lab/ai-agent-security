from __future__ import annotations

from agentsec.guards.elasticache_transit_encryption_disabled import (
    ElasticacheTransitEncryptionDisabledGuard,
)
from tests.guards._common import *  # noqa: F401,F403

_RULE = "elasticache-transit-encryption-disabled/missing-encryption"


def _run(tmp_path: Path, content: str) -> list:
    (tmp_path / "elasticache.tf").write_text(content, encoding="utf-8")
    return ElasticacheTransitEncryptionDisabledGuard().run(tmp_path, _tf_prof(tmp_path))


def test_elasticache_missing_attribute_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_elasticache_replication_group" "sessions" {\n'
        '  replication_group_id = "sessions"\n'
        '  engine                = "redis"\n'
        '  node_type             = "cache.r6g.large"\n'
        "}\n"
    ))
    assert len(findings) == 1
    assert findings[0].rule == _RULE
    assert findings[0].severity == "high"


def test_elasticache_explicit_false_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_elasticache_replication_group" "sessions" {\n'
        '  replication_group_id        = "sessions"\n'
        "  transit_encryption_enabled   = false\n"
        "}\n"
    ))
    assert len(findings) == 1
    assert findings[0].rule == _RULE


def test_elasticache_enabled_silent(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_elasticache_replication_group" "sessions" {\n'
        '  replication_group_id        = "sessions"\n'
        "  transit_encryption_enabled   = true\n"
        "}\n"
    ))
    assert findings == []


def test_elasticache_variable_silent(tmp_path: Path) -> None:
    # A non-literal value cannot be proven unsafe (review H6) -- stays silent, unlike absence.
    findings = _run(tmp_path, (
        'resource "aws_elasticache_replication_group" "sessions" {\n'
        '  replication_group_id        = "sessions"\n'
        "  transit_encryption_enabled   = var.tls\n"
        "}\n"
    ))
    assert findings == []


def test_elasticache_pragma_silences(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_elasticache_replication_group" "sessions" {\n'
        "  # security: allow-elasticache-plaintext\n"
        '  replication_group_id = "sessions"\n'
        "}\n"
    ))
    assert findings == []


def test_elasticache_comment_does_not_suppress_finding(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_elasticache_replication_group" "sessions" {\n'
        '  replication_group_id = "sessions"\n'
        "  # transit_encryption_enabled = true\n"
        "}\n"
    ))
    assert len(findings) == 1


def test_elasticache_unrelated_resource_silent(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_db_instance" "app" {\n'
        '  engine = "postgres"\n'
        "}\n"
    ))
    assert findings == []


def test_elasticache_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert ElasticacheTransitEncryptionDisabledGuard().applies(profile) is False


def test_elasticache_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert ElasticacheTransitEncryptionDisabledGuard().applies(profile) is True


def test_elasticache_tag_key_sharing_the_attribute_name_does_not_silence(tmp_path: Path) -> None:
    # PR #1162 round-3 L-1: a quoted non-bool tag value under a key named like the attribute
    # read as "nonliteral" and silenced the guard on a group that never enables transit
    # encryption.
    findings = _run(tmp_path, (
        'resource "aws_elasticache_replication_group" "sessions" {\n'
        '  replication_group_id = "sessions"\n'
        "  tags = {\n"
        '    transit_encryption_enabled = "pending"\n'
        "  }\n"
        "}\n"
    ))
    assert [f.rule for f in findings] == [_RULE]


def _group(lines: str) -> str:
    return (
        'resource "aws_elasticache_replication_group" "sessions" {\n'
        '  replication_group_id = "sessions"\n'
        f"{lines}"
        "}\n"
    )


def test_elasticache_quoted_bool_tag_value_does_not_decide_the_verdict(tmp_path: Path) -> None:
    # PR #1162 round-4 M2: same first-match exposure as EFS.
    assert [f.rule for f in _run(tmp_path, _group('  tags = { transit_encryption_enabled = "true" }\n'))] == [_RULE]
    assert [f.rule for f in _run(tmp_path, _group(
        '  tags = {\n    transit_encryption_enabled = "true"\n  }\n'
    ))] == [_RULE]
    assert _run(tmp_path, _group(
        '  tags = { transit_encryption_enabled = "false" }\n  transit_encryption_enabled = true\n'
    )) == []
    # Still fires: the real attribute off, next to a "true" tag.
    assert [f.rule for f in _run(tmp_path, _group(
        '  tags = { transit_encryption_enabled = "true" }\n  transit_encryption_enabled = false\n'
    ))] == [_RULE]
