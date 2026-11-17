from __future__ import annotations

from agentsec.guards.msk_cluster_transit_encryption_disabled import (
    MskClusterTransitEncryptionDisabledGuard,
)
from tests.guards._common import *  # noqa: F401,F403

_CLIENT_BROKER_RULE = "msk-cluster-transit-encryption-disabled/client-broker-not-tls"
_CLIENT_BROKER_OPPORTUNISTIC_RULE = (
    "msk-cluster-transit-encryption-disabled/client-broker-opportunistic-tls"
)
_IN_CLUSTER_RULE = "msk-cluster-transit-encryption-disabled/in-cluster-disabled"


def _run(tmp_path: Path, content: str) -> list:
    (tmp_path / "msk.tf").write_text(content, encoding="utf-8")
    return MskClusterTransitEncryptionDisabledGuard().run(tmp_path, _tf_prof(tmp_path))


# --- client_broker (Rule A) --------------------------------------------------------------------

def test_msk_no_encryption_info_block_stays_silent(tmp_path: Path) -> None:
    # Default-config cluster (no encryption_info block at all). The AWS provider defaults
    # client_broker to "TLS", which is safe, so an absent block must not fire -- this is the
    # FP-bait for H1 (review: absence was wrongly treated as unsafe).
    findings = _run(tmp_path, (
        'resource "aws_msk_cluster" "events" {\n'
        '  cluster_name           = "events"\n'
        "  number_of_broker_nodes = 3\n"
        "}\n"
    ))
    assert findings == []


def test_msk_encryption_in_transit_block_absent_stays_silent(tmp_path: Path) -> None:
    # encryption_info present, but encryption_in_transit (and so client_broker) absent --
    # still defaults to "TLS", still safe.
    findings = _run(tmp_path, (
        'resource "aws_msk_cluster" "events" {\n'
        '  cluster_name = "events"\n'
        "  encryption_info {\n"
        "    encryption_at_rest_kms_key_arn = \"arn:aws:kms:us-east-1:111111111111:key/abc\"\n"
        "  }\n"
        "}\n"
    ))
    assert not any(f.rule == _CLIENT_BROKER_RULE for f in findings)


def test_msk_client_broker_attribute_absent_but_block_present_stays_silent(tmp_path: Path) -> None:
    # encryption_in_transit present, client_broker attribute itself omitted -> still defaults
    # to "TLS".
    findings = _run(tmp_path, (
        'resource "aws_msk_cluster" "events" {\n'
        '  cluster_name = "events"\n'
        "  encryption_info {\n"
        "    encryption_in_transit {\n"
        "      in_cluster = true\n"
        "    }\n"
        "  }\n"
        "}\n"
    ))
    assert not any(f.rule == _CLIENT_BROKER_RULE for f in findings)


def test_msk_client_broker_variable_stays_silent(tmp_path: Path) -> None:
    # A non-literal (variable-wrapped) value cannot be proven unsafe -- stays silent (H6).
    findings = _run(tmp_path, (
        'resource "aws_msk_cluster" "events" {\n'
        '  cluster_name = "events"\n'
        "  encryption_info {\n"
        "    encryption_in_transit {\n"
        "      client_broker = var.client_broker\n"
        "    }\n"
        "  }\n"
        "}\n"
    ))
    assert not any(f.rule == _CLIENT_BROKER_RULE for f in findings)
    assert not any(f.rule == _CLIENT_BROKER_OPPORTUNISTIC_RULE for f in findings)


def test_msk_client_broker_tls_plaintext_fires_medium(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_msk_cluster" "events" {\n'
        '  cluster_name = "events"\n'
        "  encryption_info {\n"
        "    encryption_in_transit {\n"
        '      client_broker = "TLS_PLAINTEXT"\n'
        "      in_cluster    = true\n"
        "    }\n"
        "  }\n"
        "}\n"
    ))
    matches = [f for f in findings if f.rule == _CLIENT_BROKER_OPPORTUNISTIC_RULE]
    assert len(matches) == 1
    assert matches[0].severity == "medium"
    assert not any(f.rule == _CLIENT_BROKER_RULE for f in findings)


def test_msk_client_broker_plaintext_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_msk_cluster" "events" {\n'
        '  cluster_name = "events"\n'
        "  encryption_info {\n"
        "    encryption_in_transit {\n"
        '      client_broker = "PLAINTEXT"\n'
        "    }\n"
        "  }\n"
        "}\n"
    ))
    assert any(f.rule == _CLIENT_BROKER_RULE for f in findings)


def test_msk_client_broker_tls_silent(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_msk_cluster" "events" {\n'
        '  cluster_name = "events"\n'
        "  encryption_info {\n"
        "    encryption_in_transit {\n"
        '      client_broker = "TLS"\n'
        "      in_cluster    = true\n"
        "    }\n"
        "  }\n"
        "}\n"
    ))
    assert not any(f.rule == _CLIENT_BROKER_RULE for f in findings)


# --- in_cluster (Rule B) -------------------------------------------------------------------------

def test_msk_in_cluster_false_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_msk_cluster" "events" {\n'
        '  cluster_name = "events"\n'
        "  encryption_info {\n"
        "    encryption_in_transit {\n"
        '      client_broker = "TLS"\n'
        "      in_cluster    = false\n"
        "    }\n"
        "  }\n"
        "}\n"
    ))
    matches = [f for f in findings if f.rule == _IN_CLUSTER_RULE]
    assert len(matches) == 1
    assert matches[0].severity == "high"
    # client_broker is "TLS" here, so Rule A must stay silent.
    assert not any(f.rule == _CLIENT_BROKER_RULE for f in findings)


def test_msk_in_cluster_true_silent(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_msk_cluster" "events" {\n'
        '  cluster_name = "events"\n'
        "  encryption_info {\n"
        "    encryption_in_transit {\n"
        '      client_broker = "TLS"\n'
        "      in_cluster    = true\n"
        "    }\n"
        "  }\n"
        "}\n"
    ))
    assert not any(f.rule == _IN_CLUSTER_RULE for f in findings)


def test_msk_in_cluster_absent_does_not_fire_rule_b(tmp_path: Path) -> None:
    # in_cluster missing but the block is present -> Rule B stays silent (only Rule A's
    # absence-of-structure case governs a missing attribute).
    findings = _run(tmp_path, (
        'resource "aws_msk_cluster" "events" {\n'
        '  cluster_name = "events"\n'
        "  encryption_info {\n"
        "    encryption_in_transit {\n"
        '      client_broker = "TLS"\n'
        "    }\n"
        "  }\n"
        "}\n"
    ))
    assert not any(f.rule == _IN_CLUSTER_RULE for f in findings)


# --- pragma / applies / unrelated resource -------------------------------------------------------

def test_msk_pragma_silences(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_msk_cluster" "events" {\n'
        '  cluster_name = "events"  # security: allow-msk-plaintext\n'
        "  encryption_info {\n"
        "    encryption_in_transit {\n"
        '      client_broker = "PLAINTEXT"\n'
        "      in_cluster    = false\n"
        "    }\n"
        "  }\n"
        "}\n"
    ))
    assert findings == []


def test_msk_unrelated_resource_silent(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_db_instance" "app" {\n'
        '  engine = "postgres"\n'
        "}\n"
    ))
    assert findings == []


def test_msk_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert MskClusterTransitEncryptionDisabledGuard().applies(profile) is False


def test_msk_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert MskClusterTransitEncryptionDisabledGuard().applies(profile) is True
