from __future__ import annotations

from agentsec.guards.opensearch_domain_encryption_disabled import (
    OpensearchDomainEncryptionDisabledGuard,
)
from tests.guards._common import *  # noqa: F401,F403

_ENFORCE_HTTPS_RULE = "opensearch-domain-encryption-disabled/enforce-https-disabled"
_NODE_TO_NODE_RULE = "opensearch-domain-encryption-disabled/node-to-node-disabled"
_ENCRYPT_AT_REST_RULE = "opensearch-domain-encryption-disabled/encrypt-at-rest-disabled"


def _run(tmp_path: Path, content: str, name: str = "opensearch.tf") -> list:
    (tmp_path / name).write_text(content, encoding="utf-8")
    return OpensearchDomainEncryptionDisabledGuard().run(tmp_path, _tf_prof(tmp_path))


_FULLY_UNCONFIGURED = (
    'resource "aws_opensearch_domain" "logs" {\n'
    '  domain_name    = "logs"\n'
    '  engine_version = "OpenSearch_2.11"\n'
    "}\n"
)

_FULLY_HARDENED = (
    'resource "aws_opensearch_domain" "logs" {\n'
    '  domain_name    = "logs"\n'
    '  engine_version = "OpenSearch_2.11"\n'
    "  domain_endpoint_options {\n"
    "    enforce_https = true\n"
    "  }\n"
    "  node_to_node_encryption {\n"
    "    enabled = true\n"
    "  }\n"
    "  encrypt_at_rest {\n"
    "    enabled = true\n"
    "  }\n"
    "}\n"
)


# --- all three rules fire together on a fully unconfigured domain -------------------------------

def test_opensearch_fully_unconfigured_fires_the_off_by_default_two(tmp_path: Path) -> None:
    # enforce_https defaults to true (safe) per the AWS provider docs, so a fully unconfigured
    # domain must NOT fire that rule -- only the two that default off (review H2).
    findings = _run(tmp_path, _FULLY_UNCONFIGURED)
    rules = {f.rule for f in findings}
    assert rules == {_NODE_TO_NODE_RULE, _ENCRYPT_AT_REST_RULE}
    assert all(f.severity == "high" for f in findings)


def test_opensearch_fully_hardened_silent(tmp_path: Path) -> None:
    assert _run(tmp_path, _FULLY_HARDENED) == []


# --- Rule A: enforce_https ------------------------------------------------------------------------

def test_opensearch_enforce_https_block_absent_stays_silent(tmp_path: Path) -> None:
    # Provider default for enforce_https is true (safe) -- an absent block must not fire
    # (review H2 FP-bait: this test used to assert the opposite).
    findings = _run(tmp_path, (
        'resource "aws_opensearch_domain" "logs" {\n'
        '  domain_name = "logs"\n'
        "  node_to_node_encryption {\n    enabled = true\n  }\n"
        "  encrypt_at_rest {\n    enabled = true\n  }\n"
        "}\n"
    ))
    assert not any(f.rule == _ENFORCE_HTTPS_RULE for f in findings)


def test_opensearch_enforce_https_attribute_absent_stays_silent(tmp_path: Path) -> None:
    # Block present, enforce_https attribute itself omitted -> still defaults to true (safe).
    findings = _run(tmp_path, (
        'resource "aws_opensearch_domain" "logs" {\n'
        '  domain_name = "logs"\n'
        "  domain_endpoint_options {\n"
        '    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"\n'
        "  }\n"
        "  node_to_node_encryption {\n    enabled = true\n  }\n"
        "  encrypt_at_rest {\n    enabled = true\n  }\n"
        "}\n"
    ))
    assert not any(f.rule == _ENFORCE_HTTPS_RULE for f in findings)


def test_opensearch_enforce_https_variable_stays_silent(tmp_path: Path) -> None:
    # A non-literal value cannot be proven unsafe (review H6) -- stays silent.
    findings = _run(tmp_path, (
        'resource "aws_opensearch_domain" "logs" {\n'
        '  domain_name = "logs"\n'
        "  domain_endpoint_options {\n    enforce_https = var.https\n  }\n"
        "  node_to_node_encryption {\n    enabled = true\n  }\n"
        "  encrypt_at_rest {\n    enabled = true\n  }\n"
        "}\n"
    ))
    assert not any(f.rule == _ENFORCE_HTTPS_RULE for f in findings)


def test_opensearch_enforce_https_false_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_opensearch_domain" "logs" {\n'
        '  domain_name = "logs"\n'
        "  domain_endpoint_options {\n    enforce_https = false\n  }\n"
        "  node_to_node_encryption {\n    enabled = true\n  }\n"
        "  encrypt_at_rest {\n    enabled = true\n  }\n"
        "}\n"
    ))
    assert any(f.rule == _ENFORCE_HTTPS_RULE for f in findings)


def test_opensearch_enforce_https_true_silent(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_opensearch_domain" "logs" {\n'
        '  domain_name = "logs"\n'
        "  domain_endpoint_options {\n    enforce_https = true\n  }\n"
        "  node_to_node_encryption {\n    enabled = true\n  }\n"
        "  encrypt_at_rest {\n    enabled = true\n  }\n"
        "}\n"
    ))
    assert not any(f.rule == _ENFORCE_HTTPS_RULE for f in findings)


# --- Rule B: node_to_node_encryption ---------------------------------------------------------------

def test_opensearch_node_to_node_block_absent_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_opensearch_domain" "logs" {\n'
        '  domain_name = "logs"\n'
        "  domain_endpoint_options {\n    enforce_https = true\n  }\n"
        "  encrypt_at_rest {\n    enabled = true\n  }\n"
        "}\n"
    ))
    assert any(f.rule == _NODE_TO_NODE_RULE for f in findings)


def test_opensearch_node_to_node_enabled_false_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_opensearch_domain" "logs" {\n'
        '  domain_name = "logs"\n'
        "  domain_endpoint_options {\n    enforce_https = true\n  }\n"
        "  node_to_node_encryption {\n    enabled = false\n  }\n"
        "  encrypt_at_rest {\n    enabled = true\n  }\n"
        "}\n"
    ))
    assert any(f.rule == _NODE_TO_NODE_RULE for f in findings)


def test_opensearch_node_to_node_enabled_true_silent(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_opensearch_domain" "logs" {\n'
        '  domain_name = "logs"\n'
        "  domain_endpoint_options {\n    enforce_https = true\n  }\n"
        "  node_to_node_encryption {\n    enabled = true\n  }\n"
        "  encrypt_at_rest {\n    enabled = true\n  }\n"
        "}\n"
    ))
    assert not any(f.rule == _NODE_TO_NODE_RULE for f in findings)


def test_opensearch_node_to_node_variable_stays_silent(tmp_path: Path) -> None:
    # A non-literal value cannot be proven unsafe (review H6) -- stays silent, unlike absence.
    findings = _run(tmp_path, (
        'resource "aws_opensearch_domain" "logs" {\n'
        '  domain_name = "logs"\n'
        "  domain_endpoint_options {\n    enforce_https = true\n  }\n"
        "  node_to_node_encryption {\n    enabled = var.e\n  }\n"
        "  encrypt_at_rest {\n    enabled = true\n  }\n"
        "}\n"
    ))
    assert not any(f.rule == _NODE_TO_NODE_RULE for f in findings)


# --- Rule C: encrypt_at_rest -----------------------------------------------------------------------

def test_opensearch_encrypt_at_rest_block_absent_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_opensearch_domain" "logs" {\n'
        '  domain_name = "logs"\n'
        "  domain_endpoint_options {\n    enforce_https = true\n  }\n"
        "  node_to_node_encryption {\n    enabled = true\n  }\n"
        "}\n"
    ))
    assert any(f.rule == _ENCRYPT_AT_REST_RULE for f in findings)


def test_opensearch_encrypt_at_rest_enabled_false_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_opensearch_domain" "logs" {\n'
        '  domain_name = "logs"\n'
        "  domain_endpoint_options {\n    enforce_https = true\n  }\n"
        "  node_to_node_encryption {\n    enabled = true\n  }\n"
        "  encrypt_at_rest {\n    enabled = false\n  }\n"
        "}\n"
    ))
    assert any(f.rule == _ENCRYPT_AT_REST_RULE for f in findings)


def test_opensearch_encrypt_at_rest_enabled_true_silent(tmp_path: Path) -> None:
    findings = _run(tmp_path, _FULLY_HARDENED)
    assert not any(f.rule == _ENCRYPT_AT_REST_RULE for f in findings)


def test_opensearch_encrypt_at_rest_variable_stays_silent(tmp_path: Path) -> None:
    # A non-literal value cannot be proven unsafe (review H6) -- stays silent, unlike absence.
    findings = _run(tmp_path, (
        'resource "aws_opensearch_domain" "logs" {\n'
        '  domain_name = "logs"\n'
        "  domain_endpoint_options {\n    enforce_https = true\n  }\n"
        "  node_to_node_encryption {\n    enabled = true\n  }\n"
        "  encrypt_at_rest {\n    enabled = var.e\n  }\n"
        "}\n"
    ))
    assert not any(f.rule == _ENCRYPT_AT_REST_RULE for f in findings)


# --- aws_elasticsearch_domain carries the identical logic -----------------------------------------

def test_elasticsearch_domain_legacy_type_fires_the_off_by_default_two(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_elasticsearch_domain" "logs" {\n'
        '  domain_name = "logs"\n'
        "}\n"
    ))
    rules = {f.rule for f in findings}
    assert rules == {_NODE_TO_NODE_RULE, _ENCRYPT_AT_REST_RULE}


def test_elasticsearch_domain_legacy_type_hardened_silent(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_elasticsearch_domain" "logs" {\n'
        '  domain_name = "logs"\n'
        "  domain_endpoint_options {\n    enforce_https = true\n  }\n"
        "  node_to_node_encryption {\n    enabled = true\n  }\n"
        "  encrypt_at_rest {\n    enabled = true\n  }\n"
        "}\n"
    ))
    assert findings == []


# --- pragma / applies / unrelated resource ---------------------------------------------------------

def test_opensearch_pragma_silences(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_opensearch_domain" "logs" {\n'
        '  domain_name = "logs"  # security: allow-opensearch-unencrypted\n'
        "}\n"
    ))
    assert findings == []


def test_opensearch_unrelated_resource_silent(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_db_instance" "app" {\n'
        '  engine = "postgres"\n'
        "}\n"
    ))
    assert findings == []


def test_opensearch_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert OpensearchDomainEncryptionDisabledGuard().applies(profile) is False


def test_opensearch_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert OpensearchDomainEncryptionDisabledGuard().applies(profile) is True


def _domain(*blocks: str) -> str:
    return (
        'resource "aws_opensearch_domain" "logs" {\n'
        '  domain_name    = "logs"\n'
        + "".join(blocks)
        + "}\n"
    )


_N2N_ON = "  node_to_node_encryption {\n    enabled = true\n  }\n"
_AT_REST_ON = "  encrypt_at_rest {\n    enabled = true\n  }\n"


def test_opensearch_interpolated_kms_key_does_not_hide_enabled_at_rest(tmp_path: Path) -> None:
    # PR #1162 round-2 M-2: `kms_key_id = "${...}"` used to end the `[^{}]*` block regex at the
    # interpolation's own `}`, so a compliant `encrypt_at_rest { enabled = true }` read as absent
    # and fired HIGH.
    at_rest = '  encrypt_at_rest {\n    kms_key_id = "${aws_kms_key.k.arn}"\n    enabled    = true\n  }\n'
    assert _run(tmp_path, _domain(_N2N_ON, at_rest)) == []
    # Still fires: the same interpolated block with encryption explicitly off.
    off = '  encrypt_at_rest {\n    kms_key_id = "${aws_kms_key.k.arn}"\n    enabled    = false\n  }\n'
    assert [f.rule for f in _run(tmp_path, _domain(_N2N_ON, off))] == [_ENCRYPT_AT_REST_RULE]


def test_opensearch_interpolated_custom_endpoint_does_not_hide_enforce_https_false(
    tmp_path: Path,
) -> None:
    # PR #1162 round-2 M-2: `enforce_https = false` after an interpolated `custom_endpoint` was a
    # false negative (the block regex stopped at the interpolation's `}`).
    options = (
        "  domain_endpoint_options {\n"
        '    custom_endpoint = "search.${var.domain}.com"\n'
        "    enforce_https   = false\n"
        "  }\n"
    )
    assert [f.rule for f in _run(tmp_path, _domain(_N2N_ON, _AT_REST_ON, options))] == [
        _ENFORCE_HTTPS_RULE
    ]
    # FP-bait: the same block with HTTPS enforced stays silent.
    ok = options.replace("enforce_https   = false", "enforce_https   = true")
    assert _run(tmp_path, _domain(_N2N_ON, _AT_REST_ON, ok)) == []


def test_opensearch_quoted_and_interpolated_booleans(tmp_path: Path) -> None:
    # Quoted literals carry their meaning (Terraform coerces "true"/"false"), and a legacy
    # `"${var.x}"` interpolation is non-literal, so it stays silent like a bare `var.x`.
    quoted_on = '  node_to_node_encryption {\n    enabled = "true"\n  }\n'
    interp = '  encrypt_at_rest {\n    enabled = "${var.at_rest}"\n  }\n'
    assert _run(tmp_path, _domain(quoted_on, interp)) == []
    quoted_off = '  node_to_node_encryption {\n    enabled = "false"\n  }\n'
    assert [f.rule for f in _run(tmp_path, _domain(quoted_off, _AT_REST_ON))] == [_NODE_TO_NODE_RULE]


def test_opensearch_commented_out_block_is_not_set(tmp_path: Path) -> None:
    # A block written only in a comment does not enable anything.
    commented = "  # encrypt_at_rest {\n  #   enabled = true\n  # }\n"
    assert [f.rule for f in _run(tmp_path, _domain(_N2N_ON, commented))] == [_ENCRYPT_AT_REST_RULE]
