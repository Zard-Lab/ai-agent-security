from __future__ import annotations

from agentsec.guards.aws_weak_tls_policy import AwsWeakTlsPolicyGuard
from tests.guards._common import *  # noqa: F401,F403

_APIGW_RULE = "aws-weak-tls-policy/apigateway-domain"
_OPENSEARCH_RULE = "aws-weak-tls-policy/opensearch-domain"
_LB_RULE = "aws-weak-tls-policy/lb-listener"


def _run(tmp_path: Path, content: str) -> list:
    (tmp_path / "tls.tf").write_text(content, encoding="utf-8")
    return AwsWeakTlsPolicyGuard().run(tmp_path, _tf_prof(tmp_path))


# --- Rule A: API Gateway custom domain ----------------------------------------------------

def test_apigateway_v1_missing_security_policy_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_api_gateway_domain_name" "api" {\n'
        '  domain_name = "api.example.com"\n'
        "}\n"
    ))
    assert any(f.rule == _APIGW_RULE for f in findings)


def test_apigateway_v1_tls12_silent(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_api_gateway_domain_name" "api" {\n'
        '  domain_name     = "api.example.com"\n'
        '  security_policy = "TLS_1_2"\n'
        "}\n"
    ))
    assert not any(f.rule == _APIGW_RULE for f in findings)


def test_apigateway_v1_weak_policy_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_api_gateway_domain_name" "api" {\n'
        '  domain_name     = "api.example.com"\n'
        '  security_policy = "TLS_1_0"\n'
        "}\n"
    ))
    assert any(f.rule == _APIGW_RULE for f in findings)


def test_apigateway_v2_missing_security_policy_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_apigatewayv2_domain_name" "api" {\n'
        '  domain_name = "api.example.com"\n'
        "\n"
        "  domain_name_configuration {\n"
        "    certificate_arn = aws_acm_certificate.api.arn\n"
        '    endpoint_type   = "REGIONAL"\n'
        "  }\n"
        "}\n"
    ))
    matches = [f for f in findings if f.rule == _APIGW_RULE]
    assert len(matches) == 1
    # Absent policy: no source states the default, so it is reported as unpinned at LOW
    # (PR #1162 round-1 M2); an explicit weak literal stays MEDIUM.
    assert matches[0].severity == "low"


def test_apigateway_v2_tls12_silent(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_apigatewayv2_domain_name" "api" {\n'
        '  domain_name = "api.example.com"\n'
        "\n"
        "  domain_name_configuration {\n"
        "    certificate_arn  = aws_acm_certificate.api.arn\n"
        '    endpoint_type    = "REGIONAL"\n'
        '    security_policy  = "TLS_1_2"\n'
        "  }\n"
        "}\n"
    ))
    assert not any(f.rule == _APIGW_RULE for f in findings)


def test_apigateway_v2_weak_policy_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_apigatewayv2_domain_name" "api" {\n'
        '  domain_name = "api.example.com"\n'
        "\n"
        "  domain_name_configuration {\n"
        "    certificate_arn  = aws_acm_certificate.api.arn\n"
        '    endpoint_type    = "REGIONAL"\n'
        '    security_policy  = "TLS_1_0"\n'
        "  }\n"
        "}\n"
    ))
    assert any(f.rule == _APIGW_RULE for f in findings)


# --- Rule B: OpenSearch / Elasticsearch domain TLS policy ---------------------------------

def test_opensearch_missing_tls_policy_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_opensearch_domain" "search" {\n'
        '  domain_name = "search"\n'
        "\n"
        "  domain_endpoint_options {\n"
        "    enforce_https = true\n"
        "  }\n"
        "}\n"
    ))
    matches = [f for f in findings if f.rule == _OPENSEARCH_RULE]
    assert len(matches) == 1
    # Absent policy: no source states the default, so it is reported as unpinned at LOW
    # (PR #1162 round-1 M2); an explicit weak literal stays MEDIUM.
    assert matches[0].severity == "low"


def test_opensearch_weak_named_policy_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_opensearch_domain" "search" {\n'
        '  domain_name = "search"\n'
        "\n"
        "  domain_endpoint_options {\n"
        "    enforce_https      = true\n"
        '    tls_security_policy = "Policy-Min-TLS-1-0-2019-07"\n'
        "  }\n"
        "}\n"
    ))
    assert any(f.rule == _OPENSEARCH_RULE for f in findings)


def test_opensearch_strong_policy_silent(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_opensearch_domain" "search" {\n'
        '  domain_name = "search"\n'
        "\n"
        "  domain_endpoint_options {\n"
        "    enforce_https      = true\n"
        '    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"\n'
        "  }\n"
        "}\n"
    ))
    assert not any(f.rule == _OPENSEARCH_RULE for f in findings)


def test_elasticsearch_domain_also_checked(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_elasticsearch_domain" "search" {\n'
        '  domain_name = "search"\n'
        "\n"
        "  domain_endpoint_options {\n"
        "    enforce_https = true\n"
        "  }\n"
        "}\n"
    ))
    assert any(f.rule == _OPENSEARCH_RULE for f in findings)


# --- Rule C: ALB/NLB listener SSL policy ---------------------------------------------------

def test_https_listener_missing_ssl_policy_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_lb_listener" "https" {\n'
        "  load_balancer_arn = aws_lb.main.arn\n"
        '  port              = "443"\n'
        '  protocol          = "HTTPS"\n'
        "  certificate_arn   = aws_acm_certificate.main.arn\n"
        "\n"
        "  default_action {\n"
        '    type             = "forward"\n'
        "    target_group_arn = aws_lb_target_group.main.arn\n"
        "  }\n"
        "}\n"
    ))
    matches = [f for f in findings if f.rule == _LB_RULE]
    assert len(matches) == 1
    assert matches[0].severity == "medium"


def test_https_listener_weak_ssl_policy_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_lb_listener" "https" {\n'
        "  load_balancer_arn = aws_lb.main.arn\n"
        '  port              = "443"\n'
        '  protocol          = "HTTPS"\n'
        '  ssl_policy        = "ELBSecurityPolicy-TLS-1-0-2015-04"\n'
        "  certificate_arn   = aws_acm_certificate.main.arn\n"
        "\n"
        "  default_action {\n"
        '    type             = "forward"\n'
        "    target_group_arn = aws_lb_target_group.main.arn\n"
        "  }\n"
        "}\n"
    ))
    assert any(f.rule == _LB_RULE for f in findings)


def test_https_listener_legacy_2016_policy_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_lb_listener" "https" {\n'
        "  load_balancer_arn = aws_lb.main.arn\n"
        '  port              = "443"\n'
        '  protocol          = "HTTPS"\n'
        '  ssl_policy        = "ELBSecurityPolicy-2016-08"\n'
        "  certificate_arn   = aws_acm_certificate.main.arn\n"
        "\n"
        "  default_action {\n"
        '    type             = "forward"\n'
        "    target_group_arn = aws_lb_target_group.main.arn\n"
        "  }\n"
        "}\n"
    ))
    assert any(f.rule == _LB_RULE for f in findings)


def test_https_listener_modern_ssl_policy_silent(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_lb_listener" "https" {\n'
        "  load_balancer_arn = aws_lb.main.arn\n"
        '  port              = "443"\n'
        '  protocol          = "HTTPS"\n'
        '  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"\n'
        "  certificate_arn   = aws_acm_certificate.main.arn\n"
        "\n"
        "  default_action {\n"
        '    type             = "forward"\n'
        "    target_group_arn = aws_lb_target_group.main.arn\n"
        "  }\n"
        "}\n"
    ))
    assert not any(f.rule == _LB_RULE for f in findings)


def test_lb_listener_variable_ssl_policy_stays_silent(tmp_path: Path) -> None:
    # A non-literal ssl_policy cannot be proven weak (review H5b) -- stays silent, unlike
    # an absent attribute.
    findings = _run(tmp_path, (
        'resource "aws_lb_listener" "https" {\n'
        "  load_balancer_arn = aws_lb.main.arn\n"
        '  port              = "443"\n'
        '  protocol          = "HTTPS"\n'
        "  ssl_policy        = var.ssl_policy\n"
        "  certificate_arn   = aws_acm_certificate.main.arn\n"
        "\n"
        "  default_action {\n"
        '    type             = "forward"\n'
        "    target_group_arn = aws_lb_target_group.main.arn\n"
        "  }\n"
        "}\n"
    ))
    assert not any(f.rule == _LB_RULE for f in findings)


def test_lb_listener_redirect_with_nested_https_protocol_stays_silent(tmp_path: Path) -> None:
    # No top-level protocol attribute at all; a nested redirect's own protocol = "HTTPS"
    # must not be mistaken for the listener's own protocol (review H5a).
    findings = _run(tmp_path, (
        'resource "aws_lb_listener" "http" {\n'
        "  load_balancer_arn = aws_lb.main.arn\n"
        '  port              = "80"\n'
        "\n"
        "  default_action {\n"
        '    type = "redirect"\n'
        "    redirect {\n"
        '      protocol = "HTTPS"\n'
        "    }\n"
        "  }\n"
        "}\n"
    ))
    assert not any(f.rule == _LB_RULE for f in findings)


def test_alb_listener_alias_also_checked(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_alb_listener" "https" {\n'
        "  load_balancer_arn = aws_alb.main.arn\n"
        '  port              = "443"\n'
        '  protocol          = "HTTPS"\n'
        "  certificate_arn   = aws_acm_certificate.main.arn\n"
        "\n"
        "  default_action {\n"
        '    type             = "forward"\n'
        "    target_group_arn = aws_lb_target_group.main.arn\n"
        "  }\n"
        "}\n"
    ))
    assert any(f.rule == _LB_RULE for f in findings)


def test_http_listener_out_of_scope_for_this_guard(tmp_path: Path) -> None:
    # Plain HTTP (no TLS at all) is the OTHER guard's concern -- this rule stays silent.
    findings = _run(tmp_path, (
        'resource "aws_lb_listener" "http" {\n'
        "  load_balancer_arn = aws_lb.main.arn\n"
        '  port              = "80"\n'
        '  protocol          = "HTTP"\n'
        "\n"
        "  default_action {\n"
        '    type             = "forward"\n'
        "    target_group_arn = aws_lb_target_group.main.arn\n"
        "  }\n"
        "}\n"
    ))
    assert not any(f.rule == _LB_RULE for f in findings)


def test_classic_elb_out_of_scope(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_elb" "classic" {\n'
        '  name = "classic"\n'
        "}\n"
    ))
    assert not any(f.rule == _LB_RULE for f in findings)


# --- Pragma -----------------------------------------------------------------------------------

def test_pragma_silences_all_rules(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_api_gateway_domain_name" "api" {\n'
        '  domain_name = "api.example.com"  # security: allow-weak-tls-policy\n'
        "}\n"
    ))
    assert not any(f.rule == _APIGW_RULE for f in findings)


# --- applies() ---------------------------------------------------------------------------------

def test_applies_gate(tmp_path: Path) -> None:
    guard = AwsWeakTlsPolicyGuard()
    assert guard.applies(mkprofile(tmp_path, features=set())) is False


def test_applies_with_terraform(tmp_path: Path) -> None:
    guard = AwsWeakTlsPolicyGuard()
    assert guard.applies(_tf_prof(tmp_path)) is True


# --- PR #1162 round-3 fix pass: non-literal policies, interpolation, comments, legacy names ---

def _apigw_v1(policy_line: str) -> str:
    return (
        'resource "aws_api_gateway_domain_name" "api" {\n'
        '  domain_name = "api.example.com"\n'
        f"{policy_line}"
        "}\n"
    )


def _apigw_v2(config_lines: str) -> str:
    return (
        'resource "aws_apigatewayv2_domain_name" "api" {\n'
        '  domain_name = "api.example.com"\n'
        "  domain_name_configuration {\n"
        f"{config_lines}"
        '    endpoint_type   = "REGIONAL"\n'
        "  }\n"
        "}\n"
    )


def _opensearch(options_lines: str) -> str:
    return (
        'resource "aws_opensearch_domain" "search" {\n'
        '  domain_name = "search"\n'
        "  domain_endpoint_options {\n"
        "    enforce_https = true\n"
        f"{options_lines}"
        "  }\n"
        "}\n"
    )


def test_non_literal_policy_stays_silent_in_every_rule(tmp_path: Path) -> None:
    # Round-2 M-1: a variable, a local, or an interpolation cannot be proven weak -- the same
    # convention Rule C already applied to `ssl_policy = var.*`.
    cases = [
        (_APIGW_RULE, _apigw_v1("  security_policy = var.sp\n")),
        (_APIGW_RULE, _apigw_v1('  security_policy = "${var.sp}"\n')),
        (_APIGW_RULE, _apigw_v2("    certificate_arn = aws_acm_certificate.api.arn\n    security_policy = local.sp\n")),
        (_OPENSEARCH_RULE, _opensearch("    tls_security_policy = var.p\n")),
        (_OPENSEARCH_RULE, _opensearch('    tls_security_policy = "${var.p}"\n')),
    ]
    for rule, content in cases:
        assert not any(f.rule == rule for f in _run(tmp_path, content)), content


def test_literal_weak_policy_still_fires_medium(tmp_path: Path) -> None:
    # The opposite direction of the non-literal narrowing: a literal weak policy still fires,
    # and at MEDIUM (only an ABSENT policy drops to LOW).
    cases = [
        (_APIGW_RULE, _apigw_v1('  security_policy = "TLS_1_0"\n')),
        (_APIGW_RULE, _apigw_v2('    certificate_arn = aws_acm_certificate.api.arn\n    security_policy = "TLS_1_0"\n')),
        (_OPENSEARCH_RULE, _opensearch('    tls_security_policy = "Policy-Min-TLS-1-0-2019-07"\n')),
    ]
    for rule, content in cases:
        matches = [f for f in _run(tmp_path, content) if f.rule == rule]
        assert [f.severity for f in matches] == ["medium"], content


def test_absent_policy_is_reported_as_unpinned_at_low(tmp_path: Path) -> None:
    # Round-1 M2: AWS documents no default for an omitted API Gateway or OpenSearch policy, so
    # absence is "not pinned" at LOW, not a proven weak policy.
    for rule, content in (
        (_APIGW_RULE, _apigw_v1("")),
        (_OPENSEARCH_RULE, _opensearch("")),
    ):
        matches = [f for f in _run(tmp_path, content) if f.rule == rule]
        assert [f.severity for f in matches] == ["low"], content
        assert "not pinned" in matches[0].message


def test_interpolation_does_not_cut_the_block_short(tmp_path: Path) -> None:
    # Round-2 M-2: an interpolation's own `}` used to end the `[^{}]*` block regex early.
    # A compliant OpenSearch domain with an interpolated custom endpoint stays silent...
    compliant = _opensearch(
        '    custom_endpoint     = "search.${var.domain}.com"\n'
        '    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"\n'
    )
    assert not any(f.rule == _OPENSEARCH_RULE for f in _run(tmp_path, compliant))
    # ...the same block with the weak policy after the interpolation still fires...
    weak = _opensearch(
        '    custom_endpoint     = "search.${var.domain}.com"\n'
        '    tls_security_policy = "Policy-Min-TLS-1-0-2019-07"\n'
    )
    assert [f.severity for f in _run(tmp_path, weak) if f.rule == _OPENSEARCH_RULE] == ["medium"]
    # ...and an interpolated API Gateway certificate no longer hides a weak policy (it was a
    # false negative), while the TLS_1_2 neighbour stays silent.
    weak_v2 = _apigw_v2('    certificate_arn = "${var.cert_arn}"\n    security_policy = "TLS_1_0"\n')
    assert [f.severity for f in _run(tmp_path, weak_v2) if f.rule == _APIGW_RULE] == ["medium"]
    ok_v2 = _apigw_v2('    certificate_arn = "${var.cert_arn}"\n    security_policy = "TLS_1_2"\n')
    assert not any(f.rule == _APIGW_RULE for f in _run(tmp_path, ok_v2))


def test_policy_written_only_in_a_comment_is_not_set(tmp_path: Path) -> None:
    # A commented-out policy is not a policy: the resource is still unpinned.
    commented = _apigw_v1('  # security_policy = "TLS_1_2"\n')
    assert [f.severity for f in _run(tmp_path, commented) if f.rule == _APIGW_RULE] == ["low"]
    # FP-bait: a real TLS_1_2 policy next to a comment stays silent.
    real = _apigw_v1('  security_policy = "TLS_1_2"  # pinned per policy\n')
    assert not any(f.rule == _APIGW_RULE for f in _run(tmp_path, real))


def _https_listener(ssl_policy: str) -> str:
    return (
        'resource "aws_lb_listener" "https" {\n'
        "  load_balancer_arn = aws_lb.main.arn\n"
        '  port              = "443"\n'
        '  protocol          = "HTTPS"\n'
        f'  ssl_policy        = "{ssl_policy}"\n'
        "  certificate_arn   = aws_acm_certificate.main.arn\n"
        "  default_action {\n"
        '    type             = "forward"\n'
        "    target_group_arn = aws_lb_target_group.main.arn\n"
        "  }\n"
        "}\n"
    )


def test_legacy_dated_elb_policies_fire(tmp_path: Path) -> None:
    # Round-2 M-5: the dated legacy policies AWS's tables list as permitting TLS 1.0.
    for policy in (
        "ELBSecurityPolicy-2015-05",
        "ELBSecurityPolicy-2015-03",
        "ELBSecurityPolicy-2015-02",
        "ELBSecurityPolicy-2016-08",
    ):
        matches = [f for f in _run(tmp_path, _https_listener(policy)) if f.rule == _LB_RULE]
        assert [f.severity for f in matches] == ["medium"], policy


def test_modern_tls12_elb_policies_stay_silent(tmp_path: Path) -> None:
    # FP-bait for the legacy-name widening: TLS 1.2+ policies, including the dated-looking
    # `-2017-01` / `-2018-06` / `-2021-06` ones, stay silent.
    for policy in (
        "ELBSecurityPolicy-TLS-1-2-2017-01",
        "ELBSecurityPolicy-TLS-1-2-Ext-2018-06",
        "ELBSecurityPolicy-TLS13-1-2-2021-06",
        "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09",
    ):
        assert not any(f.rule == _LB_RULE for f in _run(tmp_path, _https_listener(policy))), policy


def test_null_policy_is_the_same_as_an_absent_one(tmp_path: Path) -> None:
    # PR #1162 round-2 Low: `null` hands the attribute back to its default, exactly like
    # omitting it -- it used to read as a non-literal value and stay silent.
    listener = _https_listener("X").replace('ssl_policy        = "X"', "ssl_policy        = null")
    assert [f.severity for f in _run(tmp_path, listener) if f.rule == _LB_RULE] == ["medium"]
    assert [f.severity for f in _run(tmp_path, _apigw_v1("  security_policy = null\n")) if f.rule == _APIGW_RULE] == [
        "low"
    ]
    opensearch = _opensearch("    tls_security_policy = null\n")
    assert [f.severity for f in _run(tmp_path, opensearch) if f.rule == _OPENSEARCH_RULE] == ["low"]
    # FP-bait: a reference whose name merely starts with "null" is still a non-literal value.
    assert not any(f.rule == _LB_RULE for f in _run(tmp_path, listener.replace("= null", "= nullable_policy")))


def test_brace_in_a_string_or_heredoc_does_not_hide_a_weak_listener_policy(tmp_path: Path) -> None:
    # PR #1162 round-3 L-3: the weak-TLS caller of top_level_attribute_text, pinned for the
    # string and heredoc shapes (measured correct in round 3, but untested).
    for noise in ('  tags = { note = "x{" }\n', "  description = <<EOT\n  {\nEOT\n"):
        listener = _https_listener("ELBSecurityPolicy-TLS-1-0-2015-04").replace(
            "  load_balancer_arn", noise + "  load_balancer_arn", 1
        )
        assert [f.rule for f in _run(tmp_path, listener) if f.rule == _LB_RULE] == [_LB_RULE], noise
