"""Guard: AWS Terraform resource allows a weak or unspecified TLS policy (checklist §7).

Bundles three independent resource-specific "named TLS policy" checks. Each resource type
exposes a provider-defined TLS policy name rather than a raw protocol/cipher list, and each
has its own known-weak values and its own absent-attribute default — so each is its own rule,
sharing only the underlying concept (CWE-326, Inadequate Encryption Strength; OWASP:A05).

1. **API Gateway custom domain — `security_policy`.**

       resource "aws_apigatewayv2_domain_name" "api" {
         domain_name = "api.example.com"

         domain_name_configuration {
           certificate_arn = aws_acm_certificate.api.arn
           endpoint_type   = "REGIONAL"
           # no security_policy -> the TLS floor is not pinned in code
         }
       }

   `aws_api_gateway_domain_name` carries `security_policy` directly on the resource;
   `aws_apigatewayv2_domain_name` nests it inside a `domain_name_configuration` block. Fires
   MEDIUM when the attribute is a literal that is not (case-insensitively) exactly `TLS_1_2`
   and does not contain `TLS13`/`TLS12` (e.g. `TLS_1_0`). Fires LOW when it is absent: neither
   the provider doc nor the AWS API reference states which policy an omitted
   `security_policy` gets, so absence is reported as "not pinned", not as a proven weak
   policy (PR #1162 round-1 M2).

2. **OpenSearch/Elasticsearch domain — `tls_security_policy`.**

       resource "aws_opensearch_domain" "search" {
         domain_endpoint_options {
           enforce_https = true
           # no tls_security_policy -> the TLS floor is not pinned in code
         }
       }

   Nested inside `domain_endpoint_options` on `aws_opensearch_domain` /
   `aws_elasticsearch_domain`. Fires MEDIUM when `tls_security_policy` is set to the one
   specifically weak named policy, `Policy-Min-TLS-1-0-2019-07` (TLS 1.0 to 1.2). Fires LOW
   when it is absent: the provider doc and the AWS `DomainEndpointOptions` reference state no
   default, and the only AWS-published evidence is an example `CreateDomain` response showing
   `Policy-Min-TLS-1-0-2019-07`, so absence is reported as "not pinned" (PR #1162 round-1 M2). This guard does not touch
   `encrypt_at_rest`, `node_to_node_encryption`, or `enforce_https` on these resource types —
   those are a different guard's concern.

3. **ALB/NLB listener — `ssl_policy`.**

       resource "aws_lb_listener" "https" {
         protocol = "HTTPS"
         # no ssl_policy -> provider falls back to a legacy default policy
       }

   Only relevant when the listener's own TOP-LEVEL `protocol` is `HTTPS` or `TLS`
   (case-insensitive) -- a plain HTTP listener is a different guard's concern
   (`alb_listener_http_protocol.py`), and a nested block's own `protocol` (e.g. inside a
   `default_action { redirect { ... } }`) is never read for this check, so it cannot be
   mistaken for the listener's own protocol. Fires MEDIUM when `ssl_policy` is absent (the
   provider doc: "Default is `ELBSecurityPolicy-2016-08`", which permits TLS 1.0), contains
   `-1-0-` or `-1-1-` (an ELBSecurityPolicy pinned to TLS 1.0 or 1.1), or is one of the dated
   legacy policies AWS's security-policy tables list as permitting TLS 1.0:
   `ELBSecurityPolicy-2016-08`, `-2015-05`, `-2015-03` and `-2015-02` (PR #1162 round-2 M-5).
   Older or retired names AWS no longer documents (`ELBSecurityPolicy-FS-2018-06`,
   `ELBSecurityPolicy-2014-10`, ...) are not matched, since their TLS floor cannot be cited. A non-literal `ssl_policy` (e.g. a
   variable) is treated as set and cannot be proven weak, so it stays silent. Checks
   `aws_lb_listener` and its older alias `aws_alb_listener`; the Classic ELB resource
   (`aws_elb`) is out of scope.

A non-literal policy (a variable, a local, or an interpolation) cannot be proven weak and stays
silent in all three rules (PR #1162 round-2 M-1). Every rule reads the resource through
`terraform_code_view`, so an interpolation cannot cut a block regex short and a policy written
only in a comment is not read as set.

Suppress an audited case with `# security: allow-weak-tls-policy` anywhere in the resource's
own block, for any of the three rules.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity

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

_SECURITY_POLICY_ATTR = re.compile(r'\bsecurity_policy\s*=\s*"(?P<val>[^"]*)"')
_SECURITY_POLICY_PRESENT = re.compile(r"\bsecurity_policy\s*=")
_DOMAIN_NAME_CONFIG_BLOCK = re.compile(
    r"\bdomain_name_configuration\s*\{(?P<inner>[^{}]*)\}", re.DOTALL,
)
_DOMAIN_ENDPOINT_OPTIONS_BLOCK = re.compile(
    r"\bdomain_endpoint_options\s*\{(?P<inner>[^{}]*)\}", re.DOTALL,
)
_TLS_SECURITY_POLICY_ATTR = re.compile(r'\btls_security_policy\s*=\s*"(?P<val>[^"]*)"')
_TLS_SECURITY_POLICY_PRESENT = re.compile(r"\btls_security_policy\s*=")
_PROTOCOL_ATTR = re.compile(r'\bprotocol\s*=\s*"(?P<val>[^"]*)"')
_SSL_POLICY_ATTR = re.compile(r'\bssl_policy\s*=\s*"(?P<val>[^"]*)"')
_SSL_POLICY_PRESENT = re.compile(r"\bssl_policy\s*=")
# `attr = null` hands the attribute back to its default, exactly like omitting it.
_NULL_VALUE = re.compile(r"\s*null\b")

_PRAGMA = re.compile(r"#\s*security:\s*allow-weak-tls-policy")

_STANDARDS = ["OWASP:A05", "CWE-326"]

_WEAK_OPENSEARCH_POLICY = "Policy-Min-TLS-1-0-2019-07"
# Dated legacy policies that AWS's ALB and Classic security-policy tables list as permitting
# TLS 1.0 (https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-security-policy-table.html).
_WEAK_ELB_POLICIES = frozenset({
    "ELBSecurityPolicy-2016-08",
    "ELBSecurityPolicy-2015-05",
    "ELBSecurityPolicy-2015-03",
    "ELBSecurityPolicy-2015-02",
})


def _policy_value(literal: re.Pattern[str], present: re.Pattern[str], text: str) -> tuple[bool, str | None]:
    """`(provable, value)` for one named-policy attribute in `text` (a `terraform_code_view`).
    `value` is the literal string, or None when the attribute is absent. `provable` is False
    when the attribute is set to something this guard cannot evaluate statically -- a bare
    reference (`var.p`, `local.p`) or an interpolation (`"${var.p}"`, which the view renders
    `"$(...)"`) -- and the caller stays silent rather than read it as the unsafe literal (PR
    #1162 round-2 M-1, the same convention `literal_bool_state` applies to booleans). `null`
    reads as absent: it hands the attribute back to its default."""
    match = literal.search(text)
    if match is not None:
        value = match.group("val")
        return ("$(" not in value, value)
    set_match = present.search(text)
    if set_match is not None:
        return (_NULL_VALUE.match(text, set_match.end()) is not None, None)
    return (True, None)


def _apigateway_security_policy_weak(value: str | None) -> bool:
    if value is None:
        return True
    upper = value.upper()
    if upper == "TLS_1_2":
        return False
    return "TLS13" not in upper and "TLS12" not in upper


def _opensearch_tls_policy_weak(value: str | None) -> bool:
    if value is None:
        return True
    return value == _WEAK_OPENSEARCH_POLICY


def _lb_ssl_policy_weak(value: str | None) -> bool:
    if value is None:
        return True
    return "-1-0-" in value or "-1-1-" in value or value in _WEAK_ELB_POLICIES


class AwsWeakTlsPolicyGuard(Guard):
    id = "aws-weak-tls-policy"
    title = "AWS resource allows a weak or unspecified TLS policy"
    area = "Cloud & IaC"

    # Canary plants the API Gateway v2 custom-domain shape: a `domain_name_configuration`
    # block with no `security_policy` attribute -> fires rule A only. Rules B and C get their
    # liveness proven by their own dedicated unit tests in the test file.
    canary_plant = CanaryPlant(
        files={
            "aws_weak_tls_policy.tf": (
                'resource "aws_apigatewayv2_domain_name" "canary" {\n'
                '  domain_name = "canary.example.com"\n'
                "\n"
                "  domain_name_configuration {\n"
                "    certificate_arn = aws_acm_certificate.canary.arn\n"
                '    endpoint_type   = "REGIONAL"\n'
                "  }\n"
                "}\n"
            ),
        },
        expects=frozenset({"aws-weak-tls-policy/apigateway-domain"}),
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
            body_text = "\n".join(line for _, line in body)
            if pragma_present(_PRAGMA, body_text, dialect="hcl"):
                continue
            # Every rule reads the comment-blanked, `${...}`-neutralised view: an interpolation's
            # own `}` (e.g. `custom_endpoint = "s.${var.d}.com"`) would cut a `[^{}]*` block
            # regex short, and a policy written only in a comment is not set (PR #1162 M-2).
            body_text = terraform_code_view(body_text)
            if resource_type == "aws_api_gateway_domain_name":
                out.extend(
                    self._check_apigateway_v1(root, f, resource_name, start_line, body_text)
                )
            elif resource_type == "aws_apigatewayv2_domain_name":
                out.extend(
                    self._check_apigateway_v2(root, f, resource_name, start_line, body_text)
                )
            elif resource_type in ("aws_opensearch_domain", "aws_elasticsearch_domain"):
                out.extend(
                    self._check_opensearch(
                        root, f, resource_type, resource_name, start_line, body_text
                    )
                )
            elif resource_type in ("aws_lb_listener", "aws_alb_listener"):
                out.extend(
                    self._check_lb_listener(
                        root, f, resource_type, resource_name, start_line, body_text
                    )
                )
        return out

    def _check_apigateway_v1(
        self, root: Path, f: Path, name: str, start: int, body_text: str,
    ) -> list[Finding]:
        provable, value = _policy_value(
            _SECURITY_POLICY_ATTR, _SECURITY_POLICY_PRESENT, top_level_attribute_text(body_text)
        )
        if not provable or not _apigateway_security_policy_weak(value):
            return []
        return [self._apigateway_finding(root, f, "aws_api_gateway_domain_name", name, start, value)]

    def _check_apigateway_v2(
        self, root: Path, f: Path, name: str, start: int, body_text: str,
    ) -> list[Finding]:
        config = _DOMAIN_NAME_CONFIG_BLOCK.search(body_text)
        if config is None:
            return []
        provable, value = _policy_value(
            _SECURITY_POLICY_ATTR, _SECURITY_POLICY_PRESENT, config.group("inner")
        )
        if not provable or not _apigateway_security_policy_weak(value):
            return []
        return [self._apigateway_finding(root, f, "aws_apigatewayv2_domain_name", name, start, value)]

    def _apigateway_finding(
        self, root: Path, f: Path, resource_type: str, name: str, start: int, value: str | None,
    ) -> Finding:
        if value is None:
            # No source states what an omitted policy gets: report it as unpinned, not weak.
            severity: Severity = "low"
            message = (
                f"`{resource_type}.{name}` sets no `security_policy` -- the custom domain's TLS "
                "floor is not pinned in code, and AWS documents no default for an omitted "
                "policy, so the domain may accept TLS 1.0."
            )
        else:
            severity = "medium"
            message = (
                f'`{resource_type}.{name}` has `security_policy = "{value}"` -- this custom '
                "domain does not pin TLS to the modern `TLS_1_2` policy, allowing older, weaker "
                "TLS versions to negotiate."
            )
        return Finding(
            check_id=self.id,
            severity=severity,
            title=self.title,
            location=f"{rel(root, f)}:{start}",
            message=message,
            remediation=(
                'Set `security_policy = "TLS_1_2"` (directly on the resource for '
                "`aws_api_gateway_domain_name`, inside `domain_name_configuration` for "
                "`aws_apigatewayv2_domain_name`). Suppress an audited case with "
                "`# security: allow-weak-tls-policy` anywhere in the resource block."
            ),
            rule="aws-weak-tls-policy/apigateway-domain",
            standards=list(_STANDARDS),
        )

    def _check_opensearch(
        self, root: Path, f: Path, resource_type: str, name: str, start: int, body_text: str,
    ) -> list[Finding]:
        options = _DOMAIN_ENDPOINT_OPTIONS_BLOCK.search(body_text)
        inner = options.group("inner") if options else ""
        provable, value = _policy_value(_TLS_SECURITY_POLICY_ATTR, _TLS_SECURITY_POLICY_PRESENT, inner)
        if not provable or not _opensearch_tls_policy_weak(value):
            return []
        if value is None:
            # No source states the omitted default: report it as unpinned, not weak.
            severity: Severity = "low"
            message = (
                f"`{resource_type}.{name}` sets no `tls_security_policy` inside "
                "`domain_endpoint_options` -- the domain's TLS floor is not pinned in code, and "
                "AWS documents no default for an omitted policy (its own example `CreateDomain` "
                f'response shows `"{_WEAK_OPENSEARCH_POLICY}"`, which permits TLS 1.0).'
            )
        else:
            severity = "medium"
            message = (
                f'`{resource_type}.{name}` has `tls_security_policy = "{value}"` inside '
                f'`domain_endpoint_options` -- `"{_WEAK_OPENSEARCH_POLICY}"` is the one named '
                "policy still permitting TLS 1.0."
            )
        return [Finding(
            check_id=self.id,
            severity=severity,
            title=self.title,
            location=f"{rel(root, f)}:{start}",
            message=message,
            remediation=(
                'Set `tls_security_policy = "Policy-Min-TLS-1-2-2019-07"` (or a newer policy) '
                "inside `domain_endpoint_options`. Suppress an audited case with "
                "`# security: allow-weak-tls-policy` anywhere in the resource block."
            ),
            rule="aws-weak-tls-policy/opensearch-domain",
            standards=list(_STANDARDS),
        )]

    def _check_lb_listener(
        self, root: Path, f: Path, resource_type: str, name: str, start: int, body_text: str,
    ) -> list[Finding]:
        top_level = top_level_attribute_text(body_text)
        protocol_match = _PROTOCOL_ATTR.search(top_level)
        if protocol_match is None or protocol_match.group("val").upper() not in ("HTTPS", "TLS"):
            return []
        # Absent -> the provider falls back to a legacy weak default; a non-literal expression
        # (a variable, an interpolation) cannot be proven weak and stays silent.
        provable, value = _policy_value(_SSL_POLICY_ATTR, _SSL_POLICY_PRESENT, top_level)
        if not provable or not _lb_ssl_policy_weak(value):
            return []
        observed = f'`ssl_policy = "{value}"`' if value is not None else "no `ssl_policy` set"
        return [Finding(
            check_id=self.id,
            severity="medium",
            title=self.title,
            location=f"{rel(root, f)}:{start}",
            message=(
                f"`{resource_type}.{name}` ({protocol_match.group('val')} listener) has "
                f"{observed} -- this listener either has no SSL policy pinned (the provider then "
                "applies `ELBSecurityPolicy-2016-08`) or is pinned to a policy that still "
                "permits TLS 1.0/1.1."
            ),
            remediation=(
                "Set `ssl_policy` to a modern policy (e.g. "
                '`ELBSecurityPolicy-TLS13-1-2-2021-06`). Suppress an audited case with '
                "`# security: allow-weak-tls-policy` anywhere in the resource block."
            ),
            rule="aws-weak-tls-policy/lb-listener",
            standards=list(_STANDARDS),
        )]
