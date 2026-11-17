---
type: Guard
title: "aws-weak-tls-policy"
description: "AWS resource (API Gateway custom domain, OpenSearch/Elasticsearch domain, ALB/NLB listener) allows a weak or unspecified TLS policy."
timestamp: "2026-10-27T09:00:00Z"
guard_id: "aws-weak-tls-policy"
checklist_section: ["6a"]
standards: ["OWASP:A05", "CWE-326"]
---

# AWS resource allows a weak or unspecified TLS policy

_Author — 2026-10-25. Revised 2026-10-27 (review H5: Rule C's protocol lookup scoped to the
top level only; a non-literal `ssl_policy` no longer treated as absent)._

---

## The threat

Three independent resource-specific "named TLS policy" checks, bundled into one guard because
they share the same underlying concept: each AWS resource type exposes a provider-defined TLS
policy **name** (rather than a raw protocol/cipher list), and each has its own known-weak
values and its own absent-attribute default. CWE-326 (Inadequate Encryption Strength),
OWASP:A05.

1. **API Gateway custom domain — `security_policy`.** `aws_api_gateway_domain_name` carries
   `security_policy` directly on the resource; `aws_apigatewayv2_domain_name` nests it inside a
   `domain_name_configuration` block. A custom domain pinned to a policy other than `TLS_1_2`
   allows older, weaker TLS versions to negotiate. Left unset, its TLS floor is not pinned in
   code: neither the provider doc nor the AWS API reference states which policy an omitted
   `security_policy` gets [4].
2. **OpenSearch/Elasticsearch domain — `tls_security_policy`.** Nested inside
   `domain_endpoint_options` on `aws_opensearch_domain`/`aws_elasticsearch_domain`. Set to the
   specifically weak named policy, the domain permits TLS 1.0. Left unset, the floor is not
   pinned: AWS states no default, and its own example `CreateDomain` response shows the TLS 1.0
   policy [5].
3. **ALB/NLB listener — `ssl_policy`.** Only relevant for an HTTPS/TLS listener. Left unset, the
   provider applies `ELBSecurityPolicy-2016-08` [6], which permits TLS 1.0. Pinned to a legacy
   policy still permitting TLS 1.0/1.1, the listener accepts a weaker handshake than a modern
   policy would.

## Why it's often introduced

Each of these attributes is optional, so a resource provisioned without it is silent at
`terraform apply` time:

```hcl
resource "aws_apigatewayv2_domain_name" "api" {
  domain_name = "api.example.com"

  domain_name_configuration {
    certificate_arn = aws_acm_certificate.api.arn
    endpoint_type   = "REGIONAL"
    # no security_policy -> the TLS floor is not pinned in code
  }
}

resource "aws_opensearch_domain" "search" {
  domain_endpoint_options {
    enforce_https = true
    # no tls_security_policy -> the TLS floor is not pinned in code
  }
}

resource "aws_lb_listener" "https" {
  protocol = "HTTPS"
  # no ssl_policy -> provider applies ELBSecurityPolicy-2016-08 (permits TLS 1.0)
}
```

## Detection design

1. `applies()` gate — `"terraform" in profile.features`.
2. Scans every `.tf` file under the repo root via `iter_files(root, (".tf",))`, skipping
   non-product paths (`is_nonproduct_path`).
3. Uses the shared `iter_terraform_resources()` helper, dispatching on resource type. Every rule
   reads the resource through `terraform_code_view()` (`guards/base.py`): comments blanked and
   `${...}` interpolations neutralised. An interpolation's own `}` (for example
   `custom_endpoint = "s.${var.d}.com"` or `certificate_arn = "${var.arn}"`) therefore cannot
   cut a `[^{}]*` block regex short, and a policy written only in a comment is not read as set
   (PR #1162 round-2 M-2). The suppress pragma is still read from the raw block.
4. **Rule A (`apigateway-domain`)**: `aws_api_gateway_domain_name`'s `security_policy`
   attribute is read from the resource's top-level attributes; `aws_apigatewayv2_domain_name`'s
   is read from inside its `domain_name_configuration { ... }` block. Fires MEDIUM when the
   value is a literal that is not (case-insensitively) exactly `TLS_1_2` and does not contain
   the substring `TLS13` or `TLS12`. Fires LOW when the attribute is absent, worded as "not
   pinned" rather than as a proven weak policy, since no source states the omitted default
   (PR #1162 round-1 M2).
5. **Rule B (`opensearch-domain`)**: `aws_opensearch_domain`/`aws_elasticsearch_domain`'s
   `tls_security_policy` is read from inside `domain_endpoint_options { ... }`. Fires MEDIUM on
   the exact value `Policy-Min-TLS-1-0-2019-07` (no other named policy is flagged), and LOW,
   worded as "not pinned", when the attribute is absent (PR #1162 round-1 M2). This guard does not touch `encrypt_at_rest`, `node_to_node_encryption`,
   or `enforce_https` on these resource types; those belong to a different guard.
6. **Rule C (`lb-listener`)**: `aws_lb_listener`/`aws_alb_listener`'s own TOP-LEVEL `protocol`
   attribute is read first, via the shared `top_level_attribute_text()` helper
   (`guards/base.py`) so a nested block's own same-named attribute (e.g. inside a
   `default_action { redirect { ... } }`) is never mistaken for the listener's own protocol
   (the helper also returns a one-line resource's own attribute, PR #1162 round-5 M1) —
   the rule only applies when it is `HTTPS` or `TLS` (case-insensitive); a plain HTTP listener
   is `alb_listener_http_protocol.py`'s concern, not this guard's. When applicable,
   `ssl_policy` is read from the same top-level text. Fires MEDIUM when absent (the provider
   default `ELBSecurityPolicy-2016-08` permits TLS 1.0), when it contains the substring `-1-0-`
   or `-1-1-`, or when it is one of the dated legacy policies AWS's tables list as permitting
   TLS 1.0: `ELBSecurityPolicy-2016-08`, `-2015-05`, `-2015-03`, `-2015-02` [7] (PR #1162 round-2
   M-5). Retired names AWS no longer documents (`ELBSecurityPolicy-FS-2018-06`,
   `ELBSecurityPolicy-2014-10`, ...) are not matched, because their TLS floor cannot be cited.
   The Classic ELB resource (`aws_elb`) is never checked.
   - **Non-literal values, all three rules**: a policy set to a variable, a local, or an
     interpolation (`"${var.p}"`) cannot be proven weak, so it stays silent. It must NOT be
     treated the same as an absent attribute (PR #1162 round-2 M-1; Rule C always did this).
     `null` is the exception: it hands the attribute back to its default, so it reads as
     absent in every rule (PR #1162 round-2 Low).
7. Single inline opt-out shared by all three rules, anywhere in the resource's own block:
   `# security: allow-weak-tls-policy`.
8. Severity: `medium` for a proven weak policy in any rule, and for an absent `ssl_policy` (Rule
   C, whose default is documented). `low` for an absent API Gateway or OpenSearch policy (Rules
   A and B, whose default is not). Standards: `["OWASP:A05", "CWE-326"]`.

## When NOT to flag

- API Gateway: `security_policy` set (case-insensitively) to exactly `TLS_1_2`, or containing
  `TLS13`/`TLS12`.
- OpenSearch/Elasticsearch: `tls_security_policy` set to anything other than
  `Policy-Min-TLS-1-0-2019-07` (e.g. `Policy-Min-TLS-1-2-2019-07` is fine).
- ALB/NLB listener: a plain HTTP listener (out of scope for this guard entirely), or an
  HTTPS/TLS listener whose `ssl_policy` names a modern policy (no `-1-0-`/`-1-1-` substring and
  not one of the four dated legacy names).
- Any rule: the policy is a variable, a local, or an interpolation.
- The Classic ELB resource (`aws_elb`) — never checked by rule C.
- An audited case, suppressed with `# security: allow-weak-tls-policy` anywhere in the
  resource's own block.

## Tests

| Test | What it checks |
|---|---|
| `test_apigateway_v1_missing_security_policy_fires` | Positive: `aws_api_gateway_domain_name` with no `security_policy` fires. |
| `test_apigateway_v1_tls12_silent` | FP-bait: `security_policy = "TLS_1_2"` → silent. |
| `test_apigateway_v1_weak_policy_fires` | Positive: `security_policy = "TLS_1_0"` fires. |
| `test_apigateway_v2_missing_security_policy_fires` | Positive: `aws_apigatewayv2_domain_name`'s nested `domain_name_configuration` with no `security_policy` fires. |
| `test_apigateway_v2_tls12_silent` | FP-bait: nested `security_policy = "TLS_1_2"` → silent. |
| `test_apigateway_v2_weak_policy_fires` | Positive: nested `security_policy = "TLS_1_0"` fires. |
| `test_opensearch_missing_tls_policy_fires` | Positive: `aws_opensearch_domain` with no `tls_security_policy` fires. |
| `test_opensearch_weak_named_policy_fires` | Positive: `Policy-Min-TLS-1-0-2019-07` fires. |
| `test_opensearch_strong_policy_silent` | FP-bait: `Policy-Min-TLS-1-2-2019-07` → silent. |
| `test_elasticsearch_domain_also_checked` | `aws_elasticsearch_domain` alias is checked too. |
| `test_https_listener_missing_ssl_policy_fires` | Positive: HTTPS listener with no `ssl_policy` fires. |
| `test_https_listener_weak_ssl_policy_fires` | Positive: `-1-0-` substring fires. |
| `test_https_listener_legacy_2016_policy_fires` | Positive: exact `ELBSecurityPolicy-2016-08` fires. |
| `test_https_listener_modern_ssl_policy_silent` | FP-bait: a modern TLS1.3 policy → silent. |
| `test_lb_listener_variable_ssl_policy_stays_silent` | FP-bait: `ssl_policy = var.ssl_policy` → silent (non-literal). |
| `test_lb_listener_redirect_with_nested_https_protocol_stays_silent` | FP-bait: no top-level `protocol`, nested redirect's own `protocol = "HTTPS"` → silent (scoping). |
| `test_alb_listener_alias_also_checked` | `aws_alb_listener` alias is checked too. |
| `test_http_listener_out_of_scope_for_this_guard` | FP-bait: a plain HTTP listener never triggers rule C. |
| `test_classic_elb_out_of_scope` | FP-bait: `aws_elb` is never checked. |
| `test_pragma_silences_all_rules` | Suppress pragma → silent. |
| `test_non_literal_policy_stays_silent_in_every_rule` | FP-bait (round-2 M-1): `var.*`, `local.*` and `"${...}"` policies → silent in Rules A and B. |
| `test_literal_weak_policy_still_fires_medium` | Still-fires partner: a literal weak policy fires MEDIUM in Rules A and B. |
| `test_absent_policy_is_reported_as_unpinned_at_low` | Round-1 M2: an absent API Gateway / OpenSearch policy fires LOW, worded "not pinned". |
| `test_interpolation_does_not_cut_the_block_short` | Round-2 M-2: an interpolation before the policy neither silences a weak policy nor flags a strong one. |
| `test_policy_written_only_in_a_comment_is_not_set` | A commented-out policy is not set; a real policy with a trailing comment is. |
| `test_legacy_dated_elb_policies_fire` | Round-2 M-5: `ELBSecurityPolicy-2015-05`/`-2015-03`/`-2015-02`/`-2016-08` fire MEDIUM. |
| `test_null_policy_is_the_same_as_an_absent_one` | Round-2 Low: `= null` fires like an absent policy (MEDIUM for `ssl_policy`, LOW for A/B); a `nullable_policy` reference stays silent. |
| `test_modern_tls12_elb_policies_stay_silent` | FP-bait: dated TLS 1.2+ policies (`-TLS-1-2-2017-01`, `-TLS13-1-2-2021-06`, ...) → silent. |
| `test_applies_gate` / `test_applies_with_terraform` | `applies()` gate. |

## Known bypasses

- **Variable/expression indirection (all rules)**: a policy name supplied through `var.*`, a
  local, or an interpolation is not resolved, so a variable that holds a weak policy is a false
  negative. This is deliberate: guessing would be a false positive on every correctly
  parameterised module.
- **Absent API Gateway / OpenSearch policy is LOW, not MEDIUM**: if the service default for an
  omitted policy is in fact TLS 1.0, the finding understates it. No primary source states that
  default, so the guard reports what it can prove: the floor is not pinned.
- **A resource nested inside a `module` block** passing these attributes through at the call
  site — only the resource's own literal body is inspected.
- **Rule A's substring match** (`TLS13`/`TLS12`) is deliberately permissive to tolerate
  provider-version naming drift; a contrived value containing that substring outside a real
  policy name (unlikely in practice for this attribute) would also silence the finding.

## What this guard does NOT prove

A silent guard does not confirm the applied infrastructure matches the source (drift), that
an attribute wasn't overridden via `-var`/`terraform.tfvars` at apply time in a way this
static text can't see, or that a resource provisioned outside Terraform (console,
CloudFormation, another IaC tool) carries the same configuration. This is a presence/literal-
match check across three independently-graded resource types, source-only.

# Citations

[1] agentsec checklist items `7-aws-weak-tls-policy-apigateway-domain`,
    `7-aws-weak-tls-policy-opensearch-domain`, `7-aws-weak-tls-policy-lb-listener` (§7)
[2] OWASP:A05
[3] CWE-326
[4] hashicorp/terraform-provider-aws, `aws_api_gateway_domain_name` and
`aws_apigatewayv2_domain_name` resource docs (no default stated); AWS API Gateway API reference,
`CreateDomainName` (valid values `TLS_1_0 | TLS_1_2`, no default stated).
https://docs.aws.amazon.com/apigateway/latest/api/API_CreateDomainName.html
[5] AWS OpenSearch Service API reference, `DomainEndpointOptions` (no default stated) and the
`CreateDomain` example response (`"TLSSecurityPolicy": "Policy-Min-TLS-1-0-2019-07"`).
https://docs.aws.amazon.com/opensearch-service/latest/APIReference/API_CreateDomain.html
[6] hashicorp/terraform-provider-aws, `aws_lb_listener` resource doc: "Default is
`ELBSecurityPolicy-2016-08`."
https://github.com/hashicorp/terraform-provider-aws/blob/main/website/docs/r/lb_listener.html.markdown
[7] AWS Elastic Load Balancing, security policies for Application Load Balancers and the Classic
Load Balancer security-policy table.
https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html
https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-security-policy-table.html
