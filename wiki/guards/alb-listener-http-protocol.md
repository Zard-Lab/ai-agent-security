---
type: Guard
title: "alb-listener-http-protocol"
description: "Terraform aws_lb_listener resource serving plaintext HTTP (protocol = \"HTTP\")."
timestamp: "2026-10-27T09:00:00Z"
guard_id: "alb-listener-http-protocol"
checklist_section: ["6a"]
standards: ["OWASP:A05", "CWE-319"]
---

# Application Load Balancer listener serves plaintext HTTP

_Author — 2026-10-25. Revised 2026-10-27 (review H4: the canonical HTTP->HTTPS redirect
listener no longer fires; nested-block protocol scoping fixed; `aws_alb_listener` added)._

---

## The threat

An `aws_lb_listener` with `protocol = "HTTP"` accepts plaintext traffic on the public-facing
side of the load balancer. Every request and response — including auth headers, cookies,
session tokens, and request bodies — is readable to anyone positioned on the network path
between the client and the ALB: an on-path attacker, a misconfigured intermediate proxy, or
anyone who can observe traffic at a shared network boundary. CWE-319 (Cleartext Transmission
of Sensitive Information), OWASP:A05.

## Why it's often introduced

A listener is stood up quickly during development (no certificate provisioned yet) and the
`protocol = "HTTP"` line is never revisited once TLS termination is added elsewhere:

```hcl
resource "aws_lb_listener" "front_end" {
  load_balancer_arn = aws_lb.main.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.main.arn
  }
}
```

Severity is `medium` rather than `high`, because this is a softer signal than most
encryption-in-transit gaps in this codebase: many real architectures intentionally terminate
TLS upstream of the ALB (at a CDN like CloudFront, or at an edge proxy) and run plaintext HTTP
only on the private segment between the edge and the ALB. A plaintext listener is worth
flagging to confirm the architecture, not a proven bug on its own.

## Detection design

1. `applies()` gate — `"terraform" in profile.features`.
2. Scans every `.tf` file under the repo root via `iter_files(root, (".tf",))`, skipping
   non-product paths (`is_nonproduct_path`).
3. Uses the shared `iter_terraform_resources()` helper to isolate `aws_lb_listener` AND
   `aws_alb_listener` (the older alias) blocks.
4. Fires when the resource's own TOP-LEVEL `protocol` attribute — read via the shared
   `top_level_attribute_text()` helper (`guards/base.py`), so a nested block's own same-named
   attribute (e.g. a `default_action { redirect { protocol = "HTTPS" } } }`) is never read for
   this check — is exactly the literal, case-sensitive string `"HTTP"`, UNLESS every
   `default_action` on the listener redirects to HTTPS (the canonical, already-hardened
   port-80 pattern that serves no content in the clear).
   Both the top-level `protocol` and the redirect check read the resource's
   `terraform_code_view()` (`guards/base.py`): comments blanked and `${...}` interpolations
   neutralised. A redirect carrying `host = "${var.host}"` therefore still reads as a redirect
   to HTTPS (it used to end the `[^{}]*` redirect regex early and fire, PR #1162 round-2 M-2),
   and a `protocol = "HTTP"` written only in a comment is not the listener's protocol.
5. Inline opt-out, anywhere in the resource's own block: `# security: allow-alb-http-listener`.
   The pragma is read from the raw block, not from the code view.
6. Severity: `medium`. Rule id: `alb-listener-http-protocol/plaintext-listener`. Standards:
   `["OWASP:A05", "CWE-319"]`.

## When NOT to flag

- `protocol` set to `"HTTPS"`, `"TCP"`, `"TLS"`, or any value other than the literal `"HTTP"`.
- `protocol = "HTTP"` where every `default_action` redirects to HTTPS — the canonical
  port-80-redirects-to-443 pattern serves no content over the plaintext hop.
- No top-level `protocol` attribute at all. The provider doc states `protocol` actually
  defaults to `"HTTP"` when omitted (it is NOT a required argument, contrary to an earlier
  version of this doc) — but this guard can't tell from the listener resource alone whether it
  is attached to an ALB (where that default is live) or an NLB (where `protocol` means
  TCP/UDP/TLS). This is an accepted, documented false negative, not a bug.
- An audited case, suppressed with `# security: allow-alb-http-listener` anywhere in the
  resource's own block.

## Tests

| Test | What it checks |
|---|---|
| `test_http_listener_fires` | Positive: `protocol = "HTTP"` with a forward action fires. |
| `test_http_listener_redirecting_to_https_stays_silent` | FP-bait: `protocol = "HTTP"` but every `default_action` redirects to HTTPS → silent. |
| `test_http_listener_forwarding_still_fires` | Positive: a mix of forward + redirect actions still fires (not every action is a safe redirect). |
| `test_nested_https_protocol_is_not_mistaken_for_top_level` | FP-bait: top-level `protocol = "HTTPS"`, nested redirect's own `protocol = "HTTP"` → silent (scoping). |
| `test_aws_alb_listener_alias_fires` | Positive: the older `aws_alb_listener` alias is scanned too. |
| `test_https_listener_silent` | FP-bait: `protocol = "HTTPS"` → silent. |
| `test_tcp_listener_silent` | FP-bait: `protocol = "TCP"` → silent. |
| `test_missing_protocol_silent` | FP-bait: no `protocol` attribute at all → silent (documented ALB/NLB ambiguity). |
| `test_pragma_silences` | Suppress pragma → silent. |
| `test_redirect_with_interpolated_host_stays_silent` | Round-2 M-2: an HTTPS redirect with `host = "${var.host}"` → silent (was a false positive). |
| `test_redirect_to_plain_http_with_interpolated_host_still_fires` | Still-fires partner: a redirect that stays on HTTP fires, interpolation or not. |
| `test_protocol_written_only_in_a_comment_is_not_the_listener_protocol` | A commented-out `protocol = "HTTP"` above `"HTTPS"` → silent; a real `"HTTP"` with a trailing comment fires. |
| `test_non_listener_resource_silent` | FP-bait: an `aws_lb` resource itself is not scanned. |
| `test_applies_gate` / `test_applies_with_terraform` | `applies()` gate. |

## Known bypasses

- **Case variation**: a non-standard-cased literal like `"http"` is not matched — the match is
  case-sensitive on purpose, since `"HTTP"` is the only value the AWS provider accepts for this
  attribute, so a different case would fail `terraform validate` long before this guard runs.
- **Variable/expression indirection**: `protocol = var.listener_protocol` is not resolved — only
  a literal `"HTTP"` string is matched.
- **A one-line nested block** (e.g. `default_action { ... redirect { protocol = "HTTPS" } }` all
  on one line) is read starting at depth 0, so its nested attributes can be misjudged as
  top-level. `terraform fmt` never produces this layout. The scoping helper (`top_level_attribute_text`,
  `agentsec/guards/base.py`) is otherwise string/comment/heredoc-aware (round-2 review, H-3): a
  `{` inside a `#`/`//` comment, a `"..."` string, or a `<<EOF` heredoc body no longer closes the
  top-level scope early — that used to silently drop every attribute below it for the rest of
  the resource, a false negative this guard carries a regression test for
  (`test_comment_containing_a_brace_does_not_truncate_top_level_scope`).

## What this guard does NOT prove

A silent guard does not confirm TLS is genuinely terminated anywhere in the real request path
(it may say `protocol = "HTTPS"` in source while the certificate has expired or application
code downgrades), that an attribute wasn't overridden via `-var`/`terraform.tfvars` at apply
time in a way this static text can't see, or that a resource provisioned outside Terraform
(console, CloudFormation, another IaC tool) carries the same configuration. This is a
presence/literal-match check against the committed source only.

# Citations

[1] agentsec checklist item `7-alb-listener-http-protocol-missing` (§7)
[2] OWASP:A05
[3] CWE-319
