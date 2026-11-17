"""Guard: Terraform ALB listener serving plaintext HTTP (checklist §7).

    resource "aws_lb_listener" "front_end" {
      load_balancer_arn = aws_lb.main.arn
      port              = "80"
      protocol          = "HTTP"

      default_action {
        type             = "forward"
        target_group_arn = aws_lb_target_group.main.arn
      }
    }

An `aws_lb_listener` with `protocol = "HTTP"` accepts plaintext traffic on the public-facing
side of the load balancer: every request/response (including auth headers, cookies, tokens,
and request bodies) is readable to anyone positioned on the network path between client and
ALB. CWE-319 (Cleartext Transmission of Sensitive Information), OWASP:A05.

This is a softer signal than most encryption-at-rest/in-transit gaps in this codebase: many
real architectures intentionally terminate TLS upstream of the ALB (at a CDN like CloudFront,
or at an edge proxy) and run plaintext HTTP only on the private segment between the edge and
the ALB. Severity is therefore `medium`, and the guard flags this as something to confirm
by hand, not as a proven bug.

Detection is intentionally narrow: fires ONLY on the literal, case-sensitive value
`protocol = "HTTP"` on the resource's own TOP-LEVEL `protocol` attribute — nested blocks (e.g.
a `default_action { redirect { protocol = "HTTPS" ... } } }`'s own inner `protocol`) are never
read for this check, so they cannot be mistaken for the listener's own protocol. `"HTTPS"`,
`"TCP"`, `"TLS"`, and any other top-level value never fire.

The canonical, correctly-hardened port-80 listener — `protocol = "HTTP"` paired with a
`default_action { type = "redirect" redirect { protocol = "HTTPS" ... } }` that redirects
every request to HTTPS and serves no content over the plaintext hop — stays silent. A listener
that is `protocol = "HTTP"` with any `default_action` that *forwards* (serves real content in
the clear) still fires.

A listener with no top-level `protocol` attribute at all never fires either. The provider doc
states `protocol` actually defaults to `"HTTP"` when omitted (it is NOT a required argument,
contrary to an earlier version of this docstring) — but this guard can't tell from the listener
resource alone whether it is attached to an Application Load Balancer (where that default is
live and meaningful) or a Network Load Balancer (where `protocol` means TCP/UDP/TLS and an
"HTTP" default is not applicable). This is an accepted, documented false negative, not a bug:
asserting the ALB default without knowing the LB type would risk firing on NLB listeners that
have nothing to do with HTTP at all.

Suppress an audited case (e.g. TLS terminated upstream at a CDN, with only the edge-to-ALB
hop left in plaintext by design) with `# security: allow-alb-http-listener` anywhere in the
resource block.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

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

_PROTOCOL_HTTP = re.compile(r'\bprotocol\s*=\s*"HTTP"')
_PRAGMA = re.compile(r"#\s*security:\s*allow-alb-http-listener")
_DEFAULT_ACTION = re.compile(r"\bdefault_action\s*\{(?P<inner>(?:[^{}]|\{[^{}]*\})*)\}", re.DOTALL)
_REDIRECT_TO_HTTPS = re.compile(r'\bredirect\s*\{[^{}]*\bprotocol\s*=\s*"HTTPS"', re.DOTALL)

_RESOURCE_TYPES = frozenset({"aws_lb_listener", "aws_alb_listener"})

_STANDARDS = ["OWASP:A05", "CWE-319"]


def _all_default_actions_redirect_to_https(body_text: str) -> bool:
    """True only if every `default_action` block redirects to HTTPS -- the canonical, already
    -hardened port-80 listener pattern that serves no content over the plaintext hop."""
    actions = _DEFAULT_ACTION.findall(body_text)
    if not actions:
        return False
    return all(_REDIRECT_TO_HTTPS.search(action) for action in actions)


class AlbListenerHttpProtocolGuard(Guard):
    id = "alb-listener-http-protocol"
    title = "Application Load Balancer listener serves plaintext HTTP"
    area = "Cloud & IaC"

    canary_plant = CanaryPlant(
        files={
            "alb_listener_http_protocol.tf": (
                'resource "aws_lb_listener" "canary" {\n'
                "  load_balancer_arn = aws_lb.canary.arn\n"
                '  port              = "80"\n'
                '  protocol          = "HTTP"\n'
                "\n"
                "  default_action {\n"
                '    type             = "forward"\n'
                "    target_group_arn = aws_lb_target_group.canary.arn\n"
                "  }\n"
                "}\n"
            ),
        },
        expects=frozenset({"alb-listener-http-protocol/plaintext-listener"}),
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
            if resource_type not in _RESOURCE_TYPES:
                continue
            body_text = "\n".join(line for _, line in body)
            if pragma_present(_PRAGMA, body_text, dialect="hcl"):
                continue
            # Comment-blanked and `${...}`-neutralised: a redirect carrying
            # `host = "${var.host}"` would otherwise cut the `[^{}]*` redirect regex short and
            # read as a forwarding listener (PR #1162 round-2 M-2), and a `protocol = "HTTP"`
            # written only in a comment is not the listener's protocol.
            code = terraform_code_view(body_text)
            if not _PROTOCOL_HTTP.search(top_level_attribute_text(code)):
                continue
            if _all_default_actions_redirect_to_https(code):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=f"{rel(root, f)}:{start_line}",
                    message=(
                        f"`aws_lb_listener.{resource_name}` sets `protocol = \"HTTP\"` — this "
                        "listener accepts plaintext traffic on the load balancer's public-facing "
                        "side, so anyone on the network path between the client and the ALB can "
                        "read request/response contents, including auth headers and cookies."
                    ),
                    remediation=(
                        "Terminate TLS at the listener: set `protocol = \"HTTPS\"` with a "
                        "`certificate_arn`, or confirm TLS is genuinely terminated upstream (e.g. "
                        "at a CDN) and this plaintext hop is intentional. Suppress an audited case "
                        "with `# security: allow-alb-http-listener` anywhere in the resource block."
                    ),
                    rule="alb-listener-http-protocol/plaintext-listener",
                    standards=list(_STANDARDS),
                )
            )
        return out
