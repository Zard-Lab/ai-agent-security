"""Guard: no world-open ingress in Terraform (checklist §6c).

The seed of the IaC-misconfig family. A security-group / firewall `ingress` rule
whose `cidr_blocks` is `0.0.0.0/0` (or `::/0`) exposes the port to the entire
internet — the single most common cloud-deploy mistake, and how databases,
SSH, and admin panels end up publicly reachable. CIS / OWASP:A05.

Fires HIGH on a `cidr_block(s)` line carrying `0.0.0.0/0` or `::/0` **inside an
`ingress { ... }` block** in a `*.tf` file. An identical CIDR inside an `egress`
block is silent (open egress is normal). Suppress an audited rule with
`# security: allow-open-ingress`.

Conservative seed: it tracks the `ingress`-block form only. The separate
`aws_security_group_rule` resource with `type = "ingress"` is a known
false-negative (documented in the design doc), to keep this first IaC guard
low-FP.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, pragma_present, read, rel

_WORLD_OPEN = re.compile(r"0\.0\.0\.0/0|::/0")
_CIDR_LINE = re.compile(r"cidr_blocks?\b")
_BLOCK_OPEN = re.compile(r"^\s*(\w+)\b[^{}]*\{\s*$")
_PRAGMA = re.compile(r"#\s*security:\s*allow-open-ingress")


class IacOpenIngressGuard(Guard):
    id = "iac-open-ingress"
    title = "World-open ingress in Terraform"
    area = "Cloud & IaC"

    # security group with a world-open ingress (fires iac-open-ingress); the egress
    # 0.0.0.0/0 below is normal and must stay silent (built-in FP-bait).
    canary_plant = CanaryPlant(
        files={
            "main.tf": (
                'resource "aws_security_group" "canary" {\n'
                "  ingress {\n"
                "    from_port   = 22\n"
                "    to_port     = 22\n"
                '    protocol    = "tcp"\n'
                '    cidr_blocks = ["0.0.0.0/0"]\n'
                "  }\n"
                "  egress {\n"
                "    from_port   = 0\n"
                "    to_port     = 0\n"
                '    protocol    = "-1"\n'
                '    cidr_blocks = ["0.0.0.0/0"]\n'
                "  }\n"
                "}\n"
            ),
        },
        expects=frozenset({"iac-open-ingress/world-open-ingress"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "terraform" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        out: list[Finding] = []
        for f in iter_files(root, (".tf",)):
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        labels: list[str] = []  # stack of open block labels, innermost last
        for i, raw in enumerate(read(f).splitlines(), start=1):
            is_comment = raw.lstrip().startswith("#")
            m = _BLOCK_OPEN.match(raw)
            if m and not is_comment:
                labels.append(m.group(1))
            # a world-open cidr inside an ingress block -> finding
            if (
                not is_comment
                and "ingress" in labels
                and _CIDR_LINE.search(raw)
                and _WORLD_OPEN.search(raw)
                and not pragma_present(_PRAGMA, raw, dialect="hcl")
            ):
                out.append(Finding(
                    check_id=self.id,
                    severity="high",
                    title="Security-group ingress open to the whole internet (0.0.0.0/0)",
                    location=f"{rel(root, f)}:{i}",
                    message=(
                        "This ingress rule allows traffic from any source IP (0.0.0.0/0 or ::/0), "
                        "exposing the port to the entire internet — the usual way databases, SSH, "
                        "and admin panels become publicly reachable."
                    ),
                    remediation=(
                        "Restrict `cidr_blocks` to the specific networks that need access (a VPC "
                        "range, a bastion, an office CIDR). If this rule is intentionally public "
                        "(e.g. 443 on a load balancer), suppress with `# security: allow-open-ingress`."
                    ),
                    rule="iac-open-ingress/world-open-ingress",
                    standards=["OWASP:A05", "CIS:AWS"],
                ))
            # close blocks: one pop per closing brace on the line
            if not is_comment:
                for _ in range(raw.count("}")):
                    if labels:
                        labels.pop()
        return out
