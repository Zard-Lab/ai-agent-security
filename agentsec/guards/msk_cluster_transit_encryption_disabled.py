"""Guard: Terraform MSK cluster with `client_broker` set to a plaintext-allowing value (§7).

    resource "aws_msk_cluster" "events" {
      cluster_name           = "events"
      kafka_version           = "3.5.1"
      number_of_broker_nodes  = 3
      encryption_info {
        encryption_in_transit {
          client_broker = "PLAINTEXT"  # <- fires
        }
      }
    }

An MSK (Managed Streaming for Kafka) cluster's broker-to-client transit encryption is
controlled three levels deep: a top-level `encryption_info { ... }` block, containing an
`encryption_in_transit { ... }` block, containing `client_broker` (one of `"TLS"`,
`"TLS_PLAINTEXT"`, or `"PLAINTEXT"`) and `in_cluster` (broker-to-broker). Per the AWS provider
docs, `client_broker`'s default — when the attribute, `encryption_in_transit`, or the whole
`encryption_info` block is omitted — is `"TLS"`, which is already secure. So an omitted
structure is NOT treated as unsafe here; only an explicit, literal unsafe value is. A client
reading or writing to a broker with `client_broker = "PLAINTEXT"` over an unencrypted TCP
connection is readable by anyone who can observe the network path (a shared VPC, a
misconfigured security group, a compromised node on the same subnet) — no application bug
required. CWE-319 (Cleartext Transmission of Sensitive Information), OWASP:A02.

Fires HIGH (`client-broker-not-tls`) when `client_broker` is the literal string `"PLAINTEXT"`.
Fires MEDIUM (`client-broker-opportunistic-tls`) when it is the literal string
`"TLS_PLAINTEXT"` (opportunistic encryption — a client *can* still negotiate plaintext, but it
is not forced to, unlike pure `"PLAINTEXT"`). Stays silent when the attribute is absent, the
value is `"TLS"`, or the value is not a literal (e.g. a variable reference) — none of those can
be proven unsafe, and the provider default is safe. Fires HIGH (`in-cluster-disabled`) when
`encryption_in_transit` is PRESENT and its `in_cluster` attribute is explicitly `false`
(broker-to-broker traffic sent in the clear; the provider default for `in_cluster` is `true`,
so absence is correctly left silent there).

Suppress an audited case (e.g. a cluster deliberately run inside an isolated, trusted network
for a throwaway dev workload) with `# security: allow-msk-plaintext` anywhere in the resource
block.
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
)

# `encryption_info` nests `encryption_in_transit` one level inside it, so the outer extraction
# must tolerate exactly one level of inner braces (the `[^{}]*`-only shape used for a single
# nested block elsewhere in this codebase, e.g. `aws_observability_hygiene.py`, cannot reach
# through a second level).
_ENCRYPTION_INFO = re.compile(
    r"\bencryption_info\s*\{(?P<inner>(?:[^{}]|\{[^{}]*\})*)\}", re.DOTALL
)
_ENCRYPTION_IN_TRANSIT = re.compile(r"\bencryption_in_transit\s*\{(?P<inner>[^{}]*)\}", re.DOTALL)
_CLIENT_BROKER = re.compile(r'\bclient_broker\s*=\s*"(?P<value>[^"]*)"')
_IN_CLUSTER_FALSE = re.compile(r"\bin_cluster\s*=\s*false\b", re.IGNORECASE)

_PRAGMA = re.compile(r"#\s*security:\s*allow-msk-plaintext")

_STANDARDS = ["OWASP:A02", "CWE-319"]

_RULE_CLIENT_BROKER = "msk-cluster-transit-encryption-disabled/client-broker-not-tls"
_RULE_CLIENT_BROKER_OPPORTUNISTIC = (
    "msk-cluster-transit-encryption-disabled/client-broker-opportunistic-tls"
)
_RULE_IN_CLUSTER = "msk-cluster-transit-encryption-disabled/in-cluster-disabled"


def _encryption_in_transit_body(code_body: str) -> str | None:
    """The `encryption_in_transit` block's own inner text, or `None` if it (or its parent
    `encryption_info`) is absent from the resource body entirely."""
    info_match = _ENCRYPTION_INFO.search(code_body)
    if info_match is None:
        return None
    transit_match = _ENCRYPTION_IN_TRANSIT.search(info_match.group("inner"))
    if transit_match is None:
        return None
    return transit_match.group("inner")


class MskClusterTransitEncryptionDisabledGuard(Guard):
    id = "msk-cluster-transit-encryption-disabled"
    title = "MSK cluster allows plaintext broker traffic"
    area = "Cloud & IaC"

    canary_plant = CanaryPlant(
        files={
            "msk_transit_encryption.tf": (
                'resource "aws_msk_cluster" "canary" {\n'
                '  cluster_name          = "canary-events"\n'
                '  kafka_version         = "3.5.1"\n'
                "  number_of_broker_nodes = 3\n"
                "  encryption_info {\n"
                "    encryption_in_transit {\n"
                '      client_broker = "PLAINTEXT"\n'
                "    }\n"
                "  }\n"
                "}\n"
            ),
        },
        expects=frozenset({_RULE_CLIENT_BROKER}),
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
            if resource_type != "aws_msk_cluster":
                continue
            body_text = "\n".join(line for _, line in body)
            if pragma_present(_PRAGMA, body_text, dialect="hcl"):
                continue
            code_body = "\n".join(
                "" if line.lstrip().startswith(("#", "//")) else line for _, line in body
            )
            transit = _encryption_in_transit_body(code_body)
            out.extend(self._check_client_broker(root, f, resource_name, start_line, transit))
            if transit is not None:
                out.extend(self._check_in_cluster(root, f, resource_name, start_line, transit))
        return out

    def _check_client_broker(
        self, root: Path, f: Path, name: str, start: int, transit: str | None,
    ) -> list[Finding]:
        if transit is None:
            # No encryption_in_transit block at all -> AWS defaults client_broker to "TLS",
            # which is already safe. Absence is not evidence of a problem here.
            return []
        match = _CLIENT_BROKER.search(transit)
        if match is None:
            # Attribute absent (default "TLS"), or set to a non-literal (e.g. a variable) --
            # neither can be proven unsafe.
            return []
        value = match.group("value")
        severity: Severity
        if value == "PLAINTEXT":
            severity, rule = "high", _RULE_CLIENT_BROKER
            verb = "allows a client to negotiate plaintext"
        elif value == "TLS_PLAINTEXT":
            severity, rule = "medium", _RULE_CLIENT_BROKER_OPPORTUNISTIC
            verb = "allows a client to opportunistically negotiate plaintext"
        else:
            return []
        return [
            Finding(
                check_id=self.id,
                severity=severity,
                title=self.title,
                location=f"{rel(root, f)}:{start}",
                message=(
                    f'`aws_msk_cluster.{name}` sets `client_broker = "{value}"`, which {verb} — '
                    "readable by anyone who can observe the network path to the broker."
                ),
                remediation=(
                    "Set `encryption_info { encryption_in_transit { client_broker = \"TLS\" "
                    "in_cluster = true } }` on the resource. Suppress an audited exception with "
                    "`# security: allow-msk-plaintext` anywhere in the resource block."
                ),
                rule=rule,
                standards=list(_STANDARDS),
            )
        ]

    def _check_in_cluster(
        self, root: Path, f: Path, name: str, start: int, transit: str,
    ) -> list[Finding]:
        if not _IN_CLUSTER_FALSE.search(transit):
            return []
        return [
            Finding(
                check_id=self.id,
                severity="high",
                title=self.title,
                location=f"{rel(root, f)}:{start}",
                message=(
                    f"`aws_msk_cluster.{name}` sets `encryption_in_transit.in_cluster = false` — "
                    "broker-to-broker replication traffic is sent unencrypted within the cluster."
                ),
                remediation=(
                    "Set `in_cluster = true` inside the `encryption_in_transit` block. Suppress "
                    "an audited exception with `# security: allow-msk-plaintext` anywhere in the "
                    "resource block."
                ),
                rule=_RULE_IN_CLUSTER,
                standards=list(_STANDARDS),
            )
        ]
