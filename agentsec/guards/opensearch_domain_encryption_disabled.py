"""Guard: Terraform OpenSearch/Elasticsearch domain with an encryption control disabled (§7).

    resource "aws_opensearch_domain" "logs" {
      domain_name    = "logs"
      engine_version = "OpenSearch_2.11"
      # no node_to_node_encryption or encrypt_at_rest block -> both default OFF, both fire.
      # (domain_endpoint_options / enforce_https defaults ON, so omitting it is safe.)
    }

AWS renamed `aws_elasticsearch_domain` to `aws_opensearch_domain`, but both resource types
still appear in real Terraform configs (older code on the legacy name, newer code on the
renamed one) and both carry the identical three independent encryption controls:

1. **`domain_endpoint_options { enforce_https = ... }`** — per the AWS provider docs this
   attribute **defaults to `true`**. Without it, the domain still requires HTTPS; only an
   explicit `enforce_https = false` accepts plain HTTP as well, letting a client (or a
   misconfigured proxy in front of it) send search queries and results in the clear. CWE-319
   (Cleartext Transmission of Sensitive Information), OWASP:A02.
2. **`node_to_node_encryption { enabled = ... }`** — this block/attribute **defaults OFF**
   when omitted, so traffic between the domain's own data nodes (shard replication, cluster
   coordination) is unencrypted on the wire by default. Same CWE-319 / OWASP:A02 class, one
   layer further in.
3. **`encrypt_at_rest { enabled = ... }`** — this block/attribute **defaults OFF** when
   omitted, so indexed documents are stored unencrypted on the underlying EBS volumes by
   default. CWE-311 (Missing Encryption of Sensitive Data), OWASP:A02.

The three rules are independent, each gated on its own provider default: (1) fires only on an
explicit literal `enforce_https = false` (absence is safe); (2) and (3) fire when their block
or attribute is absent, OR the attribute is explicitly `false` (absence is unsafe). None of the
three treats a non-literal value (e.g. `enabled = var.e`) as unsafe — it cannot be proven
either way, so it stays silent rather than guessing.

Suppress an audited case (e.g. a domain deliberately run inside an isolated, trusted network
for throwaway dev data) with `# security: allow-opensearch-unencrypted` anywhere in the
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
    literal_bool_state,
    pragma_present,
    read,
    rel,
    terraform_code_view,
)

_DOMAIN_ENDPOINT_OPTIONS = re.compile(r"\bdomain_endpoint_options\s*\{(?P<inner>[^{}]*)\}", re.DOTALL)
_NODE_TO_NODE_ENCRYPTION = re.compile(r"\bnode_to_node_encryption\s*\{(?P<inner>[^{}]*)\}", re.DOTALL)
_ENCRYPT_AT_REST = re.compile(r"\bencrypt_at_rest\s*\{(?P<inner>[^{}]*)\}", re.DOTALL)

_PRAGMA = re.compile(r"#\s*security:\s*allow-opensearch-unencrypted")

_TRANSIT_STANDARDS = ["OWASP:A02", "CWE-319"]
_AT_REST_STANDARDS = ["OWASP:A02", "CWE-311"]

_RESOURCE_TYPES = frozenset({"aws_opensearch_domain", "aws_elasticsearch_domain"})

_RULE_ENFORCE_HTTPS = "opensearch-domain-encryption-disabled/enforce-https-disabled"
_RULE_NODE_TO_NODE = "opensearch-domain-encryption-disabled/node-to-node-disabled"
_RULE_ENCRYPT_AT_REST = "opensearch-domain-encryption-disabled/encrypt-at-rest-disabled"


class OpensearchDomainEncryptionDisabledGuard(Guard):
    id = "opensearch-domain-encryption-disabled"
    title = "OpenSearch/Elasticsearch domain has an encryption control disabled"
    area = "Cloud & IaC"

    canary_plant = CanaryPlant(
        files={
            "opensearch_encryption.tf": (
                'resource "aws_opensearch_domain" "canary" {\n'
                '  domain_name    = "canary-logs"\n'
                '  engine_version = "OpenSearch_2.11"\n'
                "  domain_endpoint_options {\n"
                "    enforce_https = false\n"
                "  }\n"
                "}\n"
            ),
        },
        expects=frozenset({_RULE_ENFORCE_HTTPS, _RULE_NODE_TO_NODE, _RULE_ENCRYPT_AT_REST}),
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
            # Comment-blanked and `${...}`-neutralised: an interpolation's own `}` (e.g. a
            # `kms_key_id = "${aws_kms_key.k.arn}"`) would otherwise cut a `[^{}]*` block regex
            # short, so a compliant block reads as absent and fires (PR #1162 round-2 M-2).
            code_body = terraform_code_view(body_text)
            label = f"{resource_type}.{resource_name}"
            out.extend(self._check_enforce_https(root, f, label, start_line, code_body))
            out.extend(self._check_node_to_node(root, f, label, start_line, code_body))
            out.extend(self._check_encrypt_at_rest(root, f, label, start_line, code_body))
        return out

    def _check_enforce_https(
        self, root: Path, f: Path, name: str, start: int, code_body: str,
    ) -> list[Finding]:
        # Defaults to true (safe) -- fire only on an explicit literal `enforce_https = false`.
        match = _DOMAIN_ENDPOINT_OPTIONS.search(code_body)
        if match is None or literal_bool_state("enforce_https", match.group("inner")) != "false":
            return []
        return [
            Finding(
                check_id=self.id,
                severity="high",
                title="OpenSearch/Elasticsearch domain does not enforce HTTPS",
                location=f"{rel(root, f)}:{start}",
                message=(
                    f"`{name}` sets `domain_endpoint_options {{ enforce_https = false }}` — the "
                    "domain accepts plain HTTP as well as HTTPS, so queries and results can be "
                    "sent in the clear."
                ),
                remediation=(
                    "Remove `enforce_https = false` (the provider default of `true` is safe), or "
                    "set it explicitly to `true`. Suppress an audited exception with "
                    "`# security: allow-opensearch-unencrypted` anywhere in the resource block."
                ),
                rule=_RULE_ENFORCE_HTTPS,
                standards=list(_TRANSIT_STANDARDS),
            )
        ]

    def _check_node_to_node(
        self, root: Path, f: Path, name: str, start: int, code_body: str,
    ) -> list[Finding]:
        # Defaults to off (unsafe) -- fire on an absent block/attribute or a literal `false`.
        # A non-literal value (e.g. a variable) cannot be proven either way -> stays silent.
        match = _NODE_TO_NODE_ENCRYPTION.search(code_body)
        state = literal_bool_state("enabled", match.group("inner")) if match is not None else "absent"
        if state in ("true", "nonliteral"):
            return []
        return [
            Finding(
                check_id=self.id,
                severity="high",
                title="OpenSearch/Elasticsearch domain has no node-to-node encryption",
                location=f"{rel(root, f)}:{start}",
                message=(
                    f"`{name}` does not set `node_to_node_encryption {{ enabled = true }}` — "
                    "traffic between the domain's own data nodes (shard replication, cluster "
                    "coordination) is unencrypted on the wire."
                ),
                remediation=(
                    "Add `node_to_node_encryption { enabled = true }` to the resource. Suppress "
                    "an audited exception with `# security: allow-opensearch-unencrypted` anywhere "
                    "in the resource block."
                ),
                rule=_RULE_NODE_TO_NODE,
                standards=list(_TRANSIT_STANDARDS),
            )
        ]

    def _check_encrypt_at_rest(
        self, root: Path, f: Path, name: str, start: int, code_body: str,
    ) -> list[Finding]:
        # Defaults to off (unsafe) -- fire on an absent block/attribute or a literal `false`.
        # A non-literal value (e.g. a variable) cannot be proven either way -> stays silent.
        match = _ENCRYPT_AT_REST.search(code_body)
        state = literal_bool_state("enabled", match.group("inner")) if match is not None else "absent"
        if state in ("true", "nonliteral"):
            return []
        return [
            Finding(
                check_id=self.id,
                severity="high",
                title="OpenSearch/Elasticsearch domain has no encryption at rest",
                location=f"{rel(root, f)}:{start}",
                message=(
                    f"`{name}` does not set `encrypt_at_rest {{ enabled = true }}` — indexed "
                    "documents are stored unencrypted on the underlying EBS volumes."
                ),
                remediation=(
                    "Add `encrypt_at_rest { enabled = true }` to the resource. Suppress an "
                    "audited exception with `# security: allow-opensearch-unencrypted` anywhere "
                    "in the resource block."
                ),
                rule=_RULE_ENCRYPT_AT_REST,
                standards=list(_AT_REST_STANDARDS),
            )
        ]
