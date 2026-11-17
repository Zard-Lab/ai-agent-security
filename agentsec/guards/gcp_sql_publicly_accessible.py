"""Guard: Terraform GCP Cloud SQL instance reachable from the internet (checklist §7).

    resource "google_sql_database_instance" "app" {
      name             = "app-db"
      database_version = "POSTGRES_15"
      settings {
        tier = "db-f1-micro"
        # no ip_configuration block at all -> ipv4_enabled defaults to true, unrestricted
      }
    }

A `google_sql_database_instance`'s `settings.ip_configuration` block controls whether the
instance has a public IP at all, and — if it does — what is allowed to reach it.
`ipv4_enabled` defaults to `true` (a public IP is assigned) when the block or the
attribute is omitted, and an `authorized_networks` entry of `0.0.0.0/0` (or a network
that includes it) allows every IPv4 address on the internet to attempt a connection to
that public IP, subject only to database-level authentication. A Cloud SQL instance
with no `private_network` (VPC peering) and no narrow `authorized_networks` allowlist
is reachable by anyone who can reach its IP — a direct target for credential-stuffing
and brute-force attacks against the database. CWE-284 (Improper Access Control),
OWASP:A05.

Sourced from KICS's `sql_db_instance_is_publicly_accessible` query, verified against the
real fetched `query.rego`: four separate CxPolicy rules cover the sub-cases below. This
guard implements three of them (the fourth — a data-source-driven or generated dynamic
`authorized_networks` value — is not resolvable statically and is a documented bypass).

Fires HIGH on a `google_sql_database_instance` resource when any of:
1. An `authorized_networks` block's `value` contains the literal `0.0.0.0` (e.g.
   `0.0.0.0/0`) — any IPv4 address on the internet is explicitly allowlisted.
2. `ipv4_enabled = true` is set explicitly, and neither `private_network` nor an
   `authorized_networks` block is present anywhere in `ip_configuration` — a public IP
   with nothing restricting who may reach it.
3. The `ip_configuration` block (or its enclosing `settings` block) is missing entirely
   — the GCP default is a public IP (`ipv4_enabled` defaults to `true`) with no
   restriction configured at all.

Suppress an audited case (e.g. a deliberately public read-replica with its own
compensating controls) with `# security: allow-gcp-sql-public` anywhere in the
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
)

_IPV4_ENABLED_TRUE = re.compile(r"\bipv4_enabled\s*=\s*true\b")
_PRIVATE_NETWORK_SET = re.compile(r"\bprivate_network\s*=")
_AUTHORIZED_NETWORKS_BLOCK = re.compile(r"\bauthorized_networks\s*\{")
_ZERO_CIDR = re.compile(r"0\.0\.0\.0")
_PRAGMA = re.compile(r"#\s*security:\s*allow-gcp-sql-public")

_STANDARDS = ["OWASP:A05", "CWE-284"]


def _nested_block_bodies(text: str, block_name: str) -> list[str]:
    """The balanced-brace body text of every top-level `block_name { ... }` occurrence in
    `text` (repeated blocks of the same name, e.g. `authorized_networks`, all included).

    Not string-aware — the caller always passes an already comment-blanked Terraform block
    body, and none of the attribute values this guard cares about (`value = "0.0.0.0/0"`,
    booleans, resource references) legitimately contain a brace character, so a plain
    depth counter is sufficient here without pulling in a heavier quote-aware scanner."""
    out: list[str] = []
    pattern = re.compile(rf"\b{re.escape(block_name)}\s*\{{")
    pos = 0
    while True:
        m = pattern.search(text, pos)
        if not m:
            break
        start = m.end()
        depth = 1
        i = start
        n = len(text)
        while i < n and depth > 0:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        out.append(text[start : i - 1])
        pos = i
    return out


class GcpSqlPubliclyAccessibleGuard(Guard):
    id = "gcp-sql-publicly-accessible"
    title = "GCP Cloud SQL instance reachable from the internet"
    area = "Cloud & IaC"

    # gcp_sql.tf: google_sql_database_instance with no ip_configuration block at all ->
    # fires missing-ip-configuration. Must NOT contain: allow-gcp-sql-public pragma.
    canary_plant = CanaryPlant(
        files={
            "gcp_sql.tf": (
                'resource "google_sql_database_instance" "canary" {\n'
                '  name             = "canary-db"\n'
                '  database_version = "POSTGRES_15"\n'
                "  settings {\n"
                '    tier = "db-f1-micro"\n'
                "  }\n"
                "}\n"
            ),
        },
        expects=frozenset({"gcp-sql-publicly-accessible/missing-ip-configuration"}),
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
            if resource_type != "google_sql_database_instance":
                continue
            body_text = "\n".join(line for _, line in body)
            if pragma_present(_PRAGMA, body_text, dialect="hcl"):
                continue
            # Comment-blanked view for pattern matching (pragma already handled on the raw
            # text above), same shape as every other Terraform guard in this codebase.
            code_body = "\n".join(
                "" if line.lstrip().startswith(("#", "//")) else line for _, line in body
            )
            finding = self._check_resource(root, f, resource_name, start_line, code_body)
            if finding is not None:
                out.append(finding)
        return out

    def _check_resource(
        self, root: Path, f: Path, resource_name: str, start_line: int, code_body: str
    ) -> Finding | None:
        settings_bodies = _nested_block_bodies(code_body, "settings")
        settings_text = settings_bodies[0] if settings_bodies else ""
        ip_config_bodies = _nested_block_bodies(settings_text, "ip_configuration")
        ip_config_text = ip_config_bodies[0] if ip_config_bodies else None

        # Rule 3: `ip_configuration` (or the enclosing `settings` block) missing entirely ->
        # the GCP default is a public IP with no restriction configured at all.
        if ip_config_text is None:
            return self._finding(
                root,
                f,
                resource_name,
                start_line,
                rule_suffix="missing-ip-configuration",
                message=(
                    f"`google_sql_database_instance.{resource_name}` has no "
                    "`ip_configuration` block. GCP Cloud SQL defaults `ipv4_enabled` to "
                    "`true` when omitted, assigning the instance a public IP with no "
                    "`private_network` or `authorized_networks` restriction configured "
                    "at all."
                ),
            )

        # Rule 1: any authorized_networks entry allowlists 0.0.0.0(/0) — anyone on the
        # internet, regardless of ipv4_enabled/private_network.
        for net_body in _nested_block_bodies(ip_config_text, "authorized_networks"):
            if _ZERO_CIDR.search(net_body):
                return self._finding(
                    root,
                    f,
                    resource_name,
                    start_line,
                    rule_suffix="authorized-network-wildcard",
                    message=(
                        f"`google_sql_database_instance.{resource_name}` has an "
                        "`authorized_networks` entry allowlisting `0.0.0.0` — every "
                        "IPv4 address on the internet may attempt a connection to this "
                        "instance's public IP."
                    ),
                )

        # Rule 2: ipv4_enabled explicitly true, with no private_network AND no
        # authorized_networks block at all -> a public IP nothing restricts.
        if (
            _IPV4_ENABLED_TRUE.search(ip_config_text)
            and not _PRIVATE_NETWORK_SET.search(ip_config_text)
            and not _AUTHORIZED_NETWORKS_BLOCK.search(ip_config_text)
        ):
            return self._finding(
                root,
                f,
                resource_name,
                start_line,
                rule_suffix="public-ip-no-restriction",
                message=(
                    f"`google_sql_database_instance.{resource_name}` sets "
                    "`ipv4_enabled = true` with no `private_network` and no "
                    "`authorized_networks` allowlist — the instance's public IP is "
                    "reachable from any address that can route to it."
                ),
            )
        return None

    def _finding(
        self,
        root: Path,
        f: Path,
        resource_name: str,
        start_line: int,
        rule_suffix: str,
        message: str,
    ) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{start_line}",
            message=message,
            remediation=(
                "Set `ipv4_enabled = false` and connect over a private VPC network "
                "(`private_network`), or if a public IP is required, remove any "
                "`0.0.0.0/0`-style `authorized_networks` entry and scope the allowlist "
                "to specific known IP ranges. Suppress an audited exception with "
                "`# security: allow-gcp-sql-public` anywhere in the resource block."
            ),
            rule=f"gcp-sql-publicly-accessible/{rule_suffix}",
            standards=list(_STANDARDS),
        )
