"""Guard: ARM template Azure Cache for Redis allows unencrypted (non-SSL) connections
(checklist §7). agentsec's first ARM-format guard — ARM template detection and the
shared `agentsec.arm` resource parser landed in this same PR to support it.

    {
      "type": "Microsoft.Cache/redis",
      "apiVersion": "2021-06-01",
      "name": "myRedisCache",
      "properties": {
        "enableNonSslPort": true
      }
    }

`Microsoft.Cache/redis` resources accept plaintext connections on port 6379 (alongside the
default TLS port 6380) whenever `enableNonSslPort` is explicitly `true`. Redis routinely holds
session tokens, rate-limit counters, and cached application data; a plaintext connection means
any network position between the client and the cache (a shared subnet, a compromised peer VM,
a misconfigured NSG) can read or tamper with that traffic, including whatever credentials or
tokens travel through it. CWE-319 (Cleartext Transmission of Sensitive Information), OWASP:A02
(Cryptographic Failures).

Sourced from Azure/template-analyzer's `Redis.EnableSSL` rule (`TA-000022`), verified against
the real fetched `BuiltInRules.json` — a single-property check with no `allOf`/`anyOf` nesting.

Fires MEDIUM when a `Microsoft.Cache/redis` resource's `properties.enableNonSslPort` is `true`.
Silent when the property is absent (ARM's own default is `false` — non-SSL port disabled) or
explicitly `false`.

No suppression pragma: ARM templates are pure JSON, which has no comment syntax — the same
documented limitation every guard built on `agentsec.arm` shares (see that module's docstring).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.arm import arm_resources
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, read, rel

_ENABLE_NON_SSL_PORT_TRUE = re.compile(r'"enableNonSslPort"\s*:\s*true')

_STANDARDS = ["OWASP:A02", "CWE-319"]


class ArmRedisSslDisabledGuard(Guard):
    id = "arm-redis-ssl-disabled"
    title = "ARM template Azure Cache for Redis allows unencrypted (non-SSL) connections"
    area = "Cloud & IaC"

    # arm_redis.json: Microsoft.Cache/redis with enableNonSslPort: true -> fires
    # arm-redis-ssl-disabled/non-ssl-port-enabled.
    canary_plant = CanaryPlant(
        files={
            "arm_redis.json": (
                '{\n'
                '  "$schema": '
                '"https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",\n'
                '  "contentVersion": "1.0.0.0",\n'
                '  "resources": [\n'
                '    {\n'
                '      "type": "Microsoft.Cache/redis",\n'
                '      "apiVersion": "2021-06-01",\n'
                '      "name": "canaryRedisCache",\n'
                '      "properties": {\n'
                '        "enableNonSslPort": true\n'
                '      }\n'
                '    }\n'
                '  ]\n'
                '}\n'
            ),
        },
        expects=frozenset({"arm-redis-ssl-disabled/non-ssl-port-enabled"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "arm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".json",)):
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        for resource in arm_resources(read(f)):
            if resource.resource_type != "Microsoft.Cache/redis":
                continue
            if not _ENABLE_NON_SSL_PORT_TRUE.search(resource.block):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=f"{rel(root, f)}",
                    message=(
                        f"`{resource.name or resource.resource_type}` (Microsoft.Cache/redis) "
                        "sets `enableNonSslPort: true`, allowing plaintext connections on the "
                        "non-TLS port alongside the default TLS port. Traffic on that port — "
                        "including whatever session data or credentials pass through the "
                        "cache — is readable and tamperable by anyone on the network path."
                    ),
                    remediation=(
                        "Remove `enableNonSslPort` (defaults to `false`) or set it explicitly "
                        "to `false`, and configure clients to connect over the TLS port "
                        "(6380) instead."
                    ),
                    rule="arm-redis-ssl-disabled/non-ssl-port-enabled",
                    standards=list(_STANDARDS),
                )
            )
        return out
