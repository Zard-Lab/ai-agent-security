"""Guard: ARM template Azure App Service (Web App / API App / Function App) does not enforce
HTTPS-only traffic (checklist §6a).

    {
      "type": "Microsoft.Web/sites",
      "apiVersion": "2021-02-01",
      "name": "mySite",
      "kind": "app",
      "properties": {
        "httpsOnly": false
      }
    }

`Microsoft.Web/sites` is the single ARM resource type behind all three App Service flavors — a
Web App (`kind: "app"`, or `kind` absent entirely, ARM's own default), an API App (`kind: "api"`),
and a Function App (`kind: "functionapp"`) — the `kind` property only labels which flavor, it does
not change the resource type or the shape of `properties.httpsOnly`. This guard matches every
`Microsoft.Web/sites` resource regardless of `kind`, covering all three App Service variants
through one shared resource-type check rather than three near-identical guards (per the sourced
research doc, which documents the same rule shape repeating near-identically across the Web/API/
Function App `kind` variants in the upstream rule catalog).

An App Service reachable over plain HTTP means requests to it — including cookies, bearer tokens,
and any application data in the request/response body — can be read or tampered with by anyone on
the network path between the client and Azure (a shared Wi-Fi, a compromised router, a
misconfigured proxy). CWE-319 (Cleartext Transmission of Sensitive Information), OWASP:A02
(Cryptographic Failures) — the same threat class as the Terraform sibling
`azure-storage-account-https-only` for a different Azure resource type/format.

Sourced from Azure/template-analyzer's `AppServiceWebApp.OnlyHTTPS` rule (`TA-000016`), verified
against agentsec's own research doc, which explicitly notes the same rule shape repeats
near-identically for the API App and Function App `kind` variants of `Microsoft.Web/sites` (3
near-identical rules in the source catalog) — this guard checks all 3 via one shared
`Microsoft.Web/sites` resource-type match, as the research doc itself proposes, instead of three
separate guards.

Fires MEDIUM when a `Microsoft.Web/sites` resource's `properties.httpsOnly` is `false` (explicit)
or absent entirely (ARM's own default for `httpsOnly` is `false` — matches the Terraform sibling
`azure-storage-account-https-only`'s posture on its own analogous property). Silent when
`properties.httpsOnly` is `true`.

Matching is an EXACT resource-type equality (`resource.resource_type == "Microsoft.Web/sites"`),
never a substring/startswith check: `Microsoft.Web/sites/slots` (a deployment-slot CHILD resource)
and `Microsoft.Web/sites/config` (a configuration CHILD resource) are DIFFERENT resource types that
happen to share the `Microsoft.Web/sites` prefix. A substring match would either misfire on those
child resources (which don't carry an `httpsOnly` property in the same shape) or, depending on the
check's polarity, miss real Web App resources — both are wrong, so the check anchors on equality.

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

_HTTPS_ONLY_TRUE = re.compile(r'"httpsOnly"\s*:\s*true')

_STANDARDS = ["OWASP:A02", "CWE-319"]


class ArmAppserviceHttpsOnlyDisabledGuard(Guard):
    id = "arm-appservice-https-only-disabled"
    title = "ARM template Azure App Service does not enforce HTTPS-only traffic"
    area = "Cloud & IaC"

    # arm_appservice.json: Microsoft.Web/sites with no httpsOnly property (absent -> ARM default
    # false) -> fires arm-appservice-https-only-disabled/missing-or-disabled.
    canary_plant = CanaryPlant(
        files={
            "arm_appservice.json": (
                '{\n'
                '  "$schema": '
                '"https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",\n'
                '  "contentVersion": "1.0.0.0",\n'
                '  "resources": [\n'
                '    {\n'
                '      "type": "Microsoft.Web/sites",\n'
                '      "apiVersion": "2021-02-01",\n'
                '      "name": "canarySite",\n'
                '      "kind": "app",\n'
                '      "properties": {\n'
                '        "serverFarmId": "canaryPlan"\n'
                '      }\n'
                '    }\n'
                '  ]\n'
                '}\n'
            ),
        },
        expects=frozenset({"arm-appservice-https-only-disabled/missing-or-disabled"}),
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
            # EXACT match only: `Microsoft.Web/sites/slots` and `Microsoft.Web/sites/config` are
            # different resource types (deployment-slot / config child resources) that happen to
            # share this prefix — a substring/startswith check here would misfire on them.
            if resource.resource_type != "Microsoft.Web/sites":
                continue
            if _HTTPS_ONLY_TRUE.search(resource.block):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=f"{rel(root, f)}",
                    message=(
                        f"`{resource.name or resource.resource_type}` (Microsoft.Web/sites) "
                        "does not set `properties.httpsOnly: true` — either the property is "
                        "missing entirely (ARM's own default is `false`) or it is explicitly "
                        "`false`. Requests to this App Service — including cookies, bearer "
                        "tokens, and any application data — can be sent over plain HTTP, "
                        "readable and tamperable by anyone on the network path. This covers "
                        "the Web App, API App, and Function App `kind` variants alike, since "
                        "all three share the `Microsoft.Web/sites` resource type."
                    ),
                    remediation=(
                        "Set `properties.httpsOnly: true` on the `Microsoft.Web/sites` "
                        "resource so Azure rejects plain-HTTP requests to the site "
                        "regardless of its `kind` (Web App, API App, or Function App)."
                    ),
                    rule="arm-appservice-https-only-disabled/missing-or-disabled",
                    standards=list(_STANDARDS),
                )
            )
        return out
