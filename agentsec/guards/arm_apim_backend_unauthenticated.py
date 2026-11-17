"""Guard: ARM template Azure API Management backend uses a cleartext HTTP URL with no
authentication configured (checklist §6a). Second ARM-format guard (4/5), built on the
shared `agentsec.arm` resource parser `arm-redis-ssl-disabled` introduced.

    {
      "type": "Microsoft.ApiManagement/service/backends",
      "apiVersion": "2021-08-01",
      "name": "myApim/myBackend",
      "properties": {
        "url": "http://internal-service.example.com/api",
        "protocol": "http"
      }
    }

An APIM "backend" is the upstream service definition an API Management gateway proxies requests
to. A backend configured with a plaintext `http://` URL means every request the gateway forwards
travels unencrypted between APIM and the upstream — readable and tamperable by anyone on the
network path — and when that backend ALSO carries no `credentials` (no client-cert, no
Basic/header/query-key auth), the upstream itself accepts the connection with no proof of who is
calling it. Either weakness alone is a real finding; together, a gateway is relaying plaintext
traffic to a service that will accept it from anyone who can reach it. CWE-319 (Cleartext
Transmission of Sensitive Information), OWASP:A02 (Cryptographic Failures).

Sourced from Azure/template-analyzer's `APIM.APIBackendsShouldBeAuthenticated` rule
(`TA-000038`), verified against the real fetched `BuiltInRules.json` — the rule's own `allOf`
requires `properties.url` set, `properties.protocol == "http"`, AND no ServiceFabric management
endpoint / no authentication (certificate or credentials) configured.

Fires HIGH when a `Microsoft.ApiManagement/service/backends` resource has ALL of:
  - `properties.url` present and its literal value starts with `http://` (case-insensitive
    scheme match) — an expression-valued URL (`"[parameters(...)]"`) cannot be evaluated, so a
    URL that doesn't literally start with `http`/`https` at all is left alone (can't tell, don't
    flag, same posture as every guard built on `agentsec.arm`);
  - `properties.protocol` is `"http"` **if that key is present at all** — if `protocol` is
    absent, the URL scheme alone decides (see "ambiguous protocol" below);
  - `properties.credentials` is absent (its mere PRESENCE, regardless of contents, means the
    rule's "authentication configured" branch is satisfied — this guard does not validate that
    the credentials are well-formed);
  - `serviceFabricCluster` is absent anywhere under `properties` (a distinct, more specific
    backend shape used only for Service Fabric integrations, which manage their own mutual-TLS
    separately — this is the rule's own explicit exemption, not a guess).
Silent otherwise.

Ambiguous-protocol judgment call: the real rule's `allOf` lists `properties.protocol == "http"`
as its own condition, alongside the URL scheme. Some hand-written or generated templates only
set one of the two signals (e.g. a `url` beginning `http://` with no `protocol` key at all, since
`protocol` is optional and APIM often infers it from the URL). Requiring BOTH signals to be
literally present would make this guard silent on that case — a real vulnerable backend — so when
`protocol` is absent, this guard judges by the URL scheme alone. When `protocol` IS present, it
still has to actually say `"http"` (not `"https"` or something else) — a template that sets
`protocol: "https"` while the URL string happens to start `http://` (or vice versa) is a
malformed/inconsistent template this guard deliberately doesn't try to adjudicate; see "Known
bypasses" in the wiki doc for the full reasoning.

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

_URL_VALUE = re.compile(r'"url"\s*:\s*"([^"]*)"')
_PROTOCOL_HTTP = re.compile(r'"protocol"\s*:\s*"http"')
_PROTOCOL_KEY = re.compile(r'"protocol"\s*:\s*"')
_CREDENTIALS_KEY = re.compile(r'"credentials"\s*:\s*\{')
_SERVICE_FABRIC_CLUSTER_KEY = re.compile(r'"serviceFabricCluster"\s*:')

_STANDARDS = ["OWASP:A02", "CWE-319"]


class ArmApimBackendUnauthenticatedGuard(Guard):
    id = "arm-apim-backend-unauthenticated"
    title = "ARM template Azure API Management backend uses cleartext HTTP with no authentication"
    area = "Cloud & IaC"

    # arm_apim_backend.json: Microsoft.ApiManagement/service/backends with url: "http://...",
    # protocol: "http", no credentials, no serviceFabricCluster -> fires
    # arm-apim-backend-unauthenticated/http-no-auth.
    canary_plant = CanaryPlant(
        files={
            "arm_apim_backend.json": (
                '{\n'
                '  "$schema": '
                '"https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",\n'
                '  "contentVersion": "1.0.0.0",\n'
                '  "resources": [\n'
                '    {\n'
                '      "type": "Microsoft.ApiManagement/service/backends",\n'
                '      "apiVersion": "2021-08-01",\n'
                '      "name": "canaryApim/canaryBackend",\n'
                '      "properties": {\n'
                '        "url": "http://internal-service.example.com/api",\n'
                '        "protocol": "http"\n'
                '      }\n'
                '    }\n'
                '  ]\n'
                '}\n'
            ),
        },
        expects=frozenset({"arm-apim-backend-unauthenticated/http-no-auth"}),
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
            if resource.resource_type != "Microsoft.ApiManagement/service/backends":
                continue

            url_match = _URL_VALUE.search(resource.block)
            if url_match is None:
                continue
            url_value = url_match.group(1)
            if not url_value.lower().startswith("http://"):
                continue

            # protocol, if present at all, must actually say "http" -- if it's present and says
            # something else (e.g. "https"), the template is inconsistent/ambiguous and this
            # guard deliberately doesn't adjudicate it.
            if _PROTOCOL_KEY.search(resource.block) and not _PROTOCOL_HTTP.search(resource.block):
                continue

            if _CREDENTIALS_KEY.search(resource.block):
                continue

            if _SERVICE_FABRIC_CLUSTER_KEY.search(resource.block):
                continue

            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}",
                    message=(
                        f"`{resource.name or resource.resource_type}` "
                        "(Microsoft.ApiManagement/service/backends) points to a plaintext "
                        f"`{url_value}` backend with no `properties.credentials` configured. "
                        "The API Management gateway both relays this traffic unencrypted and "
                        "authenticates to the upstream with nothing at all — anyone who can "
                        "reach the backend can impersonate the gateway, and anyone on the "
                        "network path between APIM and the backend can read or tamper with "
                        "the traffic."
                    ),
                    remediation=(
                        "Point `properties.url` at an `https://` endpoint, and configure "
                        "`properties.credentials` (client-certificate, Basic/header auth, or "
                        "an API-key query/header) so the backend can verify the caller."
                    ),
                    rule="arm-apim-backend-unauthenticated/http-no-auth",
                    standards=list(_STANDARDS),
                )
            )
        return out
