---
type: Guard
title: "arm-apim-backend-unauthenticated"
description: "ARM-templated Azure API Management backend using a cleartext HTTP URL with no authentication configured."
timestamp: "2026-09-12T00:00:00Z"
guard_id: "arm-apim-backend-unauthenticated"
checklist_section: ["6a"]
standards: ["OWASP:A02", "CWE-319"]
---

# ARM template Azure API Management backend uses cleartext HTTP with no authentication

Flags `Microsoft.ApiManagement/service/backends` resources whose `properties.url` is a plaintext
`http://` endpoint AND whose `properties.credentials` is absent. Closes a new checklist item — no
existing agentsec item covers Azure API Management at all, for any format. Second ARM-format
guard (4/5), built on the `agentsec.arm` resource parser `arm-redis-ssl-disabled`
introduced.

## The threat

An APIM "backend" is the upstream service definition an API Management gateway proxies requests
to. Two independent weaknesses compound here:

- **Cleartext transport.** A backend with an `http://` URL means every request APIM forwards
  travels unencrypted between the gateway and the upstream — readable and tamperable by anyone on
  that network path.
- **No authentication.** A backend with no `properties.credentials` means the upstream accepts
  connections from the gateway (and from anyone else who can reach it) with no proof of caller
  identity — no client certificate, no Basic/header auth, no API-key query/header.

Either alone is a real finding. Together, a gateway is relaying plaintext traffic to a service
that will accept it from anyone who can reach it — worse than either weakness in isolation.
CWE-319 (Cleartext Transmission of Sensitive Information), OWASP:A02 (Cryptographic Failures).

## Exploitability rationale

HIGH. Requires network reach to the backend (not itself internet-facing in most topologies), but
the compounded failure — no encryption AND no authentication — removes both layers of defense at
once, which is a step above the single-property `arm-redis-ssl-disabled` case (MEDIUM) this guard
is built alongside.

## What counts as a hit (and what doesn't)

A `Microsoft.ApiManagement/service/backends` resource fires only when ALL of:

- `properties.url` is present and its literal string value starts with `http://` (case-insensitive
  scheme match, checked via regex over the resource's `block` text — not JSON-schema validated,
  since the value may be an ARM expression).
- `properties.protocol` says `"http"` **if the key is present at all**. If `protocol` is absent,
  the URL scheme alone decides (see the dedicated section below — this is a deliberate judgment
  call, not an oversight).
- `properties.credentials` is **absent**. Its mere presence — regardless of whether the nested
  `authorization`/`certificate`/`certificateIds`/`query`/`header` contents are well-formed — is
  read as "authentication configured." This guard does not validate the credentials themselves.
- No `serviceFabricCluster` key anywhere in the resource's `block` (see the dedicated section
  below).

Everything else stays silent:

- `properties.url` starting `https://` → silent (the fix), regardless of `protocol` or
  `credentials`.
- `properties.credentials` present (any non-empty object) → silent, even with an `http://` URL.
- `serviceFabricCluster` present anywhere under `properties` → silent — a distinct, more specific
  backend integration shape.
- Any resource type other than `Microsoft.ApiManagement/service/backends` (including
  `Microsoft.ApiManagement/service/apis`, which carries similarly-named `url`/`protocol`
  properties but is not a backend definition) → silent.
- `properties.url` absent entirely → silent (nothing to evaluate the scheme of).

**Both ARM authoring styles fire identically.** A backend declared flat with a fully-qualified
`type`, and the same backend declared as an inline child (`"type": "backends"` nested under a
`Microsoft.ApiManagement/service`), deploy to the same thing — `agentsec.arm` resolves an inline
child's relative `type` and `name` against its parent, so the guard sees one canonical form.

### The ambiguous-protocol judgment call

The real Azure/template-analyzer rule's `allOf` lists `properties.protocol == "http"` as its own
condition, separate from the URL scheme. In practice, `protocol` is an optional property — APIM
can infer transport from the URL — so a template author who only sets `url: "http://..."` and
never sets `protocol` at all is still deploying an unauthenticated cleartext backend. Requiring
BOTH signals to be literally present in the template text would make this guard **silent on that
real vulnerable case** — a false negative purely because the template took the shorter, equally
vulnerable path. So: `protocol` absent → judge by URL scheme alone. `protocol` present → it must
actually say `"http"`; a template that sets `protocol: "https"` while the URL string still starts
`http://` (an internally inconsistent template) is left alone rather than guessed at — see "Known
bypasses" below.

### The ServiceFabric exemption

A `properties.properties.serviceFabricCluster` object (a distinct, more deeply-nested shape used
only for Service Fabric backend integrations) is the real rule's own explicit exemption: Service
Fabric cluster connections manage their own mutual-TLS separately, so an `http://`-scheme URL
alongside a ServiceFabric block does not carry the same risk an ordinary HTTP backend does. This
guard checks for `serviceFabricCluster` anywhere in the resource's `block` text (not scoped to the
exact nesting depth) to stay safely conservative against the precise schema shape — a stray
`serviceFabricCluster` key anywhere in the resource is enough to exempt it, trading a
theoretical false negative for zero risk of misfiring on a legitimate ServiceFabric backend.

## When NOT to flag (and the pragma)

- `https://` URL → silent (the fix for transport).
- `credentials` configured (any form) → silent (the fix for authentication).
- ServiceFabric backend → silent (out of scope; own TLS model).
- **No suppression pragma exists for this guard.** ARM templates are pure JSON, which has no
  comment syntax — a known, documented limitation shared by every guard built on `agentsec.arm`
  (see that module's docstring). There is no equivalent to the CFN guards' YAML-only
  `# security: allow-...` pragma here.

## Tests

| Test | What it checks |
|---|---|
| `test_arm_apim_backend_flags_http_no_credentials` | Cleartext `http://` URL with no `credentials` fires `high`. |
| `test_arm_apim_backend_silent_when_credentials_present` | `credentials` present stays silent. |
| `test_arm_apim_backend_silent_on_https_url` | An `https://` URL stays silent. |
| `test_arm_apim_backend_silent_when_service_fabric_cluster_present` | FP bait: the ServiceFabric-backend exemption. |
| `test_arm_apim_backend_flags_inline_nested_child_authoring_style` | The same violation authored as an inline child (relative `type`) fires identically to the flat fully-qualified form. |
| `test_arm_apim_backend_silent_on_nested_child_with_credentials` | FP bait: nested form with `credentials` stays silent. |
| `test_arm_apim_backend_fires_when_protocol_absent_and_url_is_http` | The ambiguous-protocol call: no `protocol` key, URL scheme decides. |
| `test_arm_apim_backend_silent_when_protocol_present_but_not_http` | FP bait: inconsistent `protocol`/`url` pair is not adjudicated. |
| `test_arm_apim_backend_silent_when_url_absent` | No `url` to evaluate stays silent. |
| `test_arm_apim_backend_silent_on_unrelated_resource_type` | FP bait: `service/apis` carries similar properties but is not a backend. |
| `test_arm_apim_backend_not_applicable_without_arm` | `applies()` is `False` without the `arm` feature. |

## Known bypasses (honest limits)

- **No dataflow, no cross-resource reasoning.** Fires on the property values directly; does not
  trace where `url` or `credentials` values ultimately come from.
- **File-level location, not line-level** — like every guard built on `agentsec.arm`, the finding
  reports the template file, not a specific line (a `block` is a `json.dumps` reconstruction with
  no original line mapping to report).
- **Template expressions are not evaluated.** A `url` set via `"[parameters('backendUrl')]"`
  rather than a literal string does not start with `http://`/`https://` textually, so this guard
  stays silent on it either way — see `agentsec.arm`'s module docstring for the same posture on
  resource `name`.
- **`credentials` presence, not correctness.** An empty or malformed `credentials` object (e.g.
  `"credentials": {}`) still counts as "authentication configured" and suppresses the finding —
  this guard does not validate that the configured authentication actually works.
- **Inconsistent `url`/`protocol` pairs are left alone.** If `protocol` says `"https"` while `url`
  literally starts `http://` (or the reverse — `protocol: "http"` with an `https://` URL, which
  already fails the URL-scheme gate), this guard does not try to decide which one is authoritative
  and stays silent rather than guess.
- **Nested/linked templates** (`Microsoft.Resources/deployments` referencing a separate template
  file or URI) are not followed — each template file is scanned independently.

## What this guard does NOT prove

A clean scan means no `Microsoft.ApiManagement/service/backends` resource in the scanned templates
has both a literal `http://` URL and an absent `credentials` object — it says nothing about a
backend created outside this template entirely (the Azure Portal, a different IaC tool, a linked
template this scan didn't independently discover), about whether the configured credentials are
actually valid or correctly enforced by the upstream, nor about the backend's actual runtime
configuration if it was changed out-of-band after deployment.

## Canary plant

`arm_apim_backend.json` — a `Microsoft.ApiManagement/service/backends` resource with
`url: "http://..."`, `protocol: "http"`, no `credentials`, no `serviceFabricCluster`. Expected
rule: `arm-apim-backend-unauthenticated/http-no-auth`.

# Citations

[1] OWASP:A02 (Cryptographic Failures)
[2] CWE-319 (Cleartext Transmission of Sensitive Information)
[3] Azure/template-analyzer — `APIM.APIBackendsShouldBeAuthenticated` (`TA-000038`, provenance
    only; detection logic here is original)
