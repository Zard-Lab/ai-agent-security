---
type: Guard
title: "arm-appservice-https-only-disabled"
description: "ARM-templated Azure App Service (Web App, API App, or Function App) that does not enforce HTTPS-only traffic."
timestamp: "2026-09-12T00:00:00Z"
guard_id: "arm-appservice-https-only-disabled"
checklist_section: ["6a"]
standards: ["OWASP:A02"]
---

# ARM template Azure App Service does not enforce HTTPS-only traffic

Flags `Microsoft.Web/sites` resources whose `properties.httpsOnly` is `false` or absent. Closes a
new checklist item (§6a) — the same "HTTP Security" threat class the Terraform sibling
`azure-storage-account-https-only` covers for Azure Storage Accounts, applied here to Azure App
Service in ARM-template format.

## One guard, three App Service `kind` variants

`Microsoft.Web/sites` is the single ARM resource type behind a Web App (`kind: "app"`, or `kind`
absent — ARM's own default), an API App (`kind: "api"`), and a Function App
(`kind: "functionapp"`). Azure/template-analyzer's source catalog carries three near-identical
rules for this — one per `kind` — but `kind` only labels which App Service flavor a site is; it
does not change the resource type or the shape of `properties.httpsOnly`. This guard matches every
`Microsoft.Web/sites` resource regardless of `kind` (including when `kind` is absent) through one
shared resource-type check, rather than shipping three near-identical guards. It does not branch on
`kind` at all.

## The threat

An App Service reachable over plain HTTP means requests to it — including cookies, bearer tokens,
and any application data in the request/response body — can be read or tampered with by anyone on
the network path between the client and Azure (a shared Wi-Fi, a compromised router, a
misconfigured proxy). CWE-319 (Cleartext Transmission of Sensitive Information).

## Exploitability rationale

MEDIUM. Requires a network position between the client and the App Service — not itself remotely
exploitable, but the same severity class as the analogous Terraform Azure Storage HTTPS-enforcement
guard (`azure-storage-account-https-only`), which this guard mirrors for the App Service case.

## What counts as a hit (and what doesn't)

- `Microsoft.Web/sites` with `httpsOnly: false` (explicit) → fires.
- `Microsoft.Web/sites` with no `httpsOnly` property at all → fires (ARM's own default for
  `httpsOnly` is `false` — matches the Terraform sibling's posture on its own analogous property).
- `Microsoft.Web/sites` with `httpsOnly: true` → silent (the fix).
- Fires the same way regardless of the resource's `kind` value (`app`, `api`, `functionapp`, or
  `kind` absent) — the guard never inspects `kind`.
- **`Microsoft.Web/sites/slots`** (a deployment-slot CHILD resource) and
  **`Microsoft.Web/sites/config`** (a configuration CHILD resource) → silent, always. These are
  DIFFERENT resource types that happen to share the `Microsoft.Web/sites` string prefix. The match
  is an EXACT equality check (`resource.resource_type == "Microsoft.Web/sites"`), never a
  substring/startswith check — a substring match would misfire on these child resources (which
  don't carry an `httpsOnly` property in the same shape as their parent site).
- Any other resource type, including one that happens to carry a similarly-named property →
  silent (the guard only ever looks inside a `Microsoft.Web/sites` resource's own `block`).

## When NOT to flag (and the pragma)

- `httpsOnly` explicitly `true` → silent (the fix).
- **No suppression pragma exists for this guard.** ARM templates are pure JSON, which has no
  comment syntax — a known, documented limitation shared by every guard built on `agentsec.arm`
  (see that module's docstring). There is no equivalent to the CFN/Terraform guards' YAML-only
  `# security: allow-...` pragma here.

## Tests

| Test | What it checks |
|---|---|
| `test_arm_appservice_https_only_flags_explicit_false` | `httpsOnly: false` fires `medium`. |
| `test_arm_appservice_https_only_flags_absent_property` | Property entirely absent also fires. |
| `test_arm_appservice_https_only_silent_when_true` | `httpsOnly: true` stays silent. |
| `test_arm_appservice_https_only_fires_regardless_of_kind` | All three `kind` variants (Web/API/Function App) fire. |
| `test_arm_appservice_https_only_silent_on_config_child_resource` | FP bait: a top-level `Microsoft.Web/sites/config` shares the prefix but is a different type. |
| `test_arm_appservice_https_only_silent_on_slots_child_resource` | FP bait: likewise `Microsoft.Web/sites/slots`. |
| `test_arm_appservice_https_only_silent_on_unrelated_resource_type` | FP bait: an unrelated type carrying a similarly-named property. |
| `test_arm_appservice_https_only_counts_a_nested_site_child_once` | FP bait: a site's inline `config`/`slots` children resolve to `Microsoft.Web/sites/config` and `/slots`, which must not match this guard's exact `Microsoft.Web/sites` type. |
| `test_arm_appservice_https_only_not_applicable_without_arm` | `applies()` is `False` without the `arm` feature. |

## Known bypasses (honest limits)

- **No dataflow, no cross-resource reasoning.** Fires on the property's value directly.
- **File-level location, not line-level** — like every guard built on `agentsec.arm`, the finding
  reports the template file, not a specific line (a `block` is a `json.dumps` reconstruction with
  no original line mapping to report).
- **Template expressions are not evaluated.** If `httpsOnly` were set via
  `"[parameters('enforceHttps')]"` rather than a literal `true`/`false`, this guard would not
  recognize it either way (it looks for the literal JSON value `true`) — see `agentsec.arm`'s
  module docstring for the same posture on resource `name`.
- **Nested/linked templates** (`Microsoft.Resources/deployments` referencing a separate template
  file or URI) are not followed — each template file is scanned independently.

## What this guard does NOT prove

A clean scan means no `Microsoft.Web/sites` resource in the scanned templates has `httpsOnly` set
to anything other than `true` — it says nothing about a site created outside this template
entirely (the Azure Portal, a different IaC tool, a linked template this scan didn't independently
discover), nor about the site's actual runtime HTTPS-only setting if it was changed out-of-band
after deployment.

## Canary plant

`arm_appservice.json` — a `Microsoft.Web/sites` resource with no `httpsOnly` property (the
absent-property case, itself ARM's default-false posture). Expected rule:
`arm-appservice-https-only-disabled/missing-or-disabled`.

# Citations

[1] agentsec checklist item `6a-arm-appservice-https-only-disabled` (§6a)
[2] OWASP:A02 (Cryptographic Failures)
[3] CWE-319 (Cleartext Transmission of Sensitive Information)
[4] Azure/template-analyzer — `AppServiceWebApp.OnlyHTTPS` (`TA-000016`, provenance only; the
    source catalog carries three near-identical rules for the Web/API/Function App `kind`
    variants, which this one guard covers via a shared resource-type match; detection logic here
    is original)
