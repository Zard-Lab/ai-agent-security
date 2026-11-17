---
type: Guard
title: "k8s-automount-serviceaccount-token"
description: "Kubernetes workload doesn't disable service-account token automount."
timestamp: "2026-07-13T14:07:39+08:00"
guard_id: "k8s-automount-serviceaccount-token"
checklist_section: ["6c"]
standards: ["CIS:Kubernetes", "OWASP:A01"]
---

# Kubernetes workload doesn't disable service-account token automount

_Author — 2026-07-13_

---

## The threat

Kubernetes automounts the pod's service-account token into every container
(`/var/run/secrets/kubernetes.io/serviceaccount/token`) unless a manifest explicitly opts out with
`automountServiceAccountToken: false`. Most application workloads never call the Kubernetes API at
all — for those, the mounted token is a live, exfiltratable cluster credential sitting in every
container for no functional reason. If the container is ever compromised (prompt-injected agent
tool execution, an app-level RCE), that token is immediately usable to call the cluster API as
whatever the pod's service account can do — a real escalation path, not a hypothetical one, and
one CIS/NSA Kubernetes hardening guidance both call out explicitly. Standards: `OWASP:A01`,
`CIS:Kubernetes`.

## Why this guard fits the stack

Sourced from kubesec's `AutomountServiceAccountToken` rule
(`pkg/rules/automountServiceAccountToken.go`), verified against the real Go source — its own
comment documents the exact default-mount behavior this guard checks for: "hostUsers: false...
Otherwise... the pod shares the host's user namespace" (referring to the sibling `HostUsers` rule)
and, for this field specifically, that an unset or `true` value leaves the token mounted.

## Detection design

1. `applies()` gates on `"k8s" in profile.features`.
2. Scans `.yaml`/`.yml` files, matches Pod-shaped documents via `k8s_manifest_documents()`.
3. Within a matched document (hash-comments stripped), checks whether ANY line matches
   `automountServiceAccountToken:\s*false\s*$` (case-insensitive). If none does — the field is
   either absent (the insecure Kubernetes default) or explicitly `true` — the guard fires.
4. Inline opt-out: `# security: allow-k8s-automount-serviceaccount-token` anywhere in the document.
5. Severity: `medium`. Rule: `k8s-automount-serviceaccount-token/not-explicitly-disabled`.
   Standards: `["OWASP:A01", "CIS:Kubernetes"]`.

## When NOT to flag

`automountServiceAccountToken: false` anywhere in the document (the explicit opt-out) must stay
silent. This is the one guard in the batch whose logic is "absence of a positive marker," not
"presence of a negative one" — mirrored deliberately from kubesec's own scoring direction (it
awards a point for the explicit `false`, not for absence of `true`).

## Tests

| Test | What it checks |
|---|---|
| `test_k8s_automount_serviceaccount_token_fires_when_unset` | no field at all fires medium |
| `test_k8s_automount_serviceaccount_token_fires_when_true` | explicit `true` also fires |
| `test_k8s_automount_serviceaccount_token_passes_when_explicitly_false` | the opt-out stays silent |
| `test_k8s_automount_serviceaccount_token_pragma_opt_out` | the inline pragma suppresses |
| `test_k8s_automount_serviceaccount_token_not_applicable_without_k8s_feature` | `applies()` gates correctly |

## Known bypasses

None specific beyond the batch's shared templating-value limitation — this guard's "absent = bad"
direction actually makes it harder to accidentally bypass than a "present = bad" guard (there's no
obfuscation available for an omission).

## What this guard does NOT prove

Document-scoped: a workload where a ServiceAccount object itself sets
`automountServiceAccountToken: false` at the ServiceAccount level (rather than the Pod spec
overriding it) is invisible to this guard unless the ServiceAccount manifest is in the same scanned
tree and happens to match — this guard checks the Pod-spec-level field only, the more common and
more directly effective place to set it, per kubesec's own scope.

# Citations

[1] agentsec checklist item `6c-k8s-automount-serviceaccount-token` (§6c)
[2] CIS:Kubernetes
[3] OWASP:A01
