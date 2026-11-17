---
type: Guard
title: "k8s-unmasked-proc-mount"
description: "Kubernetes container disables the default masked /proc mount."
timestamp: "2026-09-05T00:30:00Z"
guard_id: "k8s-unmasked-proc-mount"
checklist_section: ["6c"]
standards: ["OWASP:A05", "CIS:Kubernetes"]
---

# Kubernetes container disables the default masked /proc mount

_Author — 2026-09-05_

---

## The threat

`securityContext.procMount: Unmasked` disables Kubernetes' default masking of `/proc` paths inside a
container. The default (`Default`) hides a set of `/proc` entries known to leak host/kernel
information or offer a probing surface for kernel internals from inside a container — the same
protection Docker's default `MaskedPaths`/`ReadonlyPaths` provide at the container-runtime level.
Setting `Unmasked` opts a container back into the pre-masking behavior, widening what a compromised
container process can read or attempt to manipulate via `/proc`. Standards: `OWASP:A05`,
`CIS:Kubernetes`.

## Why this guard fits the stack

Sourced from kube-linter's `UnsafeProcMount` template (`pkg/templates/unsafeprocmount/template.go`),
verified against the real Go source — a direct field-equality check on `securityContext.procMount`.
`procMount: Unmasked` is a narrow, rarely-needed field (legitimate uses are largely limited to
certain container-runtime tooling or deep debugging workflows) that is easy to leave in a manifest
copied from a troubleshooting session, the same "debug setting left on in production" pattern behind
several of this codebase's other K8s guards (`k8s-privileged-container`,
`k8s-seccomp-apparmor-unconfined`).

## Detection design

1. `applies()` gates on `"k8s" in profile.features`.
2. Scans `.yaml`/`.yml` files, matches Pod-shaped documents via `k8s_manifest_documents()` — the
   same recognizer `k8s-docker-sock-mount`/`k8s-privileged-capabilities` use.
3. Within a matched document (hash-comments stripped), checks for a `procMount:` value line equal
   to `Unmasked` (optionally quoted — routine Helm/Kustomize/yamllint output emits quoted enum
   values, the same lesson `agentsec/k8s.py`'s `kind:` matching already applies).
4. Inline opt-out: `# security: allow-k8s-unmasked-proc-mount` anywhere in the document.
5. Severity: `critical`. Rule: `k8s-unmasked-proc-mount/proc-mount-unmasked`. Standards:
   `["OWASP:A05", "CIS:Kubernetes"]`.

Like the other `k8s-*` guards, this guard does not consult `is_nonproduct_path()` — see the family
convention noted on `k8s-rbac-cluster-admin-binding`'s design doc.

## When NOT to flag

`procMount` left unset (the Kubernetes default) or explicitly set to `Default` must stay silent —
only the literal `Unmasked` value fires.

## Tests

| Test | What it checks |
|---|---|
| `test_k8s_unmasked_proc_mount_fires` | `procMount: Unmasked` fires critical |
| `test_k8s_unmasked_proc_mount_fires_quoted_value` | a quoted `"Unmasked"` value also fires |
| `test_k8s_unmasked_proc_mount_passes_default` | `procMount: Default` stays silent |
| `test_k8s_unmasked_proc_mount_passes_no_proc_mount_set` | no `procMount` field at all stays silent |
| `test_k8s_unmasked_proc_mount_pragma_opt_out` | the inline pragma suppresses |
| `test_k8s_unmasked_proc_mount_not_applicable_without_k8s_feature` | `applies()` gates correctly |

## Known bypasses

A `procMount` value built from a templated/parameterized Helm value that renders to `Unmasked` at
apply time (but not in the checked-in source) is invisible to this literal-text match.

## What this guard does NOT prove

A `procMount:` line match without full indentation-tree parsing means this guard trusts that a
`procMount:` value equal to `Unmasked` is genuinely nested under a container's `securityContext:`
key (true in every real Kubernetes container spec shape — `procMount` is not a generic YAML key used
elsewhere in a Pod spec), but it does not verify which container in a multi-container Pod carries
the setting, nor does it evaluate whether the surrounding workload has other compensating
hardening (e.g. a restrictive seccomp profile) that might partially offset the exposure.

# Citations

[1] agentsec checklist item `6c-k8s-unmasked-proc-mount` (§6c)
[2] OWASP:A05
[3] CIS:Kubernetes
[4] kube-linter `UnsafeProcMount` template — `pkg/templates/unsafeprocmount/template.go`
