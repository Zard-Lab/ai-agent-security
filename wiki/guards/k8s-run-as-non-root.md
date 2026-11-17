---
type: Guard
title: "k8s-run-as-non-root"
description: "Kubernetes workload doesn't require running as non-root."
timestamp: "2026-07-13T16:30:08+08:00"
guard_id: "k8s-run-as-non-root"
checklist_section: ["6c"]
standards: ["CIS:Docker", "OWASP:A05"]
---

# Kubernetes workload doesn't require running as non-root

_Author — 2026-07-13_

---

## The threat

A container that isn't forced to run as non-root at the cluster level runs as whatever user its
image defaults to — root, if the image was built without a `USER` directive, or if a later base-
image change silently regresses to root. A compromised process (prompt-injected agent tool
execution, an app-level RCE) then gets full root privileges inside the container. Standards:
`OWASP:A05`, `CIS:Kubernetes`.

## Why this guard fits the stack

This is the Kubernetes-manifest-level sibling of the EXISTING `6c-nonroot-container-user` checklist
item — `hadolint` already checks this control at the Dockerfile `USER` level; a repo that ships only
K8s manifests, or whose image build hadolint can't see (a private base image, a multi-stage build
hadolint doesn't fully trace), was invisible to that item until now. Sourced from kubesec's
`RunAsNonRoot` rule (`pkg/rules/runAsNonRoot.go`), verified against the real Go source — unlike most
fields in the k8s-* guard family, kubesec checks this one at BOTH pod-spec and container level
(a container-level override always wins), so this guard checks for the field's presence ANYWHERE in
the document rather than at a fixed indentation depth.

**Deliberately excludes** kubesec's `RunAsUser`/`RunAsGroup` rules (a numeric UID/GID `> 10000`
threshold) — that specific cutoff is somewhat arbitrary and a real manifest commonly runs as UID
1000-9999 (an extremely conventional non-root range, e.g. `USER 1000` in countless base images),
which the `>10000` threshold would flag as a false positive. Porting a debatable numeric threshold
as a hard finding needs its own severity/threshold decision, not a silent copy — left as a follow-up.

## Detection design

1. `applies()` gates on `"k8s" in profile.features`.
2. Scans `.yaml`/`.yml` files, matches Pod-shaped documents via `k8s_manifest_documents()`.
3. Within a matched document (hash-comments stripped), fires when NO line matches
   `runAsNonRoot:\s*true\s*$` (case-insensitive) anywhere in the document — pod-spec or
   container-level, either satisfies the control.
4. Inline opt-out: `# security: allow-k8s-run-as-non-root` anywhere in the document.
5. Severity: `high`. Rule: `k8s-run-as-non-root/not-explicitly-enabled`.
   Standards: `["OWASP:A05", "CIS:Kubernetes"]`.

**Checklist mapping:** this guard's `check_id` was added to the EXISTING `6c-nonroot-container-user`
item's `check_ids` array (alongside `hadolint`), and `"k8s"` was added to that item's
`applies_when` — the same checklist gap, a second detection layer, not a new item.

## When NOT to flag

An explicit `runAsNonRoot: true` at EITHER the pod-spec level or any container's own
`securityContext` must stay silent — either location satisfies the control.

## Tests

| Test | What it checks |
|---|---|
| `test_k8s_run_as_non_root_fires_when_unset` | no field at all fires high |
| `test_k8s_run_as_non_root_fires_when_false` | explicit `false` also fires |
| `test_k8s_run_as_non_root_passes_at_pod_level` | pod-spec-level `true` stays silent |
| `test_k8s_run_as_non_root_passes_at_container_level` | container-level `true` stays silent |
| `test_k8s_run_as_non_root_pragma_opt_out` | the inline pragma suppresses |
| `test_k8s_run_as_non_root_not_applicable_without_k8s_feature` | `applies()` gates correctly |

## Known bypasses

Same as the rest of the k8s-* guard family: a templated value (Helm/Kustomize) resolved only at
deploy time is invisible to a static scan of the checked-in manifest.

## What this guard does NOT prove

Does not verify the ACTUAL numeric UID the container would run as (that's the deferred
`RunAsUser`/`RunAsGroup` scope) — only that SOME explicit non-root enforcement is declared
somewhere in the document. A manifest could set `runAsNonRoot: true` while still using a
low-but-nonzero UID a determined attacker could target for a different escalation path; that's
outside this guard's scope.

# Citations

[1] agentsec checklist item `6c-nonroot-container-user` (§6c)
[2] CIS:Docker
[3] OWASP:A05
