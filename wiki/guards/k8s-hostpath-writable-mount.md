---
type: Guard
title: "k8s-hostpath-writable-mount"
description: "Kubernetes hostPath volume is mounted into a container without readOnly."
timestamp: "2026-09-05T00:40:00Z"
guard_id: "k8s-hostpath-writable-mount"
checklist_section: ["6c"]
standards: ["OWASP:A05", "CIS:Kubernetes"]
---

# Kubernetes hostPath volume is mounted into a container without readOnly

_Author — 2026-09-05_

---

## The threat

A `hostPath` volume gives a container direct access to a path on the NODE's filesystem, not an
isolated, container-scoped filesystem. Mounting it without `readOnly: true` means the container can
WRITE to that host path — a compromised container can plant a file the node (or another workload
scheduled onto the same node) will later read or execute, tamper with node-level state, or otherwise
break out of the container's filesystem isolation. Standards: `OWASP:A05`, `CIS:Kubernetes`.

## Why this guard fits the stack

Sourced from kube-linter's `WritableHostMount` template (`pkg/templates/writablehostmount/template.go`),
verified against the real Go source. This is the GENERAL case of a pattern this codebase already has
one NARROW instance of: `k8s-docker-sock-mount` flags a `hostPath` mount to the specific
`/var/run/docker.sock` path only. This guard is deliberately broader and complements that one rather
than duplicating it — any other writable host path (`/etc`, `/var/lib/app/data`, a shared node
directory) is entirely outside `k8s-docker-sock-mount`'s scope, and a mount to `/var/run/docker.sock`
itself legitimately trips BOTH guards at once: one names the specific docker-socket escalation, this
one flags the general writable-host-mount hygiene issue that docker.sock is also an instance of.

## Detection design

1. `applies()` gates on `"k8s" in profile.features`.
2. Scans `.yaml`/`.yml` files, matches Pod-shaped documents via `k8s_manifest_documents()` — the
   same recognizer `k8s-docker-sock-mount`/`k8s-privileged-capabilities` use.
3. Within a matched document (hash-comments stripped):
   - `_hostpath_volume_names()` walks `spec.volumes[]` and collects the `name` of every entry that
     carries a nested `hostPath:` key.
   - `_volume_mounts()` walks every `volumeMounts[]` block (one per container) and collects
     `(mount_name, is_read_only)` for each item.
   - A hostPath volume name is flagged if ANY of its mount occurrences across the document sets
     `readOnly` to anything other than `true` — deduplicated per volume name, so the same volume
     mounted safely in one container and unsafely in another still fires exactly once (a real
     writable exposure exists).
   - Both walks use the same document-scoped block-boundary heuristic every `k8s-*` guard in this
     module accepts (list items at the SAME indentation as their key end the block on dedent or a
     sibling key — no real indentation tree, no PyYAML). Deliberately does NOT fire for a hostPath
     volume that is defined but never referenced by any `volumeMounts[]` — a narrower, more precise
     contract than `k8s-docker-sock-mount`'s own deliberately conservative "fires even if unused"
     choice, made possible here because this guard already parses `volumeMounts[]` to check
     `readOnly` at all.
4. Inline opt-out: `# security: allow-k8s-hostpath-writable-mount` anywhere in the document.
5. Severity: `high`. Rule: `k8s-hostpath-writable-mount/<volume-name>-not-readonly` (one finding per
   unsafe hostPath volume name). Standards: `["OWASP:A05", "CIS:Kubernetes"]`.

Like the other `k8s-*` guards, this guard does not consult `is_nonproduct_path()` — see the family
convention noted on `k8s-rbac-cluster-admin-binding`'s design doc.

## When NOT to flag

A hostPath volume whose every mount sets `readOnly: true` must stay silent. A non-hostPath volume
(`emptyDir`, `configMap`, `secret`, a PVC) mounted without `readOnly` is completely ordinary and must
stay silent regardless — only a hostPath-backed volume is in scope. A hostPath volume defined but
never mounted anywhere must also stay silent (see "Detection design").

## Tests

| Test | What it checks |
|---|---|
| `test_k8s_hostpath_writable_mount_fires_without_readonly` | a hostPath volume mounted with no `readOnly` fires high |
| `test_k8s_hostpath_writable_mount_passes_with_readonly` | the same shape WITH `readOnly: true` stays silent |
| `test_k8s_hostpath_writable_mount_passes_non_hostpath_volume` | an `emptyDir` volume with no `readOnly` stays silent |
| `test_k8s_hostpath_writable_mount_passes_unmounted_hostpath_volume` | a defined-but-unmounted hostPath volume stays silent |
| `test_k8s_hostpath_writable_mount_co_fires_with_docker_sock_by_design` | a writable `/var/run/docker.sock` mount fires THIS guard too (non-duplication proof) |
| `test_k8s_hostpath_writable_mount_fires_on_one_of_two_containers` | one safe + one unsafe mount of the same volume still fires once |
| `test_k8s_hostpath_writable_mount_pragma_opt_out` | the inline pragma suppresses |
| `test_k8s_hostpath_writable_mount_not_applicable_without_k8s_feature` | `applies()` gates correctly |

## Known bypasses

A volume/mount name built from a templated/parameterized Helm value evades the name-correlation this
guard relies on if the rendered names in the checked-in source don't textually match (they always
will in a real manifest, but a sufficiently indirect template could break the correlation). A
`readOnly` value built the same way (renders to `true` only after templating) is invisible to this
literal-text match. An unusual multi-line YAML style for `volumes:`/`volumeMounts:` outside the
inline-list/simple-block-list shapes this guard's scanner recognizes could also be missed.

## What this guard does NOT prove

This guard proves a `hostPath` volume was mounted with write access via the K8s API shape alone — it
does not evaluate whether the specific host path chosen is sensitive (a scratch directory under
`/tmp/app-scratch` is architecturally the same shape as a mount of `/etc`, and both fire identically
here; a human reviewing the finding supplies that judgment). It also does not verify that a
`readOnly: true` mount is actually SAFE — a legitimate read path can still expose sensitive host
files, a separate concern this guard does not evaluate.

# Citations

[1] agentsec checklist item `6c-k8s-hostpath-writable-mount` (§6c)
[2] OWASP:A05
[3] CIS:Kubernetes
[4] kube-linter `WritableHostMount` template — `pkg/templates/writablehostmount/template.go`
