---
type: Guard
title: "k8s-privileged-capabilities"
description: "Kubernetes container adds a dangerous Linux capability."
timestamp: "2026-07-13T14:07:39+08:00"
guard_id: "k8s-privileged-capabilities"
checklist_section: ["6c"]
standards: ["CIS:Kubernetes", "OWASP:A05"]
---

# Kubernetes container adds a dangerous Linux capability

_Author — 2026-07-13_

---

## The threat

`securityContext.capabilities.add` granting `SYS_ADMIN` hands the container a Linux capability the
kernel documentation itself describes as "a huge hammer" — it covers mount/unmount, ptrace-adjacent
syscalls, kernel keyring operations, and dozens of other operations that are individually
security-sensitive. `ALL` grants every capability at once, equivalent to running as root with no
capability restriction whatsoever. Either turns a container compromise (prompt-injected agent tool
execution, an app-level RCE) into a straightforward host escape. Standards: `OWASP:A05`,
`CIS:Kubernetes`.

## Why this guard fits the stack

Sourced from kubesec's `CapSysAdmin` rule (`pkg/rules/capSysAdmin.go`), verified against the real
Go source; the `ALL` case applies the same detection shape to the keyword kubesec's own
`CapDropAll`/`CapDropAny` rules recognize on the `drop` side of the same field.

## Detection design

1. `applies()` gates on `"k8s" in profile.features`.
2. Scans `.yaml`/`.yml` files, matches Pod-shaped documents via `k8s_manifest_documents()`.
3. Within a matched document (hash-comments stripped), `_added_dangerous_caps()` looks for
   `SYS_ADMIN`/`ALL` either inline on an `add:` key line (`add: ["SYS_ADMIN"]`) or as a `- NAME`
   list-item line immediately following an `add:` block opener (`add:` with nothing after it).
4. Inline opt-out: `# security: allow-k8s-privileged-capabilities` anywhere in the document.
5. Severity: `critical` for both. Rules: `k8s-privileged-capabilities/sys-admin-added`,
   `.../all-capabilities-added`. Standards: `["OWASP:A05", "CIS:Kubernetes"]`.

**Deliberately excluded from this guard's scope:** kubesec's own `CapDropAll`/`CapDropAny` rules
also SCORE a manifest down for NOT setting `capabilities.drop: [ALL]` — this guard does not port
that side. Most real manifests simply omit the `capabilities` block entirely (the ordinary,
unremarkable case), and requiring an explicit `drop: [ALL]` on every manifest as a hard finding
would be a "must configure this every time" precision that generates significant noise relative to
the value it adds. This guard only fires on the unambiguous case — a capability explicitly ADDED.

## When NOT to flag

A `capabilities.add` list containing only a narrow, specific capability (e.g. `NET_BIND_SERVICE`
to bind a privileged port), paired or not with `drop: [ALL]`, must stay silent — only `SYS_ADMIN`/
`ALL` fire. A manifest with no `capabilities` block at all must also stay silent.

## Tests

| Test | What it checks |
|---|---|
| `test_k8s_privileged_capabilities_fires_sys_admin` | `add: [SYS_ADMIN]` (block-list form) fires critical |
| `test_k8s_privileged_capabilities_fires_all` | `add: ["ALL"]` (inline form) fires the other rule |
| `test_k8s_privileged_capabilities_passes_narrow_capability` | `NET_BIND_SERVICE` + `drop: [ALL]` stays silent |
| `test_k8s_privileged_capabilities_passes_no_capabilities_block` | no `capabilities` block at all stays silent |
| `test_k8s_privileged_capabilities_pragma_opt_out` | the inline pragma suppresses |
| `test_k8s_privileged_capabilities_not_applicable_without_k8s_feature` | `applies()` gates correctly |

## Known bypasses

The block-list detection (`_added_dangerous_caps`) tracks "inside an `add:` block" via simple
dedent detection rather than a real indentation tree — an unusually formatted YAML list (e.g. a
flow-style `add: [SYS_ADMIN]` mixed with other keys on oddly indented lines) could in principle
confuse the block-tracking state, though the inline-list case (`add: [...]`) is matched directly on
the `add:` line itself regardless, covering the common flow-style shape independently.

## What this guard does NOT prove

Does not flag a manifest missing `capabilities.drop: [ALL]` — see the deliberate scope note above.
A workload that needs zero elevated capabilities but never explicitly drops them is silent here;
that gap is intentionally left for future work (kubesec's own `CapDropAll`/`CapDropAny` rules, not
ported) rather than accepted as noise now.

# Citations

[1] agentsec checklist item `6c-k8s-privileged-capabilities` (§6c)
[2] CIS:Kubernetes
[3] OWASP:A05
