---
type: Guard
title: "k8s-seccomp-apparmor-unconfined"
description: "Kubernetes workload opts out of seccomp/AppArmor confinement."
timestamp: "2026-07-13T16:30:09+08:00"
guard_id: "k8s-seccomp-apparmor-unconfined"
checklist_section: ["6c"]
standards: ["CIS:Kubernetes", "OWASP:A05"]
---

# Kubernetes workload opts out of seccomp/AppArmor confinement

_Author — 2026-07-13_

---

## The threat

`seccompProfile.type: Unconfined` and `appArmorProfile.type: Unconfined` each explicitly disable a
kernel-level syscall/capability confinement layer that's on by default in modern Kubernetes
(`RuntimeDefault` is the safe default seccomp profile since v1.27). Removing it widens the blast
radius of a compromised container (prompt-injected agent tool execution, a supply-chain-compromised
base image, an app-level RCE) — the same class of risk `k8s-privileged-container` and
`k8s-privileged-capabilities` address, from the syscall-filtering angle instead of the
capability/mode angle. Standards: `OWASP:A05`, `CIS:Kubernetes`.

## Why this guard fits the stack

Sourced from kubesec's `SeccompUnconfined`/`ApparmorUnconfined` rules (`pkg/rules/seccompUnconfined.go`,
`pkg/rules/apparmorUnconfined.go`), verified against the real Go source — both check for the exact
literal string `"Unconfined"`, not "any non-default value" (a named custom profile is not flagged).
Combined into one guard (two sub-rules) since both check the identical shape (`<field>.type:
Unconfined`) against a sibling security-profile field.

## Detection design

1. `applies()` gates on `"k8s" in profile.features`.
2. Scans `.yaml`/`.yml` files, matches Pod-shaped documents via `k8s_manifest_documents()`.
3. Within a matched document (hash-comments stripped), for each of `seccompProfile`/`appArmorProfile`:
   finds a `<field>:` block-opener line, then scans the immediately following indented block for a
   `type: Unconfined` line (indentation-bounded — a dedent past the block-opener's own indent stops
   the scan, so an unrelated later `type: Unconfined` elsewhere in the document doesn't false-match).
4. Inline opt-out: `# security: allow-k8s-seccomp-apparmor-unconfined` anywhere in the document.
5. Severity: `high` for both. Rules: `k8s-seccomp-apparmor-unconfined/seccomp-unconfined`,
   `.../apparmor-unconfined`. Standards: `["OWASP:A05", "CIS:Kubernetes"]`.

## When NOT to flag

`type: RuntimeDefault`, a named custom profile (`type: Localhost` with a `localhostProfile` path, or
any other non-`Unconfined` string), or the field simply absent must all stay silent — only the
literal `Unconfined` value fires.

## Tests

| Test | What it checks |
|---|---|
| `test_k8s_seccomp_apparmor_unconfined_fires_seccomp` | `seccompProfile.type: Unconfined` alone fires 1 finding |
| `test_k8s_seccomp_apparmor_unconfined_fires_both` | both fields `Unconfined` fires both rules |
| `test_k8s_seccomp_apparmor_unconfined_passes_runtime_default` | `RuntimeDefault` stays silent |
| `test_k8s_seccomp_apparmor_unconfined_passes_named_profile` | a custom named profile stays silent |
| `test_k8s_seccomp_apparmor_unconfined_pragma_opt_out` | the inline pragma suppresses |
| `test_k8s_seccomp_apparmor_unconfined_not_applicable_without_k8s_feature` | `applies()` gates correctly |

## Known bypasses

The block-tracking indentation scan (no real indentation tree) could in principle be confused by an
unusually formatted YAML block mixing flow-style and block-style on adjacent lines — the common
block-style shape kubesec itself expects is handled correctly.

## What this guard does NOT prove

Does not verify a `RuntimeDefault`/named profile is ACTUALLY effective at runtime (a node without
the profile installed would silently fail open in some container runtimes) — only that the
manifest doesn't explicitly request `Unconfined`.

# Citations

[1] agentsec checklist item `6c-k8s-seccomp-apparmor-unconfined` (§6c)
[2] CIS:Kubernetes
[3] OWASP:A05
