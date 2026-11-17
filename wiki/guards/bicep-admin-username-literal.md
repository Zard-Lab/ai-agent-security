---
type: Guard
title: "bicep-admin-username-literal"
description: "Bicep resource adminUsername set to a hardcoded string literal instead of a parameter reference."
timestamp: "2026-09-12T00:00:00Z"
guard_id: "bicep-admin-username-literal"
checklist_section: ["6c"]
standards: ["OWASP:A07"]
---

# Bicep resource adminUsername is a hardcoded string literal, not a parameter reference

Flags any Bicep `resource` block whose `adminUsername` property is set to a quoted string literal
rather than a parameter/variable reference. Closes a new checklist item — conceptually parallel to
the existing Terraform `terraform-hardcoded-secret-literal` guard, but for Bicep's own syntax-level
distinction between a literal and a reference. This is agentsec's first Bicep-format guard
 — Bicep detection and the shared `agentsec.bicep` resource/param/output parser landed in
this same PR to support it.

## The threat

A hardcoded `adminUsername` means every VM deployed from the template shares the same, predictable
login name. This doesn't leak a secret by itself, but it narrows a brute-force or credential-
stuffing attacker's search space to just the password or key — they no longer need to guess the
username too. CWE-798 (Use of Hard-coded Credentials, the family this belongs to even though a
username alone is not itself a secret).

## Exploitability rationale

MEDIUM. Not an exploit primitive on its own — it reduces the cost of a *separate* attack (password
guessing / credential stuffing) rather than causing a compromise directly.

## What counts as a hit (and what doesn't)

- `adminUsername: 'admin'` (any quoted string) → fires.
- `adminUsername: adminUsernameParam` (a bare identifier — a parameter or variable reference; Bicep
  references are never quoted) → silent.
- `adminUsername: vmConfig.adminUsername` (a property-access expression on a reference) → silent.
- A resource with no `adminUsername` property at all, or an unrelated resource type → silent.

## When NOT to flag (and the pragma)

- Any non-literal (reference or expression) value → silent (the fix).
- **No suppression pragma.** This guard scans `resource` blocks via `agentsec.bicep`, which does
  not currently thread a pragma-check through resource extraction (unlike some Terraform guards).
  A genuinely intentional hardcoded value (rare, but possible in a fixed test/demo template) has no
  documented opt-out today — a known limitation to revisit if it proves disruptive in practice.

## Known bypasses (honest limits)

- **No dataflow.** A reference like `adminUsername: adminUsernameParam` is trusted at face value —
  if that parameter itself has a hardcoded default, THIS guard stays silent (the sibling guard
  `bicep-secure-parameter-default`, if it exists in this same batch, covers that case
  instead — a deliberate division of concerns, not a gap).
- **Resource-block location only** — the finding reports the resource's opening line, not the
  exact nested line the `adminUsername` property sits on.
- **Triple-quoted multi-line strings are not brace/quote-aware** in `agentsec.bicep`'s block
  scanner — see that module's docstring for the full disclosure.

## What this guard does NOT prove

A clean scan means no scanned `.bicep` file's resource sets `adminUsername` to a literal — it says
nothing about a resource declared in a linked/nested template this scan didn't independently
discover, nor about a parameter reference whose own default value is itself hardcoded (a different,
sibling guard's concern).

## Canary plant

`bicep_vm.bicep` — a `Microsoft.Compute/virtualMachines` resource with `adminUsername: 'admin'`.
Expected rule: `bicep-admin-username-literal/hardcoded-literal`.

# Citations

[1] OWASP:A07 (Identification and Authentication Failures)
[2] CWE-798 (Use of Hard-coded Credentials)
[3] Azure/bicep — `AdminUsernameShouldNotBeLiteralRule.cs` (`adminusername-should-not-be-literal`,
    provenance only; detection logic here is original)
