---
type: Guard
title: "bicep-commandtoexecute-plaintext-settings"
description: "Bicep VM CustomScript extension puts a secret-bearing commandToExecute under plaintext settings instead of protectedSettings."
timestamp: "2026-09-12T00:00:00Z"
guard_id: "bicep-commandtoexecute-plaintext-settings"
checklist_section: ["6c"]
standards: ["OWASP:A02", "CWE-522"]
---

# Bicep CustomScript commandToExecute carries a secret under plaintext settings, not protectedSettings

Flags a Bicep `Microsoft.Compute/virtualMachines/extensions` resource (the VM `CustomScriptExtension`,
or its Linux equivalent, the `Microsoft.Azure.Extensions`/`CustomScript` publisher+type pair) whose
`commandToExecute` property sits under the PLAINTEXT `settings` object instead of the encrypted
`protectedSettings` object, when the command string itself looks like it carries a secret. Part of
the same Bicep-SYNTAX guard batch as `bicep-admin-username-literal`, built on the shared
`agentsec.bicep` resource parser.

## The threat

`settings` on a VM extension resource is stored and returned in CLEARTEXT: `az vm extension show`,
the Azure Portal, and deployment history all expose it to anyone with read access to the VM
resource. `protectedSettings` is encrypted at rest and never returned by a read. A
`commandToExecute` that embeds a password, API token, or other secret (commonly via Bicep string
interpolation of a `@secure()` parameter, e.g. `'echo ${dbPassword} > /tmp/config'`) belongs in
`protectedSettings`. Putting it in `settings` instead is CWE-522 (Insufficiently Protected
Credentials) — a real, not hypothetical, exposure to anyone who can read the resource.

## Exploitability rationale

HIGH. No exploit chain is required — the secret is visible to any principal with read access to
the VM/extension resource (Reader RBAC is enough), via a standard, unauthenticated-relative-to-the-
secret-itself read path (`az vm extension show`, ARM export, deployment history, the Portal UI).

## What counts as a hit (and what doesn't)

- `resource_type` must be `Microsoft.Compute/virtualMachines/extensions`, **exact match** — this
  mirrors the exact-match discipline other ARM/CFN guards in this codebase use for resource-type
  gating (e.g. the `resource_type == "..."` comparisons in `aws_observability_hygiene.py` /
  `iam_policy_attached_to_user_directly.py`). A substring or prefix match would over-fire on
  unrelated `.../extensions/...` sub-resource types.
- Within the matched resource's block, every `commandToExecute:` occurrence is checked
  independently: for each one, whichever of `settings:` / `protectedSettings:` has its nearest
  PRIOR occurrence in the block text (found via `str.rfind()`, not a brace-scope parser) decides
  which object that command sits in. Nearest-preceding `settings:` → plaintext → candidate hit.
  Nearest-preceding `protectedSettings:` → safe → silent for that occurrence.
- The command value must also "look secret-bearing": lower-cased, it contains one of `password`,
  `secret`, `token`, `apikey`, or `-p ` (a common CLI secret-flag pattern). A Bicep
  `${paramName}`-style interpolation of a secret-shaped name (e.g. `${dbPassword}`) is caught by
  the SAME substring check for free, since the interpolated text is part of the value's literal
  source — no separate interpolation parsing is implemented.
- `commandToExecute: 'echo hello'` under `settings` → silent (no secret signal — the guard's core
  false-positive-avoidance mechanism; tested explicitly).
- Any other resource type → silent, regardless of its properties.

## When NOT to flag (and the pragma)

- A `commandToExecute` with no secret signal at all → silent (the common case: most
  `commandToExecute` values are ordinary install/config commands with nothing sensitive in them).
- The same secret-bearing command correctly placed under `protectedSettings` → silent (the fix).
- **No suppression pragma.** Like its sibling `bicep-admin-username-literal`, this guard scans
  `resource` blocks via `agentsec.bicep`, which does not thread a pragma-check through resource
  extraction. No documented opt-out today.

## Known bypasses (honest limits)

- **The nearest-preceding-keyword heuristic is text-based, not scope-based.** `str.rfind()` has no
  concept of brace nesting or string-literal boundaries. If the `commandToExecute` value (or any
  other string elsewhere in the block) happened to contain the literal substring `"settings:"` or
  `"protectedSettings:"` inside a quoted value — not as the actual property key — the "nearest"
  keyword could be misidentified and the classification could flip in either direction. Not
  expected in practice for a shell-command string, but not proven impossible; this is the most
  heuristic guard in the current Bicep batch and this limitation is disclosed deliberately rather
  than glossed over.
- **Case-sensitive by construction, not by explicit design choice.** The two keywords are
  distinguished only because `settings:` (lowercase `s`) is not a substring of `protectedSettings:`
  (`...edSettings:`, capital `S`) under Python's case-sensitive `str.rfind()`. Bicep source that
  breaks the conventional camelCase property-name casing (unusual, but not forbidden by the
  language) could desync this.
- **The secret-name term list is fixed and small** (`password`, `secret`, `token`, `apikey`,
  `-p `). A secret carried through a term outside this list (e.g. `credential`, `connstring`,
  `-pw`) is not detected. This is a deliberate precision/recall tradeoff, not an oversight — a
  broader term list trades false negatives here for false positives on the (much more common)
  non-secret `commandToExecute` case.
- **No dataflow.** A `${paramName}` reference is trusted at face value for whether its NAME looks
  secret-shaped; the guard does not resolve the parameter's own default value or whether it is
  actually `@secure()`-decorated.
- **Resource-block location only** — the finding reports the resource's opening line, not the
  exact nested line the `commandToExecute` property sits on.

## What this guard does NOT prove

A clean scan means no scanned `.bicep` file's `Microsoft.Compute/virtualMachines/extensions`
resource has a `commandToExecute` that both (a) the nearest-preceding-keyword heuristic classifies
as under plaintext `settings`, and (b) matches the fixed secret-term list. It says nothing about a
resource in a linked/nested template this scan didn't independently discover, a secret carried
through a term outside the fixed list, or a secret passed via a different extension property
entirely (e.g. a custom extension's own plaintext field).

## Canary plant

`bicep_cmdexec.bicep` — a `Microsoft.Compute/virtualMachines/extensions` resource with
`commandToExecute: 'echo ${dbPassword}'` under `settings` (not `protectedSettings`). Expected rule:
`bicep-commandtoexecute-plaintext-settings/secret-in-plaintext-settings`.

# Citations

[1] OWASP:A02 (Cryptographic Failures)
[2] CWE-522 (Insufficiently Protected Credentials)
[3] Azure/bicep — `UseProtectedSettingsForCommandToExecuteSecretsRule.cs`
    (`protect-commandtoexecute-secrets`, provenance only; detection logic here is original)
