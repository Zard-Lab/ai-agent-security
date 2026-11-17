---
type: Guard
title: "bicep-param-file-insecure-secret-value"
description: "Bicep .bicepparam file assigns a secret-shaped parameter a hardcoded literal value instead of sourcing it from an environment variable or a Key Vault reference."
timestamp: "2026-09-12T00:00:00Z"
guard_id: "bicep-param-file-insecure-secret-value"
checklist_section: ["6c"]
standards: ["OWASP:A02", "CWE-798"]
---

# Bicep .bicepparam file assigns a secret-shaped parameter a hardcoded literal value

Flags a `.bicepparam` file's `param <name> = <value>` assignment when the NAME looks
secret-shaped (case-insensitive `password`/`pwd`/`secret`/`accountkey`/`acctkey`) and the value
is a hardcoded string literal rather than one of the two known secure-sourcing mechanisms
(`readEnvironmentVariable(...)` or a Key Vault-style `getSecret`/`keyVault` call). 7/7
in the same Bicep batch as `bicep-admin-username-literal`. This is the last, and explicitly the
most limited, guard in the batch — see "What this guard does NOT prove" below before relying on it.

## The threat

Sourced from Bicep's own compiler-embedded linter, `SecureParamsInParametersFileRule.cs`
(`secure-params-in-parameters-file`). The real rule checks whether a `.bicepparam` file's
`using '<target>.bicep'` template declared the referenced parameter `@secure()`, and if so,
flags the `.bicepparam` file for supplying that parameter's value as a plaintext literal — a
secret assigned this way lands in the `.bicepparam` file's own source (and likely its git
history), defeating the point of marking the parameter `@secure()` in the first place.
CWE-798 (Use of Hard-coded Credentials), OWASP:A02 (Cryptographic Failures / secrets-at-rest).

## Why this guard fits the stack

A `.bicepparam` file is a companion file to a `.bicep` template: `using 'main.bicep'` at the top,
then `param <name> = <value>` assignments with no type annotation (the type comes from the
target template). Because it carries the actual VALUES that get deployed, a hardcoded secret
here is materially worse than one merely referenced in the template — it's the literal secret,
committed.

```
using 'main.bicep'

param dbPassword = 'hardcoded-value-in-the-params-file'   // <- fires
param environmentName = readEnvironmentVariable('ENV_NAME')  // <- silent, env-sourced
param apiKey = az.getSecret('mySubscription', 'myRG', 'myVault', 'apiKeySecretName')  // <- silent, vault-sourced
```

## Detection design

1. `applies()` — `"bicep" in profile.features` (the same feature flag as the rest of the batch;
   `detect.py` now also gates `bicep` on a `.bicepparam` suffix alone, so a repo with only
   `.bicepparam` files still gets scanned).
2. Files scanned: every `.bicepparam` file (`iter_files(root, (".bicepparam",))`) — a distinct
   suffix from `.bicep`, and a distinct sub-syntax parsed by the new
   `agentsec.bicep.bicepparam_assignments()`.
3. Pattern: for each `param <name> = <value>` assignment, the NAME is matched case-insensitively
   against `(password|pwd|secret|accountkey|acctkey)`. If it matches, the raw VALUE text is
   checked: a leading `'` marks a literal (fires, unless the value also matches the secure-source
   pattern below — a defensive belt-and-braces check, since a literal-looking value never starts
   with a function call); a value matching `readEnvironmentVariable\(` or `\w*[Gg]et[Ss]ecret\w*\(`
   (lenient about Azure's exact `az.getSecret(...)` surface) is treated as securely sourced and
   stays silent.
4. No suppression pragma — see "When NOT to flag" below.
5. Severity: `medium` (rule `bicep-param-file-insecure-secret-value/local-literal`, standards
   `["OWASP:A02", "CWE-798"]`) — deliberately LOWER than the sibling literal-value guards in this
   batch, because this one is a name-only heuristic with no cross-file confirmation that the
   target template actually declared the parameter `@secure()`; it is a weaker signal by design.

## When NOT to flag

- `readEnvironmentVariable(...)` or a `getSecret`/`keyVault`-style call → silent (the two
  recognized secure-sourcing mechanisms).
- A value that isn't a bare `'...'` literal at all — a reference to another param, an expression,
  a function call this guard doesn't recognize — → silent (conservative: only a clear literal
  fires).
- A param name that doesn't match the secret-shaped heuristic, even with a literal value → silent
  (out of scope by design, exactly like the sibling `bicep-secret-param-not-secure` guard's name
  heuristic).
- No suppression pragma today — a known limitation, consistent with the rest of this batch.

## Tests

| Test | What it checks |
|---|---|
| `test_bicep_param_file_flags_secret_name_with_literal_value` | secret-shaped name + literal value fires |
| `test_bicep_param_file_silent_on_environment_variable_source` | `readEnvironmentVariable(...)` stays silent |
| `test_bicep_param_file_silent_on_keyvault_secret_source` | `az.getSecret(...)` stays silent |
| `test_bicep_param_file_silent_on_non_secret_shaped_name` | non-secret-shaped name + literal stays silent |
| `test_bicep_param_file_not_applicable_without_bicep` | `applies()` is `False` without the `bicep` feature |

## Known bypasses (honest limits)

- **Name heuristic only** — a secret-shaped value assigned to a param name that doesn't match
  the list (e.g. `dbCreds`, `authToken`) is invisible to this guard.
- **No dataflow** — a literal wrapped in a local variable or an indirection this guard doesn't
  parse (Bicep's `.bicepparam` syntax is narrow, but not exhaustively modeled) could evade the
  literal check.
- **Lenient function-name matching** (`\w*[Gg]et[Ss]ecret\w*\(`) trusts any call whose name
  contains `getSecret` as securely sourced, even a locally-defined helper that just returns a
  hardcoded string — a name-based trust, not a proof the call is actually safe.

## What this guard does NOT prove

**This is the most important limitation in this guard, and the whole reason it exists as a
reduced check.** The real Bicep-compiler rule this is sourced from (`secure-params-in-parameters-
file`) does CROSS-FILE resolution: it opens the `.bicep` template named in this file's `using`
directive and checks whether THAT template actually declared the referenced parameter
`@secure()`. agentsec is a dependency-free, per-file static scanner — it does not resolve
`using` targets or cross-reference `@secure()` decorators across files. This guard therefore
implements only the LOCAL-FILE half the research doc scoped it to: a name-shaped heuristic on
the `.bicepparam` file alone.

Concretely: a clean scan from this guard does NOT prove that every secret this template needs is
sourced securely. A parameter named something that doesn't match the heuristic (`dbCreds`,
`connString`) can carry a hardcoded secret and this guard will never see it. Conversely, a fired
finding does NOT prove the target template declared the parameter `@secure()` at all — the name
heuristic fires the same way whether or not the target template cares about this parameter being
secure. Full confirmation of either direction requires the cross-file resolution this guard
explicitly does not attempt.

## Canary plant

`bicep_param_file.bicepparam` — `using 'main.bicep'` + `param dbPassword = 'hardcoded'`.
Expected rule: `bicep-param-file-insecure-secret-value/local-literal`.

# Citations

[1] agentsec checklist item `6c-bicep-param-file-insecure-secret-value` (§6c)
[2] OWASP:A02 (Cryptographic Failures)
[3] CWE-798 (Use of Hard-coded Credentials)
[4] Azure/bicep — `SecureParamsInParametersFileRule.cs` (`secure-params-in-parameters-file`,
    provenance only; detection logic here is original and deliberately reduced to local-file
    scope, per the research doc that queued this guard)
