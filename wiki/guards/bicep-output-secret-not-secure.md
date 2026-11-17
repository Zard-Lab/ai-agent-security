---
type: Guard
title: "bicep-output-secret-not-secure"
description: "Bicep output has a secret-shaped name but no @secure() decorator."
timestamp: "2026-09-12T00:00:00Z"
guard_id: "bicep-output-secret-not-secure"
checklist_section: ["6c"]
standards: ["OWASP:A02", "CWE-532"]
---

# Bicep output has a secret-shaped name but no @secure() decorator

Flags any Bicep `output` declaration whose NAME looks like it holds a secret (case-insensitive
match on `password`, `pwd`, `secret`, `accountkey`, `acctkey`, `connectionstring`, `token`,
`apikey`) that is declared without a `@secure()` decorator on the output itself. Sibling of
`bicep-secure-parameter-default` in the same batch — sourced from Bicep's own
compiler-embedded linter, `OutputsShouldNotContainSecretsRule.cs`
(`outputs-should-not-contain-secrets`), verified against the real fetched source.

## The threat

A Bicep `output` value is **always** recorded in the deployment's resource-manager activity log /
deployment history in **plaintext** once the template runs. This is true regardless of how the
value was computed — a literal, a parameter reference, or (a very common real-world pattern for
exactly this class of name) a `list*()` function-call result, e.g.
`listKeys(storageAccount.id, '2021-09-01').keys[0].value`, the standard way to surface a storage
account key as an output for a follow-up script to consume. `@secure()` on the OUTPUT itself is
Bicep's only mechanism to suppress that plaintext history entry. CWE-532 (Insertion of Sensitive
Information into Log File) is exactly this class of exposure — the deployment history is a log.

This is a genuinely different, and arguably worse, threat than the sibling params guard
(`bicep-secure-parameter-default`): an unsecured parameter default is a *possible* exposure route
(it depends on how the parameter is subsequently used); an unsecured secret-shaped output is a
**near-certain** one — the value lands in plaintext history the moment the template deploys,
independent of everything else in the template.

## Exploitability rationale

HIGH. Structurally, this is not a possibility to reason about — it is a near-certainty. Anyone with
read access to the deployment's activity log / deployment history (a broader audience than
"anyone with access to the running resource") gets the plaintext value the first time the template
deploys.

## What counts as a hit (and what doesn't)

- `output adminPassword string = '...'` (name matches, no `@secure()`) → fires, regardless of what
  the RHS `value` expression is.
- `output storageAccountKey string = listKeys(storageAccount.id, '2021-09-01').keys[0].value` (name
  matches, no `@secure()`, value is a function call rather than a literal) → **still fires** — this
  guard does not reason about the value expression's shape at all, only the name + decorator
  combination. This is the key distinction from `bicep-secure-parameter-default`, and the whole
  reason this guard's logic is simpler.
- `@secure()` immediately above the output declaration → silent, regardless of name.
- An output name that doesn't match any of the 8 terms (e.g. `storageAccountName`) → silent,
  regardless of value.

## When NOT to flag (and the pragma)

- `@secure()` present → silent (the fix).
- **No suppression pragma.** This guard scans `output` declarations via `agentsec.bicep`, which
  does not currently thread a pragma-check through output extraction. A genuinely intentional
  unsecured secret-shaped output (rare) has no documented opt-out today — a known limitation to
  revisit if it proves disruptive in practice.

## Known bypasses (honest limits)

- **Name heuristic only.** A secret-holding output named something that doesn't match any of the 8
  terms (e.g. `dbCreds`, `vaultUri`) is not flagged. Conversely, a genuinely non-secret output whose
  name happens to contain one of the terms (e.g. `tokenExpiryDate`) is flagged — a deliberate
  false-positive tradeoff mirroring the upstream Bicep linter's own name list.
- **Decorators are recognized on the line(s) immediately above the `output` declaration**
  (see `agentsec.bicep` module docstring), skipping blank lines and `//` line comments — a `@secure()`
  separated from its output by a `//` doc comment, or carrying a `//` comment trailing on its own line,
  IS associated (the guard stays silent). A `/* ... */` **block** comment between them still severs the
  association.
- **Triple-quoted multi-line strings are not brace/quote-aware** in `agentsec.bicep`'s scanner —
  see that module's docstring for the full disclosure (not expected to affect output-line matching
  itself, since `output` lines are single-line by regex construction).

## What this guard does NOT prove

A clean scan means no scanned `.bicep` file declares a secret-shaped output without `@secure()` —
it says nothing about an output declared in a linked/nested template this scan didn't independently
discover, and it does not evaluate whether the output's value is *actually* sensitive (the name
heuristic is a proxy, same as the upstream linter it's sourced from).

## Canary plant

`bicep_output_secret.bicep` — `output storageAccountKey string = 'not-a-real-key-but-looks-like-one'`
with no `@secure()`. Expected rule: `bicep-output-secret-not-secure/unsecured-secret-output`.

# Citations

[1] OWASP:A02 (Cryptographic Failures)
[2] CWE-532 (Insertion of Sensitive Information into Log File)
[3] Azure/bicep — `OutputsShouldNotContainSecretsRule.cs` (`outputs-should-not-contain-secrets`,
    provenance only; detection logic here is original)
