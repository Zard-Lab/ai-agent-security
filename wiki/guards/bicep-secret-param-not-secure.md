---
type: Guard
title: "bicep-secret-param-not-secure"
description: "Bicep param whose name looks like a secret is declared without @secure() or a secure type."
timestamp: "2026-09-12T00:00:00Z"
guard_id: "bicep-secret-param-not-secure"
checklist_section: ["6c"]
standards: ["OWASP:A02", "CWE-256"]
---

# Bicep param name looks like a secret but is not marked @secure()

Flags any Bicep `param` whose name matches a secret-name heuristic (`password`, `pwd`, `secret`,
`accountkey`, `acctkey`, case-insensitively, as a whole name or a camelCase substring/suffix) but is
declared without the `@secure()` decorator and without a legacy `securestring`/`secureobject` type.
Second guard in the Bicep batch, built on the same `agentsec.bicep` param parser landed
with `bicep-admin-username-literal`.

## The threat

A Bicep `param` marked `@secure()` gets Azure's secure-value handling: the value is redacted from
deployment history and the Portal's deployment operations blade. A plain `string`/`object` param
gets no such treatment — its value can appear in plaintext in logs, deployment history, and CI
output. CWE-256 (Plaintext Storage of a Password): the parameter isn't marked to get secure-value
handling, so a credential-shaped value risks persisting in plaintext outside the guard's control.

## Exploitability rationale

HIGH. Unlike the sibling `bicep-admin-username-literal` guard (which flags a non-secret username,
MEDIUM), this guard's target is an actual credential-shaped value (a password, API secret, or
storage account key) with zero secure handling — anyone with read access to deployment history or
CI logs gets the plaintext value directly, no separate attack required.

## What counts as a hit (and what doesn't)

- `param password string` (no `@secure()`, plain type) → fires.
- `param dbPassword string`, `param apiSecret string`, `param storageAccountKey string` (camelCase
  names containing one of the 5 terms) → fires.
- `@secure()` present immediately above the `param` → silent.
- `type_str` is `securestring` or `secureobject` (case-insensitive; Bicep's legacy ARM-JSON-era
  secure type aliases) → silent, even without `@secure()`.
- A param name that doesn't match any of the 5 terms (e.g. `location`, `environmentName`) → silent.

## When NOT to flag (and the pragma)

- Any param already `@secure()`-decorated, or typed `securestring`/`secureobject` → silent (the fix).
- **No suppression pragma.** Same limitation as `bicep-admin-username-literal`: `agentsec.bicep`'s
  param extraction does not currently thread a pragma-check through. No documented opt-out today.

## Secret-name heuristic (honest limitation)

The name match is a plain case-insensitive substring search against 5 fixed terms — `password`,
`pwd`, `secret`, `accountkey`, `acctkey` — via `re.compile(r"(?i)(password|pwd|secret|accountkey|
acctkey)")`, **not** a word-boundary or camelCase-segment-aware regex. This is a deliberate choice:
a stricter boundary-aware match would risk false NEGATIVES on real secret-shaped camelCase names
like `dbPassword`/`apiSecret`/`storageAccountKey`, since `\b` does not fire at a lowercase-to-
uppercase camelCase boundary without extra lookaround machinery.

The accepted cost is a known false positive: a param literally named `secretary` (or any other
English word that happens to contain one of the 5 terms as a true substring) will fire even though
it holds no secret. This is intentional and documented rather than "fixed" with a regex that could
silently stop matching a genuine camelCase secret name — for a security guard, a false positive that
a human triages away is a better failure mode than a false negative that goes unnoticed.

## Tests

| Test | What it checks |
|---|---|
| `test_bicep_secret_param_flags_unsecured_password_param` | plain `password string`, no `@secure()` → fires, `high` |
| `test_bicep_secret_param_flags_camel_case_names` | `dbPassword`/`apiSecret`/`storageAccountKey` → all fire |
| `test_bicep_secret_param_silent_when_secure_decorator_present` | `@secure()` above the param → silent |
| `test_bicep_secret_param_silent_when_securestring_type` | `securestring` type → silent |
| `test_bicep_secret_param_silent_when_secureobject_type` | `secureobject` type → silent |
| `test_bicep_secret_param_silent_on_unrelated_param_name` | `location`/`environmentName` → silent |
| `test_bicep_secret_param_not_applicable_without_bicep` | `applies()` false without the `bicep` feature |

## Known bypasses

- **Name-only heuristic, no value inspection.** A param named something unrelated to the 5 terms
  (e.g. `credential`, `token`, `apiKey`) that genuinely holds a secret is not caught — only the 5
  listed terms are matched, deliberately narrow per the source rule's own list.
- **Decorator association is line-adjacency** (inherited from `agentsec.bicep`): a `@secure()` above
  the `param` is associated across blank lines and `//` line comments, and a `//` comment trailing on
  the `@secure()` line itself is stripped before the match (the guard stays silent in all three cases),
  but a `/* ... */` **block** comment between them still severs the association and would incorrectly
  fire — an accepted remaining limit of the shared parser.
- **No dataflow** — a param's default value or downstream use is not inspected, only the declaration
  line itself.

## What this guard does NOT prove

A clean scan means no scanned `.bicep` file has a secret-name-matching `param` without `@secure()`
or a secure type — it says nothing about secrets embedded as literal values elsewhere (variables,
resource properties), nor about a secret-shaped param whose name doesn't match one of the 5 listed
terms.

## Canary plant

`bicep_secret_param.bicep` — `param dbPassword string` with no `@secure()` decorator and a plain
`string` type. Expected rule: `bicep-secret-param-not-secure/unmarked-secret-param`.

# Citations

[1] agentsec checklist item `6c-bicep-secret-param-not-secure` (§6c)
[2] OWASP:A02 (Cryptographic Failures)
[3] CWE-256 (Plaintext Storage of a Password)
[4] Azure/bicep — `SecretsInParamsMustBeSecureRule.cs` (`secure-secrets-in-params`, provenance
    only; detection logic here is original)
