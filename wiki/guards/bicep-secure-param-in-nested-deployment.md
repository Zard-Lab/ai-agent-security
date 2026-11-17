---
type: Guard
title: "bicep-secure-param-in-nested-deployment"
description: "Bicep outer-scoped nested deployment whose embedded template references a @secure() parameter or a list*() function, leaking it into cleartext deployment history."
timestamp: "2026-09-12T00:00:00Z"
guard_id: "bicep-secure-param-in-nested-deployment"
checklist_section: ["6c"]
standards: ["OWASP:A02"]
---

# Bicep nested deployment (outer-scoped) references a secure parameter or list*() function, leaking it into cleartext deployment history

Flags a Bicep `Microsoft.Resources/deployments` resource (the "nested deployment" / "linked
template" pattern) whose embedded `template`/`properties.template` block references either a
`@secure()`-decorated parameter from the current file or a `list*()` credential-retrieval function
(`listKeys(`, `listSecrets(`, `listAdminKeys(`, etc.), when the nested deployment is evaluated in
Bicep/ARM's default outer scope. Sixth guard in the Bicep batch. Sourced from Bicep's own
compiler-embedded linter, `SecureParamsInNestedDeploymentsRule.cs`
(`secure-params-in-nested-deploy`), verified against the real fetched source.

## The threat

`Microsoft.Resources/deployments` resources can embed a whole second ("nested"/"linked") template.
That embedded template's `expressionEvaluationOptions.scope` controls when its parameter
expressions are resolved. In the default **outer scope**, the nested template's expressions are
evaluated as part of submitting the OUTER deployment — before the nested deployment call itself
happens — and the resolved plaintext value gets written into the OUTER deployment's own deployment
history, which ARM keeps in cleartext by default. This defeats `@secure()`/`list*()` protection
entirely: the whole point of marking a parameter `@secure()` or fetching a value through `list*()`
is to keep a credential-shaped value out of exactly that kind of durable, readable record, and
outer-scope nested evaluation puts it right back in. In **inner scope**
(`expressionEvaluationOptions: { scope: 'inner' }`), the expressions are evaluated inside the nested
deployment's own protected context instead, and this guard does not flag that case. CWE-532
(Insertion of Sensitive Information into Log File) — the same exposure class as other
deployment-history-leak guards, applied here to a distinct mechanism (parameter evaluation timing,
not an `output` statement).

## Exploitability rationale

HIGH. Near-guaranteed plaintext exposure of a value the author explicitly tried to protect (either
by marking a parameter `@secure()` or by fetching it through a `list*()` accessor instead of storing
it directly), to anyone who can read the outer deployment's history — typically anyone with
`Microsoft.Resources/deployments/read` on the resource group, a much larger audience than the set of
people meant to see the credential.

## What counts as a hit (and what doesn't)

- An outer-scoped `Microsoft.Resources/deployments` resource whose block contains a `list\w*\(`
  call (e.g. `listKeys(...)`, `listAdminKeys(...)`) → fires. The match is deliberately a PREFIX,
  not an allowlist of known names: Azure's `list*` family is open-ended by design (any
  resource-provider operation whose name starts with `list`), so an allowlist would decay into
  false negatives every time a provider ships a new list action.
- The same block calling a function the FILE ITSELF declares (`func listActiveRegions(...) ... =>`,
  Bicep's user-defined-function syntax) → silent for that call. A user function may legally be
  named anything, including something starting with `list`, and reporting one as a
  "credential-retrieval function" is a false positive. Only a LOCAL declaration excuses a call, so
  this cannot hide a real list action — and a genuine `listKeys(...)` elsewhere in the same block
  still fires.
- An outer-scoped `Microsoft.Resources/deployments` resource whose block references, by bare
  identifier, one of the CURRENT file's `@secure()`-decorated parameters → fires.
- The same resource referencing a parameter that is NOT `@secure()`-decorated → silent (the threat
  is specifically about values the author marked as secure; an ordinary parameter leaking into
  history is a different, much lower-severity concern this guard does not cover).
- Any resource type other than exactly `Microsoft.Resources/deployments` → silent, even if its text
  happens to contain a `list(` substring elsewhere (e.g. a comment or an unrelated property value) —
  the resource-type gate is checked first.
- A `Microsoft.Resources/deployments` resource whose block contains
  `expressionEvaluationOptions` + `scope:` + the literal `'inner'`, all present → silent (see the
  simplification below).

## When NOT to flag (and the pragma)

- Inner-scoped nested deployments (the literal exemption marker present) → silent (the documented
  fix pattern).
- A reference to a non-secure parameter → silent (out of scope for this guard).
- **No suppression pragma.** Like its sibling `bicep-admin-username-literal`, this guard scans
  `resource` blocks via `agentsec.bicep`, which does not thread a pragma-check through resource
  extraction. No documented opt-out today.

## Known bypasses (honest limits — the outer/inner-scope simplification)

This is the guard in the batch with the most real-world nuance simplified away, and it is
deliberate:

- **The inner-scope exemption is a literal string match, not scope resolution.** Precisely
  determining `expressionEvaluationOptions.scope` in the general case requires resolving
  indirection — a variable, a parameter, a conditional expression supplying the scope value —
  which a dependency-free text scanner cannot do. This guard recognizes ONLY the literal three
  tokens `expressionEvaluationOptions`, `scope:`, and `'inner'` all present in the resource's block
  text. A template that sets `scope: innerScopeVar` (where `innerScopeVar` is a variable holding
  `'inner'`) is NOT recognized as exempt and will still fire — a conservative bias toward flagging
  over silence, but a genuine false positive if that variable is truly `'inner'`.
- **No cross-file resolution.** `@secure()` parameter names are collected only from the CURRENT
  file. A nested deployment referencing a secure parameter declared in a different file (passed
  through as a module parameter, for example) is not detected.
- **Name-based matching, no dataflow.** The `list*()`/secure-param search is a regex over the
  resource's block text, not an expression parser — a value that reaches the nested template only
  indirectly (through an intermediate variable that itself holds a `list*()` result or a secure
  param) is not traced.
- **Resource-block location only** — the finding reports the resource's opening line, not the exact
  nested property line.
- **A user function IMPORTED from another module** (`import { listX } from './shared.bicep'`) is
  not resolved, so a call to it is still treated as an Azure list action — the same conservative
  flag-rather-than-miss bias as the outer-vs-inner scope shortcut.
- **Triple-quoted multi-line strings are not brace/quote-aware** in `agentsec.bicep`'s block
  scanner — see that module's docstring.

## What this guard does NOT prove

A clean scan means no scanned `.bicep` file has an outer-scoped `Microsoft.Resources/deployments`
resource whose block text references a same-file `@secure()` parameter or a `list*()` call by the
patterns above. It says nothing about a genuinely inner-scoped-via-indirection template this guard's
literal exemption check misses (which fails safe toward flagging, not silence), a secure value
threaded through cross-file module parameters, or a value reaching the nested template only through
intermediate variables.

## Canary plant

`bicep_nested_deploy.bicep` — a `@secure()`-decorated parameter `dbPassword`, declared in the same
file as an outer-scoped `Microsoft.Resources/deployments` resource whose nested template references
`dbPassword` by name. Expected rule:
`bicep-secure-param-in-nested-deployment/outer-scope-secure-leak`.

# Citations

[1] OWASP:A02 (Cryptographic Failures)
[2] CWE-532 (Insertion of Sensitive Information into Log File)
[3] Azure/bicep — `SecureParamsInNestedDeploymentsRule.cs` (`secure-params-in-nested-deploy`,
    provenance only; detection logic and the outer/inner-scope simplification here are original)
