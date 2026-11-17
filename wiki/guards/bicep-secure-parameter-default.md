---
type: Guard
title: "bicep-secure-parameter-default"
description: "Bicep @secure() parameter given a hardcoded, non-empty literal default value."
timestamp: "2026-09-12T00:00:00Z"
guard_id: "bicep-secure-parameter-default"
checklist_section: ["6c"]
standards: ["OWASP:A02", "CWE-798"]
---

# Bicep @secure() parameter given a hardcoded, non-empty literal default value

Flags any Bicep `param` decorated `@secure()` whose default value is a non-empty hardcoded literal
rather than an expression or one of the documented empty-placeholder forms. Sibling to
`bicep-admin-username-literal` in the same Bicep batch, built against the shared
`agentsec.bicep` param parser (`bicep_params()`).

## The threat

`@secure()` tells Azure to treat a parameter's *runtime* value specially: masked in deployment logs
and not persisted in plaintext deployment history. But a hardcoded default is baked into the Bicep
SOURCE FILE itself, in plaintext, regardless of that runtime handling. Anyone with read access to the
source, including its full git history, can read the value directly. The author explicitly marked
this parameter as sensitive and then immediately undermined that marking with the very next token.
CWE-798 (Use of Hard-coded Credentials) — a more direct signal of an actual leaked secret than
`bicep-admin-username-literal`'s unmarked-value case, hence HIGH rather than MEDIUM severity.

## Exploitability rationale

HIGH. Unlike a hardcoded `adminUsername` (which only narrows a brute-force search space), a
`@secure()` default with real content is very likely to BE the actual secret — connection strings,
API keys, and passwords are exactly what `@secure()` is used to annotate. Anyone with source/git
access has the credential outright, no further attack needed.

## What counts as a hit (and what doesn't)

- `@secure()` + `param dbPassword string = 'hunter2'` (a non-empty quoted string) → fires.
- `@secure()` + `param dbConfig object = { password: 'hunter2' }` (a non-empty object literal) →
  fires.
- `@secure()` + `param dbSecrets array = [ 'hunter2' ]` (a non-empty array literal) → fires.
- `@secure()` + `param dbPassword string` (no default at all) → silent.
- `@secure()` + `param dbPassword string = ''` (empty string) → silent — the empty string is Bicep's
  documented deliberate placeholder, not a hardcoded value.
- `@secure()` + `param dbPassword string = ''''''` (empty triple-quoted string) → silent, same
  reasoning, checked defensively even though rare in practice.
- `@secure()` + `param dbConfig object = {}` / `param dbSecrets array = []` (empty object/array) →
  silent — a valid, empty default for a `secureobject`/`securestring`-adjacent array/object param.
- The same empty default written across lines (`= {` then `}`, ordinary Bicep formatting) → silent
  too. Inside a CONTAINER literal, whitespace is formatting, so the multi-line spelling is judged
  with whitespace collapsed and recognized as the same deliberate empty placeholder as `{}`.
- `@secure()` + a multi-line POPULATED object/array default (`= {` / `  password: 'hunter2'` / `}`)
  → fires, and the message names the value on one line. `bicep_params()` accumulates a default
  until its brackets balance; a whitespace-only STRING default (`= '  '`) still fires, because
  inside a string whitespace is content rather than formatting.
- `@secure()` + `param dbPassword string = otherParam` (a bare identifier — a reference to another
  parameter or variable) → silent. Not a literal; `agentsec.bicep` gives us only the raw RHS text, so
  this guard judges "literal" syntactically: only text that itself opens with a string/object/array
  literal token (`'`, `{`, `[`) counts as hardcoded.
- `@secure()` + `param dbPassword string = newGuid()` (a function-call expression) → silent, same
  reasoning — it doesn't start with a literal token.
- A hardcoded default on a param that is NOT `@secure()`-decorated → silent. That is a completely
  normal, common Bicep pattern (e.g. `param environmentName string = 'production'`) and a different
  concern entirely — this guard only cares about the contradiction between `@secure()` and a literal
  default, not about hardcoded defaults in general.

## When NOT to flag (and the pragma)

- No default, an empty-placeholder default, or an expression default → silent (all three are the
  legitimate, non-leaking patterns).
- **No suppression pragma.** Like `bicep-admin-username-literal`, this guard scans via
  `agentsec.bicep`'s regex-based parser, which does not currently thread a pragma-check through
  param extraction. A genuinely intentional hardcoded value in a fixed test/demo template has no
  documented opt-out today — a known limitation to revisit if it proves disruptive in practice.

## Known bypasses (honest limits)

- **No dataflow past the literal-vs-expression syntax check.** A reference default
  (`= otherParam`) is trusted at face value even if `otherParam` itself is hardcoded elsewhere
  (that's a different parameter's own default, and would be caught independently if IT is also
  `@secure()`-decorated with a literal default — this guard only reasons about one parameter at a
  time).
- **Indirection through a variable or module input** that ultimately supplies a hardcoded string is
  not traced — only the `param`'s own `default` text is inspected.
- **Triple-quoted multi-line strings are not brace/quote-aware** in `agentsec.bicep`'s underlying
  scanner — a `{`/`[` inside one can desync the bracket balancing that accumulates a multi-line
  default. See that module's docstring for the full disclosure on the shared parser.
- **A multi-line default is capped** at `agentsec.bicep`'s `_MAX_DEFAULT_LINES`, and an unbalanced
  or truncated literal is judged on whatever it absorbed (it still fires if a hardcoded value is in
  there) rather than raising.
- **Parameter-level location only** — the finding reports the `param` declaration's own line.

## What this guard does NOT prove

A clean scan means no scanned `.bicep` file's `@secure()` parameter carries a non-empty hardcoded
literal default — it says nothing about a secret hardcoded elsewhere (a variable, a module input, a
non-`@secure()` parameter), about a secret supplied via an expression this guard can't evaluate
(e.g. a base64-encoded literal buried inside a function call argument), or about a parameter declared
in a linked/nested template this scan didn't independently discover.

## Canary plant

`bicep_secure_default.bicep` — a `@secure()`-decorated `dbPassword` param with default
`'hardcoded-value'`. Expected rule: `bicep-secure-parameter-default/hardcoded-literal-default`.

# Citations

[1] OWASP:A02 (Cryptographic Failures)
[2] CWE-798 (Use of Hard-coded Credentials)
[3] Azure/bicep — `SecureParameterDefaultRule.cs` (`secure-parameter-default`, provenance only;
    detection logic here is original)
