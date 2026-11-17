---
type: Guard
title: "unsafe-deserialization"
description: "No unsafe deserialization of untrusted data."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "unsafe-deserialization"
checklist_section: ["3b"]
standards: ["OWASP-LLM:LLM03", "OWASP:A08"]
---

# No unsafe deserialization of untrusted data

Flags `pickle`/`dill`/`marshal`/`joblib` loads, `torch.load` without `weights_only=True`,
`yaml.load` without a Safe loader, `from_pretrained(trust_remote_code=True)`, and
(2026-07-03) Haystack's `Pipeline.load`/`.loads`/`.load_from_yaml` — all Python-side.
(2026-07-15) Also flags the JS/Node counterpart: `js-yaml`'s `load`/`loadAll`/
`safeLoad`/`safeLoadAll` called with an unsafe `schema:` option (`DEFAULT_FULL_SCHEMA`,
`js-yaml-js-types`, or a `.extend()` of either) — see the dedicated section below. Closes
checklist item `3b-unsafe-deserialization` (Python and JS/TS).

## The threat

These formats execute code as a side effect of *loading* — `pickle.loads(blob)` runs `__reduce__`
on the attacker's object. On any attacker-reachable bytes (a file upload, a downloaded Hugging Face
model, a cached session, a tool payload) this is remote code execution. It is the mechanism behind
malicious-pickle HF models (ATLAS T0004) and insecure-deserialization tool payloads (CWE-502).
OWASP A08 (Software & Data Integrity), OWASP-LLM:LLM03.

## Exploitability rationale

CRITICAL. Direct RCE the moment untrusted bytes reach the sink; the payload is fully attacker-chosen.

## Patterns detected

- `pickle`/`cPickle`/`_pickle`/`dill`/`marshal` `.load`/`.loads(` — always fires (CRITICAL).
- `joblib.load(` — always fires (CRITICAL).
- `torch.load(` without `weights_only=True` — fires CRITICAL; safe variant is silent.
- `yaml.load(` without `safe_load`/`SafeLoader`/`CSafeLoader` — fires CRITICAL; safe variants are silent.
- `from_pretrained(..., trust_remote_code=True)` — fires CRITICAL (rule: `trust-remote-code-rce`).
  Downloads and executes arbitrary Python from the model hub — equivalent to pip-installing arbitrary
  code from an untrusted author. Remediation: remove `trust_remote_code=True` or pin to a verified
  commit SHA and audit the remote code manually.
- `Pipeline.load(`/`.loads(`/`.load_from_yaml(` (Haystack) — fires CRITICAL (rule:
  `haystack-pipeline-load`), unconditionally, matching the same "always fires" tier as
  pickle/dill/joblib. Haystack's own `SECURITY.md` states these "intentionally support
  dynamic imports at runtime to enable extensibility" and are explicitly out-of-scope for
  their bug bounty when loading from untrusted sources — the same CWE-502 class as
  pickle/yaml.load under a Haystack-specific function name.

## When NOT to flag (and the pragma)

- **Safe variants** — `yaml.safe_load` / `yaml.load(..., Loader=SafeLoader)`, `torch.load(...,
  weights_only=True)`, JSON/Protobuf → silent.
- `from_pretrained(..., trust_remote_code=False)` — silent (explicit opt-out is safe).
- `from_pretrained("model")` with no `trust_remote_code` argument — silent.
- A genuinely trusted-source load (a file the app itself wrote, never attacker-influenced) → suppress
  that line with `# security: allow-unsafe-deserialize`.

## Matching mechanics (`trust-remote-code-rce`)

Unlike the single-line sinks, `from_pretrained(...)` is matched against **whole-file text**, because
these calls are overwhelmingly written multi-line (one kwarg per line) — a line-by-line scan would miss
the dominant idiom. The finding is reported at the `from_pretrained(` opening line. The arg gap allows
one level of nested parens (`from_pretrained(resolve_id(), trust_remote_code=True)`); the pragma is
honored whether it trails the opening line or the `trust_remote_code=True` kwarg line.

## Known bypasses (honest limits)

- An aliased import (`from pickle import loads as L; L(b)`) or a wrapper function is not matched —
  the guard keys on the dotted sink name.
- `torch.load` whose `weights_only` is set on a later line (multi-line call) is treated as unsafe
  (conservative) — pragma covers an audited case.
- `from_pretrained` whose args nest more than one paren level before `trust_remote_code=True`
  (`from_pretrained(load(cfg(x)), trust_remote_code=True)`) is not matched — a rare shape; the more
  common single-nesting case is covered. Precision-first FN.
- `Pipeline.load(`/`.loads(`/`.load_from_yaml(` is matched on the literal class name `Pipeline` —
  an aliased import (`from haystack import Pipeline as P; P.loads(...)`) or a differently-named
  wrapper is not matched.

## What this guard does NOT prove

It flags the sink; it does not prove the bytes are attacker-reachable (they may be a trusted local
artifact) nor that no other deserialization path exists. Absence of a finding ≠ no unsafe load.

## JS/Node: js-yaml unsafe schema (2026-07-15)

`applies()` now also fires when `"javascript"`/`"typescript"` is in `profile.features` — the
Python-side detection above is unchanged; this is a second, independent scan branch over
`.js`/`.jsx`/`.ts`/`.tsx` files (rule: `js-yaml-unsafe-schema`).

### The threat

Sourced from GitHub CodeQL's `javascript/ql/src/Security/CWE-502/UnsafeDeserialization.ql` +
`UnsafeDeserializationCustomizations.qll`. The `js-yaml` npm package's `load`/`loadAll`/
`safeLoad`/`safeLoadAll` all resolve against a **safe** schema by default (in v4+, even
`load()` defaults safe) — but any of them becomes unsafe the moment the caller passes an
explicit `schema:` option that resolves to:

- `DEFAULT_FULL_SCHEMA` — js-yaml's own dangerous schema, which allows `!!js/function`,
  `!!js/regexp`, `!!js/undefined` YAML type tags.
- a schema from the `js-yaml-js-types` package — its `all`/`function` schemas re-add the same
  dangerous tags on top of a schema that would otherwise be safe.
- a `.extend()` call on either of the above.

A YAML document containing `!!js/function` executes arbitrary JavaScript the instant it is
parsed — the js-yaml analogue of Python's `pickle.loads`/`yaml.load`. On attacker-reachable
YAML (an uploaded config, a webhook payload, a CI file a PR can edit) this is remote code
execution. CWE-502, OWASP:A08, OWASP-LLM:LLM03.

**Not this guard:** `node-serialize`'s `unserialize()` is a *separate* CodeQL query under
CWE-094 (Code Injection) — a different sink class, deliberately not folded in here.

### Exploitability rationale

CRITICAL — same tier as the Python-side sinks. The moment untrusted YAML reaches a
`load`/`safeLoad` call carrying one of the dangerous schemas, the payload is fully
attacker-chosen arbitrary JS.

### Patterns detected

- `yaml.load(`/`yaml.loadAll(` — requires the literal `yaml.` prefix (the idiomatic
  `import yaml from 'js-yaml'` binding).
- `.safeLoad(`/`.safeLoadAll(` — accepts any object prefix (`jsYaml.safeLoad(`, etc.), since
  js-yaml's safe-by-name functions are commonly re-bound under an alias.
- Fires only when the call's argument list contains an explicit `schema:` option **and** that
  option resolves to `DEFAULT_FULL_SCHEMA` (used directly, or as the base of a `.extend()`), OR
  the args reference a `js-yaml-js-types` binding imported in this file. A `.extend()` on the
  SAFE `DEFAULT_SCHEMA` with a custom type is NOT flagged — the old bare `.extend(` match
  false-flagged js-yaml's own README-documented pattern CRITICAL (PR #395 C3).
- The call's arguments are captured with a bracket-depth balancer (not a bounded regex), so a
  multi-line options object (the dominant real-world style —
  `yaml.load(input, {\n  schema: DEFAULT_FULL_SCHEMA,\n})`) is matched whole; the finding is
  reported at the call's opening line.

### When NOT to flag (and the pragma)

- `yaml.load(data)` / `yaml.loadAll(data)` — no schema option at all. js-yaml's own default
  (safe in v4+; `DEFAULT_SAFE_SCHEMA` in the 3.x line under the historical `load` naming)
  applies. Silent.
- `yaml.safeLoad(data)` / `yaml.safeLoadAll(data)` — the always-safe function, called with no
  schema override. Silent.
- A `schema:` option resolving to a safe named schema (`schema: DEFAULT_SCHEMA`/`JSON_SCHEMA`/
  `CORE_SCHEMA`), or a `.extend()` of the safe `DEFAULT_SCHEMA` with a custom type — silent;
  these are already-safe.
- Suppress an audited (trusted-source) file with a `// security: allow-unsafe-deserialize`
  comment anywhere in the file (a string literal quoting the phrase does not count, #424; same
  pragma text as the Python side; whole-file suppression, matching the convention of this
  guard's JS sibling guards — `js-client-side-open-redirect`,
  `js-insecure-download-sensitive-file`).

### Matching mechanics

Unlike the single-line Python sinks, the JS call is matched against **whole-file text** via a
call-name regex (`_JS_YAML_CALL_OPEN`) that locates the opening `(`, then a small
bracket-depth balancer (`_js_call_args_span`, counts `()`/`{}`/`[]` together, no regex
backtracking risk) walks forward to the matching close — capturing the full argument list even
across many lines, over the **anchor mask** (a comment- and string-blanked copy, see below) so a commented-out
example can't fire (PR #395 M2). The `schema:`/`DEFAULT_FULL_SCHEMA` checks then run against
that captured span. `js-yaml-js-types` is resolved to its **imported binding names**
(`_js_types_bindings` mines `import X from`/`import { all }`/`const { all } = require(...)`),
and a call fires only when its OWN args reference one of those bindings — a **call-scoped**
signal, not a file-wide "the package is imported anywhere" flag, so importing it for one schema
no longer taints every unrelated `schema:`-carrying `yaml.load` in the same file (PR #395 M2).

Only live code counts (#1055). The call's `(` must be code on the shared anchor mask
(`strip_js_comments(raw, strip_strings=True, keep_substitutions=True)`, tested through
`js_code_matches`), which blanks string and template text but keeps `${...}` substitution code;
and each signal (`schema:`, `DEFAULT_FULL_SCHEMA`, a js-yaml-js-types binding) counts only where
its first character is code on it. A call spelled out in a docs or log string does not fire, nor
does a real call whose dangerous name appears only in a string (`loadSchema('DEFAULT_FULL_SCHEMA.yml')`);
a call nested in a `${...}` still fires, and every match is tried, so a quoted copy cannot hide a
real call after it. The bracket balancer walks that same mask, so a `)` or `}` inside a string
argument is not a bracket: before #1055, `yaml.load(input.replace(')', ''), { schema:
DEFAULT_FULL_SCHEMA })` ended the walk at the quoted `)`, never reached the options object, and
the CRITICAL went silent.

### Known bypasses (honest limits)

- No identifier/dataflow resolution: `const s = DEFAULT_FULL_SCHEMA; yaml.load(x, { schema: s })`
  is not matched — the schema reference must be textually present inside the call's own
  argument list, not assigned on an earlier line. A rare style; the inline form is dominant.
- The `js-yaml-js-types` signal is call-scoped to the imported binding name (PR #395 M2), so a
  binding aliased through an intermediate variable (`const t = all; ...extend(t)`) or a
  namespace-property access this simple miner doesn't track is a possible FN — the direct
  `.extend(all)` / `{ all }` forms (the README-documented usage) are covered.
- A destructured, unqualified `load(data, { schema: DEFAULT_FULL_SCHEMA })` (no `yaml.`/object
  prefix at all) is not matched — `yaml.load(`/`.safeLoad(` require a prefix, per the upstream
  CodeQL characterization this guard mirrors.
- Brackets inside a regex literal (#1055 residual, pinned): the anchor mask keeps regex-literal
  bodies as code, so `yaml.load(input.replace(/\)/g, ''), { schema: DEFAULT_FULL_SCHEMA })`
  still ends the walk at the regex's `)` and stays silent, exactly as before #1055
  (`test_unsafe_deserialization_js_regex_literal_paren_is_a_known_limit`).
- A quoted option key (`{ 'schema': DEFAULT_FULL_SCHEMA }`) never matched `schema\s*:`, before or
  after #1055 (a separate FN).
- Inherited anchor-mask limits: a `{` inside a regex or comment in one `${...}` substitution, then
  a `}` in a later one, rebalances the frame, so code between the two reads as template text (#543,
  pinned in `test_base.py`). Where the stripper's parity cap restores a template verbatim, the walk
  there is exactly the pre-#1055 walk.

# Citations

[1] agentsec checklist item `3b-unsafe-deserialization` (§3b)
[2] OWASP-LLM:LLM03
[3] OWASP:A08
