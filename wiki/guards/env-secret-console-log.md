---
type: Guard
title: "env-secret-console-log"
description: "Environment secret read directly inside a console.* call."
timestamp: "2026-10-01T12:21:54Z"
guard_id: "env-secret-console-log"
checklist_section: ["10"]
standards: ["OWASP:A02", "OWASP:A09"]
---

# Environment secret read directly inside a console.* call

_Author — 2026-07-12_

---

## The threat

`console.log(process.env.STRIPE_SECRET_KEY)` writes a secret's actual value to a console
sink. Depending on where this code runs, that sink is one of:

- The **browser DevTools console**, if the code executes client-side (e.g. a misconfigured
  bundler that inlines a server-only env var into a browser bundle, or a component that
  accidentally runs during SSR hydration) — readable by anyone with the page open, and often
  captured by session-replay tools (LogRocket, FullStory) that record console output.
- The **Node process's stdout/stderr**, which is routinely captured by process managers
  (pm2, systemd journal), container log drivers (Docker/Kubernetes), and error-monitoring
  SDKs (Sentry, Datadog RUM) that patch `console.*` to forward output.

Either destination is broader-audience and longer-retention than the source code itself, so
a debug `console.log` line that survives into production is a durable secret leak.
OWASP:A09 (Security Logging & Monitoring Failures) and OWASP:A02 (Cryptographic Failures)
both apply.

This guard is the JS/TS analogue of `env-secret-logged` (Python), and both are a narrowed,
static translation of a real Bearer detection concept: `pkg/detectors/javascript/javascript.go`
defines an `environmentVariableQuery` that tags every `process.env.X` / `process.env["X"]`
read as tainted `variables.VariableEnvironment` data and tracks that taint through Bearer's
generic dataflow engine to any sink. agentsec has no dataflow engine, so this guard keeps
only the highest-value, statically detectable sink: a `console.*` call, on the same line.

## Why this guard fits the stack

`process.env.X` reads are ubiquitous in a Vite/React + Node/Express-style stack for config
and feature flags, and `console.log` is the reflexive debugging tool reached for when a
build or a runtime value looks wrong — precisely the moment a developer is most likely to
log a secret directly to see its value:

```js
console.log(process.env.STRIPE_SECRET_KEY);   // "is this even set?"
console.error(process.env['DB_PASSWORD']);
```

No existing agentsec guard scans for `console.*` calls at all: `vite-client-secret` only
scans `.env*` FILES, and `token-in-localstorage` matches an unrelated sink
(`localStorage`/`sessionStorage.setItem`).

## Detection design

1. **`applies()` gate** — `"frontend" in profile.features or "javascript" in
   profile.features` (mirrors `token-in-localstorage`).
2. **Files scanned** — `iter_files(root, (".js", ".jsx", ".ts", ".tsx"))`, skipping
   `is_nonproduct_path` (test/spec/fixture files), same as `dom-xss-sinks` and
   `token-in-localstorage`.
3. **Pattern** — per physical line: find a `console.*` call (`_CONSOLE_CALL`:
   `console.log/debug/info/warn/error(`). If found, take the text after the call's opening
   parenthesis (`rest`) and search it for `_ENV_SECRET_ACCESS`: `process.env.X` or
   `process.env["X"]`/`process.env['X']` where the key name has KEY, APIKEY(S), SECRET(S),
   PASSWORD(S), TOKEN, PASS, CRED(S), PRIVATE, or AUTH as a whole `_`/`.`-delimited SEGMENT
   (case-insensitive). The name pattern (`_SECRET_NAME`) is imported from `env-secret-logged`,
   so the two siblings share one word list. Until #560 this guard kept its own narrow copy, and
   stayed silent on the fused and plural spellings (`SENDGRID_APIKEY`, `AWS_SECRETS`,
   `DB_PASSWORDS`, camelCase `apiKey`) that #445 had added to the Python guard.
   Segment-anchoring (not a bare substring) keeps `MAX_TOKENS`/`NUM_TOKENS` (a ubiquitous LLM
   config var, TOKEN), `BYPASS_CACHE` (PASS), and `MONKEY_MODE` (KEY) silent while `API_TOKEN`/
   `SECRET_KEY_BASE` still fire (PR #397 review #1). The plural is allowed only where it is
   not itself a common non-secret term, so `TOKENS` stays out. In the attribute arm there is
   no closing quote, so the trailing `\b` does that job: `process.env.MAX_TOKENS` cannot
   match on its `TOKEN` prefix. The shared pattern also carries a case-sensitive camelCase
   branch (#987), so `process.env.dbPassword`/`authToken`/`clientSecret`/`awsSecretKey` fire in
   both arms while `maxTokens`/`bypassCache`/`monkeyPatch`/`authorName` stay silent.
   Requiring the match to be in
   `rest` keeps an unrelated preceding `process.env` read on the same physical line from
   firing (mirrors the Python sibling's same design choice).
4. **Boolean/type-coercion exemption** — the text immediately BEFORE the matched
   `process.env` access (`before = rest[:env_m.start()]`) is checked against
   `_SAFE_COERCION_PREFIX` (`!!`, `Boolean(`, `typeof `). If present, the read only ever
   reveals presence or JS type, never the secret's value, so the guard stays silent.
5. **Inline opt-out pragma** — a `// security: allow-env-secret-console-log` comment anywhere in the
   file (a string literal quoting the phrase does not count, #424).
6. **Severity/rule/standards** — one finding per site, `severity="high"`,
   `rule="env-secret-console-log/direct-console-sink"`,
   `standards=["OWASP:A09", "OWASP:A02"]`.

## When NOT to flag

- `console.log(!!process.env.API_KEY)` / `Boolean(process.env.API_KEY)` /
  `typeof process.env.API_KEY` — presence/type only, never the value. Verified in the
  adversarial self-test pass before finalizing (see Tests below) — this was the first
  version's most realistic false-positive shape, since "is this env var set?" debug logging
  is extremely common in Node startup code.
- `console.log(process.env.NODE_ENV)` — the key name has no secret-sounding segment; likewise
  `process.env.MAX_TOKENS` (TOKEN is only a substring of TOKENS, not a whole segment, and
  `TOKENS` is deliberately not in the plural list).
- A config name with a `SECRETS` segment (`AWS_SECRETS_MANAGER_REGION`, `SECRETS_DIR`) DOES
  fire. That is the price of the #445 plural, accepted in the Python guard first. If it proves
  noisy, narrow the shared `_SECRET_NAME` so both guards move together; don't fork a JS copy.
- A secret read into a variable and logged on a later line (`const k = process.env.API_KEY;
  console.log(k)`) is a documented false-negative scope limit, not a false positive.

## Tests

| Test | What it checks |
|---|---|
| `test_env_secret_console_log_flags_dot_access` | `console.log(process.env.STRIPE_SECRET_KEY)` fires HIGH at the correct line |
| `test_env_secret_console_log_flags_bracket_access` | `process.env['DB_PASSWORD']` subscript form fires |
| `test_env_secret_console_log_pragma_opt_out` | the pragma comment silences the check |
| `test_env_secret_console_log_silent_on_boolean_presence_check` | FP-bait: `!!process.env.API_KEY` stays silent |
| `test_env_secret_console_log_silent_on_boolean_wrapper` | FP-bait: `Boolean(process.env.API_KEY)` stays silent |
| `test_env_secret_console_log_silent_on_typeof_check` | FP-bait: `typeof process.env.API_KEY` stays silent |
| `test_env_secret_console_log_silent_on_non_secret_env_var` | FP-bait: `process.env.NODE_ENV` stays silent |
| `test_env_secret_console_log_silent_two_line_alias_bypass` | documents the two-line dataflow gap (silent by design) |
| `test_env_secret_console_log_silent_on_max_tokens_substring` | FP-bait: `MAX_TOKENS`/`NUM_TOKENS` and bracket-form `BYPASS_CACHE` stay silent (PR #397 review #1) |
| `test_env_secret_console_log_still_flags_real_token_secrets` | segment-anchoring still fires on `GITHUB_TOKEN`/`AUTH_TOKEN` |
| `test_env_secret_console_log_not_applicable_without_frontend_or_js` | `applies()` gate |
| `test_env_secret_console_log_silent_on_commented_example` | FP-bait (#424): a commented-out `console.log(process.env.API_SECRET)` stays silent |
| `test_env_secret_console_log_flags_fused_and_plural_secret_names` | #560: `SENDGRID_APIKEY(S)`, `AWS_SECRETS`, `AWS_CREDS`, `DB_PASSWORDS` and `apiKey` fire once each, in both the attribute and the bracket form |
| `test_env_secret_console_log_silent_for_substring_and_plural_lookalikes` | #560 FP-bait: attribute-form `MAX_TOKENS`, `BYPASS_CACHE`, `MONKEY` and `MAX_TOKENS.toString()` stay silent; pins the attribute arm's trailing `\b` |
| `test_env_secret_console_log_flags_camelcase_secret_names` | #987: camelCase `dbPassword`, `authToken`, `clientSecret` and `awsSecretKey` fire once each, in both the attribute and the bracket form |
| `test_env_secret_console_log_silent_for_camelcase_substring_lookalikes` | #987 FP-bait: attribute-form `maxTokens`, `bypassCache`, `monkeyPatch` and `authorName` stay silent |
| `test_env_secret_console_log_unterminated_bracket_camel_name_stays_linear` | #987 (slow): an unterminated bracket-form camelCase name scans in linear time (`assert_growth`) |
| `test_env_secret_console_log_attribute_arm_camel_name_stays_linear` | #987 (slow): the same for the attribute arm, which has no closing quote, only the trailing `\b` |

## Known bypasses

- **Two-line / cross-scope dataflow**: `const key = process.env.API_KEY;` then
  `console.log(key)` on a later line — requires dataflow analysis beyond this guard's
  line-level scope.
- **Destructuring**: `const { API_KEY } = process.env; console.log(API_KEY)` — the secret
  read and the console call are structurally separated even on the same line's AST, and this
  guard has no AST; a purely textual `process.env.API_KEY` match is required.
- **Wrapper/helper functions**: `console.log(getSecret())` — invisible to a static line scan.
- **Dynamic key construction**: `process.env[keyVar]` where `keyVar` is a variable, not a
  string literal — the key-name regex requires a literal to classify it as secret-sounding.
- **Non-`console` sinks**: a custom logger (`logger.log(process.env.API_KEY)`), a toast/UI
  notification, or a network call are not covered by this guard (console-only scope).
- **camelCase with the secret word first**: `process.env.secretArn`, `tokenValue`,
  `authHeader`. The shared camel branch matches only capital-led secret words, so a leading
  lowercase secret word never fires, while the snake twin does. Deliberate: the same rule keeps
  `keyCount`/`passThrough` silent. See `env-secret-logged`, which owns the pattern and pins it.

## What this guard does NOT prove

A silent guard does NOT prove no secret ever reaches a client-visible or captured log sink —
it only proves no *single-line* `process.env` read, with a secret-sounding key literal, was
found nested directly inside a `console.*` call in a non-test file. Multi-line flows,
destructured access, custom logger wrappers, dynamic key names, and non-console sinks
(network beacons, third-party analytics calls) are all outside this guard's detection
surface.

# Citations

[1] agentsec checklist item `10-no-sensitive-data-in-logs` (§10)
[2] OWASP:A02
[3] OWASP:A09
