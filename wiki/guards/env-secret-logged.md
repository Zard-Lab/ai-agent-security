---
type: Guard
title: "env-secret-logged"
description: "Environment secret read directly inside a logging call."
timestamp: "2026-10-01T12:21:54Z"
guard_id: "env-secret-logged"
checklist_section: ["10"]
standards: ["OWASP:A02", "OWASP:A09"]
---

# Environment secret read directly inside a logging call

_Author — 2026-07-12_

---

## The threat

Any process that can read application logs — a log aggregator (Datadog, Splunk, CloudWatch),
an on-call engineer without secret-access rights, or an attacker who gained read access to a
log bucket/volume — recovers a live credential the moment a developer writes
`logger.info(os.getenv("DB_PASSWORD"))` or `print(os.environ["STRIPE_SECRET_KEY"])`. Unlike a
sensitive-*field-name* leak (a password value assigned to a variable that happens to be
logged), this pattern puts the environment secret's **actual value** on the wire to the log
sink directly, with zero indirection. OWASP:A09 (Security Logging & Monitoring Failures) and
OWASP:A02 (Cryptographic Failures — secret exposure) both apply.

This guard is a narrowed, static-analysis translation of a real detection concept from Bearer
(`Bearer/bearer`, a Go/tree-sitter SAST tool): `pkg/detectors/python/python.go` defines an
`environmentVariableQuery` that tags every `os.environ[...]` / `os.environ.get(...)` /
`os.getenv(...)` read as tainted "environment" data (`variables.VariableEnvironment`) and then
tracks that taint through Bearer's generic dataflow engine to any sink — a log call, an HTTP
request, a datastore write. agentsec has no dataflow engine, so this guard keeps only the
single highest-value, statically detectable sink: the log call, on the same line.

## Why it's often introduced

Developers frequently reach for `os.getenv(...)` inline as a debugging shortcut — "let me
just print/log the value to confirm it's set" — during local development, and the line
survives into a commit. Because the value being logged looks like ordinary code (a function
call, not an obviously-named variable), it does not visually stand out as a secret leak the
way `logger.info(f"password={password}")` would.

```python
logger.info(os.getenv("DB_PASSWORD"))          # the value, not the field name
print(os.environ["OPENAI_API_KEY"])
```

## Detection design

1. **`applies()` gate** — `"python" in profile.features` (mirrors `sensitive-logging`; not
   gated on `llm`, since this is a general logging-hygiene issue, not LLM-specific).
2. **Files scanned** — `python_scan_dirs(root, profile)` → `iter_files(d, (".py",))`, same as
   every Python guard.
3. **Pattern** — per physical line: find a logging/print call (`_LOG_CALL`: `logger.<level>(`,
   the bare stdlib module `logging.<level>(` — listed explicitly since "logging" doesn't end in
   `log`/`logger` (PR #397 review #2) — aliases ending `log`/`logger`, `get_logger(...).info(`,
   or bare `print(`). If found, take the text AFTER the call's opening parenthesis (`rest`) and
   search it for `_ENV_SECRET_ACCESS`: `os.environ.get(...)` / `os.getenv(...)` / `os.environ[...]`
   whose key-name string literal has KEY, APIKEY(S), SECRET(S), PASSWORD(S), TOKEN, PASS, CRED(S),
   PRIVATE, or AUTH as a whole `_`/`.`-delimited SEGMENT (case-insensitive). The fused and plural
   spellings (`SENDGRID_APIKEY`, `AWS_SECRETS`) were added in #445; `TOKENS` is deliberately left
   out, since `MAX_TOKENS` is word + plural too. This guard owns `_SECRET_NAME`, and
   `env-secret-in-prompt` and `env-secret-console-log` (#560) import it. Segment-anchoring
   (not a bare substring) is what keeps `MAX_TOKENS`/`NUM_TOKENS` (TOKEN), `BYPASS_CACHE` (PASS),
   and `MONKEY_MODE` (KEY) silent while `API_TOKEN`/`SECRET_KEY_BASE` still fire (PR #397 review #1).
   A second, case-sensitive branch (#987) splits camelCase names on the lower-to-upper boundary
   and matches the same words as whole capital-led segments, so `dbPassword`/`authToken`/
   `clientSecret`/`awsSecretKey` fire while `maxTokens`/`bypassCache`/`monkeyPatch`/`authorName`
   stay silent. Both branches cap their segment repeats at 20 (#986, #987), so an unterminated
   hostile name stays linear. Requiring the match
   to be in `rest` (after the log call's `(`)
   is what keeps `key = os.getenv("API_KEY"); logger.info("done")` silent — the env read
   precedes the log call on the same physical line, so it is not nested inside its arguments.
4. **Inline opt-out pragma** — `# security: allow-env-secret-logged` anywhere in the file.
5. **Severity/rule/standards** — one finding, `severity="high"`,
   `rule="env-secret-logged/direct-log-sink"`, `standards=["OWASP:A09", "OWASP:A02"]`.

## When NOT to flag

- Logging a **boolean presence check** (`bool(os.getenv("API_KEY"))`) still matches this
  guard today (it is nested inside the log call and the key name still matches) — this is a
  known conservative-FP tradeoff, mirrored from the JS/TS sibling guard
  (`env-secret-console-log`), which DOES special-case `!!`/`Boolean(`/`typeof` coercion. A
  future revision could add the same coercion exemption here if it proves noisy in practice;
  left out of this first cut to keep the Python guard's scope minimal and match its closest
  sibling (`env-secret-in-prompt`), which does not special-case coercion either.
- A secret **read into a variable and logged later** (two-line pattern) is the documented
  false-negative scope below — not a false positive, a deliberate scope limit.
- A plain, non-secret env var name (`os.getenv("APP_ENVIRONMENT")`) has no
  KEY/APIKEY(S)/SECRET(S)/PASSWORD(S)/TOKEN/PASS/CRED(S)/PRIVATE/AUTH segment and stays silent —
  as does a name where one of those words appears only as a substring of a larger segment
  (`MAX_TOKENS`, `BYPASS_CACHE`, and in camelCase `maxTokens`, `bypassCache`).

## Tests

| Test | What it checks |
|---|---|
| `test_env_secret_logged_flags_getenv_in_logger` | `logger.info(os.getenv('DB_PASSWORD'))` fires HIGH at the correct line |
| `test_env_secret_logged_flags_environ_subscript_in_print` | `print(os.environ['OPENAI_API_KEY'])` fires |
| `test_env_secret_logged_flags_environ_get_method` | `os.environ.get(...)` form fires |
| `test_env_secret_logged_pragma_opt_out` | the pragma comment silences the check |
| `test_env_secret_logged_silent_on_two_line_alias_bypass` | documents the two-line dataflow gap (silent by design) |
| `test_env_secret_logged_silent_on_non_secret_env_var` | FP-bait: a non-secret-named env var stays silent |
| `test_env_secret_logged_silent_when_env_read_precedes_unrelated_log_call` | FP-bait: an env read before an unrelated log call on the same line (semicolon-joined) stays silent |
| `test_env_secret_logged_not_applicable_without_python` | `applies()` gate |
| `test_env_secret_logged_flags_camelcase_secret_names` | #987: camelCase `dbPassword`, `authToken`, `clientSecret` and `awsSecretKey` fire once each |
| `test_env_secret_logged_silent_for_camelcase_substring_lookalikes` | #987 FP-bait: `maxTokens`, `bypassCache`, `monkeyPatch` and `authorName` stay silent |
| `test_env_secret_logged_camelcase_leading_lowercase_secret_word_is_a_known_miss` | pins the camel branch's boundary: `secretArn`/`tokenValue`/`authHeader`/`keyCount`/`passThrough` stay silent while their snake twins fire |
| `test_env_secret_logged_unterminated_snake_name_stays_linear` | #986 (slow): an unterminated `os.getenv("KEY_KEY_...` run scans in linear time (`assert_growth`) |
| `test_env_secret_logged_unterminated_camel_name_stays_linear` | #987 (slow): the same for an unterminated camelCase `KeyKey...` run, which needs the atomic segments |

## Known bypasses

- **Two-line / cross-function dataflow**: `token = os.getenv("API_KEY")` on one line,
  `logger.info(token)` on another (or in a different function) — requires interprocedural
  dataflow analysis beyond this guard's line-level scope.
- **Aliased import**: `from os import getenv; print(getenv("SECRET"))` — only the
  `os.getenv`/`os.environ` spelling is matched (mirrors `env-secret-in-prompt`'s same
  documented gap).
- **Wrapper functions**: `logger.info(get_secret())` where `get_secret()` internally reads
  the environment — invisible to a static line scan.
- **Dynamic key construction**: `os.getenv(key_var)` where `key_var` is a variable, not a
  string literal — the key-name regex requires a literal to classify it as secret-sounding.
- **camelCase with the secret word first**: `os.getenv("secretArn")`, `tokenValue`,
  `authHeader`. The camel branch matches only capital-led secret words, so a secret word in the
  leading lowercase segment never fires, while the snake twin (`SECRET_ARN`) does. This is a
  deliberate trade, not an oversight: the same rule keeps `keyCount`/`passThrough` silent where
  `KEY_COUNT`/`PASS_THROUGH` are snake-branch false positives. A bare one-word name (`secret`,
  `token`) still fires through the snake branch.

## What this guard does NOT prove

A silent guard does NOT prove the codebase never logs a secret value — it only proves no
*single-line, same-call* `os.environ`/`os.getenv` read was nested inside a logging/print
call with a secret-sounding key name. Multi-line flows, wrapper functions, non-`os.environ`
secret sources (a secrets manager SDK, a config object populated from environment variables
at import time), and dynamic key names are all outside this guard's detection surface and
require either dataflow analysis or a runtime/DAST check to catch.

# Citations

[1] agentsec checklist item `10-no-sensitive-data-in-logs` (§10)
[2] OWASP:A02
[3] OWASP:A09
