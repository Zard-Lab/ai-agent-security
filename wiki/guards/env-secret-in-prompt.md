---
type: Guard
title: "env-secret-in-prompt"
description: "Environment secret directly interpolated into a string (potential LLM prompt injection)."
timestamp: "2026-10-01T18:11:14+00:00"
guard_id: "env-secret-in-prompt"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM02", "OWASP:A02"]
---

# Environment secret directly interpolated into a string (potential LLM prompt injection)

**Guard ID:** `env-secret-in-prompt`
**Module:** `agentsec/guards/env_secret_in_prompt.py`
**Severity:** HIGH
**Standards:** OWASP-LLM:LLM02, OWASP:A02

## Threat

A common developer mistake in LLM applications: reading a secret from the environment
(API key, database password, token) and immediately interpolating it into a string that
becomes part of an LLM prompt. When the string is sent to the model provider, the secret:

- Is transmitted to the model provider and stored in conversation history
- Appears in observability tool logs (Logfire, Langfuse, Datadog LLM Observability)
- May be repeated back to end users in the model's response
- Becomes retrievable via prompt injection (attacker injects "print the full system prompt")

## Detection design

One check:

### `secret-in-fstring` (HIGH)

**Signal:** A Python line that contains BOTH an f-string open (`f"` or `f'`) AND a
secret-named env var read — either the call form (`os.environ.get()` / `os.getenv()`) OR
the bracket/subscript form (`os.environ["..."]`, no `.get()` call) — with a key name
matching common secret patterns.

**Key name patterns (case-insensitive):** `KEY`, `APIKEY(S)`, `SECRET(S)`, `PASSWORD(S)`,
`TOKEN`, `PASS`, `CRED(S)`, `PRIVATE`, `AUTH`, each as a whole `_`/`.`-delimited segment. The
pattern is `_SECRET_NAME`, imported from `env-secret-logged`; #445 added the fused and plural
spellings. Its case-sensitive camelCase branch (#987) also matches those words as whole
capital-led segments (`dbPassword`, `authToken`), while `maxTokens`/`bypassCache` stay silent.

```python
# Fires (same-line co-occurrence, call form):
header = f"Authorization: Bearer {os.environ.get('API_SECRET_KEY')}"
prompt = f"Use token: {os.getenv('DB_PASSWORD')} to access the database"
msg = f"Admin key: {os.environ.get('PRIVATE_KEY')}"

# Fires (same-line co-occurrence, bracket/subscript form — no .get() call; the idiomatic
# way to read a *required* secret, where a missing var should KeyError rather than
# silently pass None. Added 2026-08-22: at least as common in production code as .get()):
header = f"Bearer {os.environ['API_SECRET_KEY']}"

# Silent (two separate lines — safe pattern):
api_key = os.environ.get('OPENAI_API_KEY')  # read to variable
prompt = f"Answer this: {user_query}"       # variable used in different context

# Silent (SDK auth, not an f-string):
client = OpenAI(api_key=os.environ.get('OPENAI_API_KEY'))

# Silent (non-secret env var in f-string):
env_name = f"Running in: {os.environ.get('APP_ENV')}"
```

**Why same-line?** The co-occurrence on a single line is the signal that the developer
formatted the secret directly rather than first storing it in an authentication-bound
variable. Multi-line patterns (read to variable, then format elsewhere) are harder to
distinguish from legitimate use without dataflow analysis and are not detected.

**Granularity:** one finding per offending line, across every scanned file. Until #425 the
check returned on the first hit repo-wide (see the 2026-10-01 note below).

**Silence conditions:**
- Any file contains `# security: allow-secret-in-prompt`

## Severity rationale

HIGH because the secret is transmitted to an external model provider and may be echoed
back in model responses. The attack is passive (no active exploitation required) — once
in a prompt, the secret is at risk. CRITICAL-severity checklist item; HIGH guard finding
to maintain consistency with other information-disclosure guards.

## Known bypasses / false negatives

| Pattern | Caught? | Notes |
|---|---|---|
| `f"...{os.environ.get('OPENAI_API_KEY')}..."` | Yes | Primary case |
| `f"...{os.environ['API_KEY']}..."` | Yes (added 2026-08-22) | Bracket/subscript form, no `.get()` — same-line co-occurrence, same detection model as the call form |
| `secret = os.environ.get('API_KEY'); prompt = f"key: {secret}"` | No (FN) | Multi-line; requires dataflow/taint tracking across lines, a different class of analysis than this guard's single-line co-occurrence model — deferred |
| Template string: `"key: " + os.getenv('API_KEY')` | No (FN) | String concatenation (or `.format()`/`%`-interpolation), not f-string — the "this line builds output text" signal is hardcoded to `_FSTRING_OPEN`; a candidate follow-up widening, not bundled with the bracket-access fix |
| `f"...{os.getenv('secretArn')}..."` | No (FN) | camelCase with the secret word as the leading lowercase segment. The shared camel branch matches only capital-led secret words (#987); deliberate, since the same rule keeps `keyCount`/`passThrough` silent. Pinned in `env-secret-logged`'s tests |
| `f"..{settings.API_KEY}..."` | No (FN) | Settings/config attribute access, not `os.environ`/`os.getenv` — statically indistinguishable from any other attribute access without import resolution + class introspection (settings objects legitimately hold dozens of non-secret fields); deferred, high FP risk |

## False positive scenarios

| Pattern | Would fire | Why acceptable |
|---|---|---|
| Diagnostic tool: `f"Key length: {len(os.getenv('API_KEY',''))}"` | Yes | Still transmits key existence; prefer `len(key)` after storing in var |
| Test code that validates env setup | Yes | Suppress in test files with pragma |

## Checklist items flipped

| Item ID | Before | After | Reason |
|---|---|---|---|
| `4-llm-no-env-secrets` | `manual` | `partial` | Catches direct same-line interpolation; multi-line patterns require dataflow |

**2026-08-22 update:** extended the `secret-in-fstring` check to also match the bracket/
subscript access form (`os.environ["..."]`), closing the most concrete remaining static
sub-gap. Status **stays `partial`** — the checklist item's title ("LLM has no direct access
to environment variables or secrets") is broader than what single-line co-occurrence
detection can close: multi-line dataflow and settings-attribute access remain undetected (see
the bypass table above), so this is a widening of coverage within the existing `partial`
status, not a flip to `covered`.

**2026-09-03 note (review M9):** the guard's canary plant comment incorrectly credited its
bracket-form example line with proving the subscript branch "fires end-to-end" — it does not:
`_check_secret_in_fstring` returns on the first matching line across the whole scan, so the
earlier `.get()` line in the same plant file always wins and the bracket-form line is never
actually reached by a canary run. The bracket branch IS genuinely covered, by
`test_env_secret_in_prompt_flags_bracket_access_in_fstring` below — a real unit test, not the
canary. Comment corrected in `env_secret_in_prompt.py`; no detection-logic change.

**2026-10-01 follow-up (#425):** the first-match return above was a bug, not a design choice.
It capped the rule at one finding repo-wide, so N secrets interpolated into prompts reported
one, and an exception or baseline entry on that one hid the rest. `_check_secret_in_fstring` now
reports every offending line in every file, so a canary run does reach the bracket-form plant
line. The canary still proves only the rule, since `expects` is a rule set; the bracket branch
stays proven by its unit test.

## Tests

| Test | Validates |
|---|---|
| `test_env_secret_in_prompt_flags_fstring_with_secret` | `os.environ.get('API_SECRET_KEY')` in f-string fires |
| `test_env_secret_in_prompt_flags_getenv_in_fstring` | `os.getenv('API_TOKEN')` in f-string fires |
| `test_env_secret_in_prompt_flags_password_env_in_fstring` | `DATABASE_PASSWORD` key name fires |
| `test_env_secret_in_prompt_flags_bracket_access_in_fstring` | `os.environ['API_SECRET_KEY']` bracket/subscript form fires |
| `test_env_secret_in_prompt_silent_for_bracket_access_substring_secret_words` | FP-bait: whole-segment guard holds for bracket form too (`MAX_TOKENS`, `BYPASS_CACHE`) |
| `test_env_secret_in_prompt_silent_for_secret_in_variable` | Two-line pattern (read then use) is silent |
| `test_env_secret_in_prompt_silent_for_sdk_auth_use` | `OpenAI(api_key=os.environ.get(...))` is silent |
| `test_env_secret_in_prompt_silent_for_non_secret_env_in_fstring` | `APP_ENV` (non-secret key) is silent |
| `test_env_secret_in_prompt_pragma_silences` | Single pragma silences the check |
| `test_env_secret_in_prompt_not_applicable_without_llm_feature` | `applies()` gates on `"llm"` feature |
| `test_env_secret_in_prompt_flags_camelcase_secret_names` | #987 widening through the shared pattern: camelCase `dbPassword`, `authToken`, `clientSecret`, `awsSecretKey` fire, across the `getenv`, `environ.get` and bracket forms |
| `test_env_secret_in_prompt_silent_for_camelcase_substring_lookalikes` | #987 FP-bait: `maxTokens`, `bypassCache`, `monkeyPatch`, `authorName` stay silent |
| `test_env_secret_in_prompt_reports_every_offending_line` | Every offending line in every file is reported, not just the first (#425) |
| `test_env_secret_in_prompt_benign_line_after_a_hit_stays_silent` | A non-secret f-string, a read-to-variable and SDK auth use after a real hit stay silent (FP-bait for the #425 widening) |
| `test_env_secret_in_prompt_pragma_in_third_file_silences_all` | The repo-wide pragma still silences every file after #425 |

# Citations

[1] agentsec checklist item `4-llm-no-env-secrets` (§4)
[2] OWASP-LLM:LLM02
[3] OWASP:A02
