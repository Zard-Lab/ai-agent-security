---
type: Guard
title: "mcp-hardcoded-credential"
description: "MCP server source hardcodes a credential-shaped variable as a literal."
timestamp: "2026-10-18T12:00:00Z"
guard_id: "mcp-hardcoded-credential"
checklist_section: ["4"]
standards: ["OWASP:A02", "CWE-798"]
---

# MCP server source hardcodes a credential-shaped variable as a literal

_Author — 2026-10-09_

---

## The threat

A variable, object field, or dict key named like a credential (`api_key`, `secret`, `token`,
`password`, `access_key`) assigned a quoted string literal directly ships that literal with
every clone, fork, and deployed image of the repo — visible to anyone with repo read access,
regardless of whether the repo is public or private (a private repo's access list changes over
time; a committed secret in history outlives any single access grant). Mined from sentrymcp
(zaydmulani09)'s `MCPA-AUTH-STATIC-CRED-001` rule, fetched and read in full.

Standards: OWASP:A02 (Cryptographic Failures — exposed credential), CWE-798 (Use of
Hard-coded Credentials).

## Why this guard fits the stack, and why it's MCP-gated

sentrymcp's own rule has no `safe_indicators` exclusion by design (env-var reads are already
excluded by construction — the sink pattern requires a quoted literal directly after the
operator) and no provider-prefix requirement, so it is a much broader net than the existing
`client-side-secret-literal` guard (provider-prefix-gated, JS/TS-only). Applied to ANY
Python/JS/TS repo, a credential-shaped variable name assigned any 8+ character literal would be
noisy — test fixtures, example/tutorial code, and ordinary config scaffolding all do this
routinely. Scoping `applies()` to `"mcp" in profile.features` keeps the same broad name-based
vocabulary safe the same way `mcp-tool-path-traversal`/`mcp-transport-no-auth` scope their own
widened rules to MCP repos rather than general application code.

```python
# Vulnerable:
API_KEY = "sk-live-abc123def456"

# Safe:
API_KEY = os.getenv("API_KEY")
```

## Detection design

1. **`applies()` gate:** `"mcp" in profile.features`, plus any of python/javascript/typescript.
2. **Files scanned:** Python via `python_scan_dirs` + `iter_files(d, (".py",))`; JS/TS via
   `iter_files(root, (".js", ".jsx", ".ts", ".tsx"))`. Both `is_nonproduct_path` filtered.
3. **Pattern:** `_ASSIGNMENT_CANDIDATE` matches any identifier (with a leading lookbehind so the
   match cannot start inside a longer identifier run, which keeps it linear on an embedded hex or
   base64 blob: round 2 of the #1058 review measured 3.7 s on one 16 KB line without it), optionally type-annotated
   (`: str`/`: string`), then `:` or `=`, then a quoted string literal of 8+ non-whitespace
   characters with no spaces inside the quotes. `_is_credential_shaped_name` then decides whether
   that identifier is credential-shaped by splitting it into lowercase segments on `_`/`-` and
   camelCase/SCREAMING_CASE boundaries (`_name_segments`) and checking whether any segment is
   `secret`/`token`/`password`, or an adjacent pair is `api`+`key`/`access`+`key` — so the
   credential word can be ANY segment of the name (`GITHUB_TOKEN`, `tokenValue`, `client_secret`),
   not only the whole name (H3 of the #1058 review: the prior `\b`-bounded substring match
   required the operator immediately after the credential word, which only the whole-name case
   satisfies).
4. **Placeholder/mask/key-name exclusion:** `_PLACEHOLDER_VALUE` — a literal starting with
   `your-`/`<`/`${`, or containing `xxx`/`changeme`/`example`/`placeholder`/`todo`/`fixme`
   (case-insensitive) — does not fire; sentrymcp's own source rule has no such exclusion.
   `_MASKED_OR_KEY_NAME_SHAPED_VALUE` (added after the #1058 review's H3) additionally excludes a
   masked/redacted display value (`"********"`, `"***REDACTED***"`, case-insensitive), a value
   shaped like a lookup-key NAME rather than a secret — all-lowercase letters, `_` and `-`, no
   digits at all (`"access_token"`, `"auth-token-storage-key"`) — and an HTTP header name
   (`"X-API-Key"`, `"X-CSRF-Token"`, `"Authorization"`; letter words only, so a value with a digit
   after `X-` still fires, and so does a digit-bearing header name such as `"X-B3-TraceId"`, as a
   non-gating review signal). The lowercase test is case-SENSITIVE
   (round-2 M1): a real secret reliably carries digits or capitals, so `"SuperSecretPassword"`
   still fires.
   `_LOCATOR_VALUE` (round-2 H2) excludes a value that locates or dates a secret rather than
   being one, which is what a `TOKEN_URL`, `SECRET_ARN` or `PASSWORD_RESET_PATH` constant holds:
   a URL with no userinfo, an absolute path, an ARN, an ISO-8601 date or timestamp, and an
   all-lowercase relative path or resource name (`"projects/123/secrets/foo"`). A URL that embeds
   `user:password@` still fires, and so does a mixed-case base64 secret that contains `/`.
5. **Comment stripping:** `strip_python_line_comment` (Python) / `strip_js_comments`
   (JS/TS) before matching — a documented example in a comment doesn't fire. NOT
   string-stripped: the credential value itself must survive as a real string literal.
6. **Inline opt-out pragma:** `# security: allow-mcp-hardcoded-credential` (Python) /
   `// security: allow-mcp-hardcoded-credential` (JS/TS).
7. **Severity/standards:** `medium` with `surfacing = True`, `["OWASP:A02", "CWE-798"]`. Rule:
   `mcp-hardcoded-credential/hardcoded-credential-literal`. The guard shipped at `critical`, was
   demoted to `high` in round 1 of the #1058 review, and became a non-gating review signal in
   round 3 (see "Why a review signal, not a gate" below).

## Why a review signal, not a gate

A name plus a value shape cannot prove a secret. Each of the three #1058 review rounds tuned the
value filters, and each exposed the next shape. An all-letter capitalised value is a password
(`"SuperSecretPassword"`) as often as it is a class or enum label (`TOKEN_TYPE = "BearerToken"`,
`PASSWORD_FIELD = "PasswordField"`), and nothing on the line tells them apart. So the finding is
`medium` with `surfacing = True`: it stays in the report, ranks below proven findings, and does
not fail a build at the default `--fail-on high`.

What still gates a real credential elsewhere is narrower (measured in round 4 of the #1058
review):

| Credential | Gated by |
|---|---|
| Provider-prefixed key in a `.py` or `.go` file | `hardcoded-llm-provider-key` |
| Provider-prefixed key in JS/TS, with the `frontend`, `javascript` or `typescript` feature (a pure-TS repo such as `{mcp, typescript}` since #1082; the line then also carries this guard's MEDIUM, #1080's same-line class) | `client-side-secret-literal` |
| Stripe live key, with the `payments` feature | `stripe-payments` |
| A secret matching a gitleaks rule, in a full audit (not `--guards-only`) of a committed tree, with gitleaks installed | gitleaks |
| A secret assigned to a generic variable or field name (`dbPassword = "..."`) | usually no guard (a few cover specific shapes: `hardcoded-password-default-arg`, `weak-secret-key-literal`, `java-hardcoded-password-key`, `compose-credential-env-literal`); this guard reports it at `medium`, and gitleaks may catch it in a full audit |

So in an MCP repo this guard is sometimes the only signal for a hardcoded credential, and it
does not gate. Use `--fail-on medium` if you want it to (this gates every medium finding, not
only this one).

## When NOT to flag

- A value read from an environment variable or secrets manager — excluded by construction
  (the pattern requires a quoted literal directly after `:`/`=`).
- An obvious placeholder value — see the exclusion list above.
- A literal under 8 characters — a mode flag or short non-credential value, not a plausible
  credential.
- A credential word that is not a whole SEGMENT of the identifier (`tokenize_method`,
  `passwordless_mode`, `monkey`): `_name_segments` splits on `_`/`-` and camelCase boundaries
  only, so a lowercase continuation is part of the same segment.
- A masked value, a lookup-key or header name, or a URL/path/ARN/timestamp value — see the
  exclusions above.

Suppress an audited case (e.g. a test fixture) with the pragma above.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_python_api_key_literal` | `API_KEY = "sk-live-..."` fires |
| `test_fires_on_python_type_annotated_secret` | `token: str = "..."` (type-annotated) fires |
| `test_fires_on_js_camelcase_access_key` | JS: `const accessKey = "AKIA..."` fires |
| `test_fires_on_ts_object_literal_key` | TS: `{ password: "..." }` unquoted object key fires |
| `test_silent_on_env_var_read` | FP-bait: `os.getenv("API_KEY")` stays silent |
| `test_silent_on_placeholder_value` | FP-bait: `"your-api-key-here"` stays silent |
| `test_silent_on_short_literal` | FP-bait: a literal under 8 characters stays silent |
| `test_silent_without_mcp_feature` | `applies()` is False with no `mcp` feature |
| `test_applies_requires_mcp_plus_a_language` | `applies()` gate — `mcp` plus any of python/javascript/typescript |
| `test_pragma_suppresses_python_finding` | the Python pragma silences the finding |
| `test_pragma_suppresses_js_finding` | the JS/TS pragma silences the finding |
| `test_finding_is_a_non_gating_review_signal` | the finding is `medium`, below `--fail-on high`, and classified as a review signal |
| `test_silent_on_masked_value` | FP-bait: `"********"` and `"***REDACTED***"` stay silent |
| `test_silent_on_key_name_shaped_value` | FP-bait: `"access_token"`, `"auth-token-storage-key"` stay silent |
| `test_fires_on_snake_case_env_style_name` | `GITHUB_TOKEN`, `DB_PASSWORD` fire |
| `test_fires_on_camelcase_and_underscore_prefixed_token_names` | `my_token`, `tokenValue` fire |
| `test_silent_on_lowercase_substring_continuation` | FP-bait: `tokenize_method`, `passwordless_mode` stay silent |
| `test_assignment_scan_is_linear_on_a_long_identifier_run` | the assignment regex grows linearly on a long hex run (round-2 H1) |
| `test_silent_on_locator_shaped_value` | FP-bait: token URLs, absolute and relative paths, an ARN, a timestamp stay silent (round-2 H2) |
| `test_js_silent_on_token_endpoint_url` | FP-bait: JS `tokenUrl` and an unquoted `token_endpoint` key stay silent |
| `test_fires_on_secret_that_merely_contains_locator_characters` | a credential URL with `user:password@` and a base64 secret with `/` still fire |
| `test_fires_on_all_letter_mixed_case_secret` | all-letter secrets with capitals fire (round-2 M1) |
| `test_silent_on_http_header_name_value` | FP-bait: `"X-CSRF-Token"`, `"X-API-Key"`, `"Authorization"` stay silent |
| `test_descriptor_valued_constant_surfaces_without_gating` | `TOKEN_TYPE = "BearerToken"` and seven other class/enum/type labels are still reported, but below `high` (round 3) |
| `test_fires_on_x_prefixed_value_that_is_not_a_header_name` | `"X-9f8a7b6c5d4e3f2a"` is not a header name and fires (round 3) |
| `test_ts_mcp_server_credentials_surface_through_the_real_pipeline` | in a pure-TS MCP repo, the real pipeline reports both planted credentials at `medium` (round 4) |

## Known bypasses

- **An all-lowercase, digit-free secret** (a lowercase passphrase) reads as a lookup-key name
  and is excluded, and so does a secret written as an all-lowercase path. A secret that begins
  with `/`, an ISO date or `arn:` reads as a locator. All three are deliberate trade-offs of the
  shape filters above.
- **A secret embedded in a URL's path or query** (a webhook URL whose path carries the token, a
  `?api_key=` parameter) reads as a locator, because only a URL with `user:password@` userinfo
  keeps firing.
- **Quoted object-literal keys** (`{ "password": "..." }`) — only an unquoted key or a plain
  variable name matches.
- **Concatenation, template-literal interpolation, or a wrapper function** — the value must be
  a single, complete quoted literal directly after the operator.
- **Single-line only** — a value assembled across multiple statements is not traced.

## Overlap with sibling guards

On the same line this guard can fire alongside a more specific guard: `hardcoded-llm-provider-key`
(a known provider prefix such as `sk-proj-`, in Python and Go only), `client-side-secret-literal`
(a provider prefix in JS/TS, with the `frontend`, `javascript` or `typescript` feature),
`stripe-payments/live-key-literal-in-source` (`sk_live_`, with `payments`), and
`hardcoded-password-default-arg` (a `password=` default argument). That line is then reported
twice, once as the older guard's gating finding and once as this guard's `medium` review signal.
Since #1082 that includes a provider-key line in a pure-TS repo. A value with no provider prefix
usually has no gating twin (see the table above). An exception or pragma you already hold for the older guard does not
cover this rule id, so add this guard's own pragma or exception if the duplicate is noise. The
dedup design is tracked in #1080.

## What this guard does NOT prove

- That every credential in the repo is externalized — only that no credential-shaped name was
  assigned a plausible-looking literal directly, matching one of the recognized name/value
  shapes above. A credential stored under a non-credential-sounding name, or built from
  concatenation, is invisible to this guard.
- That a suppressed/silent file has no committed secret at all — git history can still carry a
  secret from a prior commit even after the live code is fixed; this guard only scans the
  current working tree.

# Citations

[1] agentsec checklist item `4-mcp-hardcoded-credential` (§4)
[2] OWASP:A02, CWE-798
[3] sentrymcp `MCPA-AUTH-STATIC-CRED-001` (zaydmulani09/sentrymcp)
