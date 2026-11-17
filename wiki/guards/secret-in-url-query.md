---
type: Guard
title: "secret-in-url-query"
description: "Secret passed as a URL query parameter (logs, history, Referer exposure)."
timestamp: "2026-06-21T18:50:26+08:00"
guard_id: "secret-in-url-query"
checklist_section: ["6a"]
standards: ["ASVS:14.2.1", "OWASP:A02", "OWASP:A09", "SOC2:CC6.7"]
---

# Secret passed as a URL query parameter (logs, history, Referer exposure)

## Threat

Embedding secret values (API keys, tokens, passwords) in URL query strings is a persistent,
high-severity mistake. Even over HTTPS, the full URL (including query string) is:

- Recorded in plaintext in server access logs, reverse-proxy logs, and CDN request logs
- Stored in the browser's navigation history and exposed to the OS (e.g. via `history` commands)
- Sent in the `Referer` header to any third-party resource loaded on the same page
- Captured by observability tools (Datadog APM, Splunk, CloudWatch) as part of request traces
- Visible in error messages that echo the request URL back to the caller

Any of these vectors can silently expose the secret to parties who should not see it, without
any active attack. Rotation is difficult because the secret may be baked into archived logs.

**OWASP:A02** — Cryptographic Failures: secrets exposed in transit or in secondary storage.

## Detection design

Two pattern families are checked on each line of every `.py` file in `python_scan_dirs`:

### Pattern (a) — f-string query param

```
[?&](?:api_key|apikey|token|secret|password|auth|key|pass|cred|private)=
```

applied only when the line also matches `\bf['"]` (an f-string opening). This catches:

```python
requests.get(f"https://api.com/data?api_key={key}")
url = f"https://x.com?token={access_token}&data=1"
requests.get(f"https://svc.io/v1?auth={bearer}&page=1")
```

### Pattern (b) — params dict literal

```
params\s*=\s*\{[^}]*['"](?:api_key|apikey|token|secret|password|auth|key|pass|cred|private)['"]\s*:
```

This catches the `requests` idiom where a dict is passed as `params=`:

```python
requests.get(url, params={"secret": os.environ["KEY"]})
requests.post(url, params={"api_key": cfg.api_key, "q": query})
```

Both patterns are case-insensitive. One finding is emitted per matching line (not per match).

### Pattern (c) — FastAPI route parameter bound to `Query(...)` (2026-07-12)

```
\b\w*(?:api_key|apikey|token|secret|password|auth|key|pass|cred|private)\w*\s*(?::[^=,\n]*)?=\s*Query\s*\(
```

Patterns (a) and (b) only catch the *outbound* side — a Python line that constructs a URL or
`requests` call embedding a secret. Pattern (c) catches the *receiving* side: the app's own
FastAPI route declaring that a secret-sounding value arrives via the query string, e.g.:

```python
def login(password: str = Query(...)):
def reset(api_key = Query(None)):
```

Every legitimate caller of such a route puts the secret in the URL, so it lands in access
logs on every real request — not just when a developer misuses `requests` elsewhere. The
`\w*` on both sides of the alternation lets a secret-sounding word appear as a prefix or
suffix of the parameter name (`auth_token`, `my_secret`), anchored by `\b` so it still binds
to the start of a real identifier rather than matching mid-word.

Pattern (c) is checked first per line and emits a distinct rule
(`secret-in-url-query/secret-query-param-declared`) and remediation (move the parameter to
`Header(...)` or the request body) from patterns (a)/(b).

**Also fixed in the same pass:** the per-line loop previously `break`-ed out of the *entire
file* scan after the first match on any line (a stray `break` at the wrong nesting level),
silently missing every later violation in a multi-line file. Removed — the loop now scans
every line.

### Pragma suppression

If a `# security: allow-secret-in-url-query` comment appears anywhere in a file (a string literal
quoting the phrase does not count, #424), the entire file is skipped. This is a
file-level opt-out, not a line-level one.

## Severity rationale

**HIGH** — URL-logged secrets are:

- Persistent (log retention is often months or years)
- Silently copied to many downstream systems without any active attack
- Difficult to detect (no obvious error when a secret leaks into a log)
- Hard to rotate if the secret is embedded in archived logs across multiple systems

A single occurrence can expose a credential to log aggregation systems, CDN vendors, and
third-party monitoring tools simultaneously.

## Known bypasses / false negatives

| Bypass | Why it evades detection |
|---|---|
| Multi-line URL construction | The `?api_key=` appears on a separate line from the f-string opening |
| Variable param name | `params={key_name: value}` where `key_name` is a variable, not a literal |
| String concatenation | `url = base + "?api_key=" + key` — no f-string, no params dict |
| urllib.parse.urlencode | `urlencode({"api_key": key})` — no f-string, params= is not present |
| Indirect secret name | `params={"k": secret_value}` — key name `k` does not match |
| Multiline params dict | `params={\n    "api_key": key\n}` — regex does not span lines |

These are inherent to single-line, pattern-based static analysis. Dataflow analysis would be
required to catch the multi-line and variable-name cases.

## False positive scenarios

| Scenario | Why it fires | Recommended action |
|---|---|---|
| `key` is a non-secret param (e.g. sort key) | `key` matches the pattern but is not a secret | Rename to `sort_key` or suppress with pragma |
| `auth` is a boolean flag (e.g. `?auth=true`) | `auth` matches the pattern | Rename to `require_auth` or suppress with pragma |
| Public analytics API key with no permissions | Legitimately in URL but not sensitive | Suppress with `# security: allow-secret-in-url-query` |
| Test file constructing fixture URLs | f-string + `?token=` in test code | Add pragma to the test file if intentional |

The `key` keyword in particular can generate false positives in non-secret contexts. Accept
this cost: it is better to review a false positive than to miss a real secret in a URL.

## Checklist items flipped

| ID | Before | After | Reason |
|---|---|---|---|
| 6a-no-secret-in-url-query | `uncovered` | `covered` | Guard detects the primary f-string and params-dict patterns; line-level static analysis |

## Tests

| Test | Validates |
|---|---|
| `test_secret_in_url_query_fstring_api_key_fires` | f-string with `?api_key=` fires one HIGH finding |
| `test_secret_in_url_query_fstring_token_fires` | f-string with `?token=` and extra params fires |
| `test_secret_in_url_query_params_dict_fires` | `params={"secret": ...}` fires |
| `test_secret_in_url_query_silent_safe_params` | `?page=` and `?limit=` f-strings stay silent |
| `test_secret_in_url_query_silent_user_id` | `?user_id=` f-string stays silent |
| `test_secret_in_url_query_pragma_silences` | Pragma in file suppresses all findings |
| `test_secret_in_url_query_applies_gate` | Guard does not apply when `python` not in features |
| `test_secret_in_url_query_applies_with_python` | Guard applies when `python` in features |
| `test_secret_in_url_query_flags_annotated_query_param` | `password: str = Query(...)` fires `secret-query-param-declared` |
| `test_secret_in_url_query_flags_bare_query_param` | `api_key = Query(None)` (no type annotation) fires |
| `test_secret_in_url_query_silent_safe_query_param` | `page`/`limit` bound to `Query(...)` stay silent |
| `test_secret_in_url_query_flags_multiple_lines` | Regression: two violations in one file both fire (the stray `break` no longer stops the scan early) |

# Citations

[1] agentsec checklist item `6a-no-secret-in-url-query` (§6a)
[2] ASVS:14.2.1
[3] OWASP:A02
[4] OWASP:A09
[5] SOC2:CC6.7
