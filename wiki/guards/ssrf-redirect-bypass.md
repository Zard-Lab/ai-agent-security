---
type: Guard
title: "ssrf-redirect-bypass"
description: "An SSRF allow-list check fires once on a caller's URL, then a fetch call follows a redirect past it."
timestamp: "2026-10-06T00:00:00Z"
guard_id: "ssrf-redirect-bypass"
checklist_section: ["3a"]
standards: ["OWASP-ASI:ASI06", "CWE-918"]
---

# SSRF allow-list is bypassed by following a redirect past it

_Author — 2026-09-26_

---

## The threat

CVE-2026-41481: `langchain-text-splitters` < 1.1.2's
`HTMLHeaderTextSplitter.split_text_from_url()` validated the caller's URL against an
allow-list, then fetched it with `requests.get(url)` — which follows redirects by default.
A 302 response to `http://169.254.169.254/latest/meta-data/...` (the cloud metadata
endpoint) is followed transparently, and the metadata content is parsed back into the
returned document. CWE-918 (SSRF), OWASP-ASI:ASI06. The allow-list check is real and does
run — it is simply checking the wrong thing (the URL the caller supplied) against the
wrong guarantee (that the URL the socket ultimately connects to is the same one). Sourced
from `agent-audit-kit`'s `ssrf_redirect.py` (AAK-LANGCHAIN-SSRF-REDIR-001), verified
against the real repo source.

## Why it's often introduced

An allow-list check that runs and passes FEELS like the request is safe — redirect
semantics are an HTTP-client implementation detail most callers never think about, and
`requests`/`fetch`/`axios` all follow redirects by default without any explicit opt-in.

## Detection design

1. `applies()` returns `True` unconditionally.
2. Python: via `ast`, within each function body, walks `Call` nodes in source order; once
   a call to a recognized validator name (`validate_safe_url`, `validate_url`,
   `is_safe_url`, `ensure_safe_url`, `check_safe_url`, `ssrf_guard`, `is_url_safe`) is seen,
   the next call that is an HTTP fetch fires UNLESS it carries a keyword that disables
   redirects (`allow_redirects=False`, `follow_redirects=False`, `max_redirects=0`,
   `redirect="manual"|"error"`). A call is an HTTP fetch (shared classifier
   `agentsec/ssrf_fetch.py`) when its method is fetch-shaped (`.get`/`.post`/`.put`/
   `.delete`/`.patch`/`.head`/`.request`/`.send`/`.stream`/`urlopen`/`fetch`) AND it is made
   on a client-shaped receiver (`requests`, `httpx`, `aiohttp`, `urllib`, `session`,
   `client`, `http`, ... in any dotted segment, or a name bound in the file to a client
   constructor such as `with httpx.AsyncClient() as c`) AND its target is not a string
   literal. So `config.get("key")`, `response.headers.get(name)` and
   `result.metadata.get("title", url)` after a validator call are dict reads, not fetches.
   httpx's default is modelled: httpx does not follow redirects unless
   `follow_redirects=True` is passed (on the call or on the client it is made on), so an
   httpx call with neither is not a bypass; `requests` and `aiohttp` follow by default.
3. TS/JS: a `validateSafeUrl`/`validateUrl`/`isSafeUrl`/`ensureSafeUrl`/`ssrfGuard` call
   followed within a 2KB text window by a `fetch`/`axios`/`got`/`request` call fires unless
   `redirect: 'manual'|'error'` or `maxRedirects: 0` appears before the fetch call.
4. Inline opt-out: a `# security: allow-ssrf-redirect-bypass` comment (`// …` in JS/TS) anywhere
   in the file silences the file (a string literal quoting the phrase does not count, #424).
5. Severity HIGH, rule `ssrf-redirect-bypass/redirect-not-disabled`, standards
   `["OWASP-ASI:ASI06", "CWE-918"]`.
6. A version-floor entry (`langchain-text-splitters` >= 1.1.2, CVE-2026-41481) covers repos
   that depend on the vulnerable library directly rather than shipping the pattern in their
   own code.

## When NOT to flag

- Redirects explicitly disabled on the fetch call, in any of the recognized forms.
- No SSRF-guard-shaped call precedes the fetch in the same function — that is
  `ssrf-general`'s scope (no allow-list at all), not this guard's (an allow-list exists but
  is bypassed by a redirect).
- The validator and the fetch live in different, unrelated functions.

## Tests

| Test | What it checks |
|---|---|
| `test_validate_then_fetch_no_redirect_control_fires` | The CVE-2026-41481 shape — fires |
| `test_allow_redirects_false_is_safe` | `allow_redirects=False` — silent |
| `test_max_redirects_zero_is_safe` | `max_redirects=0` — silent |
| `test_no_validator_call_is_safe` | No preceding SSRF guard at all — out of scope, silent |
| `test_fetch_before_validator_in_different_function_is_safe` | Validator/fetch in different functions — silent |
| `test_ts_validate_then_fetch_fires` | TS/JS shape — fires |
| `test_ts_redirect_manual_is_safe` | `redirect: 'manual'` — silent |
| `test_dict_get_after_validator_is_not_a_fetch` (and two siblings) | `config.get("key")` / `response.headers.get(...)` / `result.metadata.get("title", url)` — silent |
| `test_requests_get_variable_still_fires`, `test_session_and_client_receivers_still_fire`, `test_receiver_bound_to_a_client_constructor_still_fires` | Real client-shaped fetches — fire |
| `test_httpx_default_does_not_follow_redirects` / `test_httpx_with_follow_redirects_true_still_fires` | The httpx default is modelled, an explicit opt-in is not excused |
| `test_pragma_suppresses_finding` | Inline pragma silences it |
| `test_ssrf_redirect_bypass_pragma_quoted_in_a_string_does_not_suppress`, `test_ssrf_redirect_bypass_pragma_quoted_in_a_string_does_not_suppress_ts`, `test_ssrf_redirect_bypass_ts_slash_comment_pragma_suppresses` | A pragma quoted in a string literal or quoted scalar does not suppress; a real comment still opts the file out (#424 E6); a `//` comment now opts a JS/TS file out too, and a TS string quoting either form does not |

## Known bypasses

- A dict-like receiver whose name is client-shaped and which is indexed by a variable
  (`session.get(key)` on a Flask `session`) still reads as a fetch. An httpx client reached
  through an unbound attribute (`self._client.get(url)`) is not known to be httpx, so it is
  still reported.

- Single-function scope (Python) / 2KB text-window scope (TS): a validator and fetch split
  across a helper-function boundary, or further apart than the window, are not correlated. The
  validator scan is not branch-aware either: a validator call in an `if` arm sets
  `validator_seen` for the REST of the function, including a mutually-exclusive `else` arm's own,
  unrelated, unvalidated fetch (confirmed on fastmcp's `jwt.py::_fetch_jwks`, whose `if
  self.ssrf_safe: ssrf_safe_fetch(...) else: client.get(...)` reads the `if` arm's safe fetch as
  covering the `else` arm's plain one). Tracking validator calls per-`ast.If`-body rather than as
  one flat, ordered list would close this; not attempted.
- The validator-name and fetch-name vocabularies are fixed lists; a differently-named
  validator or an uncommon HTTP client method name is invisible.
- A `Session`-level redirect configuration set elsewhere (rather than as a per-call keyword)
  is not traced.
- `follow_redirects=False` on an httpx-API-compatible client under an unrecognized module name
  (not literally `httpx.*`) is trusted only when set EXPLICITLY on that constructor call; absence
  is not assumed safe the way it is for a real `httpx.*` constructor, since an unrecognized
  library's own default is unknown.

## What this guard does NOT prove

Silence does not prove the target URL is actually safe end-to-end — a DNS-rebind-based
bypass of the SAME allow-list (a different mechanism entirely, see the sibling
`ssrf-dns-rebind-toctou` guard) can still succeed even when redirects are correctly
disabled.

# Citations

[1] agentsec checklist item `3a-ssrf-redirect-bypass` (§3a)
[2] CVE-2026-41481 (langchain-text-splitters < 1.1.2), GHSA-fv5p-p927-qmxr
[3] CWE-918, OWASP-ASI:ASI06
[4] agent-audit-kit `ssrf_redirect.py`, rule AAK-LANGCHAIN-SSRF-REDIR-001
