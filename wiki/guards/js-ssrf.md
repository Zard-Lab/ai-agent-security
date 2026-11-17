---
type: Guard
title: "js-ssrf"
description: "JS/Node HTTP client call with a request-derived URL (SSRF)."
timestamp: "2026-07-15T10:28:26+08:00"
guard_id: "js-ssrf"
checklist_section: ["3a"]
standards: ["CWE-918", "OWASP:A10"]
---

# JS/Node HTTP client call with a request-derived URL (SSRF)

_Author — 2026-07-15_

Flags a JS/Node HTTP client call whose URL is built from a template-literal interpolation or
`+` concatenation carrying request-derived input. This is the JS/Node counterpart to the existing
Python-only `ssrf-general` guard — before this guard, agentsec had zero JS/Node SSRF detection
(`ssrf_general.py`'s `applies()` gates on `"python" in profile.features` only). CWE-918, OWASP:A01.

---

## The threat

Server-Side Request Forgery on the Node side: `fetch(\`https://api.example.com/${req.query.target}\`)`
with attacker-controlled `req.query.target` lets the attacker point the server's own outbound HTTP
call at internal services (`http://10.0.0.5/admin`) or the cloud metadata endpoint
(`http://169.254.169.254/latest/meta-data/iam/...`), exfiltrating IAM credentials or reaching
network-internal systems the attacker cannot address directly. Reachable by any unauthenticated
caller of the route that builds the outbound URL from request data — WHO: an external attacker,
WHAT privilege: none beyond hitting the public route, WHAT effect: server-side pivot / credential
theft via the metadata endpoint. CWE-918 (Server-Side Request Forgery), OWASP:A01
(Broken Access Control — treated here as the "the server acts as an unauthorized proxy for the
caller" framing agentsec uses for its other SSRF guard's sibling entries).

## Why this guard fits the stack

The flagship stack (FastAPI + React + Node-adjacent tooling / any Node backend or BFF layer in the
`9_Agent_SaaS`-shaped app) frequently proxies or fans out requests server-side — a webhook relay, an
internal microservice call, a "fetch this resource on the user's behalf" endpoint. The Node
ecosystem's idiomatic HTTP surface (`fetch`, `axios`, the built-in `http`/`https` modules) makes it
easy to build the target URL directly from `req`/`params`/`query`/`body` without an allow-list:

```js
app.get('/proxy', (req, res) => {
  fetch(`https://api.example.com/${req.query.target}`);
});
```

## Detection design

1. **`applies()` gate** — `"javascript" in profile.features or "typescript" in profile.features`
   (same convention as `js_client_side_open_redirect.py` / `js_insecure_download_sensitive_file.py`).
2. **Files scanned** — `.js`/`.jsx`/`.ts`/`.tsx` via `iter_files`, skipping non-product paths
   (`is_nonproduct_path` — tests/examples/fixtures/migrations) the same way every other JS guard does.
3. **Sinks** (regex `_SINK`, matched per physical line): `fetch(`, `axios.get(`/`post(`/`put(`/
   `delete(`/`patch(`, `http.request(`/`http.get(`, `https.request(`/`https.get(`.
4. **URL argument extraction** — `_first_arg()` (bracket-balance scan, ported from
   `ssrf_general.py::_first_arg`) pulls the sink's first call argument up to the first depth-0 comma.
5. **User-controlled test** (`_user_controlled_url`) — fires only when the extracted argument BOTH:
   - contains a template-literal interpolation (`_TEMPLATE_INTERP`: `\$\{`) **or** a `+` string/
     template-literal concatenation (`_CONCAT`: a quote/backtick adjacent to `+`), **and**
   - that argument text also matches `_REQUEST_SIGNAL` — a `req.`/`request.`/`params.`/`query.`/
     `body.` reference.

   Both conditions are required (not just concat/interpolation alone) — this is the precision knob
   that keeps the guard from firing on a config-built URL.
6. **Suppress pragma** — `// security: allow-js-ssrf`, checked whole-file (`_PRAGMA in text`, same
   convention as `js_insecure_download_sensitive_file.py` / `js_prototype_pollution.py` /
   `js_system_prompt_injection.py`) and also per-line, plus whole-line `//` comments are skipped
   before matching (`_COMMENT_LINE`).
7. **Severity / rule / standards** — HIGH, `rule="js-ssrf/request-derived-url"`,
   `standards=["OWASP:A01", "CWE-918"]` — pulled verbatim from the guard's `Finding(...)` call.

## When NOT to flag (and the pragma)

- `fetch(\`https://api.example.com/${API_VERSION}\`)` — a template literal built from a config
  constant, no request signal → silent.
- `fetch("https://api.example.com/static")` — fully static literal → silent.
- `fetch(url)` — a bare variable with no template/concat signal on the sink line → silent (by
  design, same conservative tradeoff `ssrf_general.py` makes for the bare-variable case).
- A commented-out line (`// fetch(...)`) → silent.
- An audited, allow-listed internal call → suppress with `// security: allow-js-ssrf`.

## Tests

| Test | What it checks |
|---|---|
| `test_flags_fetch_template_literal_query_param` | `fetch` + template literal interpolating `req.query.target` fires HIGH, correct rule/standards |
| `test_flags_axios_get_concatenated_host` | `axios.get` + `+`-concatenation of `req.body.host` fires |
| `test_flags_axios_post_params_derived` | `axios.post` + template literal interpolating `params.id` fires |
| `test_flags_http_request_body_derived` | `http.request` + template literal interpolating `body.upstreamHost` fires |
| `test_silent_on_template_literal_config_constant` | FP-bait: template literal from a config constant (`API_VERSION`), no request signal → silent |
| `test_silent_on_fully_static_url` | Fully static URL string → silent |
| `test_silent_on_bare_variable_no_signal` | Bare variable URL with no template/concat signal → silent (conservative by design) |
| `test_silent_on_comment_mentioning_pattern` | A `//`-commented line containing the anti-pattern text does not fire |
| `test_pragma_suppresses` | `// security: allow-js-ssrf` suppresses an otherwise-firing line |
| `test_not_applies_without_js_or_ts` | `applies()` is `False` with no JS/TS feature |
| `test_applies_with_typescript_only` | `applies()` is `True` with only `typescript` (not just `javascript`) |
| `test_nonproduct_path_skipped` | A finding under a non-product path (`examples/`) is suppressed |

## Known bypasses (honest limits)

- **Bare-variable SSRF.** `const url = req.query.target; fetch(url);` does not fire — the sink line
  itself carries no template/concat + request signal (indirection through a variable name is not
  tracked, the same tradeoff `ssrf_general.py` documents for its Python sinks).
- **Multi-line calls.** A call whose URL argument spans multiple physical lines, or an
  `axios.create({...})` instance's method call, is not matched — detection is single-line and keys
  on the literal sink names (`fetch`/`axios.<verb>`/`http(s).<verb>`).
- **Indirect request signal.** A URL built from a variable that was itself assigned from
  `req.something` several statements earlier is not matched — same single-line, no-dataflow
  limitation as the sibling `js-client-side-open-redirect` guard.
- **Non-standard client naming.** A renamed/aliased import (`import ax from 'axios'; ax.get(...)`)
  or a wrapped fetch helper (`myFetch(...)`) is not recognized — sink names are matched literally.
- **Other request-derived signal names.** Only `req.`/`request.`/`params.`/`query.`/`body.` count as
  a request signal; a destructured local (`const { target } = req.query; fetch(...${target})`) is
  not tracked back to its source.

## What this guard does NOT prove

It catches a request-derived, dynamically-built fetch URL in source; it does not prove the target
host is unvalidated, nor that an allow-listed call is safe. Absence of a finding is not proof of
SSRF-freedom — host allow-listing plus RFC-1918/link-local/metadata-IP blocking (resolve then check)
is still the actual control. Indirection through a variable, a wrapped HTTP client, or a renamed
import all evade detection (see Known bypasses above).

# Citations

[1] agentsec checklist item `3a-js-ssrf` (§3a)
[2] CWE-918
[3] OWASP:A10
