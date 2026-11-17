---
type: Guard
title: "tls-verify-disabled"
description: "Outbound HTTP client TLS certificate verification disabled."
timestamp: "2026-07-03T12:27:46+08:00"
guard_id: "tls-verify-disabled"
checklist_section: ["8"]
---

# Outbound HTTP client TLS certificate verification disabled

_Author — Marconi, 2026-07-03_

---

## The threat

`requests.get(url, verify=False)` / `httpx.Client(verify=False)` / `session.verify =
False` disable TLS certificate validation on outbound HTTP calls — the app now trusts
whatever server answers, with no check that it's actually the intended host. A
man-in-the-middle attacker anywhere on the network path (a compromised router, a rogue
Wi-Fi AP, a malicious proxy) can intercept and tamper with the response undetected.
CWE-295 (Improper Certificate Validation). Named as an explicit in-scope example in
LlamaIndex's own SECURITY.md ("Disabled TLS verification in external requests").

## Why this guard fits the stack

`verify=False` is one of the most common "I'll fix the cert error later" shortcuts —
typically added during local development against a self-signed cert, and left in when
the code ships:

```python
# added to get past a local dev cert error, never removed
resp = requests.get("https://internal-api.example.com/data", verify=False)
```

This is a general Python HTTP-client anti-pattern, not LLM-specific — it shows up
anywhere a Python app calls out to another service, including (but not limited to) LLM
API wrappers, webhook senders, and third-party integrations.

## Detection design

1. `applies()` gate — `"python" in profile.features` (general Python, not LLM-gated).
2. Scans every `.py` file under `python_scan_dirs(root, profile)` (file-wide pragma
   check first).
3. Fires on any of:
   - `requests.get/post/put/delete/patch/head/request(...)` or
     `httpx.get/post/put/delete/patch/head/request(...)` with `verify=False` on the
     same line (`_HTTP_CALL` + `_VERIFY_FALSE`);
   - `httpx.Client(...)` / `httpx.AsyncClient(...)` constructed with `verify=False`
     (`_CLIENT_CTOR` + `_VERIFY_FALSE`);
   - a `<var>.verify = False` attribute assignment — the `requests.Session()`
     post-construction idiom (`_ATTR_ASSIGN`, standalone — doesn't need the call regex
     since it's a separate statement);
   - `ssl._create_unverified_context()` — the documented stdlib bypass
     (`_SSL_UNVERIFIED_CTX`, rule `ssl-unverified-context`);
   - `<ctx>.check_hostname = False` on an SSLContext (`_CHECK_HOSTNAME_FALSE`, rule
     `check-hostname-false`);
   - `verify_mode`/`cert_reqs` set to `CERT_NONE` — SSLContext or urllib3
     PoolManager/HTTPSConnectionPool (`_CERT_NONE`, rule `cert-none`);
   - aiohttp `ssl=False` / the deprecated `verify_ssl=False` kwarg, scoped to files
     that import aiohttp (`_AIOHTTP_SSL_FALSE` + `_AIOHTTP_CUE`, rule
     `aiohttp-ssl-false`) — `ssl=`/`verify_ssl=` alone is a plausible kwarg name in
     unrelated code, so this form is only trusted when the file actually touches
     aiohttp (mirrors the `_HTTP_CUE` scoping used for `_ATTR_ASSIGN`).

   Added 2026-07-10 from a CodeQL `py/request-without-cert-validation` cross-check:
   that query's dataflow analysis reaches all of the above via `disablesCertificateValidation()`
   sinks; these four regexes approximate the same-line cases (each idiom sets the
   disabling flag directly next to its own construct, no cross-function flow needed).
4. Inline opt-out: `# security: allow-tls-verify-disabled` anywhere in the file.
5. Severity: `high` for every rule (each pattern IS the vulnerability once present, not
   just a signal of one — no "surfacing" hedge needed). Rule ids: `tls-verify-disabled/
   verify-false`, `/ssl-unverified-context`, `/check-hostname-false`, `/cert-none`,
   `/aiohttp-ssl-false`. Standards: `["CWE-295"]`.

**Express/Node extension (codeql `js/disabling-certificate-validation`):**
`applies()` also fires on `"express" in profile.features`, scanning `.js`/`.jsx`/`.ts`/`.tsx`
files (comment-stripped via `strip_js_comments`) independently of the Python path. Two
line-level patterns, both mapped to rule `reject-unauthorized-false`:
   - `rejectUnauthorized: false` in an `https`/`tls` options object — the Node analog of
     `verify=False`, fired unscoped (the option name is TLS-specific enough that a bare
     substring match carries negligible FP risk, unlike `.verify = False` on the Python side);
   - `process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"` — disables verification process-wide,
     not just for one client, so it gets its own message emphasizing the wider blast radius.

Both patterns share one rule id rather than two, since they're the same underlying CWE-295
class distinguished only by scope (one client vs. the whole process), not by mechanism —
unlike the five Python rules, which are genuinely different bypass mechanisms (a call kwarg,
an SSLContext flag pair, a urllib3 pool option, an aiohttp kwarg) each worth its own id for
independent tracking. JS/TS files use `// security: allow-tls-verify-disabled`.

**Relationship to `ml-model-provenance`:** that guard's `_VERIFY_FALSE` regex is
deliberately scoped to a model-download context only (its own comment: "A bare
verify=False against some unrelated API is out of scope here") — this guard is the
general-purpose sibling covering every OTHER outbound HTTP call. Both guards can fire
on the same line inside a model-download function; that's intentional, not duplication
(different rule ids, different remediation framing — one about download integrity, one
about TLS as a whole).

## When NOT to flag

- `verify=True` (the default, explicit or implicit) — the safe, common case.
- `verify="/path/to/ca.pem"` — the correct pattern for a genuinely private internal CA.
- `verify=False` passed to an unrelated function that happens to share the parameter
  name (only `requests.*`/`httpx.*` call sites and `.verify = False` attribute
  assignments are matched).
- An audited case, suppressed with `# security: allow-tls-verify-disabled` anywhere in
  the file.

## Tests

| Test | What it checks |
|---|---|
| `test_tls_verify_disabled_fires_on_requests_get` | Positive: `requests.get(url, verify=False)` fires HIGH (**verified_by**). |
| `test_tls_verify_disabled_fires_on_httpx_client_ctor` | Positive: `httpx.Client(verify=False, ...)` also fires. |
| `test_tls_verify_disabled_fires_on_session_attr_assign` | Positive: `session.verify = False` also fires. |
| `test_tls_verify_disabled_silent_on_verify_true` | FP-bait: `verify=True` → silent. |
| `test_tls_verify_disabled_silent_on_ca_bundle_path` | FP-bait: `verify="/path/to/ca.pem"` → silent. |
| `test_tls_verify_disabled_silent_on_unrelated_verify_false` | FP-bait: `verify=False` on an unrelated (non-requests/httpx) function → silent. |
| `test_tls_verify_disabled_pragma_silences` | Suppress pragma (file-wide) → silent. |
| `test_tls_verify_disabled_not_applies_without_python` | `applies()` gate false without `python`. |
| `test_tls_verify_disabled_fires_on_ssl_unverified_context` | Positive: `ssl._create_unverified_context()` fires. |
| `test_tls_verify_disabled_fires_on_check_hostname_false` | Positive: `ctx.check_hostname = False` fires. |
| `test_tls_verify_disabled_fires_on_cert_none_sslcontext` | Positive: `ctx.verify_mode = ssl.CERT_NONE` fires. |
| `test_tls_verify_disabled_fires_on_cert_none_urllib3` | Positive: `cert_reqs="CERT_NONE"` on a urllib3 pool fires. |
| `test_tls_verify_disabled_fires_on_aiohttp_ssl_false` | Positive: `aiohttp.ClientSession(connector=TCPConnector(ssl=False))` fires. |
| `test_tls_verify_disabled_silent_on_aiohttp_ssl_false_without_aiohttp_cue` | FP-bait: `ssl=False` kwarg to an unrelated function in a file that never imports aiohttp → silent. |
| `test_tls_verify_disabled_silent_on_cert_reqs_required` | FP-bait: `cert_reqs="CERT_REQUIRED"` → silent. |
| `test_tls_verify_disabled_applies_on_express` | `applies()` gate true with `express` in features. |
| `test_tls_verify_disabled_js_reject_unauthorized_fires` | Positive: `rejectUnauthorized: false` in `https.request(...)` options fires HIGH. |
| `test_tls_verify_disabled_js_node_tls_env_fires` | Positive: `NODE_TLS_REJECT_UNAUTHORIZED = "0"` fires HIGH. |
| `test_tls_verify_disabled_js_silent_on_reject_unauthorized_true` | FP-bait: `rejectUnauthorized: true` → silent. |
| `test_tls_verify_disabled_js_pragma_silences` | Suppress pragma (JS/TS file-wide) → silent. |

## Known bypasses

- **Indirection via a config variable**: `verify=SKIP_VERIFY` where `SKIP_VERIFY = False`
  is defined elsewhere — the guard matches the literal `False` on the call line, not a
  variable resolving to it.
- **`urllib3`'s lower-level API** (`urllib3.disable_warnings()` +
  `cert_reqs="CERT_NONE"`) is a different library surface entirely, not matched by this
  guard's `requests`/`httpx`-specific patterns.
- **Multi-line calls**: `requests.get(\n    url,\n    verify=False,\n)` spread across
  lines is invisible to the single-line regex.

## What this guard does NOT prove

A silent guard does not mean TLS is correctly verified everywhere — it only means no
*textually visible* `verify=False`/`.verify = False` was found across `requests`/
`httpx` call sites. It does not check custom HTTP clients, lower-level `ssl`/`urllib3`
APIs, or verification disabled via environment variables / config indirection.

## Relationship to SemgrepRunner

`agentsec/ai/semgrep-rules/python-llm.yaml` carries `agentsec-tls-verification-disabled`, which
covers 3 of this guard's 4 patterns (`requests.<m>(verify=False)`, `httpx.Client/AsyncClient(verify=False)`).
When Semgrep is installed a project sees both findings (guard + `check_id=semgrep`). This is the
intended guard-as-backup-when-Semgrep-is-absent posture (same as the `ml-model-provenance` overlap
noted above); the guard additionally catches the `<session>.verify = False` attribute-assignment
form the Semgrep rule does not.

# Citations

[1] agentsec checklist item `8-tls-verify-disabled` (§8)
