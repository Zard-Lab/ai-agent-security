---
type: Guard
title: "js-client-side-open-redirect"
description: "Client-side URL redirect built from tainted page-URL data."
timestamp: "2026-07-14T10:55:24+08:00"
guard_id: "js-client-side-open-redirect"
checklist_section: ["3a"]
standards: ["CWE-918", "OWASP:A01", "OWASP:A10"]
---

# Client-side URL redirect built from tainted page-URL data

_Author — 2026-07-14_

---

## The threat

Setting `window.location`/`location.href`/`location.replace()`/`location.assign()`
from the page's own tainted URL data (`location.search`, `document.URL`, or
`new URLSearchParams(location.search)`) — without validating the result against an
allow-list — lets an attacker craft a link whose query string redirects a visiting
user's browser to an attacker-controlled site: phishing, or leaking a session
token/referrer to the destination. CWE-079, CWE-116, CWE-601, OWASP:A01.

## Why this guard fits the stack

This is the CLIENT-SIDE counterpart to agentsec's existing `open-redirect` guard
(server-side: a backend handler reading a request parameter and issuing a redirect
response) — a genuinely different code surface (frontend JS reading its OWN current
URL in the browser, not a backend reading a request object), so it extends the same
`3a-open-redirect` checklist item rather than duplicating server-side detection.
Sourced from GitHub CodeQL's `js/client-side-unvalidated-url-redirection` query
(`ClientSideUrlRedirectQuery.ql` + `Customizations.qll`, verified against real
fetched source).

## Detection design

1. `applies()` gates on `"javascript"`/`"typescript"` language presence — broad,
   not framework-specific (matches the pattern `js-buffer-noassert` used: the
   sink APIs, `location`/`window.location`, are DOM globals with no framework
   dependency).
2. Scans `.js`/`.jsx`/`.ts`/`.tsx` files, skipping non-product paths.
3. Blanks whole-line `//` comments before matching.
4. A bidirectional, **single-line-only** regex: a redirect sink
   (`window.location =`/`location.href =`/`location.replace(`/`location.assign(`)
   and a tainted source (`location.search`/`document.URL`/`document.location.search`/
   `URLSearchParams(location.search)`) both on the SAME physical line, in either
   order. Deliberately conservative — a two-statement form (source assigned to a
   variable on one line, sink using that variable on the next) is not tracked, since
   that would require dataflow through a variable name, which is exactly the class
   of bug (a windowed multi-line search bleeding across statement/object boundaries)
   the `js-system-prompt-injection` guard built earlier this session hit and had to
   fix. Single-line matching cannot bleed across statements by construction.
5. Fires MEDIUM (matching the existing server-side `open-redirect` guard's severity
   for the same CWE-601 requirement), once per file, rule
   `js-client-side-open-redirect/tainted-location-redirect`, `["OWASP:A01",
   "CWE-601"]`.
6. Inline opt-out: `# security: allow-js-client-side-open-redirect`.

## When NOT to flag

A static redirect target (`window.location.href = "/dashboard"`) does not fire — no
tainted source is present. A doc comment merely mentioning the pattern does not fire.

## Tests

| Test | What it checks |
|---|---|
| `test_flags_location_href_from_url_search_params` | Planted violation: `location.href = new URLSearchParams(location.search).get(...)` inline — fires |
| `test_flags_location_replace_from_document_url` | Planted violation: `location.replace(document.URL...)` — fires |
| `test_flags_location_assign` | Planted violation: `location.assign(location.search...)` — fires |
| `test_silent_on_static_redirect` | FP-bait: a hardcoded redirect target — silent |
| `test_silent_when_source_and_sink_on_separate_lines` | Documents the deliberate single-line-only scope decision — silent, not a bug |
| `test_silent_on_comment_mentioning_pattern` | FP-bait: a doc comment describing the anti-pattern — silent |
| `test_pragma_suppresses` | Inline pragma silences the file |
| `test_not_applies_without_js_or_ts` | `applies()` is `False` without JS/TS |
| `test_nonproduct_path_skipped` | A file under `examples/` is skipped |
| `test_flags_fetch_from_url_search_params` | the planted violation: `fetch(... + new URLSearchParams(location.search).get(...))` — fires with the `request-forgery` rule |
| `test_flags_axios_get_from_location_search` | the planted violation: `axios.get(location.search)` — fires with the `request-forgery` rule |
| `test_flags_xhr_open_from_location_search` | the planted violation: `xhr.open('GET', location.search)` — the scoped XHR shape fires |
| `test_bypass_taint_through_callback_still_fires` | Adversarial: tainted value routed through a `setTimeout` callback before `fetch()`, all on one line — still fires (confirms the single-line, order-independent window holds for the new sinks) |
| `test_silent_on_static_fetch_url` | FP-bait: `fetch('/api/data')`, no tainted source nearby — silent |
| `test_static_fetch_and_tainted_navigation_do_not_cross_contaminate` | Adversarial FP-bait: a static-URL `axios.get(...)` in the same file as a genuinely tainted navigation sink — the static call stays silent and only the navigation finding fires (no cross-line bleed-through between sink families) |
| `test_silent_on_bare_axios_call` | FP-bait: documents the deliberate exclusion of bare `axios(...)` (config-object call) — silent |
| `test_silent_on_generic_dot_open_call` | FP-bait: a generic `.open(` call (e.g. a modal) whose first argument is not a quoted HTTP verb — the XHR precision scoping keeps this silent |
| `test_pragma_suppresses_request_forgery_sink` | Inline pragma silences a request-forgery-sink finding too (same pragma as the navigation sinks) |

## the request-forgery sink family (fetch/axios/XHR)

CodeQL has a second, closely related query: `javascript/ql/src/Security/CWE-918/
ClientSideRequestForgery.ql`. It reuses the exact same source/sink library as the
server-side SSRF query (`RequestForgeryCustomizations.qll` — the library `js_ssrf.py` is
built on), filtered to the client-side subset (`not src.isServerSide()`). The taint
SOURCE family is identical to the navigation case above (`location.search`/`document.URL`/
`URLSearchParams(location.search)`), but the SINK family is different: an outbound HTTP
call made BY THE BROWSER rather than a navigation — `fetch(...)`, `axios.<verb>(...)`, or
`XMLHttpRequest`'s `.open(method, url)` — built from the page's own tainted URL data. Risk:
a page that reads its own query string to build a `fetch()`/`axios` URL can be tricked via
a crafted link into sending a request to an attacker-chosen destination, potentially
leaking cookies/tokens/response data cross-origin — client-side request forgery / data
exfiltration, a genuinely different risk than the open-redirect/phishing risk of the
navigation sinks, so it gets its own rule slug and message rather than reusing the
navigation wording verbatim.

**Sink precision decisions:**

- `fetch(...)` and `axios.<verb>(...)` (get/post/put/delete/patch) are call-shaped sinks —
  the URL is (part of) the argument, the same shape `js_ssrf.py` already watches for the
  server-side case. Bare `axios(...)` (the config-object call form, e.g.
  `axios({url: ...})`) is deliberately **excluded** — mirrors `js_ssrf.py`'s own `_SINK`
  (verb-methods only, no bare `axios(`), keeping the two guards that share this source
  library consistent with each other.
- `.open(` is a widely-reused generic method name (modals, DB handles, file handles, ...),
  so matching it unscoped would be a precision disaster. Scoped instead by requiring the
  FIRST argument to literally be a quoted HTTP-verb string
  (`GET`/`POST`/`PUT`/`DELETE`/`PATCH`/`HEAD`/`OPTIONS`) followed by a comma — i.e. the
  `XMLHttpRequest.prototype.open(method, url)` call shape itself — rather than requiring
  the receiver be visibly `new XMLHttpRequest()` nearby. The receiver-based approach was
  considered and rejected: the realistic `const xhr = new XMLHttpRequest(); xhr.open(...)`
  idiom is two statements, which this guard's single-line-only design already can't track
  regardless of receiver scoping, so requiring the HTTP-verb-literal shape captures the
  single-line cases without the false-positive risk of matching any `.open(` call.

**Sink-family selection:** both sink families (navigation and request-forgery) are
searched independently per file; whichever source/sink pair occurs earliest in the file
wins the single per-file finding (same "one finding per file" convention as before, now
spanning both families so a file with both a navigation sink and a request-forgery sink
doesn't double-fire). They share the same suppression pragma
(a `// security: allow-js-client-side-open-redirect` comment; a string literal quoting the phrase
does not count, #424).

## Known bypasses

The dominant real-world case — a tainted value assigned to an intermediate variable
before being used in the redirect sink on a later line — is NOT caught (see the
deliberate single-line-only design decision above). A tainted value passed through a
helper function before reaching the sink is also not tracked.

## What this guard does NOT prove

Absence of a finding does not prove no client-side open redirect exists — only the
literal, same-line, inline-chained form is checked. The far more common
multi-statement form (assign to a variable, use it later) requires a real JS
dataflow engine agentsec does not have, and is explicitly out of scope rather than
approximated with a wider, riskier window.

**Known limitations (fixed, review #395):** the sink regex previously matched the `=` inside a
`===`/`==` comparison (`location.href === document.URL` false-positived) — fixed with the same
`=(?!=)` idiom `js_prototype_pollution.py` uses. `window.open()`/`window.navigate()` were
documented sinks but never implemented — both now fire for real. Comment stripping was
whole-line-`//`-only (a trailing same-line `//` comment survived) — now uses the shared,
string/regex-aware `strip_js_comments()` helper.

# Citations

[1] agentsec checklist item `3a-open-redirect` (§3a)
[2] CWE-918
[3] OWASP:A01
[4] OWASP:A10
