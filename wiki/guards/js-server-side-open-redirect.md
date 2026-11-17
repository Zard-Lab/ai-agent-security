---
type: Guard
title: "js-server-side-open-redirect"
description: "Server-side redirect target built from request input (open redirect)."
timestamp: "2026-08-09T11:23:54+08:00"
guard_id: "js-server-side-open-redirect"
checklist_section: ["3a"]
standards: ["CWE-918", "OWASP:A01", "OWASP:A10"]
---

# Server-side redirect target built from request input (open redirect)

_Author — 2026-08-09_

---

## The threat

`res.redirect(req.query.target)` in an Express handler lets an attacker send
`?target=https://evil.example` and have the SERVER itself issue an HTTP 3xx
response pointing the victim's browser at an attacker-controlled site. WHO:
any unauthenticated caller of the route (no privilege required beyond hitting
a public endpoint). WHAT effect: phishing (the redirect chain visibly starts
at the trusted domain), OAuth-authorization-code / token theft (a redirect_uri
or `next` param that isn't allow-listed lets an attacker harvest a token meant
for the legitimate app), or a filter bypass built on "we redirected them, so
it must be us." CWE-601, OWASP:A01.

The same class of bug is also reachable by writing the `Location` response
header directly — `res.set('Location', req.query.target)` — bypassing
`res.redirect()` entirely but producing the identical browser-visible 3xx
redirect.

## Why it's a real, pre-existing gap (not a hypothesis)

Checklist item `3a-open-redirect` already lists `applies_when: ["python",
"javascript", "typescript"]` and `status: covered`. Its only JS-side
`check_id` before this guard was `js-client-side-open-redirect` — which is
**client-side only**: it detects a browser reading its own current URL
(`window.location` set from `location.search`), a genuinely different code
surface from a backend handler reading REQUEST data server-side. There was
zero coverage for `res.redirect(req.query.x)` — this guard closes that gap
and corrects the checklist's own overclaim. The checklist-integration pass
should add this guard's `check_id` alongside the existing `open-redirect` /
`js-client-side-open-redirect` ones on `3a-open-redirect` — **not** create a
new checklist item; this is the same requirement the item already claims to
cover, just genuinely covering it now for the server-side JS surface.

## Why this guard fits the stack

Express route handlers routinely redirect based on a `next`/`returnUrl`/
`redirectTo` query or body parameter (post-login redirect, a "continue
where you left off" flow, a legacy-URL shim) — exactly the kind of
static, textual, per-line pattern agentsec's zero-dependency guard model
is built for:

```js
app.get('/login/callback', (req, res) => {
  const next = req.query.next;
  res.redirect(next);
});
```

This guard is the Express-side counterpart to the existing Python
`open_redirect.py` guard (§3a's other `check_id`), mirrored for
severity/message/sink philosophy rather than re-derived — see that guard's
own docstring/design doc for the shared reasoning.

## Detection design

1. **`applies()` gate** — `"express" in profile.features` (same convention
   as `js_regex_injection_dos.py`).
2. **Files scanned** — `.js`/`.jsx`/`.ts`/`.tsx` via `iter_files`, skipping
   non-product paths (`is_nonproduct_path` — tests/examples/fixtures/migrations).
3. **Sinks** (`_SINK`, matched per physical line, on `strip_js_comments`-blanked
   code — comments blanked, **string content kept intact** so the Location-header
   check below can read a literal header-name string):
   - `res.redirect(...)` — the redirect-target argument is always the **last**
     positional argument, whether called as `res.redirect(url)` or
     `res.redirect(status, url)` (Express's optional leading-status-code form).
   - `res.set(...)` / `res.header(...)` / `res.setHeader(...)` — recognized as a
     redirect sink only when the first argument is the literal string `'Location'`
     (case-insensitive, matching HTTP header-name semantics); the target is then
     the second argument.
4. **Argument extraction** (`_call_args`) — bracket-balanced, top-level-comma
   split of the sink call's arguments, from the matched `(` to its matching `)`.
   An unbalanced (multi-line) call degrades to the rest of the line — the same
   single-line-only tradeoff every sibling JS guard here accepts.
5. **Taint source** (`_UNTRUSTED`) — a direct request-derived property access:
   `req.query.target` (dot) or `req.query["next"]` / `req.query[key]` (bracket),
   restricted to `req.query`/`req.params`/`req.body` only.
6. **File-scoped variable taint** (`_ASSIGN_FROM_UNTRUSTED`) — a
   `const`/`let`/`var NAME = ...` assignment anywhere in the file whose RHS
   contains one of the direct accessors above taints `NAME`; a later (or
   earlier — order-independent) bare use of `NAME` as a sink's target then
   fires. This is the **same file-scoped, order-independent taint
   simplification `js_regex_injection_dos.py`'s docstring documents and
   justifies**: agentsec has no JS AST/dataflow engine, so "a variable
   assigned from `req.*` anywhere in the file counts as tainted" is the
   accepted conservative tradeoff for this class of guard.
7. **Suppress pragma** — `// security: allow-js-server-side-open-redirect`,
   checked per-line (on the comment-only view of the line, #424, so the pragma itself, which
   lives in a comment, is visible).
8. **Severity / rule / standards** — MEDIUM (matches `open_redirect.py`'s
   severity for the same CWE-601 checklist item),
   `rule="js-server-side-open-redirect/request-derived-redirect-target"`,
   `standards=["OWASP:A01", "CWE-601"]`.

### Why `req.session` is deliberately excluded from the taint source set

`req.session.*` (and, by the same reasoning, `req.cookies.*`/`req.headers.*`)
is **not** treated as untrusted here, even though session/cookie data
ultimately originates from the client in some loose sense. The distinction
that matters for this guard: `req.query`/`req.params`/`req.body` are read
directly off the CURRENT request with no intermediate validation — literally
whatever the attacker put in the URL/body this time. `req.session` is
populated by the app's own session middleware, generally from previously
validated/authenticated state (e.g. a `returnUrl` captured and stored at
login time, or a value the server itself wrote into the session earlier).
Treating `req.session.returnUrl` as equivalent to `req.query.returnUrl` would
misclassify a common, legitimate post-login-redirect idiom
(`res.redirect(req.session.returnUrl)`) as a vulnerability. A real app that
writes attacker-controlled data into `req.session` unvalidated has a
different bug (session-data integrity), out of scope for this guard.

## When NOT to flag (and the pragma)

- `res.redirect('/dashboard')` — a static internal path, no request signal → silent.
- `res.redirect('https://example.com/fixed-path')` — a fully static external
  URL → silent (a hardcoded destination is an app decision, not user input).
- `res.redirect(req.session.returnUrl)` — session-sourced, not directly
  request-derived → silent (see rationale above).
- `res.set('Content-Type', req.query.x)` — a header write, but not to
  `Location` → silent (not a redirect sink at all).
- A commented-out line → silent (`strip_js_comments` blanks it before matching).
- An audited, allow-listed case → suppress with
  `// security: allow-js-server-side-open-redirect`.

## Tests

| Test | What it checks |
|---|---|
| `test_flags_direct_query_param` | True positive: `res.redirect(req.query.target)` fires MEDIUM with the correct rule id. |
| `test_flags_bracket_notation_query_param` | True positive: `res.redirect(req.query["next"])` (bracket notation) fires. |
| `test_flags_variable_assigned_from_req_body_earlier_in_file` | True positive: a variable assigned from `req.body.url` earlier in the file, used bare in `res.redirect(theVar)` later — file-scoped taint. |
| `test_flags_location_header_via_res_set` | True positive: `res.set('Location', req.query.target)` fires. |
| `test_silent_on_static_dashboard_path` | FP-bait: `res.redirect('/dashboard')` (static internal literal) stays silent. |
| `test_silent_on_static_fixed_url` | FP-bait: `res.redirect('https://example.com/fixed-path')` (static external literal) stays silent. |
| `test_pragma_silences` | Pragma: inline suppress comment silences the finding. |
| `test_not_applies_without_express` | Feature gate: `applies()` is `False` when `"express"` is not in `profile.features`. |
| `test_flags_redirect_with_leading_status_code_argument` | Adversarial/bypass check: `res.redirect(302, req.query.target)` — the tainted URL is the SECOND positional argument (Express's optional leading status code) — still fires, since the target is always taken as the last argument. |
| `test_silent_on_req_session_source` | Adversarial/FP check: `res.redirect(req.session.returnUrl)` stays silent — `req.session` is server-controlled, not a recognized untrusted source (see rationale above). |

## Known bypasses

| Bypass | Description |
|--------|-------------|
| Multi-hop assignment | `const a = req.query.x; const b = a; res.redirect(b);` — only one level of direct-accessor assignment is tracked; a second intermediate variable (`b` assigned from `a`, not from `req.*` directly) breaks the chain. |
| Cross-file taint | Request input extracted in one file (e.g. a shared helper or middleware) and passed as a function argument to a handler in another file that calls the sink — the guard is file-scoped and won't join them. |
| Object/array destructuring | `const { target } = req.query; res.redirect(target);` — the assign-from-untrusted regex expects a direct `= ...req.query...` expression, not a destructuring binding. |
| Concatenation / template literals reaching the sink through a variable | `const url = base + req.query.x; res.redirect(url);` — `url`'s assignment does contain a direct accessor match (`_UNTRUSTED` searches the whole RHS), so this particular case is actually caught; the gap is specifically the destructuring/multi-hop/cross-file forms above. |
| Multi-line sink calls | `res.redirect(\n  req.query.target\n);` — detection is single-line; a sink and its argument split across physical lines is not matched. |
| `res.set({ Location: req.query.x })` (object form) | Express's `res.set(fields)` object-argument overload is not recognized — only the two-positional-argument `res.set('Location', value)` form is. |
| Non-Express response objects / renamed variable | Sink matching is literal on the identifier `res.` — a response object bound to a different name (`function handler(request, response) { response.redirect(...) }`) is not recognized. |
| Other request-derived signal names | Only `req.query`/`req.params`/`req.body` count as untrusted; a value read from `req.headers`/`req.cookies`, or destructured before reaching the guard's view, is not tracked. |

## What this guard does NOT prove

A silent guard does not prove the app validates or allow-lists redirect
targets anywhere else in its dependency graph (a shared validation
middleware, a wrapper around `res.redirect`, or manual checking done
elsewhere in the same handler before the sink line). It only proves that,
within a single file, no `req.query`/`req.params`/`req.body`-derived value
(direct, or one-hop-assigned to a bare variable, file-scoped and
order-independent) reaches `res.redirect(...)` or a `Location`-header write
as its target with no visible transformation. Indirection through a variable
chain, destructuring, cross-file dataflow, or a multi-line call all evade
detection (see Known bypasses above) — absence of a finding is not proof of
open-redirect-freedom.

## Checklist items flipped

| ID | Before | After | Reason |
|----|--------|-------|--------|
| `3a-open-redirect` | `covered` on the strength of `open-redirect` (Python) + `js-client-side-open-redirect` (client-side JS only) — no server-side JS/Express detection existed | `covered`, now genuinely — add `js-server-side-open-redirect` to `check_ids` alongside the existing two | The item's `applies_when` already claimed `javascript`/`typescript`; this guard is what makes that claim true for the server-side Express surface, correcting a real overclaim rather than adding a new requirement. |

# Citations

[1] agentsec checklist item `3a-open-redirect` (§3a)
[2] CWE-918
[3] OWASP:A01
[4] OWASP:A10
