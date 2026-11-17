---
type: Guard
title: "js-cors-wildcard"
description: "Express/Node CORS response wildcarded to any origin."
timestamp: "2026-10-21T00:00:00Z"
guard_id: "js-cors-wildcard"
checklist_section: ["6a"]
standards: ["OWASP:A05", "SOC2:CC6.6"]
---

# Express/Node CORS response wildcarded to any origin

## Threat

An Express handler that sets `Access-Control-Allow-Origin: *` — whether directly
via `res.set`/`res.header`/`res.writeHead`, or via the `cors` npm package wired
to `app.options('*', cors())` — accepts cross-origin requests from any website.
In an app that relies on cookies or bearer tokens for auth, this means any
malicious page can make an authenticated request on the logged-in user's
behalf and read the response. This is the exact same CORS/CSRF misconfiguration
(OWASP:A05, CWE-346) the existing `cors-wildcard` guard already checks for
FastAPI's `CORSMiddleware` — `js-cors-wildcard` is the Express-side equivalent.

## Why this guard fits the stack

Express is now a real, guard-backed `backend_framework`/feature in agentsec
(promoted this session from a named `uncovered_stack`), and CORS wildcarding
is a well-known, static, textual pattern in Express apps — exactly the kind of
check agentsec's zero-dependency guard model is built for. The rule set is
adapted from njsscan's `header_cors_star.yaml` (`ajinabraham/njsscan`, real
Semgrep-syntax AST rules — `generic_cors` + `express_cors`), verified against
the actual fetched source rather than taken from a description of it.

## Detection design

1. `applies()` gates on `"express" in profile.features` (set by `detect.py`
   independent of which backend framework "wins" `backend_framework` — a
   polyglot repo with both FastAPI and Express present still gets the
   `"express"` feature, so this guard isn't accidentally starved by
   `backend_framework`'s single-valued fastapi-first priority).
2. Scans all `.js`, `.jsx`, `.ts`, `.tsx` files (`iter_files`), line by line.
3. Skips a file entirely if the pragma comment is present anywhere in it (a string literal quoting it
   does not count, #424); skips
   an individual line if the pragma is on that same line.
4. Three independent patterns, each mapped to its own rule slug:
   - `_OPTIONS_CORS` — `app.options('*', cors(...))`, the `cors` npm package
     wired to a wildcard preflight route.
   - `_HEADER_CALL_WILDCARD` / `_HEADER_OBJECT_WILDCARD` — a direct
     `res.set`/`res.header`/`res.writeHead` call naming the
     `Access-Control-Allow-Origin` header (case-insensitive) with a literal
     `'*'` value, either as two positional args or inside an object literal.
   - `_CORS_CALL` + `_cors_config_object` + `_ORIGIN_PERMISSIVE` /
     `_CREDENTIALS_FALSE` — an **object-scoped** scan of a `cors({...})`
     config argument for `origin: true`/`origin: null`, unless `credentials:
     false` also appears in the same object (see below).
5. Every match must be live code, tested with `js_code_matches` on the anchor
   mask (#1055): a call (`.options(`, `.set(`, `.header(`, `.writeHead(`,
   `cors(`) on its first `(`, a config key (`origin:`, `credentials:`) or an
   Origin read (`req.headers.origin`) on its first character. Never on the
   `'*'` or header-name literal, which the patterns read inside strings on
   purpose. A shape spelled out in a string does not count, and one nested in
   a `${...}` substitution does. The multi-line object-header scan drops a
   string-anchored match without consuming its span, so a quoted `.set(` cannot
   swallow a real `writeHead` after it.

### Regexes used

```python
_OPTIONS_CORS = re.compile(r"""\.options\s*\(\s*['"]\*['"]\s*,\s*cors\s*\(""")

_HEADER_CALL_WILDCARD = re.compile(
    r"""\.(?:set|header)\s*\(\s*['"]access-control-allow-origin['"]\s*,\s*['"]\*['"]""",
    re.IGNORECASE,
)

_HEADER_OBJECT_WILDCARD = re.compile(
    r"""\.(?:set|writeHead)\s*\([^{]{0,80}\{[^}]{0,200}['"]?access-control-allow-origin['"]?\s*:\s*['"]\*['"]""",
    re.IGNORECASE | re.DOTALL,
)

_CORS_CALL = re.compile(r"\bcors\s*\(")
_ORIGIN_PERMISSIVE = re.compile(r"\borigin\s*:\s*(?:true|null)\b")
_CREDENTIALS_FALSE = re.compile(r"\bcredentials\s*:\s*false\b")
```

`_OPTIONS_CORS`/`_HEADER_CALL_WILDCARD` are matched per line; **`_HEADER_OBJECT_WILDCARD` is matched
against the whole (comment-blanked) file** via `finditer`, so a Prettier-formatted multi-line object
literal — `res.writeHead(200, {\n  'Access-Control-Allow-Origin': '*',\n})` — fires (its `[^}]`
spans newlines). Reporting the line of the `.set`/`.writeHead` call start. (PR #407 review: under the
former per-line scan the `DOTALL`/multi-line span was dead — the common formatted shape was missed.)

Both header-call variants map to the same rule slug (`response-header-wildcard`),
mirroring njsscan's own grouping — its `express_cors` rule bundles all 4 call
shapes (`res.set`, `res.header`, `res.writeHead`, both arg styles) under one id.

### `origin: true`/`origin: null` — the permissive-config shape (`permissive-origin-config`)

Verified against GitHub CodeQL's `javascript/ql/src/Security/CWE-942/
CorsPermissiveConfiguration.ql` + `CorsPermissiveConfigurationCustomizations.qll`:
the `cors` npm middleware also accepts `origin: true` (reflect whatever
`Origin` header the request sent — effectively "allow any origin," without
the literal `'*'` string ever appearing) and `origin: null`. This is a distinct
configuration surface from the literal-`'*'` shapes above and needed its own
pattern. CodeQL's real logic treats it as sanitized ONLY when `credentials:
false` is set in the same config object — `origin: true` + credentials
enabled is the genuinely dangerous combination (cookies/auth headers get sent
cross-origin to an attacker-controlled reflected origin); `origin: true` +
`credentials: false` cannot carry cookies/auth, so CodeQL (and this guard)
treats that combination as safe.

`origin:` and `credentials:` are typically on separate lines within the same
`cors({...})` call (Prettier-formatted), so a single-line regex can't see
both at once. Instead, `_CORS_CALL` finds each `cors(` call site, and
`_cors_config_object` does a small bracket-counting scan to capture the
`{...}` argument as one blob (returns `None` for `cors()` with no args or
`cors(configVar)` — a variable this guard can't resolve). `_ORIGIN_PERMISSIVE`
and `_CREDENTIALS_FALSE` are then both checked against that one blob, over
the whole (comment-blanked) file via `finditer` — not per line — the same
approach `_HEADER_OBJECT_WILDCARD` already uses for a multi-line object
literal. The reported line is the line of the `origin:` key itself.

## Severity rationale

**HIGH**, matching the existing FastAPI `cors-wildcard` guard: a wildcarded
CORS response header is a direct, unconditional exposure with no further
preconditions — any origin can read the response, and in an app with
cookie/token auth, any page can act as the user.

## When NOT to flag

An explicit origin allowlist — `cors({ origin: ["https://app.example.com"] })`,
or a handler that echoes back a specific validated origin string rather than
a literal `'*'` — never matches the literal-`'*'` patterns, since all three
require the literal `'*'` character in the matched position. `origin: true`/
`origin: null` paired with `credentials: false` in the same `cors({...})`
object is also not flagged (see above) — CodeQL's own sanitizing condition.

## Known bypasses / false negatives

| Bypass | Description |
|--------|-------------|
| Dynamic/computed wildcard | `res.set('Access-Control-Allow-Origin', someVar)` where `someVar` is computed to `'*'` at runtime — the guard matches on the literal `'*'` token and won't recognize an indirect assignment. |
| `cors()` with no `origin` option (defaults to `*`) | The `cors` middleware defaults to wildcarding when no `origin` option is passed at all (`app.use(cors())`) — the guard only recognizes the explicit `app.options('*', cors())` preflight-route shape, the direct header-set calls, and an explicit `origin: true`/`null`, not a bare default-config `cors()` call with no options object at all. |
| Cross-file header helper | A shared `setCorsHeaders(res)` helper defined in one file, the wildcard literal only visible there, called from many route files with no local evidence — the guard is file-scoped and only flags the file containing the literal. |
| JS/TS anchoring (#1055) | Every rule, and the `credentials: false` credit, counts only when its anchor is live code (`js_code_matches` on the anchor mask). A `'credentials: false'` spelled out in a note string no longer clears a permissive `cors({ origin: true })`, and a CORS shape spelled out in a docs or log string no longer fires; a real one nested in a `${...}` substitution still counts, and every match is visited, so a quoted copy earlier on the line or in the object cannot hide a real one after it. The `cors(` anchor test is defence in depth: `_cors_config_object` needs a `{` right after the `(`, so a quoted `cors(` always carries its config inside the same string, where the key test already drops it. Accepted residual: `_cors_config_object` still counts braces without quote awareness (a `'}'` inside the config ends the blob early), unchanged by #1055. Residual: the anchor mask inherits the #543 sub-lexer residual: a `{` inside a regex or comment in one `${...}` substitution, then a `}` in a later one, rebalances the frame, so the code between the two reads as template text and an anchor there is not code (the accepted trade pinned by `test_strip_js_comments_anchor_mask_balanced_desync_masks_code_accepted_trade`). A CORS shape there is missed (errs toward silence), and a `credentials: false` there no longer clears (errs toward firing). |
| `cors(configVar)` — config built elsewhere | `_cors_config_object` requires a literal `{...}` immediately after `cors(` — a config object assigned to a variable and passed by reference (`const opts = { origin: true }; app.use(cors(opts));`) is invisible to this guard. |

## What this guard does NOT prove

A silent guard does not prove the app's CORS posture is fully hardened: it
does not check for missing `Vary: Origin` headers, overly broad
`Access-Control-Allow-Methods`/`-Headers` wildcards, or a bare `cors()` call
with no options object at all (see bypass table above). It only proves that
none of the checked shapes — a literal `'*'` origin value, or an
`origin: true`/`origin: null` config without `credentials: false` — appear in
a file where "express" is a detected feature.

## False positive scenarios

| Scenario | Why it fires | Mitigation |
|----------|-------------|------------|
| Literal `'*'` in a **comment** | No longer fires — the file is comment-blanked via `strip_js_comments` before matching (PR #407 review). | n/a (fixed). |
| A CORS shape spelled out in a **string** (docs, a log line) | No longer fires: every match must be anchored in live code (#1055). | n/a (fixed). |
| Intentional fully-public, unauthenticated endpoint | A route that serves genuinely public data with no auth may legitimately want any origin to read it. | Add the pragma after confirming there is no session/token-auth exposure on that route. |

## Checklist items flipped

| ID | Before | After | Reason |
|----|--------|-------|--------|
| `6a-cors-restricted` | `applies_when: ["fastapi"]`, `check_ids: ["cors-wildcard"]` | `applies_when: ["fastapi", "express"]`, `check_ids: ["cors-wildcard", "js-cors-wildcard"]` | Extended (not a new item) — same misconfiguration, same fix, now covered for Express alongside FastAPI. |

## Tests

| Test | Validates |
|------|-----------|
| `test_js_cors_wildcard_flags_options_cors` | True positive: `app.options('*', cors())` fires `js-cors-wildcard/explicit-options-wildcard`. |
| `test_js_cors_wildcard_flags_res_set_header` | True positive: `res.set('Access-Control-Allow-Origin', '*')` fires `js-cors-wildcard/response-header-wildcard`. |
| `test_js_cors_wildcard_flags_writehead_object_literal` | True positive: `res.writeHead(200, {'Access-Control-Allow-Origin': '*', ...})` fires `js-cors-wildcard/response-header-wildcard`. |
| `test_js_cors_wildcard_silent_with_explicit_origin_allowlist` | False positive guard: an explicit origin string (allowlist config + matching header value) — no finding. |
| `test_js_cors_wildcard_pragma_silences` | Pragma: inline suppress comment silences the finding. |
| `test_js_cors_wildcard_not_applies_without_feature` | Feature gate: guard returns `[]`/`applies()` is `False` when `"express"` is not in `profile.features`. |
| `test_js_cors_wildcard_flags_origin_true` | True positive: `cors({ origin: true })` fires `js-cors-wildcard/permissive-origin-config`. |
| `test_js_cors_wildcard_flags_origin_null` | True positive: `cors({ origin: null })` fires `js-cors-wildcard/permissive-origin-config`. |
| `test_js_cors_wildcard_silent_origin_true_credentials_false` | False positive guard: `cors({ origin: true, credentials: false })` — CodeQL's sanitizing pair — no finding. |
| `test_js_cors_wildcard_silent_specific_origin_string` | False positive guard (existing behavior unchanged): `cors({ origin: "https://trusted.example.com" })` — a specific origin string, not `true`/`null` — no finding. |

# Citations

[1] agentsec checklist item `6a-cors-restricted` (§6a)
[2] OWASP:A05
[3] SOC2:CC6.6
