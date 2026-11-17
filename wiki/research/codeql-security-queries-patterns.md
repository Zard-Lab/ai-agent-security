---
type: Research
title: GitHub CodeQL Security Queries — Agentic Security Patterns
description: Statically-detectable security patterns distilled from GitHub CodeQL's Python and JavaScript Security query packs, covering TLS verification, weak crypto keys, cookie attributes, error-response information exposure, sensitive-data logging, cleartext secret storage, regex/LDAP/XPath/header injection, JavaScript prototype pollution, log-injection interpolation styles, query-string secret exposure, broken HTML sanitizers, auth-endpoint rate limiting, LLM system-prompt injection, client-side open redirect, insecure download URLs, archive extraction (Zip Slip), session fixation, file check-then-use races, CSRF middleware absence, TLS certificate validation on Node/Express, hostname/URL allowlist regex safety, incomplete URL scheme/substring checks, overly permissive regex ranges, incorrect suffix checks, CORS credential reflection, JWT verification bypass, Host-header email poisoning, loop-bound DoS, and HTTP-response-to-filesystem writes.
tags: [research, cwe, injection, xss, llm]
timestamp: "2026-08-09T00:00:00Z"
---

# GitHub CodeQL Security Queries — Agentic Security Patterns

# What this covers

CodeQL is an interprocedural dataflow analysis engine — a fundamentally different detection
technique from agentsec's regex/AST-based guards. Its Python and JavaScript Security query
packs encode precise semantic conditions (a value flows from a specific source to a specific
sink, with specific sanitizers recognized along the way) that a regex approximation can only
ever partially reconstruct. This document distills the query *descriptions and vulnerability
classes* from thirty-six Security-category queries and maps each to a same-line or same-block
heuristic approximation, in the same spirit as the earlier Semgrep and LlamaIndex research
passes in this wiki. Distilled across four research passes.

# TLS / Certificate Validation

| Pattern | What it catches | Detection approach |
|---|---|---|
| `verify=False` on `requests`/`httpx` calls | The common case — explicit cert-verification opt-out | Same-line regex on the call arguments |
| `ssl._create_unverified_context()` | The documented stdlib bypass | Direct call-site match |
| `<ctx>.check_hostname = False` | Hostname matching disabled on an `SSLContext` | Attribute-assignment match |
| `verify_mode`/`cert_reqs` set to `CERT_NONE` | Certificate chain check disabled entirely (`SSLContext` or urllib3 pool) | Keyword/constant match, both quoted-string and `ssl.CERT_NONE` forms |
| aiohttp `ssl=False` / `verify_ssl=False` | Same failure, aiohttp's client API | Kwarg match, scoped to files that import aiohttp |
| SSH host-key policy set to `AutoAddPolicy`/`WarningPolicy` (paramiko) | Accepts unknown host keys — MITM exposure | Call-site match on `set_missing_host_key_policy(` |

# Cryptographic Key Strength

| Pattern | What it catches | Detection approach |
|---|---|---|
| RSA/DSA key generated below 2048 bits | Breakable with realistic compute — factoring/discrete-log attacks are practical against small keys today | Numeric compare on `RSA.generate(<bits>)`/`DSA.generate(<bits>)` (pycryptodome) and `generate_private_key(..., key_size=<bits>)` (the `cryptography` library) |

Elliptic-curve key weakness (a weak named curve rather than a numeric key size) is a
different detection shape — a curve-name allowlist, not a numeric threshold — and is not
covered by the pattern above.

# Cookie Security Attributes

| Pattern | What it catches | Detection approach |
|---|---|---|
| Missing `HttpOnly` / `Secure` | JS-readable session cookie / cookie sent over plaintext HTTP | Balanced-paren argument scan of `set_cookie(...)`, multi-line calls included |
| `SameSite` explicitly set to `"None"` on a sensitive cookie | Deliberately re-enables cross-site delivery of a session/auth-named cookie — the exact CSRF exposure `SameSite` exists to prevent | Quoted-string match (`"none"`/`'None'`), distinguished from the unquoted Python `None` sentinel (many frameworks' "leave the attribute unset" default, a different and safe behavior), scoped to session/auth/token/csrf-named cookies |

# Information Exposure via Error Responses

| Pattern | What it catches | Detection approach |
|---|---|---|
| `detail=str(e)`/`repr(e)`/f-string in an `HTTPException` `detail=` kwarg | Internal exception message, file paths, and query structure returned to the caller on an unhandled 5xx | Keyword-argument text match, gated on the enclosing status code (a 4xx is treated as an intentional validation-error echo) |
| `traceback.format_exc()` reaching a response sink | The full Python stack trace, including source lines, returned to the caller | Sink-reachability check within a short lookahead window |
| Exception stringified into a `return`/`JSONResponse(...)`/`Response(...)`/`content=` sink outside an `HTTPException` `detail=` kwarg | The same leak via a dict literal or a bare framework response constructor, e.g. `return JSONResponse({"error": str(e)})` | Per-`except`-block scan for the bound exception variable reaching a response-shaped sink; a bare `return <value>` alone is deliberately excluded, since it matches non-HTTP code paths too broadly (ordinary functions that catch and return an error value) |

# Sensitive Data Logging and Storage

| Pattern | What it catches | Detection approach |
|---|---|---|
| Full request body logged | Credentials/PII inside a logged request payload | Match on `request.body`/`.json`/`.data`/`.form`/`.stream`/`await request.json()` inside a logging call's arguments |
| Full request header set logged | `Authorization`/`Cookie` ride inside the headers dict without ever appearing as a matched field name | Match on `request.headers`/`dict(request.headers)`, excluding a single `.get(...)`/`[...]` extraction of one specific header |
| Recognized secret/PII field name logged | Password/token/API-key/card-number values reaching a logging call | Field-name marker set matched against a "code view" of the logged arguments (string-literal prose stripped, f-string interpolations kept) |
| Secret written to a cookie value | A password/private key/credential-named value stored client-side, where a session token belongs instead | Bare-identifier match on `set_cookie("name", <value>)`'s value argument, excluding opaque-bearer-value names (token/session_id/api_key) |
| Secret written to a plaintext file | A password/private key/credential persisted unencrypted on disk | Bare-identifier match on `<file>.write(<value>)`/`.write_text(<value>)`, excluding names that look already-protected (hashed/encrypted/digest/cipher prefixes or suffixes) |

Both storage checks require the value argument to be a bare identifier, not a nested call —
`f.write(encrypt(secret))` is deliberately not matched, trading recall for precision (the
same trade a name-based heuristic has to make when it cannot evaluate what a wrapped call
does).

# Regex Injection

| Pattern | What it catches | Detection approach |
|---|---|---|
| The regex PATTERN (not the subject string) built from an f-string, concatenation, or `.format()` | An attacker-controlled regex can be made to match or reject arbitrary input, regardless of whether it also backtracks catastrophically — a distinct bug class from ReDoS | Call-site match on `re.compile`/`match`/`search`/etc. requiring the pattern argument to show dynamic construction, unless `re.escape()` appears on the same line |

This is a same-file, same-call-site check — a pattern assembled on one line and passed in via a
variable on a later line is not covered, the same limitation every check in this document shares.

# LDAP Injection

| Pattern | What it catches | Detection approach |
|---|---|---|
| An LDAP search's base-DN or filter argument built from an f-string/concatenation/`.format()` | LDAP filter/DN syntax injection, altering which directory entries match — an auth-bypass risk when the query gates access | Call-site match on `search_s`/`search_ext_s` (distinctive method names) or a bare `search(` carrying `search_base=`/`search_filter=` kwargs, unless `escape_dn_chars`/`escape_filter_chars` appears on the same line |

A bare `.search(` alone is too generic a signal on its own — it collides with unrelated APIs
(the standard library's own regex `search` call among them) — so it only counts as an LDAP sink
when paired with LDAP-specific keyword arguments.

# XPath Injection

| Pattern | What it catches | Detection approach |
|---|---|---|
| An XPath expression built from a template-literal interpolation, concatenation, or a direct `location.hash`/`location.search` reference | Altered node matching or boolean/union-based XPath injection — the XML analogue of SQL injection | Call-site match on the `xpath` package's `parse`/`select`/`select1`/`useNamespaces`, or the DOM's `document.evaluate`/`createExpression` |

# HTTP Header Injection

| Pattern | What it catches | Detection approach |
|---|---|---|
| A response-header value written from request-derived input without newline-stripping | Response splitting / additional-header injection via an unescaped CRLF in the value | Subscript-assignment match on `.headers[...] =` where the assigned value references a request-derived source, unless `.replace('\n', ...)` appears on the same line |

The outgoing-header direction of the same taint sources logging-injection checks already cover
for the log-write direction — a distinct sink, not overlapping coverage.

# CORS Origin-Regex Bypass

| Pattern | What it catches | Detection approach |
|---|---|---|
| `allow_origin_regex` set to a catch-all pattern (`.*`, `.+`, `^.*$`) | Functionally identical to a wildcard `allow_origins=["*"]` — many frameworks treat a matching origin-regex the same as an explicit allow-list entry — without ever containing the literal wildcard string a simpler check looks for | Pattern-body match on the quoted regex value, after stripping optional anchors/grouping |

# JavaScript Prototype Pollution

| Pattern | What it catches | Detection approach |
|---|---|---|
| `obj[key] = value` where `key` is a computed expression referencing request input | Setting the key to `"__proto__"`/`"constructor"`/`"prototype"` mutates the object prototype itself, affecting every object in the process — impact ranges from privilege escalation to remote code execution depending on what the polluted property later gates | Subscript-assignment match on a request-derived computed key, unless a `__proto__`/`constructor`/`prototype` denylist check or `hasOwnProperty` guard appears nearby |
| A merge/extend/deepmerge-style call fed `JSON.parse(request-body)`-derived data | The same pollution reached via a recursive merge rather than a direct assignment — the shape behind a number of real npm supply-chain advisories | Call-site match on common merge/extend helper names, requiring a request-derived argument |

# Log Injection — Eager Interpolation Styles

| Pattern | What it catches | Detection approach |
|---|---|---|
| A request-derived value baked into a log message via string concatenation, `.format()`, or eager `"..." % value` — not just an f-string | The same CRLF log-forging risk as f-string interpolation, expressed with a different formatting mechanism | Same-line regex requiring a logging call, a request-derived value, and one of: `+` concatenation, `.format(`, or a quote character immediately followed by `%` |

Lazy `%`-style logging (`logger.info("User %s logged in", value)` — value passed as a
separate positional argument, the mechanism the logging module itself recommends) is
deliberately excluded: the `%` operator only signals risk when it appears immediately after
the closing quote of the message string, which is the eager-formatting shape, not the lazy one.

# Query-String Secret Exposure — the Receiving Side

| Pattern | What it catches | Detection approach |
|---|---|---|
| A route handler declares a secret-sounding parameter bound to a query-string binding (`password: str = Query(...)`) | The endpoint itself requires callers to place a secret in the URL — every legitimate call then logs it in server/proxy access logs, browser history, and Referer headers, not just a developer's outbound `requests` misuse | Parameter-declaration match: a secret-sounding identifier (`api_key`/`token`/`secret`/`password`/`auth`/…) bound to a query-string parameter constructor, with or without a type annotation |

This complements a same-shaped outbound-construction check (a URL/HTTP-client call embedding
a secret in its query string) by covering the opposite direction: the endpoint's own contract
mandating query-string secret transport.

# Broken HTML Sanitizers

| Pattern | What it catches | Detection approach |
|---|---|---|
| A non-global, single-occurrence string-replace call stripping a literal tag string (e.g. removing `<script>` once) | Bypassable by nesting the tag: the target string reassembles once an outer, later-processed copy is stripped, since only the first match is removed | Non-global replace-call match on a stripped substring that looks like an HTML/script tag, with an empty replacement; a global flag or an explicit "replace all" call is excluded |
| A generic wildcard regex used to strip HTML tags altogether (e.g. matching "any character between angle brackets") | HTML is not a regular language — a wildcard tag-matcher cannot correctly handle an attribute value containing `>`, nested/malformed markup, or a comment wrapping a tag, regardless of how many passes are made | Call-site match requiring a wildcard construct (a repetition operator or a negated character class) inside an angle-bracket span, with an empty replacement |

These are two distinct mistakes, not the same one expressed twice: the first is about removal
*count* (fixable by removing globally instead of once); the second is about the *matching
technique itself* being fundamentally unable to tokenize arbitrary HTML, a limitation no
amount of additional passes resolves.

# Auth-Endpoint Rate Limiting

| Pattern | What it catches | Detection approach |
|---|---|---|
| A route whose path or handler name looks auth-sensitive (login, registration, password reset, token issuance) with no rate-limiting signal anywhere in the same file | Brute-force / credential-stuffing exposure on the exact class of endpoint attackers target first, when no cost-based signal (an LLM call, in the sibling check this extends) happens to also be present | Route-decorator match on the path string or the immediately-following handler name against an auth-sensitive keyword set, absent any recognized rate-limiting library import or decorator in the file |

# Coverage Summary

| Category | Detection technique difference from CodeQL | Coverage |
|---|---|---|
| TLS/certificate validation | Same-line regex vs. interprocedural dataflow to any cert-disabling sink | Same-line and same-file idioms covered; a value passed through an intermediate variable before reaching the disabling call is not |
| Cryptographic key strength | Numeric compare on literal bit-count arguments | RSA/DSA numeric key size covered; elliptic-curve weak-curve selection is a different, uncovered shape |
| Cookie attributes | Balanced-paren single-call argument scan | HttpOnly/Secure/SameSite-presence and SameSite=None-on-sensitive-cookie covered; flags set via a config object or framework default are not |
| Error-response exposure | Per-line and per-except-block text match | HTTPException `detail=` kwarg and non-kwarg response sinks (dict literal, `JSONResponse`/`Response` constructor) covered; a value re-wrapped through more than one intermediate variable is not |
| Sensitive data logging/storage | Marker-word and code-view text matching | Request body, full header set, and a fixed secret-field marker list covered; a field outside the marker set, or a value routed through a custom wrapper function, is not |
| Regex/LDAP/XPath injection | Same-line dynamic-construction detection vs. interprocedural taint tracking | A pattern/query built inline in the same call is covered; one assembled on an earlier line and passed via a variable is not |
| HTTP header injection | Subscript-assignment match vs. dataflow to any header-write sink | A direct `.headers[...] =` write from a same-line source is covered; a framework's constructor-kwarg header form (`Response(headers={...})`) is not |
| CORS origin-regex bypass | Pattern-body match on the quoted regex | A catch-all regex (`.*`/`.+`, with or without anchors) is covered; a broader-than-intended but non-catch-all regex is deliberately left unflagged |
| JavaScript prototype pollution | Same-line computed-key / merge-call match vs. dataflow with flow-state tracking | A direct request-derived computed-key assignment or an inline merge call is covered; a key/payload assembled on an earlier line is not |
| Log injection (eager interpolation styles) | Same-line formatting-mechanism match vs. dataflow to any log-write sink | f-string, concatenation, `.format()`, and eager `%` are covered; a value built across multiple lines or passed through an intermediate variable is not |
| Query-string secret exposure (receiving side) | Parameter-declaration match vs. dataflow from a route's inbound binding | A directly-declared query-string parameter with a secret-sounding name is covered; a parameter registered through a non-declarative binding style is not |
| Broken HTML sanitizers | Non-global replace-call and wildcard-pattern match vs. dataflow to a rendering sink | A single-occurrence literal-tag strip and a generic wildcard tag-matcher are both covered; a compiled-pattern object's replace method (rather than a direct call) is not |
| Auth-endpoint rate limiting | Same-file route-decorator and keyword match vs. dataflow to a rate-limiting middleware | A directly-decorated route with an auth-sensitive path or handler name is covered; a route registered through a non-decorator style, or an unusual path/name that doesn't match the keyword set, is not |
| Archive extraction (Zip Slip, JS/Node) | Same-call match vs. dataflow from an archive-entry name to a filesystem write | A direct bulk-unpack call (`.extractAllTo(`/`.extractAll(`) with no nearby containment check is covered; a manual per-entry extraction loop is not |
| Session fixation on login | Route-path keyword + bounded-window presence/absence match vs. dataflow through the session object across the login flow | A route whose path string names "login" is covered; a login handler defined elsewhere and referenced by name at the route registration site is not |
| File check-then-use race (TOCTOU) | Same-identifier match across a bounded window vs. dataflow/basic-block-dominance analysis | A check and use on a bare path identifier within the window is covered; a call-expression or property-access path argument, or a use beyond the window, is not |
| CSRF middleware absence (session-based, JS/Node) | Repo-wide marker presence/absence text match vs. dataflow from a cookie-using route through its middleware chain | `express-session`/`cookie-session` presence and CSRF-library-marker absence are covered; a custom hand-rolled CSRF scheme with no recognized marker string reads as absent |
| Exception details in an HTTP response (JS/Node) | Catch-block-scoped sink match vs. dataflow from the caught exception to any response-shaped sink | `res`/`response` sinks within a bounded lookahead of the `catch` are covered; a response object reassigned to a differently-named variable is not |
| TLS certificate validation disabled (JS/Node) | Same-line option-key / env-var match vs. dataflow to any cert-disabling sink | `rejectUnauthorized: false` and the `NODE_TLS_REJECT_UNAUTHORIZED` env var are covered; a value passed through an intermediate variable before reaching either is not |
| Hostname/URL allowlist regex unsafe | Regex-literal text scan (unescaped-dot + missing-anchor) vs. dataflow through a hostname-regex library | A regex assigned to a hostname-ish name or tested with a hostname-ish argument is covered; a differently-named variable or an indirect context signal is not |
| Incomplete URL scheme blocklist | File-wide presence/absence text match vs. dataflow tracking every equivalent scheme-comparison shape | A `javascript:` check alongside a missing `vbscript:`/`data:` literal is covered; a check written in non-lowercase or built from concatenation is not |
| Raw URL substring checked against a trusted domain | Same-line three-part gate (URL-ish receiver + domain literal + no parse evidence) vs. dataflow to a fetch/redirect sink | A same-line `.includes`/`.indexOf`/`.startsWith` check is covered; a receiver reassigned to a generic name, or a domain built from a constant, is not |
| Overly permissive regex character range | Literal substring match on 3 known bad-range spellings vs. general character-category dataflow analysis | `[A-z]`/`[0-Z]`/`[0-z]` are covered; a bad range outside this specific set is not |
| Incorrect suffix check (homemade endsWith) | Same-line backreference match vs. dataflow tracking equivalent indexOf calls and companion -1 checks across the function | A same-line, same-receiver/same-argument comparison is covered; a companion check elsewhere that already neutralizes the bug is not recognized, so this guard is more willing to fire than CodeQL's own query |

# Examples

```python
# FLAGGED: ssl module's documented cert-verification bypass
ctx = ssl._create_unverified_context()

# FLAGGED: RSA key below the 2048-bit floor
key = RSA.generate(1024)

# FLAGGED: SameSite explicitly disabled on a session cookie
response.set_cookie("session_id", token, httponly=True, secure=True, samesite="none")

# FLAGGED: exception reaches a JSONResponse dict literal, not an HTTPException detail= kwarg
except Exception as e:
    return JSONResponse({"error": str(e)}, status_code=500)

# FLAGGED: full request headers logged, leaking Authorization/Cookie
logger.info(request.headers)

# FLAGGED: a raw password value stored as a cookie
response.set_cookie("remember", password)

# SAFE: session token (not a raw secret) stored as a cookie value — the correct pattern
response.set_cookie("token", raw_token)

# SAFE: a single, non-sensitive header extracted and logged
logger.info(request.headers.get("User-Agent"))

# FLAGGED: the regex pattern itself built from unescaped user input
pattern = re.compile(f"^{user_input}$")

# SAFE: the untrusted portion escaped before reaching the pattern
pattern = re.compile(f"^{re.escape(user_input)}$")

# FLAGGED: LDAP filter built from an f-string, unescaped
conn.search_s("ou=users,dc=example,dc=com", ldap.SCOPE_SUBTREE, f"(uid={username})")

# FLAGGED: response header written from a request header, no newline-stripping
response.headers["X-Trace-Id"] = request.headers["X-Client-Trace-Id"]

# FLAGGED: allow_origin_regex is a catch-all, functionally identical to a wildcard
app.add_middleware(CORSMiddleware, allow_origin_regex=r".*", allow_credentials=True)

# FLAGGED: eager string concatenation carries the same CRLF-forging risk as an f-string
logging.info("User " + request.headers["X-User"] + " logged in")

# SAFE: lazy %-style logging — the value is a separate positional argument
logger.info("User %s logged in", request.headers["X-User"])

# FLAGGED: the endpoint's own contract requires the secret in the query string
def login(password: str = Query(...)): ...

# FLAGGED: a wildcard regex used to strip HTML tags generically
clean = re.sub(r"<.*?>", "", user_input)

# FLAGGED: an auth-sensitive route with no rate-limiting import or decorator anywhere in the file
@router.post("/login")
async def login(creds: dict) -> dict: ...
```

```javascript
// FLAGGED: computed property key taken directly from request input
obj[req.body.key] = req.body.value;

// SAFE: a denylist check on the dangerous key names
if (["__proto__", "constructor", "prototype"].includes(key)) return;
obj[key] = req.body.value;

// FLAGGED: recursive merge fed parsed request-body data
merge(target, JSON.parse(req.body.data));

// FLAGGED: a single-occurrence literal-tag strip — bypassable by nesting the tag
const clean = userInput.replace("<script>", "");

// SAFE: global removal — every occurrence is stripped, not just the first
const clean = userInput.replace(/<script>/gi, "");
```

# LLM System-Prompt Injection (JS/TS SDKs)

A `{role: "system", content: ...}` message sent to an LLM whose `content` is built
from request-derived input lets an attacker manipulate the model's own
instructions, not just the user-facing conversation — a stronger form of prompt
injection than tainted user-role content (which is often the normal, expected
shape of a chatbot).

| Pattern | What it catches | Detection approach |
|---|---|---|
| Tainted `content` in a `role: "system"`/`"assistant"` message | Request-derived input (`req.query`/`body`/`params`/`headers`) reaching a system/assistant-role prompt across the OpenAI/Anthropic/Google GenAI/OpenRouter JS/TS SDKs | Find a `role:` line, scan forward for `content:` referencing tainted input, stopping at the next `role:` line (a sibling message object) so a `role: "user"` message's tainted content is never misattributed to a preceding system message |

```javascript
// FLAGGED: system prompt persona interpolates raw request input
const messages = [
  { role: "system", content: `You are a helpful assistant for ${req.query.persona}` },
  { role: "user", content: userMessage },
];

// SAFE: tainted content in the user-role message is expected — a chatbot's whole point
const messages = [
  { role: "system", content: "You are a helpful assistant." },
  { role: "user", content: req.body.userMessage },
];
```

# Client-Side Open Redirect

The client-side counterpart to a server-side open redirect: frontend JS reading its
OWN current page URL (not a backend handler reading a request parameter) and using
it to navigate the browser elsewhere.

| Pattern | What it catches | Detection approach |
|---|---|---|
| `location.href`/`window.location`/`location.replace()`/`location.assign()` set from `location.search`/`document.URL`/`URLSearchParams(location.search)` | A crafted link's query string redirecting a visiting user's browser to an attacker-controlled site | Same-line regex (deliberately conservative — a two-statement form via an intermediate variable is not tracked, to avoid a wider window's cross-statement bleed-through risk) |

```javascript
// FLAGGED: redirect target taken directly from the page's own query string, inline
window.location.href = new URLSearchParams(location.search).get("next");

// SAFE: validated against a fixed allow-list before navigating
const next = new URLSearchParams(location.search).get("next");
if (ALLOWED_PATHS.includes(next)) window.location.href = next;
```

# Insecure Download of a Sensitive File Type

A literal `http://`/`ftp://` URL (not HTTPS) whose path ends in a dangerous file
extension is a man-in-the-middle target: an attacker on-path can substitute the
downloaded file with malicious content before it reaches the client.

| Pattern | What it catches | Detection approach |
|---|---|---|
| `http://`/`ftp://` URL ending in `exe`/`dmg`/`pkg`/`tar.gz`/`zip`/`sh`/`bat`/`cmd`/`app`/`apk`/`msi`/`js`/`py`/`jar`/`war` | An insecure-scheme download of an executable, archive, or script | Self-contained literal-string match — the insecure scheme + dangerous extension combination is a strong signal on its own, no call-context needed |

```javascript
// FLAGGED: installer downloaded over plain HTTP
const url = "http://cdn.example.com/installer.exe";

// SAFE: HTTPS
const url = "https://cdn.example.com/installer.exe";
```

# Express/Node Cookie Attributes

The JS-side counterpart to the Python cookie-flag pattern above: `res.cookie(name, value,
{...})` missing `httpOnly`/`secure`, or explicitly setting `sameSite: 'none'` on a
sensitive-named cookie.

| Pattern | What it catches | Detection approach |
|---|---|---|
| `res.cookie(...)`/`response.cookie(...)` missing `httpOnly: true` or `secure: true` in the options object | A session/auth cookie readable by JS (XSS steals it) or sent over plain HTTP | Options-object scan, scoped to a `res`/`response`-named receiver (not `document.cookie` or an unrelated `.cookie(` method) |
| `sameSite: 'none'` on a cookie whose name looks sensitive (session/auth/token/csrf) | Re-enabled cross-site request riding — the exact CSRF exposure SameSite exists to prevent | Same options-object scan, gated to sensitive-sounding cookie names only |

```javascript
// FLAGGED: missing httpOnly
res.cookie('session_id', token, { secure: true });

// SAFE: all three flags present
res.cookie('session_id', token, { httpOnly: true, secure: true, sameSite: 'lax' });
```

# CORS Credential Reflection (Manual Header Echo)

A handler that manually echoes the request's own `Origin` header back as
`Access-Control-Allow-Origin` — never going through a CORS middleware package at all —
combined with `Access-Control-Allow-Credentials: true` set anywhere in the same file.
Functionally identical to a permissive `origin: true` + `credentials: true` config, but
constructed by hand and therefore invisible to a config-object-scoped check.

| Pattern | What it catches | Detection approach |
|---|---|---|
| `res.set('Access-Control-Allow-Origin', req.headers.origin)` co-occurring with `res.set('Access-Control-Allow-Credentials', 'true')` in the same file | Any-origin-with-credentials via hand-rolled header logic, not the `cors` npm package | File-scoped: the two header calls are typically separate statements, not one config object |

```javascript
// FLAGGED: origin reflected + credentials enabled
res.set('Access-Control-Allow-Origin', req.headers.origin);
res.set('Access-Control-Allow-Credentials', 'true');

// SAFE: explicit allowlisted origin
res.set('Access-Control-Allow-Origin', 'https://app.example.com');
res.set('Access-Control-Allow-Credentials', 'true');
```

# JWT Verification Disabled (Node jsonwebtoken)

The Node `jsonwebtoken` package has a footgun distinct from the Python
algorithm-confusion pattern above: passing the literal `false` as the second argument
(the secret/public key) to `jwt.verify()` disables signature verification entirely —
any token, forged or not, verifies.

| Pattern | What it catches | Detection approach |
|---|---|---|
| `jwt.verify(token, false, ...)` | A complete signature-verification bypass, not just an unpinned algorithm | Single-line regex: a literal boolean `false` as the key argument |

```javascript
// FLAGGED: verification completely disabled
return jwt.verify(token, false);

// SAFE: real secret/key
return jwt.verify(token, process.env.JWT_SECRET);
```

# Sensitive Data in a GET Query String (Express Receiving Side)

The Express-side counterpart to a FastAPI route declaring a secret-sounding parameter via
`Query(...)`: a route handler reading a secret-named value straight off `req.query`. Every
legitimate call then logs the secret in server access logs, proxy logs, browser history, and
Referer headers.

| Pattern | What it catches | Detection approach |
|---|---|---|
| `req.query.password` / `req.query['api_key']` (dot or bracket form) with a boundaried secret-name stem | A route requiring the caller to place a secret in the URL query string | Boundaried stem match against the accessed property name (`key` alone deliberately excluded — `cache_key`/`sort_key` false-positive history) |

```javascript
// FLAGGED
app.get('/login', (req, res) => {
  const pw = req.query.password;
});

// SAFE: not secret-sounding
app.get('/search', (req, res) => {
  const id = req.query.id;
});
```

# Host Header Poisoning in Email Generation

The HTTP `Host` header is fully attacker-controlled on the attacker's own request. If a
handler builds a link embedded in an outgoing email (password reset, invite, verification)
from `req.headers.host` / `req.get('host')` / `req.hostname`, poisoning that header on the
triggering request causes a link a *different, real* user receives to point at an
attacker-controlled domain — full account takeover via one crafted request.

| Pattern | What it catches | Detection approach |
|---|---|---|
| `req.headers.host`/`req.get('host')`/`req.hostname` spliced into a URL (a `://` scheme marker on the same line) inside a file that also sends email (`.sendMail(`/`nodemailer`) | A poisoned Host header hijacking a password-reset/invite/verification link | File-scoped mail-context gate + same-line host-header-into-URL check |

```javascript
// FLAGGED
const link = `https://${req.headers.host}/reset?token=${token}`;
await transporter.sendMail({ to: user.email, html: link });

// SAFE: trusted, configured base URL
const link = `https://${process.env.APP_BASE_URL}/reset?token=${token}`;
await transporter.sendMail({ to: user.email, html: link });
```

# Loop Bound Injection

Iterating a `for`/`while` loop up to a `.length` read directly off request-controlled data
(`req.body`, `req.query`, `req.params`) lets an attacker choose how many iterations the
server performs per request — a single-request denial-of-service, no amplification needed.

| Pattern | What it catches | Detection approach |
|---|---|---|
| A comparison operator immediately adjacent to `req.(query\|body\|params)....length` inside a `for(`/`while(` header | Unbounded, attacker-sized iteration per request | Same-line adjacency check — a `Math.min(...)`-capped bound naturally doesn't match, since the token right after the operator is the cap function, not `req.` |

```javascript
// FLAGGED: unbounded
for (let i = 0; i < req.body.items.length; i++) { process(req.body.items[i]); }

// SAFE: explicit ceiling
for (let i = 0; i < Math.min(req.body.items.length, MAX_ITEMS); i++) { process(i); }
```

# HTTP Response Data Written to the Filesystem

Writing an HTTP response body straight to disk — with no validation of content, size, or
integrity — hands whoever controls the remote server (or a MITM, or a redirect chain) an
arbitrary file write onto the app's own disk.

| Pattern | What it catches | Detection approach |
|---|---|---|
| `.pipe(fs.createWriteStream(...))` off an `http`/`https`/`axios`/`fetch` response, or `fs.writeFile(Sync)?(..., response.data)`/`(..., response.body)` | An unvalidated download saved directly to disk — a backdoor primitive | File-scoped HTTP-client gate + same-line streaming-pipe or buffered-write check |

```javascript
// FLAGGED: streaming
https.get(url, (response) => { response.pipe(fs.createWriteStream(dest)); });

// FLAGGED: buffered
const response = await axios.get(url, { responseType: 'arraybuffer' });
fs.writeFileSync(dest, response.data);
```

# Archive Extraction — Zip Slip (JS/Node)

| Pattern | What it catches | Detection approach |
|---|---|---|
| `.extractAllTo(`/`.extractAll(` (adm-zip, node-stream-zip) with no path-containment check nearby | A malicious archive's `../`-prefixed member names writing files outside the target directory | Same-call match, 5-line safe-pattern window (`path.resolve`/`.startsWith(`/a named safe-extract helper) |

Deliberately does not flag the `tar` npm package's `tar.extract({file, cwd})` — it validates
member paths internally since a 2021 CVE fix, so the same textual shape is already safe there.

# Session Fixation on Login

| Pattern | What it catches | Detection approach |
|---|---|---|
| A login-path route (`/login` anywhere in the route string) writing `req.session.*` with no `req.session.regenerate(` call nearby | An attacker who fixed the victim's session identifier before login inherits the now-authenticated session, since the identifier never changes at the authentication boundary | Route-path keyword match, session-write + regenerate-absence check within a bounded window |

No library-based exemption is carried (older guidance treated Passport as automatically safe;
current Passport ships its own built-in session-fixation protection, so the absence check
applies uniformly regardless of auth library).

# File Check-Then-Use Race (TOCTOU)

| Pattern | What it catches | Detection approach |
|---|---|---|
| `fs.exists*/stat*/lstat*/access*` on a path, followed by `fs.writeFile*/appendFile*/open*/readFile*` on the same path a few lines later | A filesystem entry that changes between the check and the use (a symlink swap, a concurrent write) redirects the later call to a different target than the one that was checked | Same-identifier match across a bounded window; an `exists`-then-`readFile` pair is exempted as a benign stale-read, not a corrupted-write-target risk |

# CSRF Middleware Absence (Session-Based, JS/Node)

| Pattern | What it catches | Detection approach |
|---|---|---|
| `express-session`/`cookie-session` used anywhere with no CSRF-protection marker (`csurf`/`lusca`/`tiny-csrf`/`csrf-csync`/a `doubleCsrf` config) anywhere in the same codebase | A cookie-authenticated Express app with no defence against cross-site state-changing requests | Repo-wide presence/absence marker scan, independent of any equivalent check on a different backend language in the same repo |

# Exception Details in an HTTP Response (JS/Node)

| Pattern | What it catches | Detection approach |
|---|---|---|
| A caught exception's `.message`/`.stack`/string coercion reaching a `res`/`response` sink within a `catch` block | Internal file paths, class names, or provider error payloads returned to the caller on an unhandled error | Catch-block-scoped sink match within a bounded lookahead, with the same 4xx-is-an-intentional-validation-echo exemption used on the equivalent backend-framework check |

# TLS Certificate Validation Disabled (JS/Node)

| Pattern | What it catches | Detection approach |
|---|---|---|
| `rejectUnauthorized: false` in an `https`/`tls` options object | The Node analog of a `verify=False` kwarg — trusts whatever certificate the server presents | Same-line option-key match |
| `process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"` | Disables certificate verification process-wide, for every outbound TLS connection, not just one client | Environment-variable assignment match |

# Hostname/URL Allowlist Regex Unsafe

| Pattern | What it catches | Detection approach |
|---|---|---|
| An unescaped `.` immediately before a domain suffix (`.com`/`.org`/etc) in a hostname-checking regex | `.` matches ANY character in a regex, so `trusted.com` also matches a lookalike like `trustedXcom` | Regex-literal text scan for a bare `.` (not preceded by `\`) before a TLD-like suffix, scoped to a hostname/URL-checking context |
| A hostname-checking regex with no trailing `$` anchor | The pattern matches a PREFIX of the tested value, so `trusted.com.evil.com` still satisfies `^https://trusted.com` | Checks the extracted pattern text for a trailing `$` |

Both mistakes are scoped to a regex assigned to a hostname-ish variable name, or tested
with a hostname-ish `.test()` argument — an unrelated form-validation regex elsewhere in
the file is not swept in.

# Incomplete URL Scheme Blocklist

| Pattern | What it catches | Detection approach |
|---|---|---|
| A blocklist check covering `javascript:` but not `vbscript:`/`data:` | All three schemes reach the same script-execution outcome when a browser navigates to or renders the value | File-wide presence/absence: a `javascript:` literal in a check-shaped context, with the other two literals checked for absence anywhere in the same file |

# Raw URL Substring Checked Against a Trusted Domain

| Pattern | What it catches | Detection approach |
|---|---|---|
| `url.includes("trusted.com")` (or `.indexOf`/`.startsWith`) on an unparsed URL | Bypassable via `evil.com/trusted.com`, `trusted.com.evil.com`, or `trusted.com@evil.com` — the check has no concept of "this is the hostname" | Same-line match: a URL-ish-named receiver, a domain-shaped string-literal argument, no evidence the value was already parsed into a hostname |

# Overly Permissive Regex Character Range

| Pattern | What it catches | Detection approach |
|---|---|---|
| `[A-z]` (and the sibling `[0-Z]`/`[0-z]` shapes) instead of `[A-Za-z]` | Silently admits six unintended ASCII punctuation characters between the letter-case boundary | Literal substring match on three well-known bad-range spellings — a context-independent correctness bug, unlike the other patterns here it needs no security-context signal |

# Incorrect Suffix Check (Homemade endsWith)

| Pattern | What it catches | Detection approach |
|---|---|---|
| `x.indexOf(y) === x.length - y.length` used to emulate `endsWith()` | Breaks silently when `indexOf` returns `-1` and the length difference also equals `-1` (y is exactly one character longer than x) — the check passes when the suffix isn't actually present | Same-line, same-receiver/same-argument backreference match; narrower than a full dataflow analysis — does not verify whether a companion `-1` check elsewhere already neutralizes the bug |

# Citations
[1] [CodeQL: Request without certificate validation](https://raw.githubusercontent.com/github/codeql/main/python/ql/src/Security/CWE-295/RequestWithoutValidation.ql)
[2] [CodeQL: Accepting unknown SSH host keys when using Paramiko](https://raw.githubusercontent.com/github/codeql/main/python/ql/src/Security/CWE-295/MissingHostKeyValidation.ql)
[3] [CodeQL: Use of weak cryptographic key](https://raw.githubusercontent.com/github/codeql/main/python/ql/src/Security/CWE-326/WeakCryptoKey.ql)
[4] [CodeQL: Sensitive cookie with SameSite attribute set to None](https://raw.githubusercontent.com/github/codeql/main/python/ql/src/Security/CWE-1275/SameSiteNoneCookie.ql)
[5] [CodeQL: Sensitive cookie missing HttpOnly attribute](https://raw.githubusercontent.com/github/codeql/main/python/ql/src/Security/CWE-1004/NonHttpOnlyCookie.ql)
[6] [CodeQL: Failure to use secure cookies](https://raw.githubusercontent.com/github/codeql/main/python/ql/src/Security/CWE-614/InsecureCookie.ql)
[7] [CodeQL: Information exposure through an exception](https://raw.githubusercontent.com/github/codeql/main/python/ql/src/Security/CWE-209/StackTraceExposure.ql)
[8] [CodeQL: Clear-text logging of sensitive information](https://raw.githubusercontent.com/github/codeql/main/python/ql/src/Security/CWE-312/CleartextLogging.ql)
[9] [CodeQL: Clear-text storage of sensitive information](https://raw.githubusercontent.com/github/codeql/main/python/ql/src/Security/CWE-312/CleartextStorage.ql)
[10] [CodeQL: XML internal entity expansion](https://raw.githubusercontent.com/github/codeql/main/python/ql/src/Security/CWE-776/XmlBomb.ql)
[11] [CodeQL: Regular expression injection](https://raw.githubusercontent.com/github/codeql/main/python/ql/src/Security/CWE-730/RegexInjection.ql)
[12] [CodeQL: LDAP query built from user-controlled sources](https://raw.githubusercontent.com/github/codeql/main/python/ql/src/Security/CWE-090/LdapInjection.ql)
[13] [CodeQL: Improper CORS misconfiguration for credentials transfer](https://raw.githubusercontent.com/github/codeql/main/javascript/ql/src/Security/CWE-346/CorsMisconfigurationForCredentials.ql)
[14] [CodeQL: Prototype-polluting assignment](https://raw.githubusercontent.com/github/codeql/main/javascript/ql/src/Security/CWE-915/PrototypePollutingAssignment.ql)
[15] [CodeQL: HTTP header injection](https://raw.githubusercontent.com/github/codeql/main/python/ql/src/Security/CWE-113/HeaderInjection.ql)
[16] [CodeQL: XPath injection](https://raw.githubusercontent.com/github/codeql/main/javascript/ql/src/Security/CWE-643/XpathInjection.ql)
[17] [CodeQL: Log injection](https://raw.githubusercontent.com/github/codeql/main/python/ql/src/Security/CWE-117/LogInjection.ql)
[18] [CodeQL: Sensitive data read from GET request](https://raw.githubusercontent.com/github/codeql/main/javascript/ql/src/Security/CWE-598/SensitiveGetQuery.ql)
[19] [CodeQL: Incomplete string escaping or encoding](https://raw.githubusercontent.com/github/codeql/main/javascript/ql/src/Security/CWE-116/IncompleteSanitization.ql)
[20] [CodeQL: Bad HTML filtering regexp](https://raw.githubusercontent.com/github/codeql/main/python/ql/src/Security/CWE-116/BadTagFilter.ql)
[21] [CodeQL: Missing rate limiting](https://raw.githubusercontent.com/github/codeql/main/javascript/ql/src/Security/CWE-770/MissingRateLimiting.ql)
[22] [CodeQL: System prompt injection](https://raw.githubusercontent.com/github/codeql/main/javascript/ql/src/Security/CWE-1427/SystemPromptInjection.ql)
[23] [CodeQL: Client-side URL redirect](https://raw.githubusercontent.com/github/codeql/main/javascript/ql/src/Security/CWE-601/ClientSideUrlRedirect.ql)
[24] [CodeQL: Download of sensitive file through insecure connection](https://raw.githubusercontent.com/github/codeql/main/javascript/ql/src/Security/CWE-829/InsecureDownload.ql)
[25] [CodeQL: Sensitive server cookie exposed to the client](https://raw.githubusercontent.com/github/codeql/main/javascript/ql/src/Security/CWE-1004/ClientExposedCookie.ql)
[26] [CodeQL: Sensitive cookie without SameSite restrictions](https://raw.githubusercontent.com/github/codeql/main/javascript/ql/src/Security/CWE-1275/SameSiteNoneCookie.ql)
[27] [CodeQL: JWT missing secret or public key verification](https://raw.githubusercontent.com/github/codeql/main/javascript/ql/src/Security/CWE-347/MissingJWTKeyVerification.ql)
[28] [CodeQL: Host header poisoning in email generation](https://raw.githubusercontent.com/github/codeql/main/javascript/ql/src/Security/CWE-640/HostHeaderPoisoningInEmailGeneration.ql)
[29] [CodeQL: Loop bound injection](https://raw.githubusercontent.com/github/codeql/main/javascript/ql/src/Security/CWE-834/LoopBoundInjection.ql)
[30] [CodeQL: Network data written to file](https://raw.githubusercontent.com/github/codeql/main/javascript/ql/src/Security/CWE-912/HttpToFileAccess.ql)
[31] [CodeQL: Arbitrary file access during archive extraction ("Zip Slip")](https://raw.githubusercontent.com/github/codeql/main/javascript/ql/src/Security/CWE-022/ZipSlip.ql)
[32] [CodeQL: Failure to abandon session](https://raw.githubusercontent.com/github/codeql/main/javascript/ql/src/Security/CWE-384/SessionFixation.ql)
[33] [CodeQL: Potential file system race condition](https://raw.githubusercontent.com/github/codeql/main/javascript/ql/src/Security/CWE-367/FileSystemRace.ql)
[34] [CodeQL: Missing CSRF middleware](https://raw.githubusercontent.com/github/codeql/main/javascript/ql/src/Security/CWE-352/MissingCsrfMiddleware.ql)
[35] [CodeQL: Information exposure through a stack trace (JS)](https://raw.githubusercontent.com/github/codeql/main/javascript/ql/src/Security/CWE-209/StackTraceExposure.ql)
[36] [CodeQL: Disabling certificate validation](https://raw.githubusercontent.com/github/codeql/main/javascript/ql/src/Security/CWE-295/DisablingCertificateValidation.ql)
[37] [CodeQL: Incomplete regular expression for hostnames](https://raw.githubusercontent.com/github/codeql/main/javascript/ql/src/Security/CWE-020/IncompleteHostnameRegExp.ql)
[38] [CodeQL: Missing regular expression anchor](https://raw.githubusercontent.com/github/codeql/main/javascript/ql/src/Security/CWE-020/MissingRegExpAnchor.ql)
[39] [CodeQL: Incomplete URL scheme check](https://raw.githubusercontent.com/github/codeql/main/javascript/ql/src/Security/CWE-020/IncompleteUrlSchemeCheck.ql)
[40] [CodeQL: Incomplete URL substring sanitization](https://raw.githubusercontent.com/github/codeql/main/javascript/ql/src/Security/CWE-020/IncompleteUrlSubstringSanitization.ql)
[41] [CodeQL: Overly permissive regular expression range](https://raw.githubusercontent.com/github/codeql/main/javascript/ql/src/Security/CWE-020/OverlyLargeRange.ql)
[42] [CodeQL: Incorrect suffix check](https://raw.githubusercontent.com/github/codeql/main/javascript/ql/src/Security/CWE-020/IncorrectSuffixCheck.ql)
