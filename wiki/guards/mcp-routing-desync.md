---
type: Guard
title: "mcp-routing-desync"
description: "MCP SEP-2243 routable header (Mcp-Method/Mcp-Name) used for routing with no cross-check against the JSON-RPC body method."
timestamp: "2026-10-21T00:00:00Z"
guard_id: "mcp-routing-desync"
checklist_section: ["4"]
standards: ["CWE-441", "OWASP:A01", "OWASP-ASI:ASI01"]
---

# MCP SEP-2243 routable header used for routing with no body cross-check

_Author — 2026-09-22_

---

## The threat

The MCP spec's 2026-07-28 revision adds routable request metadata headers under SEP-2243:
`Mcp-Method` and `Mcp-Name` let a proxy or gateway route and pre-authorize a JSON-RPC call
purely from the HTTP header, without having to parse the request body first — a real
performance and architecture win for a gateway fronting many MCP servers.

The hazard is a confused-deputy / request-smuggling desync (CWE-441, Unintended Proxy or
Intermediary): a proxy makes a routing or authorization decision from the `Mcp-Method`/
`Mcp-Name` HEADER, but the authoritative JSON-RPC BODY carries a DIFFERENT `method`/tool `name`.
Concretely: a caller sends `Mcp-Method: tools/list` (a read-only, gateway-allowed operation) as
the header, while the request BODY actually says `{"method": "tools/call", "params": {"name":
"delete_all_records"}}`. If the gateway trusts the header for its allow/deny decision and then
forwards the raw body downstream, the header gate passes on the innocuous-looking method while
the body executes the privileged one. WHO reaches this: any client able to send an HTTP request
to the gateway/proxy. WHAT privilege: whatever the body's ACTUAL method grants, bypassing
whatever restriction the header-based gate was meant to enforce. TO WHAT EFFECT: privilege
escalation past a header-based access-control layer — exactly the shape a WAF/gateway rule
written against the header, rather than the body, would miss entirely.

## Why it's often introduced / Why this guard fits the stack

The routable header exists specifically so a proxy CAN avoid parsing the body — that's the whole
performance point of SEP-2243. The natural, fast implementation reads the header, checks it
against an allow-list or dispatch table, and routes — exactly the shape the spec enables, and
exactly the shape that's unsafe unless the header is also cross-checked against the body before
the routing decision is trusted for anything security-relevant:

```python
ALLOWED_METHODS = {"tools/list", "resources/list"}

def route(request):
    mcp_method = request.headers.get("mcp-method")   # fast path: trust the header
    if mcp_method not in ALLOWED_METHODS:
        raise PermissionError("blocked")
    return dispatch(request.json())                  # ...but the BODY's method is never checked
```

The fix is one extra comparison, but it's easy to miss precisely because the header exists to
make body-parsing optional — adding "parse the body anyway, just to check it matches" can look
like it defeats the point of the header in the first place, when in fact skipping that check is
what makes the header actively dangerous rather than merely a hint.

## Detection design

1. **`applies()` gate:** `"mcp" in profile.features`.
2. **Files scanned:** `iter_files(root, (".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
   ".rs", ".go", ".java"))` — the widest language set of any MCP guard in this project, since a
   gateway/proxy fronting MCP traffic is plausible in any of these ecosystems.
3. **Deterministic, offline regex — no AST.** The real source's own design choice, carried
   through faithfully: the three signals below are string/attribute reads of a header name, a
   shape regex captures cleanly; AST wouldn't add precision here the way it does for a
   data-flow-shaped check.
4. **File-level MCP-context gate (`_MCP_HINT`):** the file must reference
   `modelcontextprotocol`, `FastMCP`, `McpServer`, an `@mcp.`/`mcp.server` marker, `from mcp`/
   `import mcp`, `jsonrpc`/`json-rpc`, `tools/call`, `tools/list`, or `mcpServers` — so an
   unrelated web app with a similarly-named header never fires.
5. **Three signals, ALL required (`_check_file`):**
   - **(1) Header read (`_HEADER_READ_RE`):** `headers.get("Mcp-Method")`/`headers["mcp-name"]`,
     a bare `.get("mcp-method")`, `request.headers` / `req.headers`/`req.get` near the header
     name, the WSGI/Django env form `HTTP_MCP_METHOD`/`HTTP_MCP_NAME`, or a header-map literal
     key (`"mcp-method": ...`/`"mcp-method" => ...`).
   - **(2) Routing use (`_ROUTING_USE_RE`):** `route`/`router`/`dispatch`/`dispatcher`/
     `handler(s)`/`resolve`/`forward`; `allow(ed)`/`deny`/`denied`/`authorize(d)`/`permit`/
     `acl`/`allowlist`/`whitelist`/`is_allowed`; `Mcp-Method` compared with `in`/`==`/`===`/
     `!=`/`!==`; an `if`/`switch` on `mcp_method`/`mcp-method`; or `ROUTES`/`HANDLERS`.
   - **(3, negated) Body cross-check (`_BODY_CROSSCHECK_RE`):** any of a body/payload/message/
     rpc/request/data/params `.get("method")`/`["method"]` read, a `.method` comparison against
     `mcp_method`, an `assert` mentioning `mcp_method`, or a named
     `header_body_match`/`method_matches_body`/`validate_routing` helper — presence SUPPRESSES
     the finding.
   - **Live code only, in JS/TS (#1055).** Signals (1) and (3) count only when the match starts
     in live code on the shared anchor mask (`strip_js_comments(..., strip_strings=True,
     keep_substitutions=True)`), including code inside a `${...}` substitution, or in a string
     literal whose content is one identifier-shaped token (`'mcp-method'`, `'HTTP_MCP_METHOD'`),
     the same rule `mcp-toolgate-asymmetry` applies (its Python H-7b fix). A header name is a
     string by nature, so `req.headers['mcp-method'] !== body.method` still credits and a
     header-map key (`{ 'mcp-method': dispatch }`) still fires: the key's opening quote is a real
     delimiter. Prose does not count: `log.info('TODO: msg.method === mcpMethod check')` no longer
     clears the finding and `log.debug('req.headers mcp-method is ignored')` no longer fires one.
     Every match is tried, so a quoted copy cannot hide a real one after it. The `_MCP_HINT` gate
     (a module specifier is a string) and the routing-use window (a `'denied'` reply is routing
     evidence) keep reading strings. `.rs` files are excluded from the filter (see Known bypasses).
6. **Inline opt-out pragma:** `# security: allow-mcp-routing-desync` (or
   `// security: allow-mcp-routing-desync` in TS/JS/Go/Rust/Java), file-level. It is matched as a
   plain substring, so it works in any comment syntax (PR #923 round-3 M5: a `#`-anchored regex
   silently ignored the `//` form).
7. **Severity/standards:** `high`, `["CWE-441", "OWASP:A01", "OWASP-ASI:ASI01"]`. Rule id:
   `mcp-routing-desync/header-body-desync`.

## When NOT to flag

- **No MCP-context marker in the file** — the file-level gate exists exactly for this, so an
  unrelated app using a similarly-named header does not fire.
- **The header is read but never used for a routing/authorization decision** (e.g. only logged)
  — `_ROUTING_USE_RE` requires an actual dispatch/allow/deny/if-switch signal.
- **A cross-check against the body's own `method` is present anywhere in the file** — this is
  the correct guard, and the real source's own FP-rate contract is built around exactly this
  case staying silent.
- **The file routes purely on the JSON-RPC body's `method` field and never reads the
  `Mcp-Method`/`Mcp-Name` header at all** — no header-read signal, so the file never reaches the
  routing-use check.
- An audited, intentional case suppressed with the inline pragma.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_header_routing_without_body_crosscheck` | Fires: routes on `Mcp-Method` with no cross-check against the body's `method` |
| `test_fires_on_ts_header_dispatch` | Fires: the same shape in TypeScript (a `ROUTES[mcpMethod]` dispatch table) |
| `test_body_crosscheck_present_is_safe` | FP-bait: a file that asserts the header equals the body method stays silent |
| `test_header_read_but_not_used_for_routing_is_safe` | FP-bait: the header is only logged, never used for routing/authz |
| `test_no_mcp_context_is_safe` | FP-bait: no MCP-context marker in the file stays silent |
| `test_no_header_read_is_safe` | FP-bait: routing purely on the body's own `method` field (never reads the header) stays silent |
| `test_pragma_suppresses_finding` | the inline pragma silences the finding |
| `test_pragma_suppresses_finding_in_ts_file` | the `//` pragma form suppresses in a TS file (fire-then-silence pair) |
| `test_guard_not_applicable_without_mcp_feature` | `applies()` is False without the `mcp` feature |
| `test_guard_applicable_with_mcp_feature` | `applies()` is True with the `mcp` feature |
| `test_nonproduct_path_skipped` | files under `tests/fixtures/` are skipped |
| `test_js_quoted_crosscheck_no_longer_clears` | #1055 FN direction: a cross-check spelled in a log/error string or template text no longer clears the finding |
| `test_js_real_crosscheck_still_clears` | a real cross-check still clears, including a quoted header name, one nested in `${...}`, and one after a quoted copy on the line |
| `test_js_single_identifier_literal_crosscheck_credits_accepted_trade` | the accepted trade: a one-token log literal (`'validate_routing'`) still credits |
| `test_js_header_read_spelled_in_a_string_does_not_fire` | #1055 FP direction: a header read named in a docs string does not fire |
| `test_js_real_header_read_still_fires` | a real read still fires: header-map key, inside `${...}`, after a quoted copy, `'HTTP_MCP_METHOD'` env key |
| `test_rust_lifetime_keeps_the_plain_read` | `.rs` keeps the pre-#1055 read: two lifetimes on a line would otherwise mask the header read between them |

## Known bypasses

- **Cross-file routing.** The header-read, routing-use, and body-crosscheck signals must all
  appear in the SAME file. A gateway that reads the header in one module and does the body
  cross-check in a different module (a shared middleware helper) is not recognized — same
  same-file limitation every regex-based guard in this project documents.
- **Non-literal header name.** A header name built dynamically (`headers.get(HEADER_NAME_CONST)`
  where `HEADER_NAME_CONST = "mcp-method"` is defined elsewhere) is not recognized — the regex
  requires the literal string.
- **Case/spelling variants beyond the curated set.** The header-read pattern covers the common
  access idioms (`.get(`, `[...]`, the WSGI env form, a literal map key) but an unusual custom
  header-parsing library's own accessor shape is not recognized.
- **Presence-based cross-check, not control-flow-verified.** A body-crosscheck marker present
  ANYWHERE in the file — even in a dead code path, a different function, or a commented-out
  block that regex comment-stripping doesn't apply here — silences the finding, without proving
  it actually runs before the routing decision. Comments are blanked before any signal runs
  (the M-3 fix), and in JS/TS a cross-check spelled out in a string no longer counts (#1055).
- **String anchoring is JS/TS only (#1055).** A cross-check or header read must start in live code,
  or in a one-identifier string literal. Accepted residuals: a one-token literal holding a
  cross-check marker still credits (`log.info('validate_routing')`, pinned by
  `test_js_single_identifier_literal_crosscheck_credits_accepted_trade`), which also credited on
  main; `.rs` files go through the same JS lexer, where two lifetimes on one line
  (`&'a str = ...; f::<'a>(m)`) pair up as a phantom string, so Rust keeps the pre-#1055 read and
  its quoted-text FN/FP (Python, Go and Java use their own strippers and are unchanged); and the
  anchor mask inherits the #543 sub-lexer residual: a `{` inside a regex or comment in one
  `${...}` substitution, then a `}` in a later one, rebalances the frame, so the code between the
  two reads as template text and an anchor there is not code (the accepted trade pinned by
  `test_strip_js_comments_anchor_mask_balanced_desync_masks_code_accepted_trade`).

## What this guard does NOT prove

- That a recognized body-crosscheck marker actually executes before the routing decision is
  acted on — see "Presence-based cross-check" above.
- That the gateway's OWN cross-check logic is itself correct (e.g. a case-sensitive string
  comparison that silently fails to match `tools/list` against `Tools/List`) — this guard only
  proves a cross-check marker is present, not that it's implemented correctly.
- That every SEP-2243 consumer in a polyglot codebase is covered — a language or framework
  outside this guard's `_SCAN_EXTS` set (Ruby, PHP, C#, etc.) gets no coverage.

# Citations

[1] agentsec checklist item `4-mcp-routing-desync` (§4)
[2] CWE-441
[3] OWASP:A01
[4] OWASP-ASI:ASI01
[5] MCP spec 2026-07-28 revision, SEP-2243 (`Mcp-Method`/`Mcp-Name` routable request metadata)
[6] agent-audit-kit (sattyamjjain/agent-audit-kit), `mcp_routing_desync.py`
