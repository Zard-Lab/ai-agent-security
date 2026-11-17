---
type: Guard
title: "mcp-transport-no-auth"
description: "MCP server exposes an HTTP/SSE/Streamable-HTTP transport with no authentication."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "mcp-transport-no-auth"
checklist_section: ["4"]
standards: ["OWASP:A01", "OWASP:A07", "OWASP-ASI:ASI04"]
---

# MCP server exposes an HTTP/SSE transport with no authentication

_Author — 2026-09-21_

---

## The threat

An MCP server started with an HTTP, SSE, or Streamable-HTTP transport is a network-reachable,
mutation-capable RPC surface — every tool the server exposes becomes callable by anyone who can
reach the port, unless the server itself enforces authentication. Nothing in the MCP protocol
requires this; the reference SDKs ship it opt-in, not on by default, and a stdio-transport server
(spawned locally, no network exposure by construction) needs no such check at all — so the same
code pattern that is completely safe over stdio becomes a fully open RPC endpoint the moment it is
switched to a network transport with no auth added alongside it.

WHO reaches this: anyone who can route a request to the listening port — the public internet if
bound to `0.0.0.0`, or any other process/container on a shared host even when "internal."
WHAT privilege: every capability the server's tools expose, backed by whatever credentials the
server process itself holds (database access, cloud API keys, file system, a payment vault).
TO WHAT EFFECT: unauthenticated remote tool invocation — read, write, or destructive operations,
depending on what the server's tools do. Standards: OWASP:A01 (Broken Access Control), OWASP:A07
(Identification and Authentication Failures), OWASP-ASI:ASI04 (Agentic Supply Chain
Vulnerabilities — an unauthenticated agent-tool endpoint is exactly this class's shape).

This is a real, current, and recurring vulnerability class, not a theoretical one. Three real CVEs
of this exact shape were found and verified during this project's own MCP-server research effort:
CVE-2026-59971 (`mysql_mcp_server`, CVSS 10 — no `security_settings` configured at all, binds
`0.0.0.0` by default, giving an unauthenticated caller direct `cursor.execute()` access), CVE-2026-
44895 (GitLab MCP Server — SSE transport with no authentication and a wildcard CORS policy,
exposing 86 tools), and CVE-2026-54618 (an unauthenticated `/mcp` endpoint on a tunnel deployment
reaching a full credential vault's read/write/search/move/delete operations).

## Why it's often introduced / Why this guard fits the stack

Most MCP servers start life as a local, stdio-launched tool — spawned by a client like Claude
Desktop as a subprocess, with no network exposure to think about at all. The failure mode is what
happens when that same server is later exposed remotely (a shared team deployment, a hosted
integration, a Docker container with a published port) without anyone separately adding
authentication, because the original code simply never needed it:

```python
# Started life as a local stdio tool -- worked fine, no auth needed (spawned as a subprocess).
app = Server("my-tools")
app.run(transport="stdio")

# Later: "let's make this a shared team server" -- transport swapped, auth never added.
app.run(transport="sse", host="0.0.0.0", port=8080)
```

The second version is a straightforward, easy-to-miss upgrade: the developer's mental model is
"same tools, just reachable over HTTP now," not "I am publishing an unauthenticated RPC endpoint
with database/filesystem/API access to the network." Nothing in the MCP SDK's API surface forces
the question — `.run(transport="sse", ...)` works identically whether or not auth is configured.

## Detection design

1. **`applies()` gate:** `"mcp" in profile.features`, plus any of python/javascript/typescript.
   Originally Python-only (the official Python SDK / FastMCP idiom); (sentrymcp's
   `MCPA-AUTH-NOAUTH-JS-001`, fetched and read in full) widened this to also cover JS/TS source
   (see Known bypasses for the still-uncovered config/Dockerfile-launched variant of this class).
2. **Files scanned (Python):** `python_scan_dirs(root, profile)` + `iter_files(d, (".py",))`,
   `is_nonproduct_path` filtered — the same plain-text Python source scan several sibling MCP
   guards use. No AST. The shared walker skips `.venv`/`site-packages`/`node_modules` and nested
   worktrees; a bare `rglob` here once read every vendored file and reported a vendored MCP server
   as this repo's (#1042).
   **Files scanned (JS/TS):** `iter_files(root, (".js", ".jsx", ".ts", ".tsx"))`,
   `is_nonproduct_path` filtered — same plain-text scan, different extension set.
3. **Patterns, Python (all three must hold in the same file):**
   - `_HTTP_TRANSPORT` — an HTTP/SSE/Streamable-HTTP transport setup signal:
     `SSEServerTransport`, `StreamableHTTPServerTransport`, `sse_app(`, or
     `.run(...transport="sse"|"streamable-http"|"http"...)`. The `.run(` body between the paren
     and `transport=` is a bounded `[^)]{0,2000}`. The bound keeps the scan linear on untrusted
     input: an unbounded `[^)]*` is O(n^2) on a file of unterminated `.run(` runs. The `[^)]`
     class stops the match at the call's own `)`, so a `transport=` after the call never counts.
   - `_LOOPBACK_HOST` — its ABSENCE is required to fire: an explicit `host="127.0.0.1"` /
     `"localhost"` / `"::1"` exempts the file. An explicit non-loopback bind, an unset host, or a
     host read from config/env are all treated the same (fire) — the SDKs' own default bind is
     not loopback-only either, so "no explicit host" is not a safe default to assume.
   - `_AUTH_MARKER` — its ABSENCE anywhere in the file is required to fire: `Authorization`,
     `Bearer`, the SDK's own `AuthSettings`/`TokenVerifier`/`auth_provider`, FastAPI-style
     `Depends(`/`Security(` injection some servers wrap the transport in, `api_key`/`apiKey`,
     `oauth`, `require_auth`, plus the JS/TS-idiomatic camelCase spellings
     `verifyToken(`/`checkAuth(`/`requireAuth`/`authenticate(`/`X-API-Key` (shared across both
     the Python and JS/TS scan paths — `requireAuth` has no underscore, so it never matched the
     pre-existing `require_auth\b`). Deliberately broad — favors signal over precision the same
     way `mcp-tool-unverified`'s own trust-marker check does.
4. **Patterns, JS/TS (all three must hold in the same file):**
   - A transport call. `_JS_HTTP_TRANSPORT_MCP_SPECIFIC` (`new SSEServerTransport(`) counts on
     its own. `_JS_HTTP_TRANSPORT_GENERIC` (`app.listen(` or `createServer(`) counts only when
     `_JS_MCP_SIGNAL` also matches in the SAME file: an import from
     `@modelcontextprotocol/sdk/server/...`, `StreamableHTTPServerTransport`,
     `SSEServerTransport`, or `new McpServer(`. So a plain Express API elsewhere in an MCP repo
     does not fire (H1 of the #1058 review), and neither does a file whose only MCP mention is a
     comment, a bare `McpServer` string label, or an MCP **client** import (round-2 M2). The
     transport call and the MCP signal are both read from `strip_js_comments` output, so a
     commented-out `app.listen(` does not count either. Strings are not blanked for the MCP
     signal, so a string that quotes the server import path still counts; the transport call
     itself must be live code on the anchor mask (#1055). The two silencers below read live code
     too, not the raw text (#1055).
   - `_JS_LOOPBACK_HOST` — its ABSENCE is required to fire: an explicit
     `.listen(port, "127.0.0.1"|"localhost"|"::1")` in live code exempts the file.
   - `_AUTH_MARKER`: the same shared marker set as the Python path (above), credited when the
     match is live code or sits in a string literal that is one whitespace-free token (a header
     name, an env key, a package name or module path).
5. **Inline opt-out pragma:** `# security: allow-mcp-transport-no-auth` (Python) /
   `// security: allow-mcp-transport-no-auth` (JS/TS), checked once per file through
   `pragma_present` (`dialect="python"` / `dialect="js"`), so it counts only as a comment: a
   string that quotes it does not suppress (H2 of the #1058 review).
6. **Severity/standards:** `critical`, `["OWASP:A01", "OWASP:A07", "OWASP-ASI:ASI04"]`. Rule ids:
   `mcp-transport-no-auth/http-transport-unauthenticated` (Python),
   `mcp-transport-no-auth/js-http-transport-unauthenticated` (JS/TS).

## When NOT to flag

- **stdio-only servers.** No network exposure by construction — the guard's `_HTTP_TRANSPORT`
  pattern never matches a file that only calls `.run(transport="stdio")` (or omits `transport=`
  entirely, since stdio is the SDK's own default).
- **An explicit loopback bind** (`host="127.0.0.1"`/`"localhost"`/`"::1"`) — not reachable from
  another host, exempted regardless of whether auth is present.
- **Any real auth marker present anywhere in the file** (in JS/TS: live code or a one-token
  string literal, never a comment or a sentence; the Python path still reads raw text). Even
  with a bind-all host, the guard
  treats the presence of `Authorization`/`Bearer`/`AuthSettings`/etc. as evidence *some*
  authentication mechanism is wired, rather than trying to prove it is wired to every route.

Use the pragma (`# security: allow-mcp-transport-no-auth` in Python,
`// security: allow-mcp-transport-no-auth` in JS/TS) for an audited, intentional case (e.g. a
server that is deliberately open by design, behind a separately-managed network-layer gate this
guard cannot see — a reverse proxy enforcing auth, a private VPC with no other tenants).

## Tests

| Test | What it checks |
|---|---|
| `test_flags_sse_transport_with_no_auth_marker` | SSE transport, bind-all, no auth marker — fires |
| `test_flags_streamable_http_transport_with_unset_host` | Streamable-HTTP transport, no explicit host at all — still fires (mirrors the real CVE-2026-59971 shape) |
| `test_stdio_only_server_does_not_fire` | FP-bait: stdio transport only — no network exposure |
| `test_explicit_loopback_bind_does_not_fire` | FP-bait: explicit `host="127.0.0.1"` |
| `test_auth_provider_present_does_not_fire` | FP-bait: `TokenVerifier` import present, even with bind-all |
| `test_bearer_token_check_marker_does_not_fire` | FP-bait: an `Authorization`/`Bearer` check elsewhere in the file |
| `test_non_mcp_http_server_does_not_fire` | FP-bait: a plain unrelated Python HTTP server, no MCP transport signal |
| `test_pragma_suppresses_finding` | the inline pragma silences the finding |
| `test_applies_requires_mcp_and_python_features` | `applies()` gate — `mcp` required, plus any of python/javascript/typescript |
| `test_js_flags_app_listen_with_no_auth_marker` | JS: `app.listen(8080, '0.0.0.0')`, no auth marker — fires |
| `test_ts_flags_sse_server_transport_with_no_auth_marker` | TS: `new SSEServerTransport(...)`, no auth marker — fires |
| `test_js_silent_with_loopback_bind` | FP-bait: `.listen(8080, 'localhost')` exempt |
| `test_js_silent_with_camelcase_auth_marker` | FP-bait: `requireAuth` (camelCase, not in the pre-existing marker list) silences the finding |
| `test_js_silent_on_unrelated_listen_call` | FP-bait: an event-bus `.listen(` in a stdio MCP server file is not a network transport |
| `test_js_silent_on_generic_listen_with_no_mcp_signal_in_file` | FP-bait: a plain Express `app.listen(` with no MCP signal in the file stays silent (H1) |
| `test_js_cross_file_auth_in_sibling_file_still_silences` | multi-file: an Express API with auth from a third file stays silent, the real MCP server file still fires (H1) |
| `test_js_silent_with_loopback_bind_behind_nested_call` | FP-bait: `.listen(Number(process.env.PORT), '127.0.0.1')` is exempt (H1) |
| `test_js_pragma_suppresses_finding` | the `//` pragma silences a JS finding (H2) |
| `test_js_pragma_in_string_does_not_suppress` | a string quoting the pragma does not suppress (H2) |
| `test_js_silent_when_the_mcp_signal_is_not_a_server` | FP-bait: an MCP mention in a comment, a string, or an SDK client import does not make an Express listener fire (round-2 M2) |
| `test_js_silent_when_the_only_listen_call_is_commented_out` | FP-bait: a commented-out `app.listen(` in a stdio MCP server stays silent (round-2 M2) |
| `test_js_still_fires_on_a_real_mcp_server_listener` | a server-subpath import, a low-level `Server` import, or a wrapped `new McpServer(` with a public listener still fires (round-2 M2) |
| `test_unrelated_security_helper_no_longer_masks_finding` | an unrelated `configure_security(` helper is not an auth marker (`\b`-anchored `Depends(`/`Security(`), so the guard still fires |
| `test_real_fastapi_security_dependency_still_silences` | FP-bait: a real `Depends(get_current_user)` / `Security(oauth2_scheme)` still silences |
| `test_multiline_run_transport_anchors_to_the_run_line` | a multi-line `.run(` finding points at the `.run(` line, not line 1 |
| `test_kwarg_heavy_run_with_transport_past_300_chars_still_fires` | a kwarg-heavy `.run(` whose `transport=` sits more than 300 chars in still fires |
| `test_closed_run_then_unrelated_transport_literal_does_not_fire` | FP-bait: a closed stdio `.run()` followed by an unrelated `transport='sse'` stays silent |
| `test_http_transport_regex_is_not_superlinear` | (slow) 128k unterminated `.run(` runs scan in linear time |
| `test_many_transport_signals_stay_linear` | (slow) a file of many transport signals scans in linear time (asserts the growth class) |

## Known bypasses

- **JS/TS credits read live code (#1055).** The loopback bind and the auth marker used to be read from the raw text, so `// TODO: Authorization not wired yet` or `console.log('TODO: add Bearer auth')` silenced a CRITICAL. Both now need a live-code anchor (`js_code_matches`), and the transport call does too. A marker inside a string literal that is one whitespace-free token still credits (`'Bearer '`, `'x-api-key'`, `'x-mcp-api-key'`, `process.env['MCP_API_KEY']`, `'express-oauth2-jwt-bearer'`, `'./middleware/requireAuth'`), because a header name, scheme, env key, package name or module path is a string by nature. The same word inside a sentence (a literal with inner spaces) does not, and neither does a comment. Accepted residuals: any other one-token literal holding a marker credits too, which covers a URL (`'https://example.com/oauth/callback'`), an error code (`'missing_authorization'`, `'Authorization-header-missing'`) and a one-token log key (`'TODO:add-Bearer-auth'`, pinned by `test_js_single_token_log_literal_credits_accepted_trade`); every such literal also credited on main, so the rule is never wider than before (PR #1126 round-2 N2); the Python branch still reads raw text, so a `# Bearer` comment silences it (the #424 family); and the anchor mask inherits the #543 sub-lexer residual: a `{` inside a regex or comment in one `${...}` substitution, then a `}` in a later one, rebalances the frame, so the code between the two reads as template text and an anchor there is not code (the accepted trade pinned by `test_strip_js_comments_anchor_mask_balanced_desync_masks_code_accepted_trade`).

- **JS/TS coverage is narrower than the Python rule's own HTTP-transport vocabulary.**
  The JS/TS sink list (`SSEServerTransport`/`app.listen(`/`createServer(`) does not include a
  JS/TS equivalent of `StreamableHTTPServerTransport`/`sse_app(` — a Node/TS server using only
  the TypeScript SDK's `StreamableHTTPServerTransport` class directly (not wrapped in an
  Express/Hono `app.listen(`) is not recognized. Accepted scope boundary, matching the sink set
  sentrymcp's own `MCPA-AUTH-NOAUTH-JS-001` ships with.
- **An MCP server reached only through a local re-export.** The JS/TS same-file signal needs an
  import from `@modelcontextprotocol/sdk/server/...`, a transport class, or `new McpServer(`. A
  file that does `import { McpServer } from './mcp/index.js'` and constructs the server elsewhere,
  then calls `app.listen(`, carries none of them and is not flagged (round 3 of the #1058 review).
- **Config/CLI/Dockerfile-launched exposure is not covered.** CVE-2026-23744 (MCP Inspector) was
  reached via a config file or CLI flag (`--host 0.0.0.0`), not Python source at all — this guard
  only reads `.py` source files, not `mcp.json`/Docker Compose/Dockerfiles.
- **Whole-file marker check, not a real trust-boundary proof.** A file that imports
  `TokenVerifier` for cosmetic/unused reasons, or checks `Authorization` on an unrelated route,
  silences a genuinely unauthenticated MCP transport in the same file — the guard has no
  data-flow tracking to confirm the marker actually gates the transport in question.
- **Indirection.** A host value assembled from config/env and passed through a variable
  (`host = get_config("bind_host"); app.run(transport="sse", host=host)`) is not resolved back to
  its source — the guard only recognizes a `host=` literal string directly on the call.
- **A call inside `.run(` before `transport=`.** The `[^)]` body stops at the first `)`, so
  `mcp.run(host=os.getenv("HOST"), transport="sse")` or `port=int(os.environ["PORT"])` ahead of
  `transport=` hides the transport. For a high-level FastMCP server, that `.run(` is the only
  transport signal, so the file goes silent. Putting `transport=` first is still detected. Tracked
  in #933.
- **`transport=` more than 2000 characters past `.run(`.** This is the ReDoS bound (see Detection
  design). A realistic 12-kwarg call is about 240 characters, so reaching the bound takes a very
  heavily commented call.

## What this guard does NOT prove

- That an auth marker's presence means authentication is *correctly* implemented — a
  `TokenVerifier` subclass that always returns `True`, or a Bearer-token check with a hardcoded
  bypass, silences this guard exactly like a real one would.
- That a loopback-bound server is safe from every angle — DNS rebinding (a separate, already-
  researched MCP gap class) can still reach a loopback-only server from a malicious webpage in a
  browser on the same host; this guard's loopback exemption is about direct network reachability,
  not DNS-rebinding-class attacks.
- That the underlying deployment has network-layer protections (a firewall, a VPN, a reverse
  proxy enforcing its own auth) this guard cannot see from source alone — those are legitimate
  reasons to use the pragma, not gaps this guard claims to close.

# Citations

[1] agentsec checklist item `4-mcp-transport-auth` (§4)
[2] OWASP:A01, OWASP:A07, OWASP-ASI:ASI04
[3] CVE-2026-59971 (mysql_mcp_server, CVSS 10)
[4] CVE-2026-44895 (GitLab MCP Server)
[5] CVE-2026-54618 (unauthenticated /mcp endpoint reaching a credential vault)
[6] sentrymcp `MCPA-AUTH-NOAUTH-JS-001` (zaydmulani09/sentrymcp)
