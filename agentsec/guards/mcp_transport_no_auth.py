"""Guard: MCP server publishes an HTTP/SSE transport with no authentication (checklist §4).

An MCP server started with an HTTP / SSE / Streamable-HTTP transport is a network-reachable,
mutation-capable RPC surface backed by whatever credentials/capabilities the operator gave the
server process. Unlike stdio transport (spawned locally, no network exposure by construction),
a network transport needs its OWN authentication — nothing in the MCP protocol enforces this,
and the reference SDKs ship it opt-in, not on by default.

This is distinct from every other MCP guard's scope:
  - `mcp-tool-unverified` checks whether a CLIENT trusts the servers it connects to.
  - `mcp-config-security` checks a server's declared CONFIG entry (command/env/autoApprove).
  - `mcp-tool-env-inheritance` checks a spawned subprocess's environment.
  - This guard checks whether the SERVER's OWN transport setup requires a caller to authenticate
    at all — a different failure mode: the server process itself has no gate.

Sourced from a real MCP-server static-analysis rule (`agent-audit-kit`'s
`AAK-MCP-HTTP-NOAUTH-SERVER-001`, content-verified before porting) and the real CVE record this
project's own research surfaced: CVE-2026-59971 (mysql_mcp_server, CVSS 10 — no `security_settings`
at all, binds `0.0.0.0` by default), CVE-2026-44895 (GitLab MCP Server — SSE transport with no
auth and wildcard CORS, exposing 86 tools), CVE-2026-54618 (an unauthenticated `/mcp` endpoint on
a tunnel deployment reaching a full credential vault's read/write/delete operations).

Fires CRITICAL when, in one file:
  1. an HTTP/SSE/Streamable-HTTP MCP transport is set up (`SSEServerTransport`,
     `StreamableHTTPServerTransport`, `sse_app(`, or `.run(transport="sse"|"streamable-http"|"http")`);
  2. the file does NOT explicitly bind to a loopback host (`host="127.0.0.1"`/`"localhost"`/`"::1"`)
     — an explicit `0.0.0.0`/`"::"` bind, an unset host, or a host read from config/env are all
     treated the same way, since the SDKs' own default bind is not loopback-only either; AND
  3. no authentication marker appears anywhere in the file (`Authorization`, `Bearer`,
     `auth_provider`/`AuthSettings`/`TokenVerifier` from the SDK's own auth module, `Depends(`/
     `Security(` FastAPI-style injection, `api_key`/`apiKey`, `oauth`/`OAuth`, `require_auth`).

All three conditions must hold — a server that only sets up stdio transport, one that explicitly
binds `127.0.0.1`/`localhost`, or one with ANY auth marker present anywhere in the file, does not
fire. This is a coarse, whole-file marker check (matching the verified real-world rule this was
sourced from), not a proof that authentication is correctly wired to every route — a file that
merely imports `Authorization` for an unrelated purpose silences the guard; that tradeoff favors
signal over precision the way `mcp-tool-unverified`'s own trust-marker check already does.

**JS/TS (ported from sentrymcp's `MCPA-AUTH-NOAUTH-JS-001`, fetched and read in full)
widens this guard beyond the Python-only scope above.** Fires CRITICAL under the same
all-three-conditions structure, for `.js`/`.jsx`/`.ts`/`.tsx` files:
  1. a `new SSEServerTransport(` call is present, or an `app.listen(`/`createServer(` call in a
     file that also carries an MCP SERVER signal in code (an import from
     `@modelcontextprotocol/sdk/server/...`, `StreamableHTTPServerTransport`, `SSEServerTransport`,
     or `new McpServer(`). A plain Express API in the same repo, a file whose only MCP mention is
     a comment or a bare `McpServer` string label, and an MCP client import do not count (H1 and
     round-2 M2 of the #1058 review). These signals are read from comment-stripped text, but
     strings are NOT blanked, so a string that quotes the server import path still counts. A
     bare `McpServer` imported from a local module, with no `new McpServer(` in the file, does
     not count either (a favor-silence miss). The transport call itself must be live code (#1055),
     so a string that spells out `new SSEServerTransport(` does not count;
  2. the file does NOT explicitly bind to a loopback host (`listen(port, "127.0.0.1"|"localhost"|"::1")`)
     in live code;
  3. no auth marker (the same shared `_AUTH_MARKER` vocabulary, widened with the JS/TS-idiomatic
     spellings `verifyToken(`/`checkAuth(`/`requireAuth`/`authenticate(`/`X-API-Key` — none of
     which the pre-existing Python-oriented marker list recognized, e.g. `requireAuth` has no
     underscore so it never matched the pre-existing `require_auth\b`) appears in the file as live
     code, or inside a string literal that is one whitespace-free token, such as `'Bearer '`,
     `'x-api-key'` or a package name like `'express-oauth2-jwt-bearer'`.

Since #1055, conditions 2 and 3 no longer read the raw text. A `// TODO: Authorization not wired
yet` comment, or the same words in a log string, used to silence the CRITICAL finding.

Config/Dockerfile launch-surface variants of this rule class (CVE-2026-23744 MCP Inspector,
reached via config/CLI flags rather than source) remain accepted as not yet covered, matching
this guard's sibling `mcp-config-security`'s own "does NOT re-detect" convention of naming scope
boundaries explicitly rather than silently.

Suppress an audited case with:

    # security: allow-mcp-transport-no-auth    (Python)
    // security: allow-mcp-transport-no-auth   (JS/TS)
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    js_anchor_is_code,
    js_code_matches,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    strip_js_comments,
)

# A bare string, not a `#`-anchored regex: `pragma_present`'s `comment_view` already confines the
# match to actual comment text per-dialect (Python `#`, JS/TS `//`), so a pragma that hardcodes the
# delimiter character is dead on any dialect using a different one (H2, #1058 review) — a JS/TS
# file can never write a `#` comment, so the JS side of this guard had no working opt-out at all.
# Mirrors the bare-string convention `mcp_tool_path_traversal.py`/`mcp_hardcoded_credential.py` use.
_PRAGMA = "security: allow-mcp-transport-no-auth"

# HTTP / SSE / Streamable-HTTP MCP transport setup signals.
_HTTP_TRANSPORT = re.compile(
    r"SSEServerTransport"
    r"|StreamableHTTPServerTransport"
    r"|sse_app\s*\("
    # `[^)]` matches newlines on its own (no DOTALL needed — the pattern has no bare `.`), so the bound
    # still spans a multi-line `.run(` whose `transport=` kwarg is a few lines down. The bound (vs an
    # unbounded `[^)]*`) is what keeps this linear on a `.py` full of unterminated `.run(` runs — the
    # same O(n^2)-on-untrusted-corpus-input class the sibling js-command-injection guard already pins.
    # 2000, not 300: a kwarg-heavy `.run(` can put `transport=` more than 300 chars past the paren, and
    # for a high-level FastMCP server this `.run(` branch is the ONLY transport signal, so a tight bound
    # silenced the whole file (PR #915 re-review). Still linear: `.run(`x128k measures ~0.26s.
    r"|\.run\s*\(\s*[^)]{0,2000}transport\s*=\s*['\"](?:sse|streamable-http|http)['\"]",
)

# Explicit loopback-only bind — exempt.
_LOOPBACK_HOST = re.compile(
    r"host\s*=\s*['\"](?:127\.0\.0\.1|localhost|::1)['\"]"
)

# Any auth-related marker anywhere in the file — presence silences the guard. Deliberately broad
# (favors signal over precision, matching the real-world rule this was sourced from): the official
# SDK's own auth primitives (`AuthSettings`, `TokenVerifier`, `auth_provider`), FastAPI-style
# dependency injection some servers wrap the transport in (`Depends(`, `Security(`), generic
# textual markers (`Authorization`, `Bearer`, `api_key`, `oauth`, `require_auth`), and the
# JS/TS-idiomatic camelCase spellings sentrymcp's own JS rule recognizes that the Python-oriented
# list above does not (`requireAuth` has no underscore, so it never matched `require_auth\b`).
_AUTH_MARKER = re.compile(
    r"Authorization\b"
    r"|\bBearer\b"
    r"|AuthSettings\b"
    r"|TokenVerifier\b"
    r"|auth_provider\b"
    # `\b`-anchored like every sibling token: without it, IGNORECASE makes an unrelated helper such
    # as `configure_security(` / `enable_depends(` match as a substring and silence a genuinely
    # unauthenticated transport (a false NEGATIVE on a CRITICAL). `\b` still matches `fastapi.Security(`,
    # `Security(oauth2_scheme)`, `Depends(get_current_user)` (a non-word char or line start precedes).
    r"|\bDepends\s*\("
    r"|\bSecurity\s*\("
    r"|api[_-]?key\b"
    r"|\boauth\b"
    r"|require_auth\b"
    r"|verifyToken\s*\("
    r"|checkAuth\s*\("
    r"|requireAuth\b"
    r"|authenticate\s*\("
    r"|X-API-Key",
    re.IGNORECASE,
)

# JS/TS HTTP/SSE/network-listener transport setup signals (sentrymcp's MCPA-AUTH-NOAUTH-JS-001).
# `new SSEServerTransport(` is inherently MCP-specific — no further gate needed. `app.listen(` and
# `createServer(` are bare Node/Express primitives that fire on ANY HTTP server in ANY JS/TS file
# of a repo that merely has the `mcp` feature detected somewhere (H1, #1058 review: a plain Express
# REST API file with auth wired via `app.use(authMiddleware)` imported from another file fired
# CRITICAL). So the generic pair is split out and additionally gated on `_JS_MCP_SIGNAL` being
# present in the SAME file — mirroring how the Python branch above requires its own transport
# signal (`SSEServerTransport`/`.run(transport=...)`) in one file, not repo-wide.
_JS_HTTP_TRANSPORT_MCP_SPECIFIC = re.compile(r"new\s+SSEServerTransport\s*\(")
_JS_HTTP_TRANSPORT_GENERIC = re.compile(r"app\.listen\s*\(|createServer\s*\(")
# A same-file MCP SERVER marker for the generic branch above: an import from the SDK's `server/`
# subpath, one of the two network transport classes, or a `new McpServer(` behind a local wrapper.
# Narrower than mcp_oauth_flow_hardening.py's multi-hop import-closure resolver (#1023) — this
# guard only needs a same-file signal, not a whole-dependency-graph one. Server-side on purpose
# (round-2 M2 of the #1058 review): the bare package name also matched an MCP CLIENT import, and a
# bare `McpServer` matched a string label. `run()` tests it on comment-stripped text, so a comment
# that only mentions the SDK does not count either.
_JS_MCP_SIGNAL = re.compile(
    r"@modelcontextprotocol/sdk/server\b"
    r"|StreamableHTTPServerTransport"
    r"|SSEServerTransport"
    r"|\bnew\s+McpServer\s*\("
)
# an explicit loopback bind passed to .listen( — exempt, mirroring _LOOPBACK_HOST above.
# Tolerates one level of balanced parens before the host literal (`s.listen(Number(process.env.PORT),
# "127.0.0.1")`) — the prior `[^)]{0,80}` stopped dead at the FIRST `)`, which is the inner call's
# own closing paren, not `.listen(`'s, so it never reached the host string at all (H1, #1058 review).
_JS_LOOPBACK_HOST = re.compile(
    r"\.listen\s*\(\s*(?:[^()]|\([^()]{0,80}\)){0,80}['\"](?:127\.0\.0\.1|localhost|::1)['\"]"
)
_QUOTES = "'\"`"


def _start(m: re.Match[str]) -> int:
    return m.start()


def _is_token_literal(code: str, mask: str, m: re.Match[str]) -> bool:
    """True if `m` sits in a string literal whose content is ONE whitespace-free token, give or take
    surrounding blanks: `'Bearer '`, `'x-mcp-api-key'`, `'express-oauth2-jwt-bearer'`,
    `process.env['MCP_API_KEY']`, `'./middleware/requireAuth'`. A header name, scheme, env key, package
    name or module path lives in a string by nature, while the same word inside a sentence
    (`console.log('TODO: add Bearer auth')`) is prose, and prose has inner spaces. The accepted cost
    is every other one-token literal holding a marker: a URL (`'https://x.example/oauth/cb'`), an
    error code (`'missing_authorization'`) or a one-token log key (`'TODO:add-Bearer-auth'`) credits
    too. Each of those credited on main (raw text), so this is never wider than before. Both
    delimiters must be live code on the anchor mask, so a quote that is itself string content
    (`"use 'Bearer' here"`) does not count."""
    i = m.start() - 1
    while i >= 0 and not code[i].isspace() and code[i] not in _QUOTES:
        i -= 1
    while i >= 0 and code[i] in " \t":
        i -= 1
    j = m.end()
    while j < len(code) and not code[j].isspace() and code[j] not in _QUOTES:
        j += 1
    while j < len(code) and code[j] in " \t":
        j += 1
    return (
        i >= 0
        and j < len(code)
        and code[i] in _QUOTES
        and code[j] == code[i]
        and js_anchor_is_code(code, mask, i)
        and js_anchor_is_code(code, mask, j)
    )


def _js_auth_marker(code: str, mask: str) -> bool:
    """The JS/TS auth credit (#1055): an `_AUTH_MARKER` hit counts when it is live code, or when it is
    inside a one-token string literal (`_is_token_literal`). It used to be read from the raw text, so a
    `// TODO: Authorization not wired yet` comment or a `'TODO: add Bearer auth'` log string silenced
    a CRITICAL finding."""
    return any(
        js_anchor_is_code(code, mask, m.start()) or _is_token_literal(code, mask, m)
        for m in _AUTH_MARKER.finditer(code)
    )


class McpTransportNoAuthGuard(Guard):
    id = "mcp-transport-no-auth"
    title = "MCP server exposes an HTTP/SSE transport with no authentication"
    area = "AI agent"

    # mcp_http_server.py: SSEServerTransport + host="0.0.0.0", no auth marker anywhere in the
    # file -> fires mcp-transport-no-auth/http-transport-unauthenticated (CRITICAL).
    # Must NOT contain: any of _AUTH_MARKER's tokens, and must NOT contain a loopback host.
    # mcp_http_server.js: app.listen(8080, '0.0.0.0'), with an MCP SDK import (H1's new same-file
    # anchor) and no auth marker anywhere in the file ->
    # fires mcp-transport-no-auth/js-http-transport-unauthenticated (CRITICAL).
    canary_plant = CanaryPlant(
        files={
            "mcp_http_server.py": (
                "from mcp.server.sse import SSEServerTransport\n"
                "from mcp.server import Server\n"
                "\n"
                "app = Server('canary-mcp')\n"
                "transport = SSEServerTransport('/messages')\n"
                "\n"
                "def main():\n"
                "    app.run(transport='sse', host='0.0.0.0', port=8080)\n"
            ),
            "mcp_http_server.js": (
                "const { StreamableHTTPServerTransport } = require('@modelcontextprotocol/sdk/server/streamableHttp.js');\n"
                "const express = require('express');\n"
                "const app = express();\n\n"
                "app.listen(8080, '0.0.0.0', () => console.log('listening'));\n"
            ),
        },
        expects=frozenset({
            "mcp-transport-no-auth/http-transport-unauthenticated",
            "mcp-transport-no-auth/js-http-transport-unauthenticated",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        if "mcp" not in profile.features:
            return False
        return bool({"python", "javascript", "typescript"} & profile.features)

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        if "python" in profile.features:
            for d in python_scan_dirs(root, profile):
                for f in iter_files(d, (".py",)):
                    if is_nonproduct_path(rel(root, f), profile.archive_segments):
                        continue
                    text = read(f)
                    if pragma_present(_PRAGMA, text, dialect="python"):
                        continue
                    transport = _HTTP_TRANSPORT.search(text)
                    if not transport:
                        continue
                    if _LOOPBACK_HOST.search(text):
                        continue
                    if _AUTH_MARKER.search(text):
                        continue
                    # Anchor to the EARLIEST transport-signal match from its offset rather than a per-line
                    # re-scan: a multi-line `.run(` whose `transport=` kwarg is on a later physical line
                    # matches the whole-file regex above but no single line, so the old line-loop left
                    # `lineno` at its `1` default and mis-pointed a CRITICAL finding at the file's first
                    # import. `search` already returns the leftmost match, so ONE `count` suffices — a
                    # `min` over `finditer` with a `count` per match was O(n^2) on a file of many signals.
                    lineno = text.count("\n", 0, transport.start()) + 1
                    out.append(Finding(
                        check_id=self.id,
                        severity="critical",
                        title="MCP server exposes an HTTP/SSE transport with no authentication",
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            "This file sets up an MCP server over an HTTP/SSE/Streamable-HTTP "
                            "transport with no authentication marker anywhere in the file. Such a "
                            "server is a network-reachable, mutation-capable RPC surface backed by "
                            "the operator's own tokens/capabilities, invokable by anyone who can "
                            "reach the port — no MCP-protocol mechanism enforces authentication on "
                            "its own (CVE-2026-59971, CVE-2026-44895, CVE-2026-54618 are real "
                            "incidents of exactly this shape)."
                        ),
                        remediation=(
                            "Require authentication on the transport before accepting tool calls — "
                            "the SDK's own `AuthSettings`/`TokenVerifier` auth provider, or wrap the "
                            "transport in middleware requiring a Bearer token / API key. If the "
                            "server is genuinely intended to be localhost-only, bind explicitly to "
                            "`127.0.0.1`/`localhost` rather than `0.0.0.0` or an unset host."
                        ),
                        rule="mcp-transport-no-auth/http-transport-unauthenticated",
                        standards=["OWASP:A01", "OWASP:A07", "OWASP-ASI:ASI04"],
                    ))
        if {"javascript", "typescript"} & profile.features:
            for f in iter_files(root, (".js", ".jsx", ".ts", ".tsx")):
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                text = read(f)
                if pragma_present(_PRAGMA, text, dialect="js"):
                    continue
                # Every signal reads code only (round-2 M2), and since #1055 the transport, the
                # loopback bind and the auth credit must also be anchored in live code, tested on
                # the anchor mask: a comment or a log string that names one is not one. The
                # `_JS_MCP_SIGNAL` gate keeps reading strings, since an import specifier is a string.
                # Layout is preserved across the views, so offsets match.
                code = strip_js_comments(text)
                if not (_JS_HTTP_TRANSPORT_MCP_SPECIFIC.search(code) or _JS_HTTP_TRANSPORT_GENERIC.search(code)):
                    continue
                mask = strip_js_comments(text, strip_strings=True, keep_substitutions=True)
                transport = next(js_code_matches(_JS_HTTP_TRANSPORT_MCP_SPECIFIC, code, mask, anchor=_start), None)
                if not transport:
                    generic = next(js_code_matches(_JS_HTTP_TRANSPORT_GENERIC, code, mask, anchor=_start), None)
                    if not generic or not _JS_MCP_SIGNAL.search(code):
                        continue
                    transport = generic
                if any(js_code_matches(_JS_LOOPBACK_HOST, code, mask, anchor=_start)):
                    continue
                if _js_auth_marker(code, mask):
                    continue
                lineno = text.count("\n", 0, transport.start()) + 1
                out.append(Finding(
                        check_id=self.id,
                        severity="critical",
                        title="MCP server exposes an HTTP/SSE transport with no authentication",
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            "This file sets up an MCP server over an HTTP/SSE transport "
                            "(`SSEServerTransport`/`app.listen(`/`createServer(`) with no "
                            "authentication marker anywhere in the file. Such a server is a "
                            "network-reachable, mutation-capable RPC surface invokable by anyone "
                            "who can reach the port — no MCP-protocol mechanism enforces "
                            "authentication on its own."
                        ),
                        remediation=(
                            "Require authentication on the transport before accepting tool "
                            "calls — verify a Bearer token or API key on every request. If the "
                            "server is genuinely intended to be localhost-only, bind explicitly "
                            "to `127.0.0.1`/`localhost` in the `.listen(` call."
                        ),
                        rule="mcp-transport-no-auth/js-http-transport-unauthenticated",
                        standards=["OWASP:A01", "OWASP:A07", "OWASP-ASI:ASI04"],
                    ))
        return out
